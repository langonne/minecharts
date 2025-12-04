package handlers

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"minecharts/cmd/auth"
	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/kubernetes"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const (
	websocketWriteWait        = 10 * time.Second
	websocketReadInitTimeout  = 15 * time.Second
	websocketPongWait         = 60 * time.Second
	websocketPingInterval     = 30 * time.Second
	minecraftLogContainerName = "minecraft-server"
)

var logsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type websocketSafeWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *websocketSafeWriter) writeJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.conn.WriteJSON(v)
}

func (w *websocketSafeWriter) writeControl(messageType int, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.conn.WriteControl(messageType, data, time.Now().Add(websocketWriteWait))
}

type logStreamRequest struct {
	ServerID int64 `json:"server_id"`
}

type logStreamResponse struct {
	Type    string `json:"type"`
	Data    string `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type websocketLogWriter struct {
	writer      *websocketSafeWriter
	messageType string
	onError     func(error)
}

func (w *websocketLogWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	msg := logStreamResponse{Type: w.messageType, Data: string(p)}
	err := w.writer.writeJSON(msg)
	if err != nil && w.onError != nil {
		w.onError(err)
	}

	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// LogsWebsocketHandler upgrades the connection to a WebSocket and streams Minecraft logs.
func LogsWebsocketHandler(c *gin.Context) {
	user, ok := auth.GetCurrentUser(c)
	if !ok || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	conn, err := logsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logging.Server.WithFields(
			"remote_ip", c.ClientIP(),
			"error", err.Error(),
		).Error("WebSocket upgrade failed for logs endpoint")
		return
	}

	go handleLogStreamConnection(conn, user)
}

func handleLogStreamConnection(conn *websocket.Conn, user *database.User) {
	defer conn.Close()

	safeWriter := &websocketSafeWriter{conn: conn}
	baseFields := []logging.Field{
		logging.F("domain", "Server"),
		logging.F("component", "ws_logs"),
		logging.F("user_id", user.ID),
		logging.F("username", user.Username),
	}
	mergeFields := func(extra ...logging.Field) []logging.Field {
		fields := make([]logging.Field, 0, len(baseFields)+len(extra))
		fields = append(fields, baseFields...)
		fields = append(fields, extra...)
		return fields
	}

	logging.WithFields(mergeFields()...).Info("WebSocket log stream connected")

	// Initial acknowledgement
	if err := safeWriter.writeJSON(logStreamResponse{Type: "status", Message: "connected"}); err != nil {
		return
	}

	// Read subscription request
	conn.SetReadLimit(1024)
	conn.SetReadDeadline(time.Now().Add(websocketReadInitTimeout))

	var req logStreamRequest
	if err := conn.ReadJSON(&req); err != nil {
		logging.WithFields(
			mergeFields(
				logging.F("stage", "read_subscription"),
				logging.F("error", err.Error()),
			)...,
		).Warn("Invalid subscription request")
		safeWriter.writeJSON(logStreamResponse{Type: "error", Message: "invalid subscription request"})
		return
	}
	if req.ServerID <= 0 {
		logging.WithFields(
			mergeFields(
				logging.F("stage", "validate_subscription"),
				logging.F("server_id", req.ServerID),
			)...,
		).Warn("Invalid server ID provided")
		safeWriter.writeJSON(logStreamResponse{Type: "error", Message: "invalid server id"})
		return
	}

	conn.SetReadDeadline(time.Now().Add(websocketPongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(websocketPongWait))
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go monitorClient(conn, cancel)
	go sendPing(ctx, safeWriter, cancel)

	db := database.GetDB()
	server, err := db.GetServerByID(context.Background(), req.ServerID)
	if err != nil {
		logging.WithFields(
			mergeFields(
				logging.F("server_id", req.ServerID),
				logging.F("error", err.Error()),
			)...,
		).Warn("Server not found for log streaming")
		safeWriter.writeJSON(logStreamResponse{Type: "error", Message: "server not found"})
		return
	}

	if !user.HasServerPermission(server.OwnerID, database.PermViewServer) {
		logging.WithFields(
			mergeFields(
				logging.F("server_id", req.ServerID),
				logging.F("owner_id", server.OwnerID),
			)...,
		).Warn("Permission denied for log streaming")
		safeWriter.writeJSON(logStreamResponse{Type: "error", Message: "permission denied"})
		return
	}

	pod, err := kubernetes.GetMinecraftPod(config.DefaultNamespace, server.StatefulSetName)
	if err != nil {
		logging.WithFields(
			mergeFields(
				logging.F("server_id", server.ID),
				logging.F("statefulset", server.StatefulSetName),
				logging.F("error", err.Error()),
			)...,
		).Error("Failed to locate server pod")
		safeWriter.writeJSON(logStreamResponse{Type: "error", Message: "failed to locate server pod"})
		return
	}

	if pod == nil {
		logging.WithFields(
			mergeFields(
				logging.F("server_id", server.ID),
				logging.F("statefulset", server.StatefulSetName),
			)...,
		).Warn("No pod available for server")
		safeWriter.writeJSON(logStreamResponse{Type: "error", Message: "server pod not available"})
		return
	}

	logging.WithFields(
		mergeFields(
			logging.F("server_id", server.ID),
			logging.F("statefulset", server.StatefulSetName),
			logging.F("pod_name", pod.Name),
		)...,
	).Info("Starting log streaming")

	if err := safeWriter.writeJSON(logStreamResponse{Type: "status", Message: "streaming"}); err != nil {
		return
	}

	stdoutWriter := &websocketLogWriter{
		writer:      safeWriter,
		messageType: "log",
		onError: func(streamErr error) {
			cancel()
		},
	}

	stderrWriter := &websocketLogWriter{
		writer:      safeWriter,
		messageType: "error",
		onError: func(streamErr error) {
			cancel()
		},
	}

	streamErr := kubernetes.StreamMinecraftLogs(ctx, pod.Name, config.DefaultNamespace, minecraftLogContainerName, stdoutWriter, stderrWriter)
	if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
		logging.WithFields(
			mergeFields(
				logging.F("server_id", server.ID),
				logging.F("statefulset", server.StatefulSetName),
				logging.F("pod_name", pod.Name),
				logging.F("error", streamErr.Error()),
			)...,
		).Error("Log streaming terminated with error")
		safeWriter.writeJSON(logStreamResponse{Type: "error", Message: "log streaming failed"})
	} else {
		logging.WithFields(
			mergeFields(
				logging.F("server_id", server.ID),
				logging.F("statefulset", server.StatefulSetName),
				logging.F("pod_name", pod.Name),
			)...,
		).Info("Log streaming finished")
	}
}

func monitorClient(conn *websocket.Conn, cancel context.CancelFunc) {
	defer cancel()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func sendPing(ctx context.Context, writer *websocketSafeWriter, cancel context.CancelFunc) {
	ticker := time.NewTicker(websocketPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := writer.writeControl(websocket.PingMessage, nil); err != nil {
				cancel()
				return
			}
		}
	}
}
