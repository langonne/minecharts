package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"minecharts/cmd/auth"
	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/kubernetes"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MinecraftServerEnv extends MinecraftServer to include environment variables
type MinecraftServerEnv struct {
	*database.MinecraftServer
	Environment map[string]string `json:"environment,omitempty"`
	URL         string            `json:"url,omitempty"`
}

const (
	mcRouterAnnotation = "mc-router.itzg.me/externalServerName"
	defaultMaxMemoryGB = int64(1)
)

func formatServerURL(domain string, port int32) string {
	if domain == "" {
		return ""
	}

	if port <= 0 || port == 25565 {
		return domain
	}

	return fmt.Sprintf("%s:%d", domain, port)
}

func extractMCRouterURL(service *corev1.Service) string {
	if service == nil {
		return ""
	}

	annotations := service.Annotations
	var domain string
	if annotations != nil {
		domain = annotations[mcRouterAnnotation]
	}
	if domain == "" {
		return ""
	}

	var port int32 = 25565
	if len(service.Spec.Ports) > 0 {
		port = service.Spec.Ports[0].Port
	}

	return formatServerURL(domain, port)
}

func resolveMaxMemoryGB(env map[string]string) (int64, error) {
	if env == nil {
		return defaultMaxMemoryGB, nil
	}

	raw, ok := env["MAX_MEMORY"]
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultMaxMemoryGB, nil
	}

	trimmed := strings.TrimSpace(raw)
	// Allow optional trailing "G" or "g" suffix.
	if strings.HasSuffix(trimmed, "G") || strings.HasSuffix(trimmed, "g") {
		trimmed = strings.TrimSpace(trimmed[:len(trimmed)-1])
	}

	if trimmed == "" {
		return 0, errors.New("MAX_MEMORY must be a positive integer representing gigabytes")
	}

	value, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("MAX_MEMORY must be an integer representing gigabytes: %w", err)
	}

	if value <= 0 {
		return 0, errors.New("MAX_MEMORY must be greater than zero")
	}

	return value, nil
}

// GetMinecraftServerHandler returns a single server with env vars if it belongs to the user and has an existing StatefulSet.

func GetMinecraftServerHandler(c *gin.Context) {
	// Require authenticated user
	user, ok := auth.GetCurrentUser(c)
	if !ok || user == nil {
		logging.Server.WithFields(
			"remote_ip", c.ClientIP(),
			"reason", "not_authenticated",
		).Warn("Get server denied")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	serverName := c.Param("serverName")
	if !validateServerName(serverName) {
		logging.Server.WithFields(
			"server_name", serverName,
			"remote_ip", c.ClientIP(),
		).Warn("Invalid server name provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server name"})
		return
	}
	if !validateServerName(serverName) {
		logging.Server.WithFields(
			"server_name", serverName,
			"remote_ip", c.ClientIP(),
		).Warn("Invalid server name provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server name"})
		return
	}
	if !validateServerName(serverName) {
		logging.Server.WithFields(
			"server_name", serverName,
			"remote_ip", c.ClientIP(),
		).Warn("Invalid server name provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server name"})
		return
	}
	if !validateServerName(serverName) {
		logging.Server.WithFields(
			"server_name", serverName,
			"remote_ip", c.ClientIP(),
		).Warn("Invalid server name provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server name"})
		return
	}
	if !validateServerName(serverName) {
		logging.Server.WithFields(
			"server_name", serverName,
			"remote_ip", c.ClientIP(),
		).Warn("Invalid server name provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server name"})
		return
	}
	if !validateServerName(serverName) {
		logging.Server.WithFields(
			"server_name", serverName,
			"remote_ip", c.ClientIP(),
		).Warn("Invalid server name provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server name"})
		return
	}
	userID := user.ID

	logging.Server.WithFields(
		"server_name", serverName,
		"user_id", userID,
		"username", user.Username,
		"remote_ip", c.ClientIP(),
	).Info("Getting Minecraft server")

	db := database.GetDB()

	// Find the server by owner then by name to ensure ownership
	srv, err := db.GetServerForOwner(c.Request.Context(), userID, serverName)
	if err != nil {
		if errors.Is(err, database.ErrServerNotFound) {
			logging.Server.WithFields(
				"server_name", serverName,
				"user_id", userID,
			).Warn("Server not found for owner")
			c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		logging.DB.WithFields(
			"user_id", userID,
			"server_name", serverName,
			"error", err.Error(),
		).Error("Failed to fetch server for owner")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query server"})
		return
	}

	// Must have an existing StatefulSet
	statefulSet, err := kubernetes.Clientset.AppsV1().StatefulSets(config.DefaultNamespace).Get(
		c.Request.Context(),
		srv.StatefulSetName,
		metav1.GetOptions{},
	)
	if err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", srv.StatefulSetName,
			"error", err.Error(),
		).Warn("StatefulSet not found for server")
		c.JSON(http.StatusNotFound, gin.H{"error": "Server StatefulSet not found"})
		return
	}

	// Build response with env vars, status, and optional mc-router URL
	enriched := MinecraftServerEnv{
		MinecraftServer: srv,
		Environment:     make(map[string]string),
	}

	serviceName := srv.StatefulSetName + "-svc"
	if service, svcErr := kubernetes.GetServiceDetails(config.DefaultNamespace, serviceName); svcErr != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"service", serviceName,
			"error", svcErr.Error(),
		).Debug("Unable to retrieve service; URL will not be included")
	} else {
		if url := extractMCRouterURL(service); url != "" {
			enriched.URL = url
		}
	}

	if statefulSet.Spec.Replicas != nil && *statefulSet.Spec.Replicas == 0 {
		enriched.Status = "stopped"
	} else {
		enriched.Status = "running"
	}

	for _, container := range statefulSet.Spec.Template.Spec.Containers {
		if container.Name == "minecraft-server" {
			for _, env := range container.Env {
				enriched.Environment[env.Name] = env.Value
			}
			break
		}
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"env_vars_count", len(enriched.Environment),
		"status", enriched.Status,
	).Debug("Returning single server with environment")

	c.JSON(http.StatusOK, enriched)
}

// ListMinecraftServersHandler lists all Minecraft servers of the authenticated user.
func ListMinecraftServersHandler(c *gin.Context) {
	// Get current user for logging
	user, _ := auth.GetCurrentUser(c)
	userID := int64(0)
	username := "unknown"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	logging.Server.WithFields(
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Listing Minecraft servers")

	db := database.GetDB()
	servers, err := db.ListServersByOwner(c.Request.Context(), userID)
	if err != nil {
		logging.DB.WithFields(
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to list Minecraft servers")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list servers: " + err.Error()})
		return
	}

	// Enrich servers with environment variables - only include servers with existing StatefulSets
	enrichedServers := make([]MinecraftServerEnv, 0, len(servers))
	for _, server := range servers {
		// Get StatefulSet to extract environment variables
		statefulSet, err := kubernetes.Clientset.AppsV1().StatefulSets(config.DefaultNamespace).Get(
			c.Request.Context(),
			server.StatefulSetName,
			metav1.GetOptions{},
		)

		// Skip servers without existing StatefulSets
		if err != nil {
			logging.Server.WithFields(
				"server_name", server.ServerName,
				"statefulset", server.StatefulSetName,
				"error", err.Error(),
			).Debug("Skipping server without StatefulSet")
			continue
		}

		enriched := MinecraftServerEnv{
			MinecraftServer: server,
			Environment:     make(map[string]string),
		}

		serviceName := server.StatefulSetName + "-svc"
		if service, svcErr := kubernetes.GetServiceDetails(config.DefaultNamespace, serviceName); svcErr != nil {
			logging.Server.WithFields(
				"server_name", server.ServerName,
				"service", serviceName,
				"error", svcErr.Error(),
			).Debug("Unable to retrieve service for list; URL omitted")
		} else {
			if url := extractMCRouterURL(service); url != "" {
				enriched.URL = url
			}
		}

		// Update status based on StatefulSet replicas
		if statefulSet.Spec.Replicas != nil && *statefulSet.Spec.Replicas == 0 {
			enriched.Status = "stopped"
		} else {
			enriched.Status = "running"
		}

		// Find the minecraft-server container and extract its environment variables
		for _, container := range statefulSet.Spec.Template.Spec.Containers {
			if container.Name == "minecraft-server" {
				for _, env := range container.Env {
					enriched.Environment[env.Name] = env.Value
				}
				break
			}
		}

		logging.Server.WithFields(
			"server_name", server.ServerName,
			"env_vars_count", len(enriched.Environment),
			"status", enriched.Status,
		).Debug("Retrieved environment variables")

		enrichedServers = append(enrichedServers, enriched)
	}

	c.JSON(http.StatusOK, enrichedServers)
}

// StartMinecraftServerRequest represents the request to create a Minecraft server.
type StartMinecraftServerRequest struct {
	ServerName string            `json:"serverName" binding:"required" example:"survival"`
	Env        map[string]string `json:"env" example:"{\"DIFFICULTY\":\"normal\",\"MODE\":\"survival\",\"MEMORY\":\"4G\"}"`
}

// StartMinecraftServerHandler creates the PVC and starts the Minecraft StatefulSet.

func StartMinecraftServerHandler(c *gin.Context) {
	var req StartMinecraftServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"error", err.Error(),
			"remote_ip", c.ClientIP(),
		).Warn("Invalid server creation request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get current user for logging
	user, _ := auth.GetCurrentUser(c)
	userID := int64(0)
	username := "unknown"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	baseName := req.ServerName
	statefulSetName := config.StatefulSetPrefix + baseName
	pvcName := statefulSetName + config.PVCSuffix

	maxMemoryGB, err := resolveMaxMemoryGB(req.Env)
	if err != nil {
		logging.API.InvalidRequest.WithFields(
			"server_name", baseName,
			"error", err.Error(),
			"remote_ip", c.ClientIP(),
		).Warn("Invalid MAX_MEMORY provided for server creation")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Env == nil {
		req.Env = make(map[string]string)
	}
	req.Env["MAX_MEMORY"] = fmt.Sprintf("%dG", maxMemoryGB)

	db := database.GetDB()

	logging.Server.WithFields(
		"server_name", baseName,
		"statefulset", statefulSetName,
		"pvc", pvcName,
		"user_id", userID,
		"username", username,
		"max_memory_gb", maxMemoryGB,
	).Info("Creating new Minecraft server")

	if config.MemoryQuotaEnabled {
		limit := int64(config.MemoryQuotaLimit)
		if limit > 0 {
			totalMemory, err := db.SumServerMaxMemory(c.Request.Context())
			if err != nil {
				logging.Server.WithFields(
					"server_name", baseName,
					"user_id", userID,
					"error", err.Error(),
				).Error("Failed to verify memory quota before server creation")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify memory quota"})
				return
			}

			projected := totalMemory + maxMemoryGB
			if projected > limit {
				remaining := limit - totalMemory
				if remaining < 0 {
					remaining = 0
				}
				logging.Server.WithFields(
					"server_name", baseName,
					"user_id", userID,
					"requested_memory_gb", maxMemoryGB,
					"allocated_memory_gb", totalMemory,
					"memory_limit_gb", limit,
				).Warn("Memory quota exceeded, refusing server creation")
				c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("memory quota exceeded: %dG available, %dG requested", remaining, maxMemoryGB)})
				return
			}
		} else {
			logging.Server.WithFields(
				"server_name", baseName,
				"user_id", userID,
			).Debug("Memory quota enabled but limit is non-positive; treating as unlimited")
		}
	}

	// Creates the PVC if it doesn't already exist.
	if err := kubernetes.EnsurePVC(config.DefaultNamespace, pvcName); err != nil {
		logging.Server.WithFields(
			"server_name", baseName,
			"pvc", pvcName,
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to ensure PVC")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to ensure PVC: " + err.Error()})
		return
	}

	logging.Server.WithFields(
		"server_name", baseName,
		"pvc", pvcName,
	).Debug("PVC ensured")

	// Prepares default environment variables.
	envVars := []corev1.EnvVar{
		{
			Name:  "EULA",
			Value: "TRUE",
		},
		{
			Name:  "CREATE_CONSOLE_IN_PIPE",
			Value: "true",
		},
	}
	// Adds additional environment variables provided in the request.
	for key, value := range req.Env {
		envVars = append(envVars, corev1.EnvVar{
			Name:  key,
			Value: value,
		})
	}

	domain := fmt.Sprintf("%s.%s", baseName, config.MCRouterDomainSuffix)
	serviceName := statefulSetName + "-svc"
	mcRouterAnnotations := map[string]string{
		"mc-router.itzg.me/externalServerName": domain,
	}

	service, err := kubernetes.CreateService(config.DefaultNamespace, statefulSetName, corev1.ServiceTypeClusterIP, 25565, mcRouterAnnotations)
	if err != nil {
		logging.Server.WithFields(
			"server_name", baseName,
			"statefulset", statefulSetName,
			"service", serviceName,
			"domain", domain,
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to create mc-router service")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to expose server with mc-router: " + err.Error()})
		return
	}

	// Creates the StatefulSet with the existing PVC (created if necessary).
	if err := kubernetes.CreateStatefulSet(config.DefaultNamespace, statefulSetName, serviceName, pvcName, envVars, maxMemoryGB); err != nil {
		_ = kubernetes.DeleteService(config.DefaultNamespace, serviceName)
		logging.Server.WithFields(
			"server_name", baseName,
			"statefulset", statefulSetName,
			"pvc", pvcName,
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to create StatefulSet")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create StatefulSet: " + err.Error()})
		return
	}

	logging.Server.WithFields(
		"server_name", baseName,
		"statefulset", statefulSetName,
		"service", serviceName,
		"domain", domain,
		"user_id", userID,
	).Info("Minecraft server exposed through mc-router")

	// After successful StatefulSet creation, record the server in database
	server := &database.MinecraftServer{
		ServerName:      baseName,
		StatefulSetName: statefulSetName,
		PVCName:         pvcName,
		OwnerID:         userID,
		MaxMemoryGB:     maxMemoryGB,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Status:          "running",
	}

	if err := db.CreateServerRecord(c.Request.Context(), server); err != nil {
		// Log the error but don't fail the request since the server is already created in K8s
		logging.DB.WithFields(
			"server_name", baseName,
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to record server in database")
	}

	logging.Server.WithFields(
		"server_name", baseName,
		"statefulset", statefulSetName,
		"pvc", pvcName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server created successfully")

	response := gin.H{
		"message":         "Minecraft server started",
		"statefulSetName": statefulSetName,
		"pvcName":         pvcName,
		"domain":          domain,
		"serviceName":     service.Name,
	}

	if url := extractMCRouterURL(service); url != "" {
		response["url"] = url
	}

	c.JSON(http.StatusOK, response)
}

// RestartMinecraftServerHandler saves the world and then restarts the StatefulSet.

func RestartMinecraftServerHandler(c *gin.Context) {
	statefulSetName, _ := kubernetes.GetServerInfo(c)

	// Get current user for logging
	user, _ := auth.GetCurrentUser(c)
	userID := int64(0)
	username := "unknown"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	serverName := c.Param("serverName")

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Restarting Minecraft server")

	// Check if the StatefulSet exists
	statefulSet, ok := kubernetes.CheckStatefulSetExists(c, config.DefaultNamespace, statefulSetName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
		).Warn("StatefulSet not found for restart")
		return
	}

	// Get the pod associated with this StatefulSet to run the save command
	pod, err := kubernetes.GetMinecraftPod(config.DefaultNamespace, statefulSetName)
	if err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"error", err,
		).Error("Failed to find pod for StatefulSet")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find pod for StatefulSet: " + statefulSetName,
		})
		return
	}

	if pod == nil {
		replicas := int32(0)
		if statefulSet.Spec.Replicas != nil {
			replicas = *statefulSet.Spec.Replicas
		}
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"desired_replicas", replicas,
		).Info("No running pod found for restart; scaling StatefulSet to 1")

		if err := kubernetes.SetStatefulSetReplicas(config.DefaultNamespace, statefulSetName, 1); err != nil {
			logging.Server.WithFields(
				"server_name", serverName,
				"statefulset", statefulSetName,
				"error", err.Error(),
			).Error("Failed to scale StatefulSet while handling restart without pod")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":           "Failed to scale StatefulSet: " + err.Error(),
				"statefulSetName": statefulSetName,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":         "No running pod was found; StatefulSet scaled to 1 instead of restart",
			"statefulSetName": statefulSetName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"pod", pod.Name,
	).Debug("Found pod for server restart")

	// Save the world
	stdout, stderr, err := kubernetes.SaveWorld(pod.Name, config.DefaultNamespace)
	if err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"pod", pod.Name,
			"error", err.Error(),
		).Error("Failed to save world before restart")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":           "Failed to save world: " + err.Error(),
			"statefulSetName": statefulSetName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"pod", pod.Name,
	).Debug("World saved successfully before restart")

	// Restart the StatefulSet
	if err := kubernetes.RestartStatefulSet(config.DefaultNamespace, statefulSetName); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"error", err.Error(),
		).Error("Failed to restart StatefulSet")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":           "Failed to restart StatefulSet: " + err.Error(),
			"statefulSetName": statefulSetName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server restarted successfully")

	response := gin.H{
		"message":         "Minecraft server restarting",
		"statefulSetName": statefulSetName,
	}

	if stdout != "" || stderr != "" {
		response["save_stdout"] = stdout
		response["save_stderr"] = stderr
	}

	c.JSON(http.StatusOK, response)
}

// StopMinecraftServerHandler scales the StatefulSet to 0 replicas.

func StopMinecraftServerHandler(c *gin.Context) {
	statefulSetName, _ := kubernetes.GetServerInfo(c)

	// Get current user for logging
	user, _ := auth.GetCurrentUser(c)
	userID := int64(0)
	username := "unknown"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	serverName := c.Param("serverName")

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Stopping Minecraft server")

	// Check if the StatefulSet exists
	_, ok := kubernetes.CheckStatefulSetExists(c, config.DefaultNamespace, statefulSetName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
		).Warn("StatefulSet not found for stop operation")
		return
	}

	// Get the pod associated with this StatefulSet to run the save command
	pod, err := kubernetes.GetMinecraftPod(config.DefaultNamespace, statefulSetName)
	if err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"error", err.Error(),
		).Error("Failed to find pod for StatefulSet")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find pod for StatefulSet: " + statefulSetName,
		})
		return
	}

	if pod != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"pod", pod.Name,
		).Debug("Saving world before stopping server")
		// Save the world before scaling down
		_, _, err := kubernetes.SaveWorld(pod.Name, config.DefaultNamespace)
		if err != nil {
			logging.Server.WithFields(
				"server_name", serverName,
				"pod", pod.Name,
				"error", err.Error(),
			).Error("Failed to save world before stopping")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":           "Failed to save world: " + err.Error(),
				"statefulSetName": statefulSetName,
			})
			return
		}
		logging.Server.WithFields(
			"server_name", serverName,
			"pod", pod.Name,
		).Debug("World saved successfully before stopping")
	}

	// Scale StatefulSet to 0
	if err := kubernetes.SetStatefulSetReplicas(config.DefaultNamespace, statefulSetName, 0); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"error", err.Error(),
		).Error("Failed to scale StatefulSet to 0")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":           "Failed to scale StatefulSet: " + err.Error(),
			"statefulSetName": statefulSetName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server stopped successfully")

	c.JSON(http.StatusOK, gin.H{
		"message":         "Server stopped (StatefulSet scaled to 0), data retained",
		"statefulSetName": statefulSetName,
	})
}

// StartStoppedServerHandler scales a stopped StatefulSet back to 1 replica.

func StartStoppedServerHandler(c *gin.Context) {
	statefulSetName, _ := kubernetes.GetServerInfo(c)

	// Get current user for logging
	user, _ := auth.GetCurrentUser(c)
	userID := int64(0)
	username := "unknown"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	serverName := c.Param("serverName")

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Starting stopped Minecraft server")

	// Check if the StatefulSet exists
	_, ok := kubernetes.CheckStatefulSetExists(c, config.DefaultNamespace, statefulSetName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
		).Warn("StatefulSet not found for start operation")
		return
	}

	// Scale StatefulSet to 1
	if err := kubernetes.SetStatefulSetReplicas(config.DefaultNamespace, statefulSetName, 1); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"error", err.Error(),
		).Error("Failed to scale StatefulSet to 1")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":           "Failed to start StatefulSet: " + err.Error(),
			"statefulSetName": statefulSetName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server started successfully")

	c.JSON(http.StatusOK, gin.H{
		"message":         "Server starting (StatefulSet scaled to 1)",
		"statefulSetName": statefulSetName,
	})
}

// DeleteMinecraftServerHandler deletes a Minecraft server.

func DeleteMinecraftServerHandler(c *gin.Context) {
	statefulSetName, pvcName := kubernetes.GetServerInfo(c)

	// Get current user for logging
	user, _ := auth.GetCurrentUser(c)
	userID := int64(0)
	username := "unknown"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	serverName := c.Param("serverName")

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"pvc", pvcName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Deleting Minecraft server")

	// Delete the StatefulSet if it exists
	if err := kubernetes.DeleteStatefulSet(config.DefaultNamespace, statefulSetName); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"error", err.Error(),
		).Warn("Error when deleting StatefulSet")
	} else {
		logging.Server.Debug("StatefulSet deleted successfully")
	}

	// Delete the PVC
	if err := kubernetes.DeletePVC(config.DefaultNamespace, pvcName); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"pvc", pvcName,
			"error", err.Error(),
		).Warn("Error when deleting PVC")
	} else {
		logging.Server.Debug("PVC deleted successfully")
	}

	// Clean up network resources
	serviceName := statefulSetName + "-svc"
	if err := kubernetes.DeleteService(config.DefaultNamespace, serviceName); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"service", serviceName,
			"error", err.Error(),
		).Warn("Error when deleting service")
	} else {
		logging.Server.Debug("Service deleted successfully")
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
		"pvc", pvcName,
	).Info("Minecraft server deleted successfully")

	// Remove the server record so quota accounting stays accurate.
	db := database.GetDB()
	if err := db.DeleteServerRecord(c.Request.Context(), serverName); err != nil {
		logging.DB.WithFields(
			"server_name", serverName,
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to delete server record from database")
	} else {
		logging.DB.WithFields(
			"server_name", serverName,
			"user_id", userID,
		).Info("Server record deleted from database")
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "StatefulSet, PVC and network resources deleted",
		"statefulSetName": statefulSetName,
		"pvcName":         pvcName,
	})
}

// ExecCommandRequest represents a request to execute a command on the Minecraft server.
type ExecCommandRequest struct {
	Command string `json:"command" binding:"required" example:"say Hello, world!"`
}

// ExecCommandHandler executes a Minecraft command in the server.

func ExecCommandHandler(c *gin.Context) {
	// Extract the server name from the URL parameter
	serverName := c.Param("serverName")
	statefulSetName := config.StatefulSetPrefix + serverName

	// Get current user for logging
	user, _ := auth.GetCurrentUser(c)
	userID := int64(0)
	username := "unknown"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Executing command on Minecraft server")

	// Check if the StatefulSet exists
	_, ok := kubernetes.CheckStatefulSetExists(c, config.DefaultNamespace, statefulSetName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
		).Warn("StatefulSet not found for command execution")
		return
	}

	// Get the pod associated with this StatefulSet
	pod, err := kubernetes.GetMinecraftPod(config.DefaultNamespace, statefulSetName)
	if err != nil || pod == nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"error", err,
		).Error("Failed to find running pod for StatefulSet")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find running pod for StatefulSet: " + statefulSetName,
		})
		return
	}

	// Parse the command from the JSON body
	var req ExecCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"server_name", serverName,
			"error", err.Error(),
		).Warn("Invalid command request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if strings.TrimSpace(req.Command) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Command cannot be empty"})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"pod", pod.Name,
		"command", req.Command,
		"username", username,
	).Debug("Executing Minecraft command")

	// Prepare the command to send to the console with shell-safe quoting
	execCommand := "mc-send-to-console " + shellQuote(req.Command)

	// Execute the command in the pod
	stdout, stderr, err := kubernetes.ExecuteCommandInPod(pod.Name, config.DefaultNamespace, "minecraft-server", execCommand)
	if err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"pod", pod.Name,
			"command", req.Command,
			"error", err.Error(),
		).Error("Failed to execute command")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to execute command: " + err.Error(),
			"stderr":  stderr,
			"command": req.Command,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"pod", pod.Name,
		"command", req.Command,
		"username", username,
	).Info("Command executed successfully")

	c.JSON(http.StatusOK, gin.H{
		"stdout":  stdout,
		"stderr":  stderr,
		"command": req.Command,
	})
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func validateServerName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}
