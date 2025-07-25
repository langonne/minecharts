package handlers

import (
	"net/http"
	"time"

	"minecharts/cmd/auth"
	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/kubernetes"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"

	corev1 "k8s.io/api/core/v1"
)

// StartMinecraftServerRequest represents the request to create a Minecraft server.
type StartMinecraftServerRequest struct {
	ServerName string            `json:"serverName" binding:"required" example:"survival"`
	Env        map[string]string `json:"env" example:"{\"DIFFICULTY\":\"normal\",\"MODE\":\"survival\",\"MEMORY\":\"4G\"}"`
}

// StartMinecraftServerHandler creates the PVC and starts the Minecraft deployment.
//
// @Summary      Create Minecraft server
// @Description  Creates a new Minecraft server with the specified configuration
// @Tags         servers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Security     APIKeyAuth
// @Param        request  body      StartMinecraftServerRequest  true  "Server configuration"
// @Success      200      {object}  map[string]string           "Server created successfully"
// @Failure      400      {object}  map[string]string           "Invalid request"
// @Failure      401      {object}  map[string]string           "Authentication required"
// @Failure      403      {object}  map[string]string           "Permission denied"
// @Failure      500      {object}  map[string]string           "Server error"
// @Router       /servers [post]
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
	deploymentName := config.DeploymentPrefix + baseName
	pvcName := deploymentName + config.PVCSuffix

	logging.Server.WithFields(
		"server_name", baseName,
		"deployment", deploymentName,
		"pvc", pvcName,
		"user_id", userID,
		"username", username,
	).Info("Creating new Minecraft server")

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

	// Creates the deployment with the existing PVC (created if necessary).
	if err := kubernetes.CreateDeployment(config.DefaultNamespace, deploymentName, pvcName, envVars); err != nil {
		logging.Server.WithFields(
			"server_name", baseName,
			"deployment", deploymentName,
			"pvc", pvcName,
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to create deployment")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create deployment: " + err.Error()})
		return
	}

	// After successful deployment creation, record the server in database
	server := &database.MinecraftServer{
		ServerName:     baseName,
		DeploymentName: deploymentName,
		PVCName:        pvcName,
		OwnerID:        userID,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Status:         "running",
	}

	db := database.GetDB()
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
		"deployment", deploymentName,
		"pvc", pvcName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server created successfully")

	c.JSON(http.StatusOK, gin.H{"message": "Minecraft server started", "deploymentName": deploymentName, "pvcName": pvcName})
}

// RestartMinecraftServerHandler saves the world and then restarts the deployment.
//
// @Summary      Restart Minecraft server
// @Description  Saves the world and restarts the Minecraft server
// @Tags         servers
// @Produce      json
// @Security     BearerAuth
// @Security     APIKeyAuth
// @Param        serverName  path      string  true  "Server name"
// @Success      200         {object}  map[string]interface{}  "Server restarting"
// @Failure      401         {object}  map[string]string       "Authentication required"
// @Failure      403         {object}  map[string]string       "Permission denied"
// @Failure      404         {object}  map[string]string       "Server not found"
// @Failure      500         {object}  map[string]string       "Server error"
// @Router       /servers/{serverName}/restart [post]
func RestartMinecraftServerHandler(c *gin.Context) {
	deploymentName, _ := kubernetes.GetServerInfo(c)

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
		"deployment", deploymentName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Restarting Minecraft server")

	// Check if the deployment exists
	_, ok := kubernetes.CheckDeploymentExists(c, config.DefaultNamespace, deploymentName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
		).Warn("Deployment not found for restart")
		return
	}

	// Get the pod associated with this deployment to run the save command
	pod, err := kubernetes.GetMinecraftPod(config.DefaultNamespace, deploymentName)
	if err != nil || pod == nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
			"error", err,
		).Error("Failed to find pod for deployment")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find pod for deployment: " + deploymentName,
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
			"error":          "Failed to save world: " + err.Error(),
			"deploymentName": deploymentName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"pod", pod.Name,
	).Debug("World saved successfully before restart")

	// Restart the deployment
	if err := kubernetes.RestartDeployment(config.DefaultNamespace, deploymentName); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
			"error", err.Error(),
		).Error("Failed to restart deployment")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":          "Failed to restart deployment: " + err.Error(),
			"deploymentName": deploymentName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"deployment", deploymentName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server restarted successfully")

	response := gin.H{
		"message":        "Minecraft server restarting",
		"deploymentName": deploymentName,
	}

	if stdout != "" || stderr != "" {
		response["save_stdout"] = stdout
		response["save_stderr"] = stderr
	}

	c.JSON(http.StatusOK, response)
}

// StopMinecraftServerHandler scales the deployment to 0 replicas.
//
// @Summary      Stop Minecraft server
// @Description  Saves the world and stops the Minecraft server (scales to 0)
// @Tags         servers
// @Produce      json
// @Security     BearerAuth
// @Security     APIKeyAuth
// @Param        serverName  path      string  true  "Server name"
// @Success      200         {object}  map[string]string  "Server stopped"
// @Failure      401         {object}  map[string]string  "Authentication required"
// @Failure      403         {object}  map[string]string  "Permission denied"
// @Failure      404         {object}  map[string]string  "Server not found"
// @Failure      500         {object}  map[string]string  "Server error"
// @Router       /servers/{serverName}/stop [post]
func StopMinecraftServerHandler(c *gin.Context) {
	deploymentName, _ := kubernetes.GetServerInfo(c)

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
		"deployment", deploymentName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Stopping Minecraft server")

	// Check if the deployment exists
	_, ok := kubernetes.CheckDeploymentExists(c, config.DefaultNamespace, deploymentName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
		).Warn("Deployment not found for stop operation")
		return
	}

	// Get the pod associated with this deployment to run the save command
	pod, err := kubernetes.GetMinecraftPod(config.DefaultNamespace, deploymentName)
	if err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
			"error", err.Error(),
		).Error("Failed to find pod for deployment")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find pod for deployment: " + deploymentName,
		})
		return
	}

	if pod != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"pod", pod.Name,
		).Debug("Saving world before stopping server")
		// Save the world before scaling down
		_, _, err := kubernetes.ExecuteCommandInPod(pod.Name, config.DefaultNamespace, "minecraft-server", "mc-send-to-console save-all")
		if err != nil {
			logging.Server.WithFields(
				"server_name", serverName,
				"pod", pod.Name,
				"error", err.Error(),
			).Error("Failed to save world before stopping")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":          "Failed to save world: " + err.Error(),
				"deploymentName": deploymentName,
			})
			return
		}
		logging.Server.WithFields(
			"server_name", serverName,
			"pod", pod.Name,
		).Debug("World saved successfully before stopping")
	}

	// Scale deployment to 0
	if err := kubernetes.SetDeploymentReplicas(config.DefaultNamespace, deploymentName, 0); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
			"error", err.Error(),
		).Error("Failed to scale deployment to 0")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":          "Failed to scale deployment: " + err.Error(),
			"deploymentName": deploymentName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"deployment", deploymentName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server stopped successfully")

	c.JSON(http.StatusOK, gin.H{
		"message":        "Server stopped (deployment scaled to 0), data retained",
		"deploymentName": deploymentName,
	})
}

// StartStoppedServerHandler scales a stopped deployment back to 1 replica.
//
// @Summary      Start stopped server
// @Description  Starts a previously stopped Minecraft server (scales to 1)
// @Tags         servers
// @Produce      json
// @Security     BearerAuth
// @Security     APIKeyAuth
// @Param        serverName  path      string  true  "Server name"
// @Success      200         {object}  map[string]string  "Server starting"
// @Failure      401         {object}  map[string]string  "Authentication required"
// @Failure      403         {object}  map[string]string  "Permission denied"
// @Failure      404         {object}  map[string]string  "Server not found"
// @Failure      500         {object}  map[string]string  "Server error"
// @Router       /servers/{serverName}/start [post]
func StartStoppedServerHandler(c *gin.Context) {
	deploymentName, _ := kubernetes.GetServerInfo(c)

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
		"deployment", deploymentName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Starting stopped Minecraft server")

	// Check if the deployment exists
	_, ok := kubernetes.CheckDeploymentExists(c, config.DefaultNamespace, deploymentName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
		).Warn("Deployment not found for start operation")
		return
	}

	// Scale deployment to 1
	if err := kubernetes.SetDeploymentReplicas(config.DefaultNamespace, deploymentName, 1); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
			"error", err.Error(),
		).Error("Failed to scale deployment to 1")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":          "Failed to start deployment: " + err.Error(),
			"deploymentName": deploymentName,
		})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"deployment", deploymentName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server started successfully")

	c.JSON(http.StatusOK, gin.H{
		"message":        "Server starting (deployment scaled to 1)",
		"deploymentName": deploymentName,
	})
}

// DeleteMinecraftServerHandler deletes a Minecraft server.
//
// @Summary      Delete Minecraft server
// @Description  Deletes a Minecraft server and all associated resources
// @Tags         servers
// @Produce      json
// @Security     BearerAuth
// @Security     APIKeyAuth
// @Param        serverName  path      string  true  "Server name"
// @Success      200         {object}  map[string]string  "Server deleted"
// @Failure      401         {object}  map[string]string  "Authentication required"
// @Failure      403         {object}  map[string]string  "Permission denied"
// @Failure      500         {object}  map[string]string  "Server error"
// @Router       /servers/{serverName}/delete [post]
func DeleteMinecraftServerHandler(c *gin.Context) {
	deploymentName, pvcName := kubernetes.GetServerInfo(c)

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
		"deployment", deploymentName,
		"pvc", pvcName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Deleting Minecraft server")

	// Delete the deployment if it exists
	if err := kubernetes.DeleteDeployment(config.DefaultNamespace, deploymentName); err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
			"error", err.Error(),
		).Warn("Error when deleting deployment")
	} else {
		logging.Server.Debug("Deployment deleted successfully")
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
	serviceName := deploymentName + "-svc"
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
		"deployment", deploymentName,
		"pvc", pvcName,
		"user_id", userID,
		"username", username,
	).Info("Minecraft server deleted successfully")

	c.JSON(http.StatusOK, gin.H{
		"message":        "Deployment, PVC and network resources deleted",
		"deploymentName": deploymentName,
		"pvcName":        pvcName,
	})
}

// ExecCommandRequest represents a request to execute a command on the Minecraft server.
type ExecCommandRequest struct {
	Command string `json:"command" binding:"required" example:"say Hello, world!"`
}

// ExecCommandHandler executes a Minecraft command in the server.
//
// @Summary      Execute Minecraft command
// @Description  Executes a command on the Minecraft server
// @Tags         servers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Security     APIKeyAuth
// @Param        serverName  path      string             true  "Server name"
// @Param        request     body      ExecCommandRequest  true  "Command to execute"
// @Success      200         {object}  map[string]string  "Command executed"
// @Failure      400         {object}  map[string]string  "Invalid request"
// @Failure      401         {object}  map[string]string  "Authentication required"
// @Failure      403         {object}  map[string]string  "Permission denied"
// @Failure      404         {object}  map[string]string  "Server not found"
// @Failure      500         {object}  map[string]string  "Server error"
// @Router       /servers/{serverName}/exec [post]
func ExecCommandHandler(c *gin.Context) {
	// Extract the server name from the URL parameter
	serverName := c.Param("serverName")
	deploymentName := config.DeploymentPrefix + serverName

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
		"deployment", deploymentName,
		"user_id", userID,
		"username", username,
		"remote_ip", c.ClientIP(),
	).Info("Executing command on Minecraft server")

	// Check if the deployment exists
	_, ok := kubernetes.CheckDeploymentExists(c, config.DefaultNamespace, deploymentName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
		).Warn("Deployment not found for command execution")
		return
	}

	// Get the pod associated with this deployment
	pod, err := kubernetes.GetMinecraftPod(config.DefaultNamespace, deploymentName)
	if err != nil || pod == nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"deployment", deploymentName,
			"error", err,
		).Error("Failed to find running pod for deployment")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find running pod for deployment: " + deploymentName,
		})
		return
	}

	// Parse the command from the JSON body
	var req ExecCommandRequest
	//TODO Validate the command

	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"server_name", serverName,
			"error", err.Error(),
		).Warn("Invalid command request format")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"pod", pod.Name,
		"command", req.Command,
		"username", username,
	).Debug("Executing Minecraft command")

	// Prepare the command to send to the console
	execCommand := "mc-send-to-console " + req.Command

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
