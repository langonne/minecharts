package handlers

import (
	"net/http"

	"minecharts/cmd/auth"
	"minecharts/cmd/config"
	"minecharts/cmd/kubernetes"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"

	corev1 "k8s.io/api/core/v1"
)

// ExposeServerRequest represents the request to expose a Minecraft server.
type ExposeServerRequest struct {
	ExposureType string `json:"exposureType" binding:"required" example:"NodePort"`
	Domain       string `json:"domain" example:"mc.example.com"`
	Port         int32  `json:"port" example:"25565"`
}

// ExposeMinecraftServerHandler exposes a Minecraft server using the specified method.

func ExposeMinecraftServerHandler(c *gin.Context) {
	// Get server info from URL parameter
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
	).Info("Expose server request received")

	// Check if the StatefulSet exists
	_, ok := kubernetes.CheckStatefulSetExists(c, config.DefaultNamespace, statefulSetName)
	if !ok {
		logging.Server.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"user_id", userID,
			"error", "statefulset_not_found",
		).Warn("Server exposure failed: StatefulSet not found")
		return
	}

	// Parse request body
	var req ExposeServerRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"user_id", userID,
			"error", err.Error(),
		).Warn("Server exposure failed: invalid request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"statefulset", statefulSetName,
		"exposure_type", req.ExposureType,
		"port", req.Port,
		"domain", req.Domain,
	).Debug("Processing server exposure request")

	// Validate exposure type
	if req.ExposureType != "ClusterIP" &&
		req.ExposureType != "NodePort" &&
		req.ExposureType != "LoadBalancer" &&
		req.ExposureType != "MCRouter" {
		logging.API.InvalidRequest.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"exposure_type", req.ExposureType,
			"user_id", userID,
			"error", "invalid_exposure_type",
		).Warn("Server exposure failed: invalid exposure type")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid exposureType. Must be one of: ClusterIP, NodePort, LoadBalancer, MCRouter",
		})
		return
	}

	// Domain is required for MCRouter
	if req.ExposureType == "MCRouter" && req.Domain == "" {
		logging.API.InvalidRequest.WithFields(
			"server_name", serverName,
			"statefulset", statefulSetName,
			"exposure_type", req.ExposureType,
			"user_id", userID,
			"error", "missing_domain",
		).Warn("Server exposure failed: domain required for MCRouter")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Domain is required for MCRouter exposure type",
		})
		return
	}

	// Use default Minecraft port if not provided
	if req.Port <= 0 {
		logging.Server.Debug("Using default Minecraft port 25565")
		req.Port = 25565
	}

	// Service name will be consistent
	serviceName := statefulSetName + "-svc"

	// Clean up any existing services for this StatefulSet
	// Ignore errors in case the resources don't exist yet
	logging.Server.WithFields(
		"server_name", serverName,
		"service", serviceName,
	).Debug("Cleaning up any existing services")
	_ = kubernetes.DeleteService(config.DefaultNamespace, serviceName)

	// Create appropriate service based on exposure type
	var serviceType corev1.ServiceType
	annotations := make(map[string]string)

	switch req.ExposureType {
	case "NodePort":
		serviceType = corev1.ServiceTypeNodePort
	case "LoadBalancer":
		serviceType = corev1.ServiceTypeLoadBalancer
	case "MCRouter":
		serviceType = corev1.ServiceTypeClusterIP
		annotations["mc-router.itzg.me/externalServerName"] = req.Domain
	default:
		serviceType = corev1.ServiceTypeClusterIP
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"service", serviceName,
		"exposure_type", req.ExposureType,
		"service_type", string(serviceType),
		"port", req.Port,
	).Info("Creating Kubernetes service")

	// Create the service
	service, err := kubernetes.CreateService(config.DefaultNamespace, statefulSetName, serviceType, req.Port, annotations)
	if err != nil {
		logging.Server.WithFields(
			"server_name", serverName,
			"service", serviceName,
			"exposure_type", req.ExposureType,
			"user_id", userID,
			"error", err.Error(),
		).Error("Failed to create service")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create service: " + err.Error(),
		})
		return
	}

	response := gin.H{
		"message":      "Service created",
		"serviceName":  service.Name,
		"exposureType": req.ExposureType,
		"serviceType":  string(serviceType),
	}

	// Add service-specific information to response
	switch req.ExposureType {
	case "NodePort":
		if len(service.Spec.Ports) > 0 && service.Spec.Ports[0].NodePort > 0 {
			response["nodePort"] = service.Spec.Ports[0].NodePort
		}
	case "LoadBalancer":
		// External IP might not be assigned immediately
		if len(service.Status.LoadBalancer.Ingress) > 0 {
			ip := service.Status.LoadBalancer.Ingress[0].IP
			if ip != "" {
				response["externalIP"] = ip
			} else {
				response["externalIP"] = service.Status.LoadBalancer.Ingress[0].Hostname
			}
		} else {
			response["externalIP"] = "pending"
			response["note"] = "LoadBalancer external IP is being provisioned and may take a few minutes"
		}
	case "MCRouter":
		response["domain"] = req.Domain
		response["note"] = "MCRouter configuration created. Make sure mc-router is deployed in your cluster."
	}

	logging.Server.WithFields(
		"server_name", serverName,
		"service", serviceName,
		"exposure_type", req.ExposureType,
		"service_type", string(serviceType),
		"user_id", userID,
		"username", username,
	).Info("Server exposure completed successfully")

	c.JSON(http.StatusOK, response)
}
