package kubernetes

import (
	"time"

	"minecharts/cmd/config"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

// getServerInfo returns the deployment and PVC names from a Gin context.
func GetServerInfo(c *gin.Context) (deploymentName, pvcName string) {
	// Extract the server name from the URL parameter
	serverName := c.Param("serverName")

	// Build the full deployment and PVC names
	deploymentName = config.DeploymentPrefix + serverName
	pvcName = deploymentName + config.PVCSuffix

	logging.K8s.WithFields(
		logging.F("server_name", serverName),
		logging.F("deployment_name", deploymentName),
		logging.F("pvc_name", pvcName),
		logging.F("remote_ip", c.ClientIP()),
	).Debug("Extracted server information")

	return
}

// saveWorld sends a "save-all" command to the Minecraft server pod to save the world data.
// This is a utility function to avoid code duplication across handlers.
func SaveWorld(podName, namespace string) (stdout, stderr string, err error) {
	logging.K8s.WithFields(
		logging.F("pod_name", podName),
		logging.F("namespace", namespace),
	).Debug("Sending save-all command to Minecraft server pod")

	stdout, stderr, err = ExecuteCommandInPod(podName, namespace, "minecraft-server", "mc-send-to-console save-all")
	if err != nil {
		logging.K8s.WithFields(
			logging.F("pod_name", podName),
			logging.F("namespace", namespace),
			logging.F("error", err.Error()),
		).Error("Failed to execute save-all command")

		return stdout, stderr, err
	}

	// Wait for the save to complete
	logging.K8s.WithFields(
		logging.F("pod_name", podName),
		logging.F("namespace", namespace),
	).Debug("Waiting for save-all command to complete")

	time.Sleep(10 * time.Second)

	logging.K8s.WithFields(
		logging.F("pod_name", podName),
		logging.F("namespace", namespace),
	).Debug("Save-all command completed")

	return stdout, stderr, err
}
