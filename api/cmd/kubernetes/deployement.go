// Package kubernetes provides functionality for managing Kubernetes resources.
//
// This package handles the creation, management and deletion of Kubernetes resources
// like deployments, services, pods and persistent volume claims for Minecraft servers.
package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"minecharts/cmd/config"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CheckDeploymentExists checks if a deployment exists and returns an HTTP error if it does not.
// Returns the deployment and a boolean indicating whether it exists.
func CheckDeploymentExists(c *gin.Context, namespace, deploymentName string) (*appsv1.Deployment, bool) {
	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"remote_ip", c.ClientIP(),
	).Debug("Checking if deployment exists")

	deployment, err := Clientset.AppsV1().Deployments(namespace).Get(context.Background(), deploymentName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
			"remote_ip", c.ClientIP(),
		).Warn("Deployment not found")
		c.JSON(http.StatusNotFound, gin.H{"error": "Deployment not found"})
		return nil, false
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
	).Debug("Deployment found")
	return deployment, true
}

// CreateDeployment creates a Minecraft deployment using the specified PVC, environment variables and memory settings.
// It configures the deployment with appropriate lifecycle hooks, volume mounts and optional resource limits.
func CreateDeployment(namespace, deploymentName, pvcName string, envVars []corev1.EnvVar, maxMemoryGB int64) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"pvc_name", pvcName,
	).Info("Creating Minecraft server deployment")

	replicas := int32(config.DefaultReplicas)
	userID := int64(1000)
	groupID := int64(1000)
	fsGroupID := int64(1000)

	container := corev1.Container{
		Name:  "minecraft-server",
		Image: "itzg/minecraft-server",
		Env:   envVars,
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: 25565,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "minecraft-storage",
				MountPath: "/data",
			},
		},
		Lifecycle: &corev1.Lifecycle{
			PreStop: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/bin/sh", "-c",
						"mc-send-to-console save-all stop && sleep 5",
					},
				},
			},
		},
	}

	if config.MemoryQuotaEnabled && maxMemoryGB > 0 {
		requestMi := config.MemoryRequestMi(maxMemoryGB)
		limitMi := config.MemoryLimitMi(maxMemoryGB)

		container.Resources = corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", requestMi)),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", limitMi)),
			},
		}
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: deploymentName,
			Labels: map[string]string{
				"created-by": "minecharts-api",
				"app":        deploymentName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": deploymentName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": deploymentName,
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  &userID,
						RunAsGroup: &groupID,
						FSGroup:    &fsGroupID,
					},
					Containers: []corev1.Container{
						container,
					},
					Volumes: []corev1.Volume{
						{
							Name: "minecraft-storage",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: pvcName,
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := Clientset.AppsV1().Deployments(namespace).Create(context.Background(), deployment, metav1.CreateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"pvc_name", pvcName,
			"error", err.Error(),
		).Error("Failed to create deployment")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"pvc_name", pvcName,
	).Info("Deployment created successfully")
	return nil
}

// RestartDeployment restarts a deployment by updating an annotation to trigger a rollout.
// This is a non-disruptive way to restart pods in a deployment.
func RestartDeployment(namespace, deploymentName string) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
	).Info("Restarting deployment")

	deployment, err := Clientset.AppsV1().Deployments(namespace).Get(context.Background(), deploymentName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
		).Error("Failed to get deployment for restart")
		return err
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = make(map[string]string)
	}

	// Add or update a restart timestamp annotation
	restartTime := time.Now().Format(time.RFC3339)
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = restartTime

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"restart_time", restartTime,
	).Debug("Setting restart annotation")

	_, err = Clientset.AppsV1().Deployments(namespace).Update(context.Background(), deployment, metav1.UpdateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
		).Error("Failed to update deployment for restart")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
	).Info("Deployment restart triggered successfully")
	return nil
}

// UpdateDeployment updates a deployment with new environment variables.
// This allows reconfiguring a Minecraft server without restarting it.
func UpdateDeployment(namespace, deploymentName string, envVars []corev1.EnvVar) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
	).Info("Updating deployment environment variables")

	deployment, err := Clientset.AppsV1().Deployments(namespace).Get(context.Background(), deploymentName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
		).Error("Failed to get deployment for update")
		return err
	}

	// Update environment variables for the minecraft-server container
	containerUpdated := false
	for i := range deployment.Spec.Template.Spec.Containers {
		if deployment.Spec.Template.Spec.Containers[i].Name == "minecraft-server" {
			deployment.Spec.Template.Spec.Containers[i].Env = envVars
			containerUpdated = true
			break
		}
	}

	if !containerUpdated {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
		).Warn("Minecraft server container not found in deployment")
	}

	_, err = Clientset.AppsV1().Deployments(namespace).Update(context.Background(), deployment, metav1.UpdateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
		).Error("Failed to update deployment")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
	).Info("Deployment updated successfully")
	return nil
}

// DeleteDeployment deletes a deployment by name.
func DeleteDeployment(namespace, deploymentName string) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
	).Info("Deleting deployment")

	err := Clientset.AppsV1().Deployments(namespace).Delete(context.Background(), deploymentName, metav1.DeleteOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
		).Error("Failed to delete deployment")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
	).Info("Deployment deleted successfully")
	return nil
}

// SetDeploymentReplicas updates the number of replicas for a deployment.
// This is used to scale up (start) or down (stop) Minecraft servers.
func SetDeploymentReplicas(namespace, deploymentName string, replicas int32) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"replicas", replicas,
	).Info("Setting deployment replicas")

	deployment, err := Clientset.AppsV1().Deployments(namespace).Get(
		context.Background(), deploymentName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
		).Error("Failed to get deployment for scaling")
		return err
	}

	deployment.Spec.Replicas = &replicas
	_, err = Clientset.AppsV1().Deployments(namespace).Update(
		context.Background(), deployment, metav1.UpdateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"replicas", replicas,
			"error", err.Error(),
		).Error("Failed to update deployment replicas")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"replicas", replicas,
	).Info("Deployment replicas updated successfully")
	return nil
}
