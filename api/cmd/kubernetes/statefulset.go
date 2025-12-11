// Package kubernetes provides functionality for managing Kubernetes resources.
//
// This package handles the creation, management and deletion of Kubernetes resources
// like StatefulSets, services, pods and persistent volume claims for Minecraft servers.
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

// CheckStatefulSetExists checks if a StatefulSet exists and returns an HTTP error if it does not.
// Returns the StatefulSet and a boolean indicating whether it exists.
func CheckStatefulSetExists(c *gin.Context, namespace, statefulSetName string) (*appsv1.StatefulSet, bool) {
	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
		"remote_ip", c.ClientIP(),
	).Debug("Checking if StatefulSet exists")

	statefulSet, err := Clientset.AppsV1().StatefulSets(namespace).Get(context.Background(), statefulSetName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
			"remote_ip", c.ClientIP(),
		).Warn("StatefulSet not found")
		c.JSON(http.StatusNotFound, gin.H{"error": "StatefulSet not found"})
		return nil, false
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
	).Debug("StatefulSet found")
	return statefulSet, true
}

// CreateStatefulSet creates a Minecraft StatefulSet using the specified PVC, environment variables and memory settings.
// It configures the StatefulSet with appropriate lifecycle hooks, volume mounts and optional resource limits.
func CreateStatefulSet(namespace, statefulSetName, serviceName, pvcName string, envVars []corev1.EnvVar, maxMemoryGB int64) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
		"service_name", serviceName,
		"pvc_name", pvcName,
	).Info("Creating Minecraft server StatefulSet")

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

	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: statefulSetName,
			Labels: map[string]string{
				"created-by": "minecharts-api",
				"app":        statefulSetName,
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			ServiceName: serviceName,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": statefulSetName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": statefulSetName,
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

	_, err := Clientset.AppsV1().StatefulSets(namespace).Create(context.Background(), statefulSet, metav1.CreateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"service_name", serviceName,
			"pvc_name", pvcName,
			"error", err.Error(),
		).Error("Failed to create StatefulSet")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
		"service_name", serviceName,
		"pvc_name", pvcName,
	).Info("StatefulSet created successfully")
	return nil
}

// RestartStatefulSet restarts a StatefulSet by updating an annotation to trigger a rollout.
// This is a non-disruptive way to restart pods in a StatefulSet.
func RestartStatefulSet(namespace, statefulSetName string) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
	).Info("Restarting StatefulSet")

	statefulSet, err := Clientset.AppsV1().StatefulSets(namespace).Get(context.Background(), statefulSetName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
		).Error("Failed to get StatefulSet for restart")
		return err
	}

	if statefulSet.Spec.Template.Annotations == nil {
		statefulSet.Spec.Template.Annotations = make(map[string]string)
	}

	// Add or update a restart timestamp annotation
	restartTime := time.Now().Format(time.RFC3339)
	statefulSet.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = restartTime

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
		"restart_time", restartTime,
	).Debug("Setting restart annotation")

	_, err = Clientset.AppsV1().StatefulSets(namespace).Update(context.Background(), statefulSet, metav1.UpdateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
		).Error("Failed to update StatefulSet for restart")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
	).Info("StatefulSet restart triggered successfully")
	return nil
}

// UpdateStatefulSet updates a StatefulSet with new environment variables.
// This allows reconfiguring a Minecraft server without restarting it.
func UpdateStatefulSet(namespace, statefulSetName string, envVars []corev1.EnvVar) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
	).Info("Updating StatefulSet environment variables")

	statefulSet, err := Clientset.AppsV1().StatefulSets(namespace).Get(context.Background(), statefulSetName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
		).Error("Failed to get StatefulSet for update")
		return err
	}

	// Update environment variables for the minecraft-server container
	containerUpdated := false
	for i := range statefulSet.Spec.Template.Spec.Containers {
		if statefulSet.Spec.Template.Spec.Containers[i].Name == "minecraft-server" {
			statefulSet.Spec.Template.Spec.Containers[i].Env = envVars
			containerUpdated = true
			break
		}
	}

	if !containerUpdated {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
		).Warn("Minecraft server container not found in StatefulSet")
	}

	_, err = Clientset.AppsV1().StatefulSets(namespace).Update(context.Background(), statefulSet, metav1.UpdateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
		).Error("Failed to update StatefulSet")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
	).Info("StatefulSet updated successfully")
	return nil
}

// DeleteStatefulSet deletes a StatefulSet by name.
func DeleteStatefulSet(namespace, statefulSetName string) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
	).Info("Deleting StatefulSet")

	err := Clientset.AppsV1().StatefulSets(namespace).Delete(context.Background(), statefulSetName, metav1.DeleteOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
		).Error("Failed to delete StatefulSet")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
	).Info("StatefulSet deleted successfully")
	return nil
}

// SetStatefulSetReplicas updates the number of replicas for a StatefulSet.
// This is used to scale up (start) or down (stop) Minecraft servers.
func SetStatefulSetReplicas(namespace, statefulSetName string, replicas int32) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
		"replicas", replicas,
	).Info("Setting StatefulSet replicas")

	statefulSet, err := Clientset.AppsV1().StatefulSets(namespace).Get(
		context.Background(), statefulSetName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
		).Error("Failed to get StatefulSet for scaling")
		return err
	}

	statefulSet.Spec.Replicas = &replicas
	_, err = Clientset.AppsV1().StatefulSets(namespace).Update(
		context.Background(), statefulSet, metav1.UpdateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"replicas", replicas,
			"error", err.Error(),
		).Error("Failed to update StatefulSet replicas")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
		"replicas", replicas,
	).Info("StatefulSet replicas updated successfully")
	return nil
}
