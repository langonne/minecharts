package kubernetes

import (
	"context"

	"minecharts/cmd/logging"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// createService creates a Kubernetes Service to expose a Minecraft server deployment
func CreateService(namespace, deploymentName string, serviceType corev1.ServiceType, port int32, annotations map[string]string) (*corev1.Service, error) {
	serviceName := deploymentName + "-svc"

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"service_name", serviceName,
		"service_type", serviceType,
		"port", port,
	).Info("Creating Kubernetes service")

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Labels: map[string]string{
				"created-by": "minecharts-api",
				"app":        deploymentName,
			},
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type: serviceType,
			Ports: []corev1.ServicePort{
				{
					Name:       "minecraft",
					Port:       port,
					TargetPort: intstr.FromInt32(25565),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app": deploymentName,
			},
		},
	}

	createdService, err := Clientset.CoreV1().Services(namespace).Create(context.Background(), service, metav1.CreateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"service_name", serviceName,
			"error", err.Error(),
		).Error("Failed to create service")
		return nil, err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"service_name", serviceName,
		"service_type", serviceType,
		"cluster_ip", createdService.Spec.ClusterIP,
	).Info("Service created successfully")

	return createdService, nil
}

// deleteService removes a service if it exists
func DeleteService(namespace, serviceName string) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"service_name", serviceName,
	).Debug("Attempting to delete service")

	err := Clientset.CoreV1().Services(namespace).Delete(context.Background(), serviceName, metav1.DeleteOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"service_name", serviceName,
			"error", err.Error(),
		).Error("Failed to delete service")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"service_name", serviceName,
	).Info("Service deleted successfully")

	return nil
}

// getServiceDetails retrieves information about an existing service
func GetServiceDetails(namespace, serviceName string) (*corev1.Service, error) {
	logging.K8s.WithFields(
		"namespace", namespace,
		"service_name", serviceName,
	).Debug("Getting service details")

	service, err := Clientset.CoreV1().Services(namespace).Get(context.Background(), serviceName, metav1.GetOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"service_name", serviceName,
			"error", err.Error(),
		).Error("Failed to get service details")
		return nil, err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"service_name", serviceName,
		"service_type", service.Spec.Type,
		"cluster_ip", service.Spec.ClusterIP,
	).Debug("Retrieved service details")

	return service, nil
}
