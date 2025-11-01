package kubernetes

import (
	"context"
	"minecharts/cmd/config"
	"minecharts/cmd/logging"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// ensurePVC checks if a PVC exists in the given namespace; if not, it creates it.
func EnsurePVC(namespace, pvcName string) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"pvc_name", pvcName,
	).Debug("Checking if PVC exists")

	_, err := Clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.Background(), pvcName, metav1.GetOptions{})
	if err == nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pvc_name", pvcName,
		).Debug("PVC already exists")
		return nil // PVC already exists.
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"pvc_name", pvcName,
		"storage_size", config.StorageSize,
		"storage_class", config.StorageClass,
	).Info("Creating new PVC")

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName,
			Namespace: namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(config.StorageSize),
				},
			},
			StorageClassName: ptr.To(config.StorageClass),
		},
	}
	_, err = Clientset.CoreV1().PersistentVolumeClaims(namespace).Create(context.Background(), pvc, metav1.CreateOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pvc_name", pvcName,
			"error", err.Error(),
		).Error("Failed to create PVC")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"pvc_name", pvcName,
	).Info("PVC created successfully")

	return nil
}

// deletePVC removes a PVC if it exists
func DeletePVC(namespace, pvcName string) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"pvc_name", pvcName,
	).Debug("Attempting to delete PVC")

	err := Clientset.CoreV1().PersistentVolumeClaims(namespace).Delete(context.Background(), pvcName, metav1.DeleteOptions{})
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pvc_name", pvcName,
			"error", err.Error(),
		).Error("Failed to delete PVC")
		return err
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"pvc_name", pvcName,
	).Info("PVC deleted successfully")

	return nil
}
