package kubernetes

import (
	"flag"
	"os"
	"path/filepath"

	"minecharts/cmd/logging"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Clientset is a global Kubernetes clientset instance.
// In your kubernetes package
var (
	Clientset *kubernetes.Clientset
	Config    *rest.Config
)

// Init initializes the global Kubernetes clientset.
// It uses the local kubeconfig if available; otherwise, it falls back to in-cluster config.
func Init() error {
	logging.K8s.Info("Initializing Kubernetes client")

	var err error
	var kubeconfig string

	// Set default kubeconfig path from HOME if available.
	if home := os.Getenv("HOME"); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
		logging.K8s.WithFields(
			"kubeconfig_path", kubeconfig,
		).Debug("Using default kubeconfig path from HOME")
	}
	flag.StringVar(&kubeconfig, "kubeconfig", kubeconfig, "absolute path to the kubeconfig file")
	flag.Parse()

	// Use kubeconfig if available; otherwise, use in-cluster config.
	if _, err := os.Stat(kubeconfig); err == nil {
		logging.K8s.WithFields(
			"kubeconfig_path", kubeconfig,
		).Debug("Using external kubeconfig file")

		Config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logging.K8s.WithFields(
				"kubeconfig_path", kubeconfig,
				"error", err.Error(),
			).Error("Failed to build config from kubeconfig file")
			return err
		}
	} else {
		logging.K8s.Debug("Using in-cluster configuration")
		Config, err = rest.InClusterConfig()
		if err != nil {
			logging.K8s.WithFields(
				"error", err.Error(),
			).Error("Failed to create in-cluster config")
			return err
		}
	}

	Clientset, err = kubernetes.NewForConfig(Config)
	if err != nil {
		logging.K8s.WithFields(
			"error", err.Error(),
		).Error("Failed to create Kubernetes clientset")
		return err
	}

	logging.K8s.Info("Kubernetes client initialized successfully")
	return nil
}
