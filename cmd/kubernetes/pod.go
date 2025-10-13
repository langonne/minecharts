package kubernetes

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"minecharts/cmd/logging"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// getMinecraftPod gets the first pod associated with a deployment
func GetMinecraftPod(namespace, deploymentName string) (*corev1.Pod, error) {
	labelSelector := "app=" + deploymentName

	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"label_selector", labelSelector,
	).Debug("Looking for Minecraft pod with label selector")

	podList, err := Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})

	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
			"error", err.Error(),
		).Error("Failed to list pods")
		return nil, err
	}

	if len(podList.Items) == 0 {
		logging.K8s.WithFields(
			"namespace", namespace,
			"deployment_name", deploymentName,
		).Warn("No pods found for deployment")
		return nil, nil // No pods found
	}

	pod := &podList.Items[0]
	logging.K8s.WithFields(
		"namespace", namespace,
		"deployment_name", deploymentName,
		"pod_name", pod.Name,
		"pod_status", pod.Status.Phase,
	).Debug("Found Minecraft pod")
	return pod, nil
}

// executeCommandInPod executes a command in the specified pod and returns the output.
// This is a utility function to avoid code duplication across handlers.
func ExecuteCommandInPod(podName, namespace, containerName, command string) (stdout, stderr string, err error) {
	logging.K8s.WithFields(
		"namespace", namespace,
		"pod_name", podName,
		"container_name", containerName,
		"command", command,
	).Debug("Executing command in pod")

	// Prepare the execution request in the pod.
	execReq := Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	wrappedCommand := fmt.Sprintf(`if [ "$(id -u)" != "1000" ]; then
	if command -v gosu >/dev/null 2>&1; then
		exec gosu 1000:1000 /bin/bash -c %q
	elif command -v runuser >/dev/null 2>&1; then
		exec runuser -u 1000 -- /bin/bash -c %q
	else
		exec /bin/bash -c %q
	fi
else
	exec /bin/bash -c %q
fi`, command, command, command, command)

	execReq.VersionedParams(&corev1.PodExecOptions{
		Container: containerName,
		Command:   []string{"/bin/bash", "-c", wrappedCommand},
		Stdout:    true,
		Stderr:    true,
	}, scheme.ParameterCodec)

	// Create buffers to capture the command output.
	var stdoutBuf, stderrBuf bytes.Buffer

	// Execute the command in the pod.
	exec, err := remotecommand.NewSPDYExecutor(Config, "POST", execReq.URL())
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pod_name", podName,
			"container_name", containerName,
			"error", err.Error(),
		).Error("Failed to create SPDY executor")
		return "", "", err
	}

	// Set a timeout context for the command execution.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stream the command output to our buffers.
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
	})

	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pod_name", podName,
			"container_name", containerName,
			"command", command,
			"stdout", stdout,
			"stderr", stderr,
			"error", err.Error(),
		).Error("Command execution failed")
	} else {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pod_name", podName,
			"container_name", containerName,
			"command", command,
			"stdout_length", len(stdout),
			"stderr_length", len(stderr),
		).Debug("Command executed successfully")
	}

	// Return the command output even if there was an error.
	return stdout, stderr, err
}
