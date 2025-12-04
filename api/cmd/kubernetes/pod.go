package kubernetes

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"minecharts/cmd/logging"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const wrapHeredocName = "MINECHARTS_CMD"

func wrapCommandForUser(command string) string {
	script := fmt.Sprintf("<<'%s'\n%s\n%s\n", wrapHeredocName, command, wrapHeredocName)
	return fmt.Sprintf(`if [ "$(id -u)" != "1000" ]; then
if command -v gosu >/dev/null 2>&1; then
	exec gosu 1000:1000 /bin/bash %s
elif command -v runuser >/dev/null 2>&1; then
	exec runuser -u 1000 -- /bin/bash %s
else
	exec /bin/bash %s
fi
else
	exec /bin/bash %s
fi`, script, script, script, script)
}

// getMinecraftPod gets the first pod associated with a StatefulSet
func GetMinecraftPod(namespace, statefulSetName string) (*corev1.Pod, error) {
	labelSelector := "app=" + statefulSetName

	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
		"label_selector", labelSelector,
	).Debug("Looking for Minecraft pod with label selector")

	podList, err := Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})

	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
			"error", err.Error(),
		).Error("Failed to list pods")
		return nil, err
	}

	if len(podList.Items) == 0 {
		logging.K8s.WithFields(
			"namespace", namespace,
			"statefulset_name", statefulSetName,
		).Warn("No pods found for StatefulSet")
		return nil, nil // No pods found
	}

	pod := &podList.Items[0]
	logging.K8s.WithFields(
		"namespace", namespace,
		"statefulset_name", statefulSetName,
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

	wrappedCommand := wrapCommandForUser(command)

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

// StreamCommandInPod executes a long-running command inside a pod and streams its output.
func StreamCommandInPod(ctx context.Context, podName, namespace, containerName, command string, stdout, stderr io.Writer) error {
	logging.K8s.WithFields(
		"namespace", namespace,
		"pod_name", podName,
		"container_name", containerName,
		"command", command,
	).Debug("Streaming command output from pod")

	execReq := Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	wrappedCommand := wrapCommandForUser(command)

	execReq.VersionedParams(&corev1.PodExecOptions{
		Container: containerName,
		Command:   []string{"/bin/bash", "-c", wrappedCommand},
		Stdout:    true,
		Stderr:    true,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(Config, "POST", execReq.URL())
	if err != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pod_name", podName,
			"container_name", containerName,
			"error", err.Error(),
		).Error("Failed to create SPDY executor for streaming")
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	streamErr := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: stdout,
		Stderr: stderr,
	})

	if streamErr != nil {
		logging.K8s.WithFields(
			"namespace", namespace,
			"pod_name", podName,
			"container_name", containerName,
			"command", command,
			"error", streamErr.Error(),
		).Error("Streaming command output failed")
		return streamErr
	}

	logging.K8s.WithFields(
		"namespace", namespace,
		"pod_name", podName,
		"container_name", containerName,
		"command", command,
	).Debug("Streaming command completed")
	return nil
}

// StreamMinecraftLogs streams the Minecraft server logs (logs/latest.log) from the given pod.
func StreamMinecraftLogs(ctx context.Context, podName, namespace, containerName string, stdout, stderr io.Writer) error {
	command := `
set -euo pipefail
PRIMARY_LOG="logs/latest.log"
ALT_LOG="/data/logs/latest.log"
if [ -f "$PRIMARY_LOG" ]; then
	LOG_FILE="$PRIMARY_LOG"
elif [ -f "$ALT_LOG" ]; then
	LOG_FILE="$ALT_LOG"
else
	LOG_FILE="$PRIMARY_LOG"
	mkdir -p "$(dirname "$LOG_FILE")"
	touch "$LOG_FILE"
fi
tail -n +1 -F "$LOG_FILE"`

	return StreamCommandInPod(ctx, podName, namespace, containerName, command, stdout, stderr)
}
