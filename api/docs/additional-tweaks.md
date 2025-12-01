# Additional Tweaks

Some behaviours live outside the environment variable matrix but remain easy to tailor if your deployment model differs from the defaults.

- **Default replicas**: The API provisions one pod per server by default (`DefaultReplicas = 1`). Adjust the value in `cmd/config/config.go` if you want newly created worlds to spawn with more replicas.
- **Container security context**: Managed pods run as UID/GID `1000` and include a pre-stop hook that flushes the world save. Modify `cmd/kubernetes/deployement.go` to adapt permissions or lifecycle hooks.
- **Graceful shutdown timing**: The command guard (`mc-send-to-console save-all`) and wait duration before pod restart (`time.Second * 10`) are located in `cmd/kubernetes/utils.go`. Update them to match your workload’s expectations.

!!! tip "Expose new knobs"
    Whenever you add a setting, route it through `cmd/config/config.go` so it’s configurable via environment variables instead of code changes.
