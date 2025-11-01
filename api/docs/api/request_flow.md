# Request Flow

1. **Authenticate** with a cookie or API key.
2. **Authorise**: middleware checks the caller's permission mask (plus server ownership when applicable).
3. **Persist** changes in the database to keep track of owners, deployments, and volumes.
4. **Apply** changes to the Kubernetes cluster using Client-Go.
5. **Log** outcomes with per-domain loggers for auditing and troubleshooting.
