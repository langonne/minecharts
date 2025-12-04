# Helm chart (minecharts)

This chart deploys the API and web UI with ingress routing.

## Exposure
- API Service defaults to `ClusterIP` and is reached via the ingress rule `/api`. Traefik middleware (`stripPrefix /api`) rewrites URLs so the API—served without a prefix—keeps working. Change only if you expose the API differently.
- Web Service is `ClusterIP` and served at `/`.
- Ingress annotations (`cert-manager.io/cluster-issuer`, Traefik entrypoints/TLS, etc.) are examples; adapt them to your cluster (issuer name, ingress class, entrypoints).

!!! warning "URL rewriting"
    The `stripPrefix /api` middleware is enabled by default so the backend can stay prefix-less. If you expose the API anywhere other than `/api`, adjust or disable it (`middleware.enabled=false`) to avoid 404s.

## Persistence
- API: PVC enabled by default to persist the JWT signing key and optionally SQLite. Disable with `api.persistence.enabled=false` if you run Postgres and accept a regenerated JWT on restart. Size guidance: ~1Mi for JWT only; ~1Gi if you keep SQLite on disk (default `size: 32Mi` for compatibility).
- Web: stateless; no PVC requested.

!!! tip "Postgres in production"
    If you run Postgres, disable API persistence (`api.persistence.enabled=false`) to skip the PVC and supply the JWT key via a Kubernetes Secret.

## Secrets
!!! example "Inject secrets without putting them in `values.yaml`"
    - `secretEnv`: map specific keys from an existing Secret to environment variables
      ```yaml
      api:
        secretEnv:
          - name: MINECHARTS_DB_CONNECTION
            secretName: minecharts-api-secrets
            secretKey: db-connection
          - name: MINECHARTS_JWT_SECRET
            secretName: minecharts-api-secrets
            secretKey: jwt-secret
      ```
      Each entry becomes an environment variable in the container.

    - `envFromSecrets`: load all keys of a Secret as environment variables (watch for collisions)
      ```yaml
      api:
        envFromSecrets:
          - minecharts-shared-env
      ```

    - The chart does not create Secrets for you: create them separately (kubectl/Argo/etc.) to avoid embedding secrets in `values.yaml` or the chart.

## Middleware
- `middleware.enabled` creates a Traefik `stripPrefix` middleware (default prefix `/api`) and annotates the ingress when `ingress.middlewareAnnotation` is true. Disable only if you serve the API with an `/api` prefix or use another ingress rewrite mechanism.
- `ingress.middlewareAnnotation`: when true, the ingress is annotated to use the middleware. Set false if you don’t want the ingress to reference it (e.g., you handle rewrites elsewhere).
