# Helm chart (minecharts)

This chart deploys the API and web UI with ingress routing.

## Exposure
- API Service defaults to `ClusterIP` and is reached via the ingress rule `/api`. Traefik middleware (`stripPrefix /api`) rewrites URLs so the API—served without a prefix—keeps working. Change only if you expose the API differently.
- Web Service is `ClusterIP` and served at `/`.
- Ingress annotations (`cert-manager.io/cluster-issuer`, Traefik entrypoints/TLS, etc.) are examples; adapt them to your cluster (issuer name, ingress class, entrypoints).

## Persistence
- API: PVC enabled by default to persist the JWT signing key and optionally SQLite. Disable with `api.persistence.enabled=false` if you run Postgres and accept a regenerated JWT on restart. Size guidance: ~1Mi for JWT only; ~1Gi if you keep SQLite on disk (default `size: 32Mi` for compatibility).
- Web: stateless; no PVC requested.

## Secrets
- Use `secretEnv` for individual secret keys and `envFromSecrets` to load whole Secret objects as environment variables without putting sensitive values in `values.yaml`.

## Middleware
- `middleware.enabled` creates a Traefik `stripPrefix` middleware (default prefix `/api`) and annotates the ingress when `ingress.middlewareAnnotation` is true. Disable only if you serve the API with an `/api` prefix or use another ingress rewrite mechanism.
- `ingress.middlewareAnnotation`: when true, the ingress is annotated to use the middleware. Set false if you don’t want the ingress to reference it (e.g., you handle rewrites elsewhere).
