# Minecharts

All-in-one platform to provision, monitor, and manage Minecraft servers on Kubernetes. The repository hosts the Go API and the Bun/Vite frontend, together with Docker workflows for GitHub and GitLab.

## Quick tour
- **API (`api/`)**: Go service orchestrating Minecraft pods (Gin, client-go, multi-stage Docker builds).
- **Web (`web/`)**: Bun/Vite interface powered by HTMX/AlpineJS to drive the orchestrator.
- **Manifests (`kubernetes/`)**: base and overlay manifests for deploying to Kubernetes.
- **CI/CD**: GitHub Actions (`.github/workflows/`) and GitLab (`.gitlab/ci/`) build/push two Docker images (`api` and `web`) with `-dev`, `-latest`, and commit-hash tags.

## Getting started
```bash
git clone https://github.com/ZenT0x/minecharts.git
cd minecharts

# API: install deps (running requires a Kubernetes cluster)
cd api
go mod download
# go run .

# Frontend: install and start Vite dev server
cd ../web
bun install         
bun run dev
```
These commands launch the API and dashboard in development mode. Use Docker and the Kubernetes manifests to mirror a production setup or your CI pipelines for reproducible builds.

## Docker images
Pipelines automatically publish:
- `…/minecharts/api:main`, `…/minecharts/api:latest`, `…/minecharts/api:<commit>` and `…/minecharts/api:dev[,-latest,-<commit>]`
- `…/minecharts/web:main`, `…/minecharts/web:latest`, `…/minecharts/web:<commit>` and `…/minecharts/web:dev[,-latest,-<commit>]`

Configure registry secrets/variables in CI if you target anything other than GHCR or the GitLab Container Registry.

## Kubernetes (Helm prod, Kustomize dev)
- **Prod (Helm)**: chart is published to the GitLab Helm registry.
  ```bash
  helm repo add minecharts https://gitlab.prod.nasdak.fr/api/v4/projects/37/packages/helm/stable
  helm install -f values.yaml minecharts minecharts/minecharts \
    -n minecharts --create-namespace
  ```
  A custom `values.yaml` is mandatory (the chart ships without production defaults). Start from `kubernetes/helm/minecharts/values.yaml`, adapt every section to your cluster, and at minimum set:
  - `MINECHARTS_MCROUTER_DOMAIN_SUFFIX`
  - `ingress.host` (URL that fronts the dashboard/API)
  Check the documentation for the complete list of environment variables and Helm-configurable options.

  **Storage & secrets**: the API claims a small PVC by default to persist the JWT signing key (and optionally SQLite if you use it). Disable it with `api.persistence.enabled=false` when you run Postgres and can tolerate regenerating the JWT on restart; keep it and raise `api.persistence.size` (JWT alone fits in ~1Mi, SQLite closer to ~1Gi) if you store SQLite on disk. The web pod is stateless and does not request storage. Deployments can read Kubernetes `Secret` objects without putting the sensitive values in your `values.yaml`. Ingress annotations (cert-manager, Traefik entrypoints/TLS, etc.) must be aligned with your cluster setup. Une documentation dédiée au chart Helm est présente dans le dépôt.
  ```yaml
  # values.prod.yaml
  api:
    secretEnv:
      - name: DB_PASSWORD
        secretName: minecharts-api-secrets
        secretKey: db-password
    envFromSecrets:
      - minecharts-shared-env
  web:
    envFromSecrets:
      - minecharts-frontend-env
  ```
  `secretEnv` maps individual env vars to `secretKeyRef`. `envFromSecrets` attaches whole Secrets via `envFrom`. Both sections exist for the API and the web deployment.

- **Dev (Kustomize)**: keep the `kubernetes/overlays/test` overlay. Copy the example locally (untracked):

```bash
cp kubernetes/overlays/test/dev-env.example.yaml kubernetes/overlays/test/dev-env.yaml
# edit kubernetes/overlays/test/dev-env.yaml to match your environment
kubectl apply -k kubernetes/overlays/test
```

The `.gitignore` keeps `dev-env.yaml` out of Git; only the samples stay tracked. Adjust hosts/TLS/storage to match your cluster.

All manifests in `kubernetes/` are provided as examples; update hosts, TLS secrets, storage classes, etc. to suit your own cluster.

## Documentation
Full documentation (installation, Kubernetes playbooks, CI details) will be linked here once it is available. This README stays lightweight, refer to the docs for deep dives.

The API expects a kubeconfig and access to a Kubernetes cluster. Running it locally without that context will fail, prefer the Docker images or a local cluster such as kind/minikube.
