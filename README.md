# Minecharts

All-in-one platform to provision, monitor, and manage Minecraft servers on Kubernetes. The repository hosts the Go API and the Bun/Vite frontend, together with Docker workflows for GitHub and GitLab.

## Quick tour
- **API (`api/`)**: Go service orchestrating Minecraft pods (Gin, client-go, multi-stage Docker builds).
- **Web (`web/`)**: Bun/Vite interface powered by HTMX/AlpineJS to drive the orchestrator.
- **Manifests (`kubernetes/`)**: base and overlay manifests for deploying to Kubernetes.
- **CI/CD**: GitHub Actions (`.github/workflows/`) and GitLab (`.gitlab/ci/`) build/push two Docker images (`api` and `web`) with `-dev`, `-latest`, and commit-hash tags.

## Getting started
```bash
# Clone the repository
git clone https://github.com/ZenT0x/minecharts.git
cd minecharts

# API: install deps and run locally
cd api
go mod download
go run ./cmd

# Frontend: install and start Vite dev server
cd ../web
bun install         # or npm/pnpm if you prefer
bun run dev
```
These commands launch the API and dashboard in development mode. Use Docker and the Kubernetes manifests to mirror a production setup or your CI pipelines for reproducible builds.

## Docker images
Pipelines automatically publish:
- `…/minecharts:api`, `api-latest`, `api-<commit>` and `api-dev[-<commit>]`
- `…/minecharts:web`, `web-latest`, `web-<commit>` and `web-dev[-<commit>]`

Configure registry secrets/variables in CI if you target anything other than GHCR or the GitLab Container Registry.

## Documentation
Full documentation (installation, Kubernetes playbooks, CI details) will be linked here once it is available. This README stays lightweight—refer to the docs for deep dives.
