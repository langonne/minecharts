# Minecharts Web

## Overview

The frontend component of the Minecharts ecosystem - a web interface specifically designed to interact with the [Minecharts API](https://github.com/ZenT0x/minecharts-api). This UI provides an intuitive way to manage Minecraft servers deployed in Kubernetes clusters through the existing Go-based [Minecharts API](https://github.com/ZenT0x/minecharts-api) backend.

## Tech stack

  - [Vite](https://github.com/vitejs/vite)
  - [HTMX](https://github.com/bigskysoftware/htmx)
  - [AlpineJS](https://github.com/alpinejs/alpine)
  - [UnoCSS](https://github.com/unocss/unocss) (with wind4 preset)

## Getting started

### Prerequesites

  - Bun package manager
  - Minecharts API (Go backend) running and accessible

### Installation
```bash
bun install
```
### Development
```bash
bun run dev
```
### Building for production
```bash
bun run build
```

### Configuring the backend URL

Set `MINECHARTS_API_URL` before running `bun run dev` or `bun run build` to point the web app at your API instance:

```bash
MINECHARTS_API_URL="http://minecharts-api.kube.local:8080" bun run dev
```

## Backend Integration
This frontend is designed to work exclusively with the Minecharts API (Go backend). It consumes the API endpoints to perform all server management operations. Ensure the API is properly configured and accessible before using this frontend.

## Container image

A production-ready container image is provided through the `Dockerfile`. It builds the static assets with Bun and serves them with Nginx over HTTPS.

```bash
docker build -t minecharts-web .
# run with a backend exposed at http://minecharts-api:8080
docker run -p 8080:80 -p 8443:443 \
  -e MINECHARTS_API_URL="http://minecharts-api:8080" \
  minecharts-web
```

TLS is enabled by default. Provide your own certificate by mounting it at `/etc/nginx/certs/tls.crt` and `/etc/nginx/certs/tls.key`. When no certificate is supplied, a self-signed certificate is generated automatically (subject configurable through `SSL_SELF_SIGNED_SUBJECT`).

If the container is deployed behind an ingress controller (for example Traefik) that already terminates TLS, disable HTTPS inside the container by setting `ENABLE_TLS=false`. In that mode, the application is served over plain HTTP on port 80 and certificates are not generated.
