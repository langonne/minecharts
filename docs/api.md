# API Overview

Minecharts API is organised around a small set of REST endpoints that manage authentication, API keys, and Minecraft servers. All requests must use HTTPS in production and include either the session cookie issued at login or an API key in the `X-API-Key` header.

## Authentication Model
- **JWT cookie (`auth_token`)**: returned by `POST /auth/login` and `POST /auth/register`. The cookie is HttpOnly; enable the `Secure` flag behind TLS. Include it automatically when calling other endpoints from a browser or HTTP client.
- **API key**: obtain one through `POST /apikeys` after logging in. Supply it via `X-API-Key`. Keys inherit the permissions of their owner and are ideal for automation where cookies are inconvenient.
- **Permissions**: each user carries a bitmask (admin, create server, restart, etc.). The handler chain performs the permission check after authentication; server owners automatically gain control over their own instances even when they do not hold the global bit.

## Endpoint Reference
Each section below summarises the endpoint’s purpose, the authentication requirement, and provides a sample request you can adapt.

### Authentication

#### `POST /auth/register`
- **Purpose:** Create a user account and issue an authenticated session.
- **Auth required:** None

=== "Request"

    ```http
    POST /auth/register HTTP/1.1
    Content-Type: application/json

    {
      "username": "overseer",
      "email": "overseer@example.com",
      "password": "Sup3rStrongPassword!"
    }
    ```

=== "Response"

    ```json
    {
      "token": "<jwt>",
      "user_id": 1,
      "username": "overseer",
      "email": "overseer@example.com",
      "permissions": 0
    }
    ```

#### `POST /auth/login`
- **Purpose:** Authenticate an existing user and receive the `auth_token` cookie.
- **Auth required:** None

=== "Request"

    ```http
    POST /auth/login HTTP/1.1
    Content-Type: application/json

    {
      "username": "overseer",
      "password": "Sup3rStrongPassword!"
    }
    ```

=== "Response"

    ```json
    {
      "user_id": 1,
      "username": "overseer",
      "email": "overseer@example.com",
      "permissions": 255
    }
    ```

#### `POST /auth/logout`
- **Purpose:** Invalidate the active session cookie.
- **Auth required:** JWT cookie

=== "Request"

    ```http
    POST /auth/logout HTTP/1.1
    Cookie: auth_token=<jwt>
    ```

=== "Response"

    ```json
    {
      "message": "Logout successful",
      "status": "success"
    }
    ```

#### `GET /auth/me`
- **Purpose:** Retrieve the authenticated user profile and permissions.
- **Auth required:** JWT cookie

=== "Request"

    ```http
    GET /auth/me HTTP/1.1
    Cookie: auth_token=<jwt>
    ```

=== "Response"

    ```json
    {
      "user_id": 1,
      "username": "overseer",
      "email": "overseer@example.com",
      "permissions": 255,
      "active": true,
      "last_login": "2024-05-10T18:12:44Z",
      "created_at": "2024-03-01T09:15:32Z"
    }
    ```

### API Keys

#### `POST /apikeys`
- **Purpose:** Generate a new API key (revealed once).
- **Auth required:** JWT cookie

=== "Request"

    ```http
    POST /apikeys HTTP/1.1
    Cookie: auth_token=<jwt>
    Content-Type: application/json

    {
      "description": "CI pipeline",
      "expires_at": "2025-01-01T00:00:00Z"
    }
    ```

=== "Response"

    ```json
    {
      "id": 42,
      "key": "mcapi.1df3c0d9f95f4a6f",
      "description": "CI pipeline",
      "expires_at": "2025-01-01T00:00:00Z",
      "created_at": "2024-05-06T18:42:11Z"
    }
    ```

#### `GET /apikeys`
- **Purpose:** List keys owned by the caller.
- **Auth required:** JWT cookie

=== "Request"

    ```http
    GET /apikeys HTTP/1.1
    Cookie: auth_token=<jwt>
    ```

=== "Response"

    ```json
    [
      {
        "id": 42,
        "key": "mcapi.1df3c0...",
        "description": "CI pipeline",
        "last_used": "2024-05-12T09:17:22Z",
        "expires_at": "2025-01-01T00:00:00Z",
        "created_at": "2024-05-06T18:42:11Z"
      }
    ]
    ```

#### `DELETE /apikeys/{id}`
- **Purpose:** Revoke a key immediately.
- **Auth required:** JWT cookie

=== "Request"

    ```http
    DELETE /apikeys/42 HTTP/1.1
    Cookie: auth_token=<jwt>
    ```

=== "Response"

    ```json
    {
      "message": "API key deleted successfully"
    }
    ```

### Servers

#### `POST /servers`
- **Purpose:** Provision a server (PVC + Deployment + Service) for the caller.
- **Auth required:** JWT cookie or API key + `PermCreateServer`

=== "Request"

    ```http
    POST /servers HTTP/1.1
    Authorization: Bearer <token>
    Content-Type: application/json

    {
      "serverName": "survival",
      "env": {
        "EULA": "TRUE",
        "TYPE": "PAPER",
        "VERSION": "1.21.1",
        "MEMORY": "4G",
        "DIFFICULTY": "hard"
      }
    }
    ```

=== "Response"

    ```json
    {
      "message": "Minecraft server started",
      "deploymentName": "minecraft-server-survival",
      "pvcName": "minecraft-server-survival-pvc",
      "domain": "survival.test.nasdak.fr",
      "serviceName": "minecraft-server-survival-svc",
      "url": "survival.test.nasdak.fr"
    }
    ```

!!! note "Environment variables"
    Every key/value under `env` is passed directly to the underlying `itzg/minecraft-server` container. Refer to the image documentation for the exhaustive list of supported options: <https://docker-minecraft-server.readthedocs.io/en/latest/variables/>.

!!! info "MCRouter URL"
    The `url` field is returned only when the backing Kubernetes service carries the `mc-router.itzg.me/externalServerName` annotation (i.e. the server is routed through mc-router).

#### `GET /servers`
- **Purpose:** List servers owned by the caller.
- **Auth required:** JWT cookie or API key + `PermViewServer`

=== "Request"

    ```http
    GET /servers HTTP/1.1
    X-API-Key: mcapi.abcd1234
    ```

=== "Response"

    ```json
    [
      {
        "id": 12,
        "server_name": "survival",
        "deployment_name": "minecraft-server-survival",
        "pvc_name": "minecraft-server-survival-pvc",
        "owner_id": 1,
        "status": "running",
        "created_at": "2024-05-01T10:00:00Z",
        "updated_at": "2024-05-12T08:30:00Z",
        "url": "survival.test.nasdak.fr",
        "environment": {
          "EULA": "TRUE",
          "MEMORY": "4G",
          "MODE": "survival"
        }
      }
    ]
    ```

!!! info "Conditional URL"
    `url` is emitted only for servers exposed via mc-router.

#### `GET /servers/{serverName}`
- **Purpose:** Retrieve logical metadata, environment variables, and status for a server.
- **Auth required:** JWT cookie or API key + owner or `PermViewServer`

=== "Request"

    ```http
    GET /servers/survival HTTP/1.1
    Authorization: Bearer <token>
    ```

=== "Response"

    ```json
    {
      "id": 12,
      "server_name": "survival",
      "deployment_name": "minecraft-server-survival",
      "pvc_name": "minecraft-server-survival-pvc",
      "owner_id": 1,
      "status": "running",
      "created_at": "2024-05-01T10:00:00Z",
      "updated_at": "2024-05-12T08:30:00Z",
      "url": "survival.test.nasdak.fr",
      "environment": {
        "EULA": "TRUE",
        "TYPE": "PAPER",
        "VERSION": "1.21.1",
        "MEMORY": "4G"
      }
    }
    ```

!!! info "Conditional URL"
    The per-server `url` appears only when the Kubernetes service uses the mc-router annotation.

#### `POST /servers/{serverName}/restart`
- **Purpose:** Save the world, update the deployment template, and trigger a rollout.
- **Auth required:** JWT cookie or API key + owner or `PermRestartServer`

=== "Request"

    ```http
    POST /servers/survival/restart HTTP/1.1
    Authorization: Bearer <token>
    ```

=== "Response"

    ```json
    {
      "message": "Server restart triggered",
      "deploymentName": "minecraft-server-survival",
      "stdout": "[Server thread/INFO]: Saved the game",
      "stderr": ""
    }
    ```

#### `POST /servers/{serverName}/stop`
- **Purpose:** Scale the deployment to zero replicas.
- **Auth required:** JWT cookie or API key + owner or `PermStopServer`

=== "Request"

    ```http
    POST /servers/survival/stop HTTP/1.1
    Authorization: Bearer <token>
    ```

=== "Response"

    ```json
    {
      "message": "Server stopping (replicas scaled to 0)",
      "deploymentName": "minecraft-server-survival"
    }
    ```

#### `POST /servers/{serverName}/start`
- **Purpose:** Scale the deployment back to one replica.
- **Auth required:** JWT cookie or API key + owner or `PermStartServer`

=== "Request"

    ```http
    POST /servers/survival/start HTTP/1.1
    Authorization: Bearer <token>
    ```

=== "Response"

    ```json
    {
      "message": "Server starting (deployment scaled to 1)",
      "deploymentName": "minecraft-server-survival"
    }
    ```

#### `POST /servers/{serverName}/delete`
- **Purpose:** Delete the deployment, service, PVC, and database record.
- **Auth required:** JWT cookie or API key + owner or `PermDeleteServer`

=== "Request"

    ```http
    POST /servers/survival/delete HTTP/1.1
    Authorization: Bearer <token>
    ```

=== "Response"

    ```json
    {
      "message": "Deployment, PVC and network resources deleted",
      "deploymentName": "minecraft-server-survival",
      "pvcName": "minecraft-server-survival-pvc"
    }
    ```

#### `POST /servers/{serverName}/exec`
- **Purpose:** Run a console command via `mc-send-to-console` inside the pod.
- **Auth required:** JWT cookie or API key + owner or `PermExecCommand`

=== "Request"

    ```http
    POST /servers/survival/exec HTTP/1.1
    X-API-Key: mcapi.abcd1234
    Content-Type: application/json

    {
      "command": "say Hello from automation!"
    }
    ```

=== "Response"

    ```json
    {
      "stdout": "[Server thread/INFO]: [Server] Hello from automation!\n",
      "stderr": "",
      "command": "say Hello from automation!"
    }
    ```

#### `POST /servers/{serverName}/expose`
- **Purpose:** Recreate the service (ClusterIP, NodePort, LoadBalancer, or mc-router mode).
- **Auth required:** JWT cookie or API key + owner or `PermCreateServer`

=== "Request"

    ```http
    POST /servers/survival/expose HTTP/1.1
    Authorization: Bearer <token>
    Content-Type: application/json

    {
      "exposureType": "NodePort",
      "port": 25565
    }
    ```

=== "Response"

    ```json
    {
      "message": "Service created",
      "serviceName": "minecraft-server-survival-svc",
      "exposureType": "NodePort",
      "serviceType": "NodePort",
      "nodePort": 32751
    }
    ```

### Users (administration)

#### `GET /users`
- **Purpose:** List every user in the system.
- **Auth required:** JWT cookie + `PermAdmin`

=== "Request"

    ```http
    GET /users HTTP/1.1
    Cookie: auth_token=<admin_jwt>
    ```

=== "Response"

    ```json
    [
      {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "permissions": 255,
        "active": true,
        "last_login": "2024-05-10T18:12:44Z",
        "created_at": "2024-03-01T09:15:32Z",
        "updated_at": "2024-05-10T18:12:44Z"
      }
    ]
    ```

#### `GET /users/{id}`
- **Purpose:** Retrieve a specific user. Non-admins can fetch their own record only.
- **Auth required:** JWT cookie + `PermAdmin` (or matching user ID)

=== "Request"

    ```http
    GET /users/2 HTTP/1.1
    Cookie: auth_token=<admin_jwt>
    ```

=== "Response"

    ```json
    {
      "id": 2,
      "username": "builder",
      "email": "builder@example.com",
      "permissions": 10,
      "active": true,
      "last_login": "2024-05-08T14:02:11Z",
      "created_at": "2024-04-20T12:00:00Z",
      "updated_at": "2024-05-08T14:02:11Z"
    }
    ```

#### `PUT /users/{id}`
- **Purpose:** Update username, email, password, permissions, or active flag.
- **Auth required:** JWT cookie + `PermAdmin`

=== "Request"

    ```http
    PUT /users/2 HTTP/1.1
    Cookie: auth_token=<admin_jwt>
    Content-Type: application/json

    {
      "email": "player2@example.com",
      "permissions": 10,
      "active": true
    }
    ```

=== "Response"

    ```json
    {
      "id": 2,
      "username": "builder",
      "email": "player2@example.com",
      "permissions": 10,
      "active": true,
      "last_login": "2024-05-08T14:02:11Z",
      "updated_at": "2024-05-12T10:05:33Z"
    }
    ```

#### `POST /users/{id}/permissions/grant`
- **Purpose:** Add one or more permission bits to a user.
- **Auth required:** JWT cookie + `PermAdmin`

=== "Request"

    ```http
    POST /users/2/permissions/grant HTTP/1.1
    Cookie: auth_token=<admin_jwt>
    Content-Type: application/json

    {
      "permissions": [
        { "permission": 2, "name": "PermDeleteServer" },
        { "permission": 64, "name": "PermExecCommand" }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "user_id": 2,
      "username": "builder",
      "old_permissions": 8,
      "new_permissions": 74
    }
    ```

#### `POST /users/{id}/permissions/revoke`
- **Purpose:** Remove permission bits from a user.
- **Auth required:** JWT cookie + `PermAdmin`

=== "Request"

    ```http
    POST /users/2/permissions/revoke HTTP/1.1
    Cookie: auth_token=<admin_jwt>
    Content-Type: application/json

    {
      "permissions": [
        { "permission": 2 },
        { "permission": 64 }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "user_id": 2,
      "username": "builder",
      "old_permissions": 74,
      "new_permissions": 8
    }
    ```

#### `DELETE /users/{id}`
- **Purpose:** Permanently delete a user account.
- **Auth required:** JWT cookie + `PermAdmin`

=== "Request"

    ```http
    DELETE /users/2 HTTP/1.1
    Cookie: auth_token=<admin_jwt>
    ```

=== "Response"

    ```json
    {
      "message": "User deleted"
    }
    ```

## Request Flow
1. **Authenticate** with a cookie or API key.
2. **Authorise**: middleware checks the caller's permission mask (plus server ownership when applicable).
3. **Persist** changes in the database to keep track of owners, deployments, and volumes.
4. **Apply** changes to the Kubernetes cluster using Client-Go.
5. **Log** outcomes with per-domain loggers for auditing and troubleshooting.

## Operational Notes
- The service automatically triggers `mc-send-to-console save-all` before restart and stop operations. Recent tests with Ceph-backed persistent volumes showed that writes can take a few minutes to settle, occasionally omitting the most recent ticks. The extra save mitigates the inconsistency but plan for a short grace period after each lifecycle change when running on Ceph.
- API key responses only reveal the raw token during creation. Store it immediately; subsequent listings return masked values.
- The `/servers/{serverName}/expose` endpoint deletes any existing service for the deployment before creating a new one, preventing stale exposure modes from lingering.
- Server creation forwards the `env` map directly to the `itzg/minecraft-server` container. Use the upstream variable reference (<https://docker-minecraft-server.readthedocs.io/en/latest/variables/>) when choosing flags and options.

With these fundamentals you can wire Minecharts API into control panels, scripts, or CI pipelines without diving into implementation details.
