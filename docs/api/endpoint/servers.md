# Server Endpoints

## `POST /servers`
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

## `GET /servers`
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

## `GET /servers/{serverName}`
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

## `POST /servers/{serverName}/restart`
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

## `POST /servers/{serverName}/stop`
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

## `POST /servers/{serverName}/start`
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

## `POST /servers/{serverName}/delete`
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

## `POST /servers/{serverName}/exec`
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

## `POST /servers/{serverName}/expose`
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

## `GET /ws` (WebSocket log stream)
- **Purpose:** Stream `logs/latest.log` from a running Minecraft pod in real time.
- **Auth required:** JWT cookie (`auth_token`) or API key (`X-API-Key` header on the upgrade request) + owner or `PermViewServer` permission for the target server.

1. Open a WebSocket connection to `GET /ws`, including the authentication headers/cookies you normally use with the API.
2. Immediately after the handshake, send a single JSON message selecting the server:

    ```json
    { "server_id": 42 }
    ```

    The `server_id` is the numeric identifier returned by `GET /servers`.

3. When the subscription is accepted, the API responds with a `status` message and begins streaming the log file.

### Message types

- `{"type":"status","message":"connected"}` — WebSocket upgrade acknowledged.
- `{"type":"status","message":"streaming"}` — log streaming has started.
- `{"type":"log","data":"[Server thread/INFO]: ...\n"}` — raw lines from `logs/latest.log` (standard output).
- `{"type":"error","message":"..."}` — authentication/authorization errors, missing pods, or stderr output from the tail command.

The server executes `tail -n +1 -F`, so the entire file is replayed before following new lines. Each client connection has its own tail process; closing the WebSocket stops the stream immediately.
