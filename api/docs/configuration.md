# Configuration

Minecharts API reads its configuration from environment variables at startup (`cmd/config/config.go`). The following tables enumerate every supported variable and the resulting behaviour.

## Core Settings
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_NAMESPACE` | `minecharts` | Kubernetes namespace that hosts StatefulSets, services, and PVCs. |
| `MINECHARTS_STATEFULSET_PREFIX` | `minecraft-server-` | Prefix applied to server names to build StatefulSet/service names. |
| `MINECHARTS_PVC_SUFFIX` | `-pvc` | Suffix appended to PVC names. |
| `MINECHARTS_STORAGE_SIZE` | `10Gi` | Capacity requested for each persistent volume claim. |
| `MINECHARTS_STORAGE_CLASS` | *(empty)* | Storage class used when creating PVCs; leave empty to let Kubernetes pick the cluster default automatically.<br />Example: `local-path` |
| `MINECHARTS_MCROUTER_DOMAIN_SUFFIX` | *(empty)* | Domain suffix used when exposing servers through mc-router; required for the API to start.<br />Example: `mc.example.com` |
| `MINECHARTS_TRUSTED_PROXIES` | `127.0.0.1` | Comma-separated list passed to Gin to mark upstream proxies as trusted. |
| `MINECHARTS_TIMEZONE` | `UTC` | Application-wide timezone for logging and time calculations. |
| `MINECHARTS_MEMORY_QUOTA_ENABLED` | `false` | Enables enforcement of the global Minecraft memory quota. |
| `MINECHARTS_MEMORY_QUOTA_LIMIT` | `0` | Maximum total memory (gigabytes) the cluster may allocate to Minecraft servers when the quota is enabled. `0` or negative values are treated as unlimited. |
| `MINECHARTS_MEMORY_LIMIT_OVERHEAD_PERCENT` | `25` | Percentage of each server’s `MEMORY` added as overhead when enforcing Kubernetes limits (e.g. `MEMORY=4G` and `25` → limit set to `5Gi`). |
| `DATA_DIR` | `./app/data` | Local directory for SQLite data when the DB is auto-initialised. |

!!! info "Memory quota accounting"
    When `MINECHARTS_MEMORY_QUOTA_ENABLED` is `true`, quota checks use the same value as the Kubernetes limit: `MEMORY + overhead%`. The remaining budget is therefore the cluster-side cost (including overhead), not just the raw `MEMORY` value.

!!! info "Memory overhead (limit buffer)"
    The `MEMORY` value is forwarded as-is to the `itzg/minecraft-server` container and set as the pod’s memory **request**. The **limit** is `MEMORY + (MEMORY * MINECHARTS_MEMORY_LIMIT_OVERHEAD_PERCENT / 100)`. With the default `25`, a `MEMORY` of `4G` translates to a request of `4Gi` and a limit of roughly `5Gi`. If the container exceeds the limit, Kubernetes will OOM-kill the pod. Negative overhead values are clamped to zero.

!!! warning "Deprecated alias"
    `MINECHARTS_MEMORY_LIMIT_OVERHEAD_MI` remains accepted for backward compatibility but is deprecated and will be removed in a future release. A startup warning is logged when it is used. Migrate to `MINECHARTS_MEMORY_LIMIT_OVERHEAD_PERCENT`.

## Minecraft server environment variables
Every key/value under the `env` object of `POST /servers` is forwarded to the underlying `itzg/minecraft-server` container. `MEMORY` sets the pod’s memory **request** and, with the configured overhead percentage, the **limit** (see above). Quota checks also use this limit. Refer to the image documentation for supported options: <https://docker-minecraft-server.readthedocs.io/en/latest/variables/>.

!!! note "Legacy vanilla safeguard"
    For vanilla servers targeting versions older than `1.12`, Minecharts automatically injects `USE_NATIVE_TRANSPORT=false` (unless you set it yourself) to prevent native transport issues on these builds.

!!! note "MOTD limits"
    The MOTD may contain at most one newline (two lines total) and up to 59 visible characters. Formatting/color codes (`&x`/`§x`) don’t count toward the limit and are forwarded to the server as `§` codes.

## Database
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_DB_TYPE` | `sqlite` | Database backend (`sqlite` or `postgres`). |
| `MINECHARTS_DB_CONNECTION` | `./app/data/minecharts.db` | File path for SQLite or connection string for PostgreSQL. |

## Authentication & Security
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_JWT_EXPIRY_HOURS` | `24` | Token lifespan in hours. |
| `MINECHARTS_API_KEY_PREFIX` | `mcapi` | Prefix applied to generated API keys. |
| `MINECHARTS_ALLOW_SELF_REGISTRATION` | `false` | When `false`, `/auth/register` is restricted to authenticated admins; when `true`, anyone can create an account (rate-limited). |
| `MINECHARTS_DEFAULT_USER_PERMISSIONS` | `operator` | Default permissions for newly created users (self-registration and OAuth); accepts aliases (`none`, `readonly`, `operator`, `all`) or a numeric bitmask. The admin bit is always stripped. |
| `MINECHARTS_FRONTEND_URL` | `http://localhost:3000` | Frontend base URL used for OAuth callbacks/redirects after login. |

!!! tip "Handy defaults"
    `operator` grants every permission except admin (`PermOperator`), making it a safe default for non-privileged accounts. Aliases also accept numeric bitmasks if you want direct control.

### Permission flags and common masks
| Name | Value | Grants |
| --- | --- | --- |
| `PermAdmin` | `1` | Full administrator access. |
| `PermCreateServer` | `2` | Create new servers. |
| `PermDeleteServer` | `4` | Delete servers. |
| `PermStartServer` | `8` | Start servers. |
| `PermStopServer` | `16` | Stop servers. |
| `PermRestartServer` | `32` | Restart servers. |
| `PermExecCommand` | `64` | Execute commands on servers. |
| `PermViewServer` | `128` | View server details. |

Common combinations:
- `PermReadOnly` = `128`
- `PermOperator` = `254` (all above except admin)
- `PermAll` = `255` (admin + all other flags)

!!! warning "Admin bit is stripped"
    `MINECHARTS_DEFAULT_USER_PERMISSIONS` and `MINECHARTS_AUTHENTIK_USER_PERMISSIONS` always drop the admin bit, even if you provide `all` or `255`, to avoid accidental escalation. Reserve admin for the dedicated group (`MINECHARTS_AUTHENTIK_ADMIN_GROUP`) or manual assignment.

## OAuth & OIDC (single provider)
OAuth integration is optional. Enable it by setting `MINECHARTS_OAUTH_ENABLED` to `true`. A single OIDC provider is configured via environment variables.

### OIDC provider settings
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_OAUTH_ENABLED` | `false` | Enables the OAuth endpoints under `/auth/oauth/:provider`. |
| `MINECHARTS_OAUTH_PROVIDER_NAME` | *(empty)* | Required. Slug used in routes `/auth/oauth/{name}` and the callback path; no spaces. Exposed to the frontend. |
| `MINECHARTS_OAUTH_PROVIDER_DISPLAY_NAME` | *(empty)* | Human-friendly name exposed to the frontend; defaults to `MINECHARTS_OAUTH_PROVIDER_NAME` when empty. |
| `MINECHARTS_OIDC_ISSUER` | *(empty)* | OIDC issuer URL used for discovery via `/.well-known/openid-configuration`. |
| `MINECHARTS_OIDC_CLIENT_ID` | *(empty)* | Client ID registered with the OIDC provider. |
| `MINECHARTS_OIDC_CLIENT_SECRET` | *(empty)* | Client secret registered with the OIDC provider. |
| `MINECHARTS_OIDC_REDIRECT_URL` | *(empty)* | Redirect URL registered with the OIDC provider. |

!!! note
    The issuer must expose a valid OIDC discovery document at `/.well-known/openid-configuration`. Pure OAuth2 providers without OIDC discovery (e.g. GitHub/Discord OAuth) are not supported by this generic flow; you need an OIDC-compliant provider.
    There is no dedicated Authentik enable toggle; use the OIDC variables above.

### Authentik (compat and group sync)
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_AUTHENTIK_GROUP_SYNC_ENABLED` | `false` | When `true`, Minecharts inspects the `groups` claim to map users to Minecharts roles automatically; admin rights are granted and revoked to mirror the configured group membership. |
| `MINECHARTS_AUTHENTIK_ADMIN_GROUP` | *(empty)* | Name of the group that should receive Minecharts admin permissions (case-insensitive). Required when group sync is enabled. |
| `MINECHARTS_AUTHENTIK_USER_GROUP` | *(empty)* | Optional non-admin Authentik group to sync. When present, members receive `MINECHARTS_AUTHENTIK_USER_PERMISSIONS`; others fall back to `MINECHARTS_DEFAULT_USER_PERMISSIONS`. |
| `MINECHARTS_AUTHENTIK_USER_PERMISSIONS` | *(empty)* | Permissions to grant to members of `MINECHARTS_AUTHENTIK_USER_GROUP`. Accepts the same aliases/bitmask as `MINECHARTS_DEFAULT_USER_PERMISSIONS`. Defaults to the configured default user permissions. The admin bit is always stripped. |

!!! example "Authentik sync scenario"
    - `MINECHARTS_AUTHENTIK_GROUP_SYNC_ENABLED=true`
    - `MINECHARTS_AUTHENTIK_ADMIN_GROUP=minecharts-admins`
    - `MINECHARTS_AUTHENTIK_USER_GROUP=minecharts-operators`
    - `MINECHARTS_AUTHENTIK_USER_PERMISSIONS=operator`

    Outcome: `minecharts-admins` members get admin; `minecharts-operators` members get all permissions except admin; everyone else falls back to `MINECHARTS_DEFAULT_USER_PERMISSIONS` (default `operator`).

## Logging
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_LOG_LEVEL` | `info` | Supported levels: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`. |
| `MINECHARTS_LOG_FORMAT` | `json` | Output format for Logrus (`json` or `text`). |
| `MINECHARTS_BCRYPT_COST` | `14` | Work factor for bcrypt hashing (valid range 4–31); raise for stronger security at the cost of CPU. |

## Rate Limiting
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_RATE_LIMIT_LOGIN_CAPACITY` | `10` | Maximum bursts allowed for `POST /auth/login` per IP. |
| `MINECHARTS_RATE_LIMIT_LOGIN_INTERVAL` | `1m` | Refill interval (Go duration format) for login tokens. |
| `MINECHARTS_RATE_LIMIT_REGISTER_CAPACITY` | `4` | Maximum bursts allowed for `POST /auth/register` per IP. |
| `MINECHARTS_RATE_LIMIT_REGISTER_INTERVAL` | `5m` | Refill interval for registration tokens. |
| `MINECHARTS_RATE_LIMIT_USER_PATCH_CAPACITY` | `10` | Maximum bursts allowed for `PATCH /users/:id` per IP. |
| `MINECHARTS_RATE_LIMIT_USER_PATCH_INTERVAL` | `1m` | Refill interval for user patch tokens. |
| `MINECHARTS_RATE_LIMIT_CLEANUP_EVERY` | `100` | Cleanup frequency (in requests) for purging stale rate-limit rows. |
| `MINECHARTS_RATE_LIMIT_RETENTION` | `30m` | How long to retain inactive rate-limit rows before cleanup. |
| `MINECHARTS_API_KEYS_PER_USER` | `5` | Maximum number of active API keys per user. |

!!! note
    The limiter state lives in the application database. PostgreSQL handles concurrent updates efficiently; SQLite serialises writes and may emit short `database is locked` retries under load. For high-traffic deployments, prefer PostgreSQL or an external rate-limiting tier.

## Feedback & Issue Reporting
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_FEEDBACK_ENABLED` | `false` | Enables the authenticated `POST /feedback` endpoint that raises issues on behalf of users. |
| `MINECHARTS_FEEDBACK_PROVIDER` | *(unset)* | Required when feedback is enabled; set to `github` or `gitlab`. |
| `MINECHARTS_FEEDBACK_GITHUB_TOKEN` | *(empty)* | GitHub personal access token used when the provider is `github`. |
| `MINECHARTS_FEEDBACK_GITHUB_REPO_OWNER` | *(empty)* | GitHub repository owner (user or organisation) that will receive feedback issues. |
| `MINECHARTS_FEEDBACK_GITHUB_REPO_NAME` | *(empty)* | GitHub repository name where issues are created. |
| `MINECHARTS_FEEDBACK_GITLAB_TOKEN` | *(empty)* | GitLab personal access token used when the provider is `gitlab`. |
| `MINECHARTS_FEEDBACK_GITLAB_PROJECT` | *(empty)* | GitLab project path or numeric ID that receives feedback issues.<br />Examples: `group/subgroup/minecharts` or `37`. |
| `MINECHARTS_FEEDBACK_GITLAB_URL` | `https://gitlab.com` | Base URL for the GitLab instance (e.g. `https://gitlab.example.com`). |
| `MINECHARTS_FEEDBACK_DEFAULT_LABELS` | `feedback` | Comma-separated labels automatically added to each generated issue (in addition to type-specific labels). |

The API automatically manages the JWT signing key in `<DATA_DIR>/jwt.secret`. Delete the file to rotate the key, and keep `DATA_DIR` on persistent storage so tokens remain valid across restarts.

If feedback is enabled but the required credentials for the selected provider are missing, the API logs an error and any submission returns a `500` response.

Extend the configuration package with additional environment variables when introducing new behaviours so that operators can tune the system without recompiling.
