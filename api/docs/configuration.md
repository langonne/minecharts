# Configuration

Minecharts API reads its configuration from environment variables at startup (`cmd/config/config.go`). The following tables enumerate every supported variable and the resulting behaviour.

## Core Settings
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_NAMESPACE` | `minecharts` | Kubernetes namespace that hosts deployments, services, and PVCs. |
| `MINECHARTS_DEPLOYMENT_PREFIX` | `minecraft-server-` | Prefix applied to server names to build deployment/service names. |
| `MINECHARTS_PVC_SUFFIX` | `-pvc` | Suffix appended to PVC names. |
| `MINECHARTS_STORAGE_SIZE` | `10Gi` | Capacity requested for each persistent volume claim. |
| `MINECHARTS_STORAGE_CLASS` | *(empty)* | Storage class used when creating PVCs; leave empty to let Kubernetes pick the cluster default automatically.<br />Example: `local-path` |
| `MINECHARTS_MCROUTER_DOMAIN_SUFFIX` | *(empty)* | Domain suffix used when exposing servers through mc-router; required for the API to start.<br />Example: `mc.example.com` |
| `MINECHARTS_TRUSTED_PROXIES` | `127.0.0.1` | Comma-separated list passed to Gin to mark upstream proxies as trusted. |
| `MINECHARTS_TIMEZONE` | `UTC` | Application-wide timezone for logging and time calculations. |
| `MINECHARTS_MEMORY_QUOTA_ENABLED` | `false` | Enables enforcement of the global Minecraft memory quota. |
| `MINECHARTS_MEMORY_QUOTA_LIMIT` | `0` | Maximum total memory (gigabytes) the cluster may allocate to Minecraft servers when the quota is enabled. `0` or negative values are treated as unlimited. |
| `MINECHARTS_MEMORY_LIMIT_OVERHEAD_MI` | `256` | Extra memory (in mebibytes) added on top of each server’s `MAX_MEMORY` when enforcing Kubernetes limits, to account for JVM/process overhead. |
| `DATA_DIR` | `./app/data` | Local directory for SQLite data when the DB is auto-initialised. |

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

## OAuth & Authentik
OAuth integration is optional. Enable it by setting `MINECHARTS_OAUTH_ENABLED` to `true`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_OAUTH_ENABLED` | `false` | Enables the OAuth endpoints under `/auth/oauth/:provider`. |
| `MINECHARTS_AUTHENTIK_ENABLED` | `false` | Toggles the Authentik provider implementation. |
| `MINECHARTS_AUTHENTIK_ISSUER` | *(empty)* | Authentik issuer URL, e.g. `https://auth.example.com/application/o/`. |
| `MINECHARTS_AUTHENTIK_CLIENT_ID` | *(empty)* | OAuth client ID registered with Authentik. |
| `MINECHARTS_AUTHENTIK_CLIENT_SECRET` | *(empty)* | OAuth client secret. |
| `MINECHARTS_AUTHENTIK_REDIRECT_URL` | *(empty)* | Redirect URL registered with Authentik, e.g. `https://api.example.com/auth/callback/authentik`. |

## Logging
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_LOG_LEVEL` | `info` | Supported levels: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`. |
| `MINECHARTS_LOG_FORMAT` | `json` | Output format for Logrus (`json` or `text`). |
| `MINECHARTS_BCRYPT_COST` | `14` | Work factor for bcrypt hashing (valid range 4–31); raise for stronger security at the cost of CPU. |

## Rate Limiting
| Variable | Default | Purpose |
| --- | --- | --- |
| `MINECHARTS_RATE_LIMIT_LOGIN_CAPACITY` | `5` | Maximum bursts allowed for `POST /auth/login` per IP. |
| `MINECHARTS_RATE_LIMIT_LOGIN_INTERVAL` | `1m` | Refill interval (Go duration format) for login tokens. |
| `MINECHARTS_RATE_LIMIT_REGISTER_CAPACITY` | `2` | Maximum bursts allowed for `POST /auth/register` per IP. |
| `MINECHARTS_RATE_LIMIT_REGISTER_INTERVAL` | `5m` | Refill interval for registration tokens. |
| `MINECHARTS_RATE_LIMIT_USER_PATCH_CAPACITY` | `5` | Maximum bursts allowed for `PATCH /users/:id` per IP. |
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
| `MINECHARTS_FEEDBACK_GITLAB_PROJECT` | *(empty)* | GitLab project path or numeric ID that receives feedback issues. |
| `MINECHARTS_FEEDBACK_GITLAB_URL` | `https://gitlab.com` | Base URL for the GitLab instance (e.g. `https://gitlab.example.com`). |
| `MINECHARTS_FEEDBACK_DEFAULT_LABELS` | `feedback` | Comma-separated labels automatically added to each generated issue (in addition to type-specific labels). |

The API automatically manages the JWT signing key in `<DATA_DIR>/jwt.secret`. Delete the file to rotate the key, and keep `DATA_DIR` on persistent storage so tokens remain valid across restarts.

If feedback is enabled but the required credentials for the selected provider are missing, the API logs an error and any submission returns a `500` response.

Extend the configuration package with additional environment variables when introducing new behaviours so that operators can tune the system without recompiling.
