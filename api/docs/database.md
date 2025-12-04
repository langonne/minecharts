# Database Architecture

Minecharts API keeps a compact schema that mirrors the main concepts exposed by the service: users, their credentials, issued API keys, and Minecraft servers with their Kubernetes bindings. The database layer implements the same interface for SQLite (default) and PostgreSQL, so the schema applies to both backends.

## Core Tables
### `users`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | BIGINT | Primary key. |
| `username` | TEXT | Unique per user; used for login. |
| `email` | TEXT | Optional contact address; must be unique. |
| `password_hash` | TEXT | bcrypt hash created by the API. |
| `permissions` | BIGINT | Bitmask containing permission flags (admin, create server, etc.). |
| `active` | BOOLEAN | Controls whether the account can authenticate. |
| `last_login` | TIMESTAMP NULL | Updated after successful login. |
| `created_at` / `updated_at` | TIMESTAMP | Auditing metadata. |

The permission mask is defined in `cmd/database/models.go` and shared across backends. Administrators can update it directly through the API.

### `api_keys`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | BIGINT | Primary key. |
| `user_id` | BIGINT | Foreign key to `users.id`. |
| `key` | TEXT | Generated token (hash or plain string depending on backend). Stored in full; listings only display a masked prefix. |
| `description` | TEXT | Optional label to distinguish automated clients. |
| `last_used` | TIMESTAMP NULL | Updated when the key authenticates a request. |
| `expires_at` | TIMESTAMP NULL | Optional expiration timestamp. |
| `created_at` | TIMESTAMP | Creation time. |

Deleting a key removes the row and immediately invalidates future requests using the token.

### `minecraft_servers`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | BIGINT | Primary key. |
| `server_name` | TEXT | Logical name provided by the user. |
| `statefulset_name` | TEXT | Prefixed name used for the Kubernetes StatefulSet. |
| `pvc_name` | TEXT | Persistent volume claim name derived from the StatefulSet. |
| `owner_id` | BIGINT | Foreign key to `users.id`; identifies who can manage the server. |
| `max_memory_gb` | INTEGER | Memory cap (gigabytes) propagated to the `MAX_MEMORY` container variable. Defaults to `1` when omitted. |
| `status` | TEXT | Cached status (`running`, `stopped`, etc.). |
| `created_at` / `updated_at` | TIMESTAMP | Lifecycle metadata. |

The API derives `statefulset_name` and `pvc_name` using configuration values (`MINECHARTS_STATEFULSET_PREFIX` and `MINECHARTS_PVC_SUFFIX`) to keep database records and Kubernetes resources aligned.

When `MINECHARTS_MEMORY_QUOTA_ENABLED` is `true`, the API sums `max_memory_gb` across all rows before creating a new server and rejects the request if it would exceed `MINECHARTS_MEMORY_QUOTA_LIMIT`.

## Relationships and Cascade Rules
- `api_keys.user_id` and `minecraft_servers.owner_id` reference `users.id`. The implementations enforce referential integrity at the application layer; deleting a user should be preceded by reassignment or cleanup of dependent records.
- Server operations first consult the database to verify ownership and permissions, then apply changes to Kubernetes. After a successful cluster operation, the handler updates the corresponding row (status, timestamps) to keep the database authoritative.

## Backend Considerations
- **SQLite** is the default backend for development. The database file is created automatically under `./app/data/minecharts.db` (or `DATA_DIR`). It supports foreign keys, but ensure `PRAGMA foreign_keys = ON` if you interact with it manually.
- **PostgreSQL** is recommended for production deployments. Provide the connection string through `MINECHARTS_DB_CONNECTION`. Schema migrations are executed at startup via the database implementation.

Keeping the schema lean makes it straightforward to extend Minecharts with new concepts—add a column, adjust the interface methods, and update both SQLite and PostgreSQL implementations accordingly.
