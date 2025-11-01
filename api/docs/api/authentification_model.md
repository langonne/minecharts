# Authentication Model

- **JWT cookie (`auth_token`)**: returned by `POST /auth/login` and `POST /auth/register`. The cookie is HttpOnly; enable the `Secure` flag behind TLS. Include it automatically when calling other endpoints from a browser or HTTP client.
- **API key**: obtain one through `POST /apikeys` after logging in. Supply it via `X-API-Key`. Keys inherit the permissions of their owner and are ideal for automation where cookies are inconvenient.
- **Permissions**: each user carries a bitmask (admin, create server, restart, etc.). The handler chain performs the permission check after authentication; server owners automatically gain control over their own instances even when they do not hold the global bit.
