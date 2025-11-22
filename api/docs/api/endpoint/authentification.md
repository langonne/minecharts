# Authentication Endpoints

## `POST /auth/register`
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

## `POST /auth/login`
- **Purpose:** Authenticate an existing user and receive the `auth_token` cookie.
- **Auth required:** None

!!! warning "Rate limiting"
    This endpoint (and user registration) is protected by a shared token-bucket rated at ten login attempts per minute (four registrations every five minutes) per client IP. Successful requests refill progressively. When the bucket is empty, the API responds with HTTP 429 (`Retry-After` header in seconds). The limiter state is stored in the configured database so limits are consistent across application instances. On SQLite, heavy login traffic may lead to short lock retries; for high-volume production deployments prefer PostgreSQL or an external rate-limit tier.

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

## `POST /auth/logout`
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

## `GET /auth/me`
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
