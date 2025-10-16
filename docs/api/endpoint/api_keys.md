# API Key Endpoints

## `POST /apikeys`
- **Purpose:** Generate a new API key (revealed once).
- **Auth required:** JWT cookie

!!! info "Storage"
    API keys are hashed before being stored in the database. Only the identifier and metadata are kept, so the raw value is visible **only** in the creation response. Rotate or reissue keys if you suspect a leak.

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

## `GET /apikeys`
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

## `DELETE /apikeys/{id}`
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
