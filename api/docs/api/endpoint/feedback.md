# Feedback Endpoint

## `POST /feedback`
- **Purpose:** Allow signed-in users to report bugs or request features.
- **Auth required:** JWT cookie (`MINECHARTS_FEEDBACK_ENABLED` must be `true`).

The backend validates submissions and forwards them to either GitHub or GitLab, depending on `MINECHARTS_FEEDBACK_PROVIDER`.

=== "Request"

    ```http
    POST /feedback HTTP/1.1
    Content-Type: application/json

    {
      "type": "bug",
      "title": "Nether portal crashes the server",
      "description": "Whenever we light the portal the server stops responding after ~30s.",
      "email": "player@example.com",
      "page_url": "https://app.minecharts.com/servers/creative",
      "screenshot_url": "https://example.com/portal.png"
    }
    ```

=== "Response"

    ```json
    {
      "issue_url": "https://gitlab.example.com/my-group/minecharts/-/issues/101",
      "issue_number": 101
    }
    ```

### Validation rules
- `type` accepts `bug`, `feature`, or anything else (treated as `other`).
- `title` and `description` are mandatory; titles are capped at 140 characters, descriptions at 5000.
- Optional fields (`email`, `page_url`, `screenshot_url`) are trimmed and length-checked (320 characters max for email, 2048 for URLs).
- Caller must be authenticated; the issue body includes the user ID and username.

### Failure responses
- `404 Not Found` when the feedback endpoint is disabled.
- `401 Unauthorized` if the caller is not logged in.
- `400 Bad Request` for invalid payloads or missing required fields.
- `500 Internal Server Error` when feedback is enabled but misconfigured (missing token, bad provider, etc.).
- `502 Bad Gateway` if the target forge rejects the issue creation (temporary error).
