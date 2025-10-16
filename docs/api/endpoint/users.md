# User Administration Endpoints

## `GET /users`
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

## `GET /users/{id}`
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

## `PATCH /users/{id}`
- **Purpose:** Partially update username, email, password, permissions, or active flag.
- **Auth required:** JWT cookie. Users may patch their own record; administrators may patch any user. Only admins may modify `permissions` or `active`.

=== "Self-update"

    ```http
    PATCH /users/2 HTTP/1.1
    Cookie: auth_token=<user_jwt>
    Content-Type: application/json

    {
      "email": "player2@example.com",
      "password": {
        "current": "OldPassword123!",
        "new": "NewPassword456@",
        "confirm": "NewPassword456@"
      }
    }
    ```

=== "Admin update"

    ```http
    PATCH /users/2 HTTP/1.1
    Cookie: auth_token=<admin_jwt>
    Content-Type: application/json

    {
      "username": "builder",
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

!!! info "Password policy"
    When changing a password, the payload must include `current`, `new`, and `confirm`. The new password must be at least 12 characters long and contain upper-case, lower-case, digit, and symbol characters.

## `POST /users/{id}/permissions/grant`
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

## `POST /users/{id}/permissions/revoke`
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

## `DELETE /users/{id}`
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
