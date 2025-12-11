# Quota Endpoints

## `GET /quota/memory`
- **Purpose:** Report memory quota usage (requests + overhead) for Minecraft servers.
- **Auth required:** JWT or API key + `PermCreateServer`

=== "Response"

    ```json
    {
      "unlimited": false,
      "limitGi": 64,
      "usedGi": 18.75,
      "remainingGi": 45.25,
      "overheadPercent": 25
    }
    ```

### Fields
- `unlimited` - `true` when the quota is disabled (`MINECHARTS_MEMORY_QUOTA_ENABLED=false` or limit ≤ 0).
- `limitGi` - Quota limit in GiB (includes overhead).
- `usedGi` / `remainingGi` - Current usage and available budget in GiB, computed as `MEMORY + overhead%` for every server.
- `overheadPercent` - Current overhead percentage used to compute limits/quota (`MINECHARTS_MEMORY_LIMIT_OVERHEAD_PERCENT`, clamped at zero).

!!! tip "Client-side validation"
    To estimate the cost of a new server locally: `costGi = MEMORY + (MEMORY * overheadPercent / 100)`. Compare `costGi` to `remainingGi` to pre-flight the request before calling `POST /servers`.
