# Operational Notes

- The service automatically triggers `mc-send-to-console save-all` before restart and stop operations. Recent tests with Ceph-backed persistent volumes showed that writes can take a few minutes to settle, occasionally omitting the most recent ticks. The extra save mitigates the inconsistency but plan for a short grace period after each lifecycle change when running on Ceph.
- API key responses only reveal the raw token during creation. Store it immediately; subsequent listings return masked values.
- The `/servers/{serverName}/expose` endpoint deletes any existing service for the deployment before creating a new one, preventing stale exposure modes from lingering.
- Server creation forwards the `env` map directly to the `itzg/minecraft-server` container. Use the upstream variable reference (<https://docker-minecraft-server.readthedocs.io/en/latest/variables/>) when choosing flags and options.
