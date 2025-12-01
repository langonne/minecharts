# Local Development Overlay

The `kubernetes/overlays/test` overlay ships with a patch template that keeps developer-specific values outside of Git while still letting you exercise the stack end-to-end.

1. Copy the sample file:
   ```bash
   cp kubernetes/overlays/test/dev-env.example.yaml kubernetes/overlays/test/dev-env.yaml
   ```
2. Update `dev-env.yaml` with your own values (e.g. `MINECHARTS_MCROUTER_DOMAIN_SUFFIX`, logging verbosity).
3. Apply the overlay:
   ```bash
   kubectl apply -k kubernetes/overlays/test
   ```

!!! tip "Keep local secrets out of Git"
    `dev-env.yaml` is ignored by Git so your local values (domains, tokens, etc.) never get committed. Only the example file stays tracked to show the expected structure.
