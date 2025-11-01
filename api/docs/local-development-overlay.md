# Local Development Overlay

The `kubernetes/overlays/test` overlay ships with a patch template that keeps developer-specific values outside of Git while still letting you exercise the stack end-to-end.

1. Copy the sample file:
   ```bash
   cp kubernetes/overlays/test/dev-env.exemple.yaml kubernetes/overlays/test/dev-env.yaml
   ```
2. Update `dev-env.yaml` with your own values (e.g. `MINECHARTS_MCROUTER_DOMAIN_SUFFIX`, `MINECHARTS_JWT_SECRET`, logging verbosity).
3. Apply the overlay:
   ```bash
   kubectl apply -k kubernetes/overlays/test
   ```

The directory contains a `.gitignore` entry that excludes `dev-env.yaml`, ensuring personal overrides never leak into commits. Only the `.exemple` file is tracked, which keeps teammates aligned on the expected structure.

