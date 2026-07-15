# Repository guidance for coding agents

## Repository and deployment hygiene

- Keep verified changes committed and pushed to this repository as work is
  completed.
- Treat a production Courier API deployment as a release: run the service and
  deployment tests, deploy the exact pushed revision, and verify health and any
  changed public routes before declaring it complete.
- Keep production secrets and persistent data on the host. Never commit them or
  copy them into public release roots.
- Assets promoted through `firmware.courier.systems` are immutable by version.
  Do not replace an existing release with different bytes; publish a higher
  semantic version instead.
- A release that publishes Courier-hosted assets is complete only after the
  public metadata, byte sizes, cache policy, and digests have been verified.
