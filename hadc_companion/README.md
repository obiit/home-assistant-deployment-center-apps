# HADC Companion

Read-only server-side component for Home Assistant Deployment Center.

- App version: **0.1.0**
- Protocol version: **1**
- Persistent data schema: **1**
- Architectures: **amd64**, **aarch64**
- Home Assistant configuration access: **read-only**
- Image: `ghcr.io/obiit/hadc-companion:0.1.0`

The App does not request Supervisor API, Home Assistant API, Docker API, host networking, privileged Linux capabilities or full host access.

`homeassistant_config` is mounted read-only. `.storage` is excluded and `secrets.yaml` contents are never read.

The HTTPS identity is persisted in `/data/tls`. Pairing uses a short-lived six-digit code. Companion stores only the SHA-256 hash of the resulting bearer token.

0.1.0 performs no Home Assistant mutations.
