# HADC Companion

Home Assistant App for Home Assistant Deployment Center.

- App version: **0.2.0**
- Protocol version: **1**
- Persistent data schema: **1**
- Architectures: **amd64**, **aarch64**
- Home Assistant configuration access: **read-only**
- Supervisor access: **backup role only**
- Image: `ghcr.io/obiit/hadc-companion:0.2.0`

## Security model

`homeassistant_config` remains mounted read-only. `.storage` is excluded and `secrets.yaml` contents are never read.

For Desktop 0.1.11 checkpoint support the App uses Home Assistant's documented Supervisor API with:

- `hassio_api: true`
- `hassio_role: backup`

It does not request Home Assistant API, Docker API, host networking, privileged Linux capabilities or full host access. Companion does not expose generic Supervisor access to Desktop: only the narrow checkpoint endpoints implemented by HADC are available.

The HTTPS identity is persisted in `/data/tls`. Pairing uses a short-lived six-digit code. Companion stores only the SHA-256 hash of the resulting bearer token.

Checkpoint passwords are received only for the duration of a checkpoint request, passed to Supervisor, and are not persisted by Companion.
