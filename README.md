# Home Assistant Deployment Center Apps

Public Home Assistant App repository for **Home Assistant Deployment Center**.

## HADC Companion 0.1.2

Read-only server-side evidence component.

- Read-only `homeassistant_config`.
- No direct `.storage` access.
- `secrets.yaml` values are never read.
- No Supervisor API, Home Assistant API, Docker API, host network or privileged capabilities.
- AppArmor profile.
- Persistent lifecycle state under `/data`.
- HTTPS API with persistent local TLS identity.
- Separate pairing flow; Home Assistant Long-Lived Access Token is never reused.
- Native amd64 and aarch64 images.

### Install repository

In Home Assistant open **Settings → Apps → App store → Repositories** and add:

`https://github.com/obiit/home-assistant-deployment-center-apps`

Then reload the App store and install **HADC Companion**.

Published image: `ghcr.io/obiit/hadc-companion`.

## Release lifecycle

- Pull requests validate tests and native amd64/aarch64 container builds.
- Merges to `main` publish signed per-architecture images and a signed generic multi-arch manifest with the official Home Assistant Builder actions.
- App version tags are immutable.
- Publish CI verifies the resulting generic image anonymously, proving that Home Assistant Supervisor can pull it without GitHub credentials.
