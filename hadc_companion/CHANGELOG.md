# Changelog

## 0.1.0

Initial read-only HADC Companion release.

- Home Assistant App packaging for amd64 and aarch64.
- Read-only `homeassistant_config` mount.
- Static inventory of YAML/includes, packages, blueprints, templates and custom integrations.
- Explicit exclusion of `.storage` and secret values.
- HTTPS API with persistent self-signed identity.
- Time-limited pairing code and hashed Companion bearer-token storage.
- Persistent `/data` state with data-schema version 1.
- Protocol version 1.
- Health endpoint and Home Assistant watchdog support.
- No Supervisor API, Home Assistant API, Docker API, host network or privileged capabilities.
