# HADC Companion 0.2.0

HADC Companion provides two narrowly scoped capabilities for Home Assistant Deployment Center:

1. **Read-only configuration evidence** from the mounted Home Assistant configuration.
2. **Protected checkpoint operations** through Home Assistant Supervisor's documented backup API using the dedicated `backup` role.

It does not expose a generic Supervisor proxy.

## Evidence

The read-only scanner derives:
- file metadata and SHA-256 for analyzed non-secret files,
- static `!include` / `!include_dir_*` relationships,
- entity-ID candidates with source file and line,
- static versus potentially dynamic Jinja observations,
- custom integration manifest metadata,
- coverage status and scan issues.

It deliberately does not read `secrets.yaml` values or `.storage`.

## Pairing

At App start a six-digit pairing code is written to the App log for the configured pairing window. A successful pairing returns a random bearer token once and invalidates the code. Companion stores only the token SHA-256 hash. Re-pairing rotates the old token.

The existing pairing state and persistent TLS identity remain under `/data`, so upgrading from 0.1.3 does not intentionally require re-pairing.

## Backup/checkpoint boundary

Companion requests:

- `hassio_api: true`
- `hassio_role: backup`

It does **not** request `homeassistant_api`, Docker API, host networking, privileged capabilities or full host access.

The HADC API intentionally exposes only:
- listing backup metadata,
- reading one backup's metadata,
- creating a full protected checkpoint,
- streaming one backup file to an authenticated Desktop client.

Restore and delete are not exposed by Companion 0.2.0.

A checkpoint created by HADC is:
- full,
- compressed,
- stored in Supervisor local backup storage,
- database-inclusive,
- password protected,
- synchronous: success is returned only after Supervisor has created the backup.

The password is supplied by Desktop over the TLS-pinned Companion connection. Companion does not persist it.

## API

Existing protocol v1 endpoints:
- `GET /health`
- `POST /api/v1/pair`
- `GET /api/v1/info`
- `GET /api/v1/inventory`
- `GET /api/v1/coverage`
- `POST /api/v1/scan`

Checkpoint capability:
- `GET /api/v1/backups`
- `GET /api/v1/backups/{slug}/info`
- `GET /api/v1/backups/{slug}/download`
- `POST /api/v1/checkpoints`

Port **18091/tcp**, HTTPS.

Protocol remains **v1** and persistent data schema remains **v1**. Desktop discovers checkpoint support through `capabilities.backup_checkpoint_v1` in `/api/v1/info`.
