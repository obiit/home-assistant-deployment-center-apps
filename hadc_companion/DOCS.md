# HADC Companion 0.1.1

HADC Companion closes Home Assistant filesystem visibility gaps while remaining read-only.

## Evidence

It derives:
- file metadata and SHA-256 for analyzed non-secret files,
- static `!include` / `!include_dir_*` relationships,
- entity-ID candidates with source file and line,
- static versus potentially dynamic Jinja observations,
- custom integration manifest metadata,
- coverage status and scan issues.

It deliberately does not read `secrets.yaml` values or `.storage`.

## Pairing

At App start a six-digit pairing code is written to the App log for the configured pairing window. A successful pairing returns a random bearer token once and invalidates the code. Companion stores only the token SHA-256 hash. Re-pairing rotates the old token.

## API

- `GET /health`
- `POST /api/v1/pair`
- `GET /api/v1/info`
- `GET /api/v1/inventory`
- `GET /api/v1/coverage`
- `POST /api/v1/scan`

Port **18091/tcp**, HTTPS.

Persistent state, inventory cache and TLS identity live under `/data`.
