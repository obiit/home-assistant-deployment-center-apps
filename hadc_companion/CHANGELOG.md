# Changelog

## 0.2.0

Backup & Validation foundation for Desktop 0.1.11.

- Adds Home Assistant Supervisor API access with the dedicated `backup` role only.
- Keeps Home Assistant configuration mounted read-only.
- Adds `backup_checkpoint_v1` capability discovery without changing protocol v1 or persistent data schema v1.
- Adds a narrow authenticated API for backup metadata, protected full checkpoint creation and backup download.
- HADC checkpoints are compressed, local, database-inclusive and password protected.
- Companion never persists the checkpoint password.
- Restore and delete are deliberately not exposed.
- Keeps Home Assistant API, Docker API, host networking, privileged capabilities and full host access disabled.
- Adds unit tests for strict checkpoint policy, metadata sanitization, streamed download and path-traversal rejection.

## 0.1.3

Verified AppArmor runtime compatibility release.

- Includes the complete S6/AppArmor fixes validated under the actual custom AppArmor profile.
- Explicit read+execute access for S6 script paths.
- Executable mmap permission for Python/shared libraries.
- Read-only access to Companion application code.
- Precise persistent `/data` permissions without granting `dac_override`.
- S6 directory-read rules without the broad AppArmor `file,` permission.
- CI loads the custom AppArmor profile, starts the container under it, verifies HTTPS `/health`, and verifies Home Assistant config remains read-only.
- Native amd64 and aarch64 container smoke tests remain required.
- Protocol remains v1; persistent data schema remains v1.

## 0.1.2

AppArmor runtime compatibility fix.

- Grants explicit read+execute access to S6 shell-script paths under `/package/**` and `/command/**`.
- Restores explicit S6 service/init directory rules alongside the current `/etc/s6-overlay/**` paths.
- Keeps the broad AppArmor `file,` permission deliberately disabled.
- Adds CI coverage intended to start the container under the actual custom AppArmor profile, catching Supervisor-only startup denials before release.
- Home Assistant configuration remains read-only and `.storage` remains explicitly denied.
- Protocol remains v1 and persistent data schema remains v1.

## 0.1.2

S6 shell-script read compatibility fix.

- Allows S6 package and command scripts to be read as well as executed under AppArmor.
- Fixes Supervisor startup failure `/bin/sh: can't open '/package/admin/s6-overlay-3.2.3.0/libexec/preinit': Permission denied`.
- Keeps Home Assistant configuration read-only and preserves explicit `.storage` deny rules.
- Protocol remains v1 and persistent data schema remains v1.

## 0.1.1

Startup compatibility fix.

- Allows the Home Assistant base image S6 entrypoint `/init` through the custom AppArmor profile.
- Adds the supported S6 runtime/service paths required by Home Assistant base images.
- Keeps `homeassistant_config` read-only and preserves the explicit `.storage` deny rules.
- No protocol, data-schema or Home Assistant write-capability change.

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
