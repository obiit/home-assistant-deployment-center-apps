from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import ssl
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import APP_VERSION, DATA_SCHEMA_VERSION, PROTOCOL_VERSION
from .backup import SupervisorBackupClient, SupervisorBackupError
from .scanner import ConfigScanner
from .state import StateStore
from .tls import ensure_tls_material

_LOGGER = logging.getLogger("hadc_companion")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_options(data_root: Path) -> dict[str, int]:
    defaults = {
        "scan_interval_minutes": 15,
        "pairing_window_minutes": 10,
        "max_file_size_kb": 2048,
    }
    path = data_root / "options.json"
    if not path.exists():
        return defaults

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _LOGGER.warning("Could not read options.json; using safe defaults.")
        return defaults

    result = dict(defaults)
    for key, value in defaults.items():
        candidate = raw.get(key)
        if isinstance(candidate, int) and candidate > 0:
            result[key] = candidate
    return result


class PairingManager:
    def __init__(self, state: StateStore, window_minutes: int) -> None:
        self._state = state
        self._lock = threading.Lock()
        self._code = f"{secrets.randbelow(1_000_000):06d}"
        self._expires_at = time.monotonic() + (window_minutes * 60)
        self._attempts_remaining = 5
        self._window_minutes = window_minutes

    @property
    def code(self) -> str:
        return self._code

    @property
    def window_minutes(self) -> int:
        return self._window_minutes

    def is_active(self) -> bool:
        with self._lock:
            return bool(self._code) and time.monotonic() <= self._expires_at and self._attempts_remaining > 0

    def pair(self, supplied_code: str) -> str:
        with self._lock:
            if not self._code or time.monotonic() > self._expires_at:
                raise PairingError("PAIRING_WINDOW_EXPIRED", "Pairing window has expired.")
            if self._attempts_remaining <= 0:
                raise PairingError("PAIRING_LOCKED", "Pairing attempts are exhausted.")

            if not hmac.compare_digest(self._code, supplied_code.strip()):
                self._attempts_remaining -= 1
                raise PairingError("PAIRING_CODE_INVALID", "Pairing code is invalid.")

            token = secrets.token_urlsafe(32)
            self._state.set_api_token(token)
            self._code = ""
            self._attempts_remaining = 0
            return token


class PairingError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CompanionContext:
    def __init__(
        self,
        config_root: Path,
        data_root: Path,
        max_file_size_kb: int,
        scan_interval_minutes: int,
        pairing_window_minutes: int,
        certificate_sha256: str,
        supervisor_token: str | None,
    ) -> None:
        self.config_root = config_root
        self.data_root = data_root
        self.scanner = ConfigScanner(config_root, max_file_size_kb)
        self.state = StateStore(data_root)
        self.pairing = PairingManager(self.state, pairing_window_minutes)
        self.certificate_sha256 = certificate_sha256
        self.backups = SupervisorBackupClient(supervisor_token) if supervisor_token else None
        self.scan_interval_seconds = scan_interval_minutes * 60
        self.inventory_path = data_root / "latest-inventory.json"
        self._scan_lock = threading.Lock()
        self._inventory_lock = threading.Lock()
        self._latest_inventory: dict[str, Any] | None = None
        self._stop_event = threading.Event()

    def run_scan(self) -> dict[str, Any]:
        with self._scan_lock:
            inventory = self.scanner.scan()
            temporary = self.inventory_path.with_suffix(".tmp")
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(inventory, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.inventory_path)
            os.chmod(self.inventory_path, 0o600)
            with self._inventory_lock:
                self._latest_inventory = inventory
            self.state.record_scan(inventory["captured_at"])
            _LOGGER.info(
                "Read-only scan complete: %s files, %s entity-ID candidates, %s issues.",
                inventory["stats"]["files_analyzed"],
                inventory["stats"]["entity_id_candidates"],
                inventory["stats"]["issues"],
            )
            return inventory

    def latest_inventory(self) -> dict[str, Any]:
        with self._inventory_lock:
            if self._latest_inventory is not None:
                return self._latest_inventory

        if self.inventory_path.exists():
            try:
                inventory = json.loads(self.inventory_path.read_text(encoding="utf-8"))
                with self._inventory_lock:
                    self._latest_inventory = inventory
                return inventory
            except (OSError, json.JSONDecodeError):
                pass
        return self.run_scan()

    def background_scanner(self) -> None:
        while not self._stop_event.wait(self.scan_interval_seconds):
            try:
                self.run_scan()
            except Exception:
                _LOGGER.exception("Scheduled read-only scan failed.")

    def stop(self) -> None:
        self._stop_event.set()


class CompanionServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], context: CompanionContext) -> None:
        super().__init__(server_address, CompanionRequestHandler)
        self.context = context


class CompanionRequestHandler(BaseHTTPRequestHandler):
    server: CompanionServer
    protocol_version = "HTTP/1.1"
    server_version = "HADC-Companion"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        _LOGGER.info("%s - %s", self.client_address[0], format % args)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/health":
            inventory = self.server.context.latest_inventory()
            self._json(
                HTTPStatus.OK,
                {
                    "status": "healthy" if inventory["status"] != "UNAVAILABLE" else "degraded",
                    "version": APP_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "data_schema_version": DATA_SCHEMA_VERSION,
                    "config_access": "READ_ONLY",
                    "inventory_status": inventory["status"],
                    "latest_scan_at": inventory["captured_at"],
                    "backup_checkpoint_available": self.server.context.backups is not None,
                },
            )
            return

        if not self._require_auth():
            return

        if path == "/api/v1/info":
            inventory = self.server.context.latest_inventory()
            self._json(
                HTTPStatus.OK,
                {
                    "app": "HADC Companion",
                    "version": APP_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "data_schema_version": DATA_SCHEMA_VERSION,
                    "config_access": "READ_ONLY",
                    "paired": self.server.context.state.is_paired,
                    "pairing_window_active": self.server.context.pairing.is_active(),
                    "certificate_sha256": self.server.context.certificate_sha256,
                    "capabilities": {
                        "filesystem_inventory_v1": True,
                        "backup_checkpoint_v1": self.server.context.backups is not None,
                    },
                    "supervisor_access": "BACKUP_ROLE_ONLY" if self.server.context.backups is not None else "UNAVAILABLE",
                    "inventory": {
                        "schema": inventory["schema"],
                        "status": inventory["status"],
                        "captured_at": inventory["captured_at"],
                        "stats": inventory["stats"],
                    },
                },
            )
            return

        if path == "/api/v1/inventory":
            self._json(HTTPStatus.OK, self.server.context.latest_inventory())
            return

        if path == "/api/v1/coverage":
            inventory = self.server.context.latest_inventory()
            self._json(
                HTTPStatus.OK,
                {
                    "schema": inventory["schema"],
                    "captured_at": inventory["captured_at"],
                    "coverage": inventory["coverage"],
                    "issues": inventory["issues"],
                },
            )
            return

        if path == "/api/v1/backups":
            if not self._require_backup_capability():
                return
            try:
                backups = self.server.context.backups.list_backups()
            except SupervisorBackupError as exc:
                self._supervisor_error(exc)
                return
            self._json(HTTPStatus.OK, {"backups": backups})
            return

        if path.startswith("/api/v1/backups/") and path.endswith("/info"):
            if not self._require_backup_capability():
                return
            slug = path[len("/api/v1/backups/") : -len("/info")].strip("/")
            try:
                backup = self.server.context.backups.get_backup(slug)
            except (SupervisorBackupError, ValueError) as exc:
                self._backup_error(exc)
                return
            self._json(HTTPStatus.OK, {"backup": backup})
            return

        if path.startswith("/api/v1/backups/") and path.endswith("/integrity"):
            if not self._require_backup_capability():
                return
            slug = path[len("/api/v1/backups/") : -len("/integrity")].strip("/")
            try:
                integrity = self.server.context.backups.compute_download_sha256(slug)
            except (SupervisorBackupError, ValueError) as exc:
                self._backup_error(exc)
                return
            self._json(HTTPStatus.OK, {"integrity": integrity})
            return

        if path.startswith("/api/v1/backups/") and path.endswith("/download"):
            if not self._require_backup_capability():
                return
            slug = path[len("/api/v1/backups/") : -len("/download")].strip("/")
            self._stream_backup(slug)
            return

        self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Endpoint not found.")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/pair":
            try:
                payload = self._read_json()
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_JSON", str(exc))
                return

            code = payload.get("code")
            if not isinstance(code, str):
                self._error(HTTPStatus.BAD_REQUEST, "PAIRING_CODE_REQUIRED", "Pairing code is required.")
                return

            try:
                token = self.server.context.pairing.pair(code)
            except PairingError as exc:
                status = HTTPStatus.TOO_MANY_REQUESTS if exc.code == "PAIRING_LOCKED" else HTTPStatus.UNAUTHORIZED
                self._error(status, exc.code, str(exc))
                return

            _LOGGER.info("Desktop pairing completed. Existing Companion API token, if any, has been rotated.")
            self._json(
                HTTPStatus.OK,
                {
                    "api_token": token,
                    "token_type": "Bearer",
                    "protocol_version": PROTOCOL_VERSION,
                    "certificate_sha256": self.server.context.certificate_sha256,
                    "note": "The API token is returned once. Store it in Windows Credential Manager.",
                },
            )
            return

        if not self._require_auth():
            return

        if path == "/api/v1/scan":
            try:
                inventory = self.server.context.run_scan()
            except Exception as exc:
                _LOGGER.exception("On-demand scan failed.")
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "SCAN_FAILED", str(exc))
                return

            self._json(
                HTTPStatus.OK,
                {
                    "status": inventory["status"],
                    "captured_at": inventory["captured_at"],
                    "stats": inventory["stats"],
                },
            )
            return

        if path == "/api/v1/checkpoints":
            if not self._require_backup_capability():
                return
            try:
                payload = self._read_json()
                name = payload.get("name")
                password = payload.get("password")
                if not isinstance(name, str):
                    raise ValueError("Checkpoint name is required.")
                if not isinstance(password, str):
                    raise ValueError("Checkpoint password is required.")
                backup = self.server.context.backups.create_full_backup(name, password)
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, "CHECKPOINT_REQUEST_INVALID", str(exc))
                return
            except SupervisorBackupError as exc:
                _LOGGER.exception("Supervisor checkpoint creation failed.")
                self._supervisor_error(exc)
                return

            _LOGGER.info(
                "Protected full Home Assistant checkpoint created: %s.",
                backup.get("slug", "<unknown>"),
            )
            self._json(
                HTTPStatus.CREATED,
                {
                    "status": "CREATED",
                    "backup": backup,
                    "policy": {
                        "type": "full",
                        "compressed": True,
                        "local_supervisor_storage": True,
                        "database_included": True,
                        "password_required": True,
                    },
                },
            )
            return

        self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Endpoint not found.")

    def _require_auth(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not self.server.context.state.verify_api_token(token):
            self._error(HTTPStatus.UNAUTHORIZED, "AUTH_REQUIRED", "Valid Companion bearer token required.")
            return False
        return True

    def _require_backup_capability(self) -> bool:
        if self.server.context.backups is None:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "BACKUP_CAPABILITY_UNAVAILABLE",
                "Companion does not have the Home Assistant Supervisor backup role.",
            )
            return False
        return True

    def _stream_backup(self, slug: str) -> None:
        try:
            response = self.server.context.backups.open_download(slug)
        except (SupervisorBackupError, ValueError) as exc:
            self._backup_error(exc)
            return

        try:
            length = response.headers.get("Content-Length")
            self.send_response(HTTPStatus.OK.value)
            self.send_header("Content-Type", "application/x-tar")
            if length:
                self.send_header("Content-Length", length)
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="home-assistant-backup-{slug}.tar"',
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
        finally:
            response.close()

    def _backup_error(self, exc: Exception) -> None:
        if isinstance(exc, SupervisorBackupError):
            self._supervisor_error(exc)
            return
        self._error(HTTPStatus.BAD_REQUEST, "BACKUP_REQUEST_INVALID", str(exc))

    def _supervisor_error(self, exc: SupervisorBackupError) -> None:
        status = (
            HTTPStatus.SERVICE_UNAVAILABLE
            if exc.code == "SUPERVISOR_UNREACHABLE"
            else HTTPStatus.BAD_GATEWAY
        )
        self._error(status, exc.code, str(exc))

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length.") from exc
        if length < 0 or length > 16 * 1024:
            raise ValueError("Request body exceeds 16 KiB limit.")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be UTF-8 JSON.") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON root must be an object.")
        return payload

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, status: HTTPStatus, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message}})


def run() -> None:
    logging.basicConfig(
        level=os.environ.get("HADC_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config_root = Path(os.environ.get("HADC_CONFIG_ROOT", "/homeassistant"))
    data_root = Path(os.environ.get("HADC_DATA_ROOT", "/data"))
    listen_host = os.environ.get("HADC_LISTEN_HOST", "0.0.0.0")
    listen_port = int(os.environ.get("HADC_LISTEN_PORT", "18091"))
    supervisor_token = os.environ.get("SUPERVISOR_TOKEN")

    data_root.mkdir(parents=True, exist_ok=True)
    options = load_options(data_root)
    cert_path, key_path, certificate_fingerprint = ensure_tls_material(data_root)

    context = CompanionContext(
        config_root=config_root,
        data_root=data_root,
        max_file_size_kb=options["max_file_size_kb"],
        scan_interval_minutes=options["scan_interval_minutes"],
        pairing_window_minutes=options["pairing_window_minutes"],
        certificate_sha256=certificate_fingerprint,
        supervisor_token=supervisor_token,
    )

    _LOGGER.info(
        "Starting HADC Companion %s · protocol v%s · data schema v%s · config access READ_ONLY.",
        APP_VERSION,
        PROTOCOL_VERSION,
        DATA_SCHEMA_VERSION,
    )
    _LOGGER.info("TLS certificate SHA-256: %s", certificate_fingerprint)
    _LOGGER.info(
        "Supervisor backup capability: %s.",
        "BACKUP_ROLE_ONLY" if context.backups is not None else "UNAVAILABLE",
    )
    _LOGGER.warning(
        "PAIRING CODE: %s · valid for %s minutes. Pairing rotates any existing Desktop token.",
        context.pairing.code,
        context.pairing.window_minutes,
    )

    context.run_scan()

    scanner_thread = threading.Thread(
        target=context.background_scanner,
        name="hadc-background-scanner",
        daemon=True,
    )
    scanner_thread.start()

    server = CompanionServer((listen_host, listen_port), context)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)

    _LOGGER.info("HTTPS API listening on %s:%s.", listen_host, listen_port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        context.stop()
        server.shutdown()
        server.server_close()
