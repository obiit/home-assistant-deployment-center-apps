from __future__ import annotations

import io
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, BinaryIO, Callable

SUPERVISOR_BASE_URL = "http://supervisor"


class SupervisorBackupError(RuntimeError):
    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class SupervisorBackupClient:
    def __init__(
        self,
        token: str,
        base_url: str = SUPERVISOR_BASE_URL,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        if not token:
            raise ValueError("Supervisor token is required.")
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({})
        ).open

    def list_backups(self) -> list[dict[str, Any]]:
        data = self._request_json("GET", "/backups")
        backups = data.get("backups")
        if not isinstance(backups, list):
            raise SupervisorBackupError(
                "SUPERVISOR_CONTRACT_INVALID",
                "Supervisor backup list response is missing 'backups'.",
            )
        return [self._sanitize_backup(item) for item in backups if isinstance(item, dict)]

    def get_backup(self, slug: str) -> dict[str, Any]:
        self._validate_slug(slug)
        data = self._request_json("GET", f"/backups/{urllib.parse.quote(slug)}/info")
        return self._sanitize_backup(data)

    def create_full_backup(self, name: str, password: str) -> dict[str, Any]:
        clean_name = name.strip()
        if not clean_name or len(clean_name) > 120:
            raise ValueError("Backup name must be 1-120 characters.")
        if len(password) < 20 or len(password) > 256:
            raise ValueError("Backup password must be 20-256 characters.")

        data = self._request_json(
            "POST",
            "/backups/new/full",
            {
                "name": clean_name,
                "password": password,
                "compressed": True,
                "location": None,
                "homeassistant_exclude_database": False,
                "background": False,
            },
            timeout=30 * 60,
        )
        slug = data.get("slug")
        if not isinstance(slug, str) or not slug:
            raise SupervisorBackupError(
                "SUPERVISOR_CONTRACT_INVALID",
                "Supervisor did not return a backup slug.",
            )
        return self.get_backup(slug)

    def open_download(self, slug: str, timeout: int = 30 * 60) -> BinaryIO:
        self._validate_slug(slug)
        request = urllib.request.Request(
            f"{self._base_url}/backups/{urllib.parse.quote(slug)}/download",
            method="GET",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/octet-stream",
            },
        )
        try:
            return self._opener(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            raise self._http_error(exc) from exc
        except urllib.error.URLError as exc:
            raise SupervisorBackupError(
                "SUPERVISOR_UNREACHABLE",
                f"Supervisor backup download failed: {exc.reason}",
            ) from exc

    def compute_download_sha256(self, slug: str) -> dict[str, Any]:
        digest = hashlib.sha256()
        size = 0
        response = self.open_download(slug)
        try:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        finally:
            response.close()
        return {
            "slug": slug,
            "sha256": digest.hexdigest(),
            "size_bytes": size,
        }

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        raw_body = None
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }
        if payload is not None:
            raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=raw_body,
            method=method,
            headers=headers,
        )
        try:
            response = self._opener(request, timeout=timeout)
            with response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise self._http_error(exc) from exc
        except urllib.error.URLError as exc:
            raise SupervisorBackupError(
                "SUPERVISOR_UNREACHABLE",
                f"Supervisor backup request failed: {exc.reason}",
            ) from exc

        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SupervisorBackupError(
                "SUPERVISOR_INVALID_JSON",
                "Supervisor returned invalid JSON.",
            ) from exc

        if not isinstance(envelope, dict):
            raise SupervisorBackupError(
                "SUPERVISOR_CONTRACT_INVALID",
                "Supervisor response root is not an object.",
            )

        result = envelope.get("result")
        if result != "ok":
            message = envelope.get("message")
            raise SupervisorBackupError(
                "SUPERVISOR_REQUEST_FAILED",
                str(message or "Supervisor backup request failed."),
            )

        data = envelope.get("data")
        if not isinstance(data, dict):
            raise SupervisorBackupError(
                "SUPERVISOR_CONTRACT_INVALID",
                "Supervisor response is missing object 'data'.",
            )
        return data

    @staticmethod
    def _sanitize_backup(item: dict[str, Any]) -> dict[str, Any]:
        content = item.get("content")
        if not isinstance(content, dict):
            content = {
                "homeassistant": bool(item.get("homeassistant")),
                "addons": [
                    addon.get("slug")
                    for addon in item.get("addons", [])
                    if isinstance(addon, dict) and isinstance(addon.get("slug"), str)
                ],
                "folders": item.get("folders", []) if isinstance(item.get("folders"), list) else [],
            }

        return {
            "slug": item.get("slug"),
            "date": item.get("date"),
            "name": item.get("name"),
            "type": item.get("type"),
            "size": item.get("size"),
            "protected": bool(item.get("protected", False)),
            "compressed": bool(item.get("compressed", True)),
            "location": item.get("location"),
            "homeassistant": item.get("homeassistant"),
            "homeassistant_exclude_database": bool(
                item.get("homeassistant_exclude_database", False)
            ),
            "content": {
                "homeassistant": bool(content.get("homeassistant", False)),
                "addons": content.get("addons", []) if isinstance(content.get("addons"), list) else [],
                "folders": content.get("folders", []) if isinstance(content.get("folders"), list) else [],
            },
        }

    @staticmethod
    def _validate_slug(slug: str) -> None:
        if not slug or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in slug):
            raise ValueError("Backup slug contains unsupported characters.")

    @staticmethod
    def _http_error(exc: urllib.error.HTTPError) -> SupervisorBackupError:
        message = f"Supervisor returned HTTP {exc.code}."
        try:
            raw = exc.read()
            envelope = json.loads(raw.decode("utf-8"))
            if isinstance(envelope, dict) and isinstance(envelope.get("message"), str):
                message = envelope["message"]
        except Exception:
            pass
        return SupervisorBackupError("SUPERVISOR_HTTP_ERROR", message, exc.code)
