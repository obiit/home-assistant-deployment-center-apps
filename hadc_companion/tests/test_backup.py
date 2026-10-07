from __future__ import annotations

import io
import json
import unittest
import urllib.error
from email.message import Message

from hadc_companion.backup import SupervisorBackupClient, SupervisorBackupError


class FakeResponse:
    def __init__(self, body: bytes, content_type: str = "application/json") -> None:
        self._buffer = io.BytesIO(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = str(len(body))

    def read(self, size: int = -1) -> bytes:
        return self._buffer.read(size)

    def close(self) -> None:
        self._buffer.close()

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class RecordingOpener:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, object] | None, int]] = []

    def __call__(self, request, timeout: int = 60):
        payload = None
        if request.data:
            payload = json.loads(request.data.decode("utf-8"))
        self.requests.append((request.method, request.full_url, payload, timeout))

        if request.full_url.endswith("/backups/new/full"):
            return FakeResponse(
                json.dumps({"result": "ok", "data": {"slug": "abc123"}}).encode()
            )
        if request.full_url.endswith("/backups/abc123/info"):
            return FakeResponse(
                json.dumps(
                    {
                        "result": "ok",
                        "data": {
                            "slug": "abc123",
                            "name": "HADC checkpoint",
                            "date": "2026-10-07T17:00:00Z",
                            "type": "full",
                            "size": 42.5,
                            "protected": True,
                            "compressed": True,
                            "location": None,
                            "homeassistant": "2026.9.4",
                            "homeassistant_exclude_database": False,
                            "addons": [{"slug": "hadc_companion", "name": "HADC Companion"}],
                            "folders": ["ssl", "media"],
                        },
                    }
                ).encode()
            )
        if request.full_url.endswith("/backups"):
            return FakeResponse(
                json.dumps(
                    {
                        "result": "ok",
                        "data": {
                            "backups": [
                                {
                                    "slug": "abc123",
                                    "name": "HADC checkpoint",
                                    "date": "2026-10-07T17:00:00Z",
                                    "type": "full",
                                    "size": 42.5,
                                    "protected": True,
                                    "compressed": True,
                                    "location": None,
                                    "content": {
                                        "homeassistant": True,
                                        "addons": ["hadc_companion"],
                                        "folders": ["ssl"],
                                    },
                                }
                            ]
                        },
                    }
                ).encode()
            )
        if request.full_url.endswith("/backups/abc123/download"):
            return FakeResponse(b"backup-bytes", "application/x-tar")
        raise AssertionError(f"Unexpected request: {request.method} {request.full_url}")


class SupervisorBackupClientTests(unittest.TestCase):
    def test_create_full_checkpoint_uses_strict_policy(self) -> None:
        opener = RecordingOpener()
        client = SupervisorBackupClient(
            "supervisor-test-token",
            base_url="http://supervisor.test",
            opener=opener,
        )

        backup = client.create_full_backup(
            "HADC checkpoint",
            "a-strong-generated-password-1234567890",
        )

        self.assertEqual("abc123", backup["slug"])
        self.assertTrue(backup["protected"])
        self.assertEqual("full", backup["type"])
        self.assertFalse(backup["homeassistant_exclude_database"])
        self.assertTrue(backup["content"]["homeassistant"])

        method, url, payload, timeout = opener.requests[0]
        self.assertEqual("POST", method)
        self.assertEqual("http://supervisor.test/backups/new/full", url)
        self.assertEqual(30 * 60, timeout)
        self.assertEqual(
            {
                "name": "HADC checkpoint",
                "password": "a-strong-generated-password-1234567890",
                "compressed": True,
                "location": None,
                "homeassistant_exclude_database": False,
                "background": False,
            },
            payload,
        )

    def test_list_backups_returns_sanitized_metadata(self) -> None:
        opener = RecordingOpener()
        client = SupervisorBackupClient(
            "supervisor-test-token",
            base_url="http://supervisor.test",
            opener=opener,
        )
        backups = client.list_backups()
        self.assertEqual(1, len(backups))
        self.assertEqual("abc123", backups[0]["slug"])
        self.assertTrue(backups[0]["protected"])
        self.assertEqual(["hadc_companion"], backups[0]["content"]["addons"])

    def test_download_is_streamed_without_json_wrapping(self) -> None:
        opener = RecordingOpener()
        client = SupervisorBackupClient(
            "supervisor-test-token",
            base_url="http://supervisor.test",
            opener=opener,
        )
        response = client.open_download("abc123")
        try:
            self.assertEqual(b"backup-bytes", response.read())
        finally:
            response.close()

    def test_slug_validation_blocks_path_traversal(self) -> None:
        client = SupervisorBackupClient(
            "supervisor-test-token",
            opener=RecordingOpener(),
        )
        with self.assertRaises(ValueError):
            client.get_backup("../etc/passwd")

    def test_short_checkpoint_password_is_rejected(self) -> None:
        client = SupervisorBackupClient(
            "supervisor-test-token",
            opener=RecordingOpener(),
        )
        with self.assertRaises(ValueError):
            client.create_full_backup("HADC checkpoint", "short")


if __name__ == "__main__":
    unittest.main()
