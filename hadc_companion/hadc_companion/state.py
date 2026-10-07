from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import DATA_SCHEMA_VERSION


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root
        self.path = data_root / "state.json"
        self.data_root.mkdir(parents=True, exist_ok=True)
        self._state = self._load_and_migrate()

    @property
    def state(self) -> dict[str, Any]:
        return dict(self._state)

    def _default_state(self) -> dict[str, Any]:
        return {
            "data_schema_version": DATA_SCHEMA_VERSION,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "api_token_sha256": None,
            "paired_at": None,
            "last_scan_at": None,
        }

    def _load_and_migrate(self) -> dict[str, Any]:
        if not self.path.exists():
            state = self._default_state()
            self._write(state)
            return state

        with self.path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)

        version = int(state.get("data_schema_version", 0))
        if version > DATA_SCHEMA_VERSION:
            raise RuntimeError(
                f"State schema {version} is newer than supported schema {DATA_SCHEMA_VERSION}."
            )

        if version == 0:
            state = {**self._default_state(), **state}
            state["data_schema_version"] = 1

        state["updated_at"] = utc_now()
        self._write(state)
        return state

    def _write(self, state: dict[str, Any]) -> None:
        state = dict(state)
        state["updated_at"] = utc_now()
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)

    def set_api_token(self, token: str) -> None:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self._state["api_token_sha256"] = digest
        self._state["paired_at"] = utc_now()
        self._write(self._state)

    def verify_api_token(self, token: str) -> bool:
        expected = self._state.get("api_token_sha256")
        if not expected or not token:
            return False
        actual = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return hmac.compare_digest(str(expected), actual)

    def record_scan(self, captured_at: str) -> None:
        self._state["last_scan_at"] = captured_at
        self._write(self._state)

    @property
    def is_paired(self) -> bool:
        return bool(self._state.get("api_token_sha256"))
