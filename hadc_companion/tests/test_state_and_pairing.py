from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hadc_companion.app import PairingError, PairingManager
from hadc_companion.state import StateStore


class StateAndPairingTests(unittest.TestCase):
    def test_token_is_hashed_and_pairing_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = StateStore(root)
            pairing = PairingManager(state, window_minutes=10)
            code = pairing.code

            token = pairing.pair(code)
            self.assertTrue(state.verify_api_token(token))
            self.assertTrue(state.is_paired)

            stored = (root / "state.json").read_text(encoding="utf-8")
            self.assertNotIn(token, stored)
            parsed = json.loads(stored)
            self.assertEqual(64, len(parsed["api_token_sha256"]))

            with self.assertRaises(PairingError):
                pairing.pair(code)

            replacement_pairing = PairingManager(state, window_minutes=10)
            replacement_token = replacement_pairing.pair(replacement_pairing.code)
            self.assertTrue(state.verify_api_token(replacement_token))
            self.assertFalse(state.verify_api_token(token))

    def test_schema_zero_is_migrated_to_schema_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.mkdir(parents=True, exist_ok=True)
            (root / "state.json").write_text(
                json.dumps({"data_schema_version": 0, "api_token_sha256": None}),
                encoding="utf-8",
            )
            state = StateStore(root)
            self.assertEqual(1, state.state["data_schema_version"])

    def test_invalid_pairing_code_is_limited(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pairing = PairingManager(StateStore(Path(temporary)), window_minutes=10)
            for _ in range(5):
                with self.assertRaises(PairingError):
                    pairing.pair("000000")
            self.assertFalse(pairing.is_active())


if __name__ == "__main__":
    unittest.main()
