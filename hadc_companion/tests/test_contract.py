from __future__ import annotations

import unittest
from pathlib import Path

from hadc_companion import APP_VERSION, DATA_SCHEMA_VERSION, PROTOCOL_VERSION


class AppContractTests(unittest.TestCase):
    def test_version_contract_and_least_privilege_config(self) -> None:
        app_root = Path(__file__).resolve().parents[1]
        config = (app_root / "config.yaml").read_text(encoding="utf-8")

        self.assertEqual("0.1.0", APP_VERSION)
        self.assertEqual(1, PROTOCOL_VERSION)
        self.assertEqual(1, DATA_SCHEMA_VERSION)
        self.assertIn('version: "0.1.0"', config)
        self.assertIn("read_only: true", config)
        self.assertIn("type: homeassistant_config", config)
        self.assertIn('watchdog: "tcp://[HOST]:[PORT:18091]"', config)
        self.assertIn('image: "ghcr.io/obiit/hadc-companion"', config)

        forbidden = (
            "host_network: true",
            "docker_api: true",
            "full_access: true",
            "hassio_api: true",
            "homeassistant_api: true",
            "host_pid: true",
        )
        for value in forbidden:
            self.assertNotIn(value, config)


if __name__ == "__main__":
    unittest.main()
