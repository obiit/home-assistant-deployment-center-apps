from __future__ import annotations

import unittest
from pathlib import Path

from hadc_companion import APP_VERSION, DATA_SCHEMA_VERSION, PROTOCOL_VERSION


class AppContractTests(unittest.TestCase):
    def test_version_contract_and_least_privilege_config(self) -> None:
        app_root = Path(__file__).resolve().parents[1]
        config = (app_root / "config.yaml").read_text(encoding="utf-8")
        apparmor = (app_root / "apparmor.txt").read_text(encoding="utf-8")

        self.assertEqual("0.1.1", APP_VERSION)
        self.assertEqual(1, PROTOCOL_VERSION)
        self.assertEqual(1, DATA_SCHEMA_VERSION)
        self.assertIn('version: "0.1.1"', config)
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

        # Home Assistant base images use S6 Overlay and enter through /init.
        # Missing these rules causes Supervisor-only startup failures that
        # ordinary Docker smoke tests cannot reproduce.
        self.assertIn("/init rix,", apparmor)
        self.assertIn("/run/{s6,s6-rc*,service}/** ix,", apparmor)
        self.assertIn("/package/** ix,", apparmor)
        self.assertIn("/command/** ix,", apparmor)
        self.assertIn("/etc/s6-overlay/** rwix,", apparmor)
        self.assertIn("/run/{,**} rwk,", apparmor)
        self.assertIn("/homeassistant/** r,", apparmor)
        self.assertIn("deny /homeassistant/.storage/** r,", apparmor)


if __name__ == "__main__":
    unittest.main()
