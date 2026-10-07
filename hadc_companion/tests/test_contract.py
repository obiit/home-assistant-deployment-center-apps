from __future__ import annotations

import unittest
from pathlib import Path

from hadc_companion import APP_VERSION, DATA_SCHEMA_VERSION, PROTOCOL_VERSION


class AppContractTests(unittest.TestCase):
    def test_version_contract_and_least_privilege_config(self) -> None:
        app_root = Path(__file__).resolve().parents[1]
        config = (app_root / "config.yaml").read_text(encoding="utf-8")
        apparmor = (app_root / "apparmor.txt").read_text(encoding="utf-8")

        self.assertEqual("0.2.0", APP_VERSION)
        self.assertEqual(1, PROTOCOL_VERSION)
        self.assertEqual(1, DATA_SCHEMA_VERSION)
        self.assertIn('version: "0.2.0"', config)
        self.assertIn("read_only: true", config)
        self.assertIn("type: homeassistant_config", config)
        self.assertIn('watchdog: "tcp://[HOST]:[PORT:18091]"', config)
        self.assertIn('image: "ghcr.io/obiit/hadc-companion"', config)

        self.assertIn("hassio_api: true", config)
        self.assertIn("hassio_role: backup", config)

        forbidden = (
            "host_network: true",
            "docker_api: true",
            "full_access: true",
            "homeassistant_api: true",
            "host_pid: true",
            "hassio_role: manager",
            "hassio_role: admin",
        )
        for value in forbidden:
            self.assertNotIn(value, config)

        # Home Assistant base images use S6 Overlay and enter through /init.
        # Missing these rules causes Supervisor-only startup failures that
        # ordinary Docker smoke tests cannot reproduce.
        self.assertIn("/init rix,", apparmor)
        self.assertIn("/run/{s6,s6-rc*,service}/** rix,", apparmor)
        self.assertIn("/package/** rix,", apparmor)
        self.assertIn("/command/** rix,", apparmor)
        self.assertIn("/etc/s6-overlay/** rwix,", apparmor)
        self.assertIn("/etc/fix-attrs.d/ r,", apparmor)
        self.assertIn("/etc/services.d/ r,", apparmor)
        self.assertIn("/etc/services.d/** rwix,", apparmor)
        self.assertIn("/etc/cont-init.d/** rwix,", apparmor)
        self.assertIn("/etc/cont-finish.d/** rwix,", apparmor)
        self.assertIn("/run/{,**} rwk,", apparmor)
        self.assertIn("/usr/local/lib/** mr,", apparmor)
        self.assertIn("/usr/lib/** mr,", apparmor)
        self.assertIn("/lib/** mr,", apparmor)
        self.assertIn("/opt/hadc-companion/** r,", apparmor)
        self.assertIn("/data/ rw,", apparmor)
        self.assertIn("/data/tls w,", apparmor)
        self.assertIn("/data/tls/ rwk,", apparmor)
        self.assertIn("/data/**/ rwk,", apparmor)
        self.assertIn("/data/** rwk,", apparmor)
        self.assertIn("/homeassistant/** r,", apparmor)
        self.assertIn("deny /homeassistant/.storage/** r,", apparmor)
        self.assertNotIn("\n  file,\n", apparmor)
        self.assertNotIn("capability dac_override", apparmor)


if __name__ == "__main__":
    unittest.main()
