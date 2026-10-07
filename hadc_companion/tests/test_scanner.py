from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hadc_companion.scanner import ConfigScanner


class ConfigScannerTests(unittest.TestCase):
    def test_read_only_inventory_excludes_secrets_and_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "automations").mkdir()
            (root / ".storage").mkdir()
            (root / "custom_components" / "demo").mkdir(parents=True)
            (root / "templates").mkdir()

            (root / "configuration.yaml").write_text(
                """
light: !include lights.yaml
automation: !include_dir_merge_list automations
template:
  - sensor:
      - name: Kitchen
        state: "{{ states('sensor.kok_temperatur') }}"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "lights.yaml").write_text(
                "target:\n  entity_id: light.kok_tak\n",
                encoding="utf-8",
            )
            (root / "automations" / "door.yaml").write_text(
                "- trigger:\n    - platform: state\n      entity_id: binary_sensor.entredorr_oppning\n",
                encoding="utf-8",
            )
            (root / "secrets.yaml").write_text(
                "api_key: TOP-SECRET-MUST-NOT-LEAK\n",
                encoding="utf-8",
            )
            (root / ".storage" / "core.config").write_text(
                '{"entity_id":"sensor.storage_must_not_scan"}',
                encoding="utf-8",
            )
            storage_dir = root / ".storage"
            storage_dir.chmod(0o000)
            (root / "templates" / "dynamic.jinja").write_text(
                "{{ states('sensor.' ~ room ~ '_temperatur') }}\n",
                encoding="utf-8",
            )
            (root / "custom_components" / "demo" / "manifest.json").write_text(
                json.dumps(
                    {
                        "domain": "demo",
                        "name": "Demo",
                        "version": "1.2.3",
                        "config_flow": True,
                        "requirements": ["demo-lib==1.0"],
                    }
                ),
                encoding="utf-8",
            )
            (root / "custom_components" / "demo" / "__init__.py").write_text(
                'ENTITY = "sensor.demo_static"\nfrom homeassistant import core\n',
                encoding="utf-8",
            )

            try:
                inventory = ConfigScanner(root).scan()
            finally:
                # Restore access so TemporaryDirectory can clean up.
                storage_dir.chmod(0o700)

            self.assertEqual("COMPLETE_WITH_DECLARED_LIMITATIONS", inventory["status"])
            serialized = json.dumps(inventory, ensure_ascii=False)
            self.assertNotIn("TOP-SECRET-MUST-NOT-LEAK", serialized)
            self.assertNotIn("sensor.storage_must_not_scan", serialized)
            self.assertIn("secrets.yaml", serialized)

            includes = {(item["source_path"], item["target_path"]) for item in inventory["includes"]}
            self.assertIn(("configuration.yaml", "lights.yaml"), includes)
            self.assertIn(("configuration.yaml", "automations/door.yaml"), includes)

            candidates = {item["entity_id_candidate"] for item in inventory["entity_id_candidates"]}
            self.assertIn("light.kok_tak", candidates)
            self.assertIn("binary_sensor.entredorr_oppning", candidates)
            self.assertIn("sensor.kok_temperatur", candidates)
            self.assertIn("sensor.demo_static", candidates)
            self.assertNotIn("homeassistant.core", candidates)

            self.assertTrue(any(item["dynamic_possible"] for item in inventory["template_observations"]))
            self.assertEqual("demo", inventory["custom_integrations"][0]["domain"])
            self.assertTrue(inventory["custom_integrations"][0]["config_flow"])

            coverage = {item["scope"]: item["status"] for item in inventory["coverage"]}
            self.assertEqual("VERIFIED", coverage["filesystem_yaml"])
            self.assertEqual("VERIFIED_WITH_LIMITATIONS", coverage["templates_jinja"])
            self.assertEqual("EXCLUDED_BY_POLICY", coverage["secrets"])
            self.assertEqual("EXCLUDED_BY_POLICY", coverage["internal_storage"])

    def test_missing_config_root_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            inventory = ConfigScanner(missing).scan()
            self.assertEqual("UNAVAILABLE", inventory["status"])
            self.assertEqual("NOT_AVAILABLE", inventory["coverage"][0]["status"])


if __name__ == "__main__":
    unittest.main()
