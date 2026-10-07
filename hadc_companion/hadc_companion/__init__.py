"""HADC Companion package."""

from __future__ import annotations

import os

APP_VERSION = os.environ.get("HADC_COMPANION_VERSION", "0.1.1")
PROTOCOL_VERSION = 1
DATA_SCHEMA_VERSION = 1
INVENTORY_SCHEMA = "ha-deployment-center.companion-inventory.v1"
