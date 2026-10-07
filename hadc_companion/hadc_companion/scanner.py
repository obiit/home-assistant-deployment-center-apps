from __future__ import annotations

import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import APP_VERSION, DATA_SCHEMA_VERSION, INVENTORY_SCHEMA, PROTOCOL_VERSION

ENTITY_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_])([a-z][a-z0-9_]*\.[a-z0-9_]+)(?![A-Za-z0-9_])"
)
INCLUDE_RE = re.compile(
    r"!(include|include_dir_list|include_dir_named|include_dir_merge_list|include_dir_merge_named)"
    r"\s+[\"']?([^\"'\s#]+)"
)
DYNAMIC_TEMPLATE_RE = re.compile(
    r"(?:~|states\s*\[|states\s*\(\s*[^'\"\s]|state_attr\s*\(\s*[^'\"\s])"
)

TEXT_EXTENSIONS = {".yaml", ".yml", ".jinja", ".j2", ".json"}
PYTHON_EXTENSION = ".py"
EXCLUDED_DIRECTORIES = {
    ".git",
    ".storage",
    "backups",
    "deps",
    "media",
    "node_modules",
    "tts",
    "www",
}
SECRET_FILENAMES = {"secrets.yaml", "secrets.yml"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ConfigScanner:
    def __init__(self, config_root: Path, max_file_size_kb: int = 2048) -> None:
        self.root = config_root.resolve()
        self.max_bytes = max_file_size_kb * 1024

    def scan(self) -> dict[str, Any]:
        captured_at = utc_now()
        files: list[dict[str, Any]] = []
        includes: list[dict[str, Any]] = []
        references: list[dict[str, Any]] = []
        templates: list[dict[str, Any]] = []
        custom_integrations: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []
        secret_files = 0
        skipped_files = 0

        if not self.root.exists() or not self.root.is_dir():
            return self._unavailable(captured_at, "CONFIG_ROOT_MISSING", str(self.root))

        candidates = sorted(
            (path for path in self.root.rglob("*") if path.is_file() or path.is_symlink()),
            key=lambda item: item.as_posix(),
        )

        for path in candidates:
            relative = self._relative_or_none(path)
            if relative is None:
                issues.append(self._issue("PATH_OUTSIDE_ROOT", str(path), "Path resolves outside config root."))
                skipped_files += 1
                continue

            if self._is_excluded(relative):
                continue

            if path.is_symlink():
                issues.append(self._issue("SYMLINK_SKIPPED", relative, "Symlink is not followed by the read-only scanner."))
                skipped_files += 1
                continue

            name_lower = path.name.lower()
            if name_lower in SECRET_FILENAMES:
                secret_files += 1
                stat = path.stat()
                files.append(
                    {
                        "path": relative,
                        "kind": "secrets",
                        "size_bytes": stat.st_size,
                        "content_scanned": False,
                        "sha256": None,
                        "policy": "EXCLUDED_SECRET_VALUES",
                    }
                )
                continue

            extension = path.suffix.lower()
            should_scan = extension in TEXT_EXTENSIONS or extension == PYTHON_EXTENSION
            if not should_scan:
                continue

            stat = path.stat()
            kind = self._classify(relative, extension)
            if stat.st_size > self.max_bytes:
                files.append(
                    {
                        "path": relative,
                        "kind": kind,
                        "size_bytes": stat.st_size,
                        "content_scanned": False,
                        "sha256": None,
                        "policy": "SKIPPED_MAX_SIZE",
                    }
                )
                issues.append(
                    self._issue(
                        "FILE_TOO_LARGE",
                        relative,
                        f"File is larger than configured scan limit ({self.max_bytes} bytes).",
                    )
                )
                skipped_files += 1
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                issues.append(self._issue("NON_UTF8_FILE", relative, "File is not valid UTF-8 and was skipped."))
                skipped_files += 1
                continue
            except OSError as exc:
                issues.append(self._issue("FILE_READ_FAILED", relative, str(exc)))
                skipped_files += 1
                continue

            files.append(
                {
                    "path": relative,
                    "kind": kind,
                    "size_bytes": stat.st_size,
                    "content_scanned": True,
                    "sha256": sha256_file(path),
                    "policy": "READ_ONLY_ANALYZED",
                }
            )

            if relative.startswith("custom_components/") and path.name == "manifest.json":
                manifest = self._read_manifest(relative, text, issues)
                if manifest is not None:
                    custom_integrations.append(manifest)

            if extension in {".yaml", ".yml"}:
                self._scan_includes(path, relative, text, includes, issues)

            if extension == PYTHON_EXTENSION:
                self._scan_python(relative, text, references, templates, issues)
            else:
                self._scan_text(relative, kind, text, references, templates)

        include_problem_codes = {"INCLUDE_MISSING", "INCLUDE_OUTSIDE_ROOT", "INCLUDE_TARGET_INVALID"}
        yaml_problem_codes = {"FILE_READ_FAILED", "NON_UTF8_FILE", "FILE_TOO_LARGE"}

        coverage = [
            self._coverage(
                "filesystem_yaml",
                "PARTIAL" if any(item["code"] in yaml_problem_codes for item in issues) else "VERIFIED",
                "Static read-only scan of eligible YAML/config files under homeassistant_config.",
                True,
            ),
            self._coverage(
                "include_graph",
                "PARTIAL" if any(item["code"] in include_problem_codes for item in issues) else "VERIFIED",
                "Static !include and !include_dir_* relationships resolved inside config root.",
                True,
            ),
            self._coverage(
                "templates_jinja",
                "VERIFIED_WITH_LIMITATIONS",
                "Static entity-ID candidates are detected; dynamic Jinja construction cannot always be proven statically.",
                True,
            ),
            self._coverage(
                "blueprints_packages",
                "VERIFIED",
                "Blueprint/package files inside the mounted configuration are included in the static file scan.",
                True,
            ),
            self._coverage(
                "custom_integrations",
                "VERIFIED_WITH_LIMITATIONS",
                "Manifests and static string literals in custom_components are inspected; runtime-generated Python relationships remain limited.",
                True,
            ),
            self._coverage(
                "secrets",
                "EXCLUDED_BY_POLICY",
                "secrets.yaml values are never read or returned by Companion.",
                False,
            ),
            self._coverage(
                "internal_storage",
                "EXCLUDED_BY_POLICY",
                ".storage is deliberately excluded and must never be used as a direct mutation surface.",
                False,
            ),
        ]

        return {
            "schema": INVENTORY_SCHEMA,
            "captured_at": captured_at,
            "companion": {
                "version": APP_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "data_schema_version": DATA_SCHEMA_VERSION,
                "config_access": "READ_ONLY",
            },
            "status": "PARTIAL" if issues else "COMPLETE_WITH_DECLARED_LIMITATIONS",
            "stats": {
                "files_analyzed": sum(1 for item in files if item["content_scanned"]),
                "files_recorded": len(files),
                "files_skipped": skipped_files,
                "secret_files_excluded": secret_files,
                "include_edges": len(includes),
                "entity_id_candidates": len(references),
                "template_observations": len(templates),
                "custom_integrations": len(custom_integrations),
                "issues": len(issues),
            },
            "files": files,
            "includes": includes,
            "entity_id_candidates": references,
            "template_observations": templates,
            "custom_integrations": sorted(custom_integrations, key=lambda item: item["domain"]),
            "coverage": coverage,
            "issues": issues,
        }

    def _scan_text(
        self,
        relative: str,
        source_kind: str,
        text: str,
        references: list[dict[str, Any]],
        templates: list[dict[str, Any]],
    ) -> None:
        for line_number, line in enumerate(text.splitlines(), start=1):
            ids = sorted(set(ENTITY_CANDIDATE_RE.findall(line)))
            has_template = "{{" in line or "{%" in line
            for entity_id in ids:
                references.append(
                    {
                        "entity_id_candidate": entity_id,
                        "source_path": relative,
                        "source_kind": source_kind,
                        "line": line_number,
                        "evidence_kind": "STATIC_ENTITY_ID_CANDIDATE",
                        "inside_template": has_template,
                    }
                )
            if has_template:
                templates.append(
                    {
                        "source_path": relative,
                        "line": line_number,
                        "static_entity_id_candidates": ids,
                        "dynamic_possible": bool(DYNAMIC_TEMPLATE_RE.search(line)) or not ids,
                    }
                )

    def _scan_python(
        self,
        relative: str,
        text: str,
        references: list[dict[str, Any]],
        templates: list[dict[str, Any]],
        issues: list[dict[str, Any]],
    ) -> None:
        try:
            tree = ast.parse(text, filename=relative)
        except SyntaxError as exc:
            issues.append(self._issue("PYTHON_PARSE_FAILED", relative, f"line {exc.lineno}: {exc.msg}"))
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                ids = sorted(set(ENTITY_CANDIDATE_RE.findall(node.value)))
                for entity_id in ids:
                    references.append(
                        {
                            "entity_id_candidate": entity_id,
                            "source_path": relative,
                            "source_kind": "custom_integration_python",
                            "line": getattr(node, "lineno", None),
                            "evidence_kind": "STATIC_STRING_ENTITY_ID_CANDIDATE",
                            "inside_template": False,
                        }
                    )

    def _scan_includes(
        self,
        source_path: Path,
        source_relative: str,
        text: str,
        includes: list[dict[str, Any]],
        issues: list[dict[str, Any]],
    ) -> None:
        for match in INCLUDE_RE.finditer(text):
            include_type, raw_target = match.groups()
            target = (source_path.parent / raw_target).resolve()
            try:
                target.relative_to(self.root)
            except ValueError:
                issues.append(self._issue("INCLUDE_OUTSIDE_ROOT", source_relative, raw_target))
                continue

            if include_type == "include":
                targets = [target]
            elif target.is_dir():
                targets = sorted(
                    [*target.glob("*.yaml"), *target.glob("*.yml")],
                    key=lambda item: item.as_posix(),
                )
            else:
                issues.append(self._issue("INCLUDE_TARGET_INVALID", source_relative, raw_target))
                continue

            if not targets:
                issues.append(self._issue("INCLUDE_MISSING", source_relative, raw_target))
                continue

            for resolved in targets:
                if not resolved.is_file():
                    issues.append(self._issue("INCLUDE_MISSING", source_relative, str(resolved)))
                    continue
                includes.append(
                    {
                        "source_path": source_relative,
                        "target_path": resolved.relative_to(self.root).as_posix(),
                        "include_type": include_type,
                        "evidence_kind": "STATIC_INCLUDE",
                    }
                )

    def _read_manifest(
        self,
        relative: str,
        text: str,
        issues: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        try:
            manifest = json.loads(text)
        except json.JSONDecodeError as exc:
            issues.append(self._issue("MANIFEST_JSON_INVALID", relative, str(exc)))
            return None

        domain = Path(relative).parts[1] if len(Path(relative).parts) > 1 else "unknown"
        return {
            "domain": domain,
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "config_flow": bool(manifest.get("config_flow", False)),
            "iot_class": manifest.get("iot_class"),
            "requirements_count": len(manifest.get("requirements", []))
            if isinstance(manifest.get("requirements"), list)
            else 0,
        }

    def _relative_or_none(self, path: Path) -> str | None:
        try:
            return path.resolve(strict=False).relative_to(self.root).as_posix()
        except ValueError:
            return None

    @staticmethod
    def _is_excluded(relative: str) -> bool:
        parts = Path(relative).parts
        return any(part in EXCLUDED_DIRECTORIES for part in parts)

    @staticmethod
    def _classify(relative: str, extension: str) -> str:
        if relative == "configuration.yaml":
            return "configuration"
        if relative.startswith("blueprints/"):
            return "blueprint"
        if relative.startswith("packages/"):
            return "package"
        if relative.startswith("custom_components/"):
            return "custom_integration"
        if extension in {".jinja", ".j2"}:
            return "template"
        lower = relative.lower()
        if "lovelace" in lower or "dashboard" in lower:
            return "dashboard_yaml"
        if extension == ".py":
            return "python"
        if extension == ".json":
            return "json"
        return "yaml"

    @staticmethod
    def _issue(code: str, path: str, message: str) -> dict[str, str]:
        return {"code": code, "path": path, "message": message}

    @staticmethod
    def _coverage(scope: str, status: str, detail: str, required: bool) -> dict[str, Any]:
        return {
            "scope": scope,
            "status": status,
            "required_for_entity_id_rename": required,
            "detail": detail,
        }

    def _unavailable(self, captured_at: str, code: str, path: str) -> dict[str, Any]:
        return {
            "schema": INVENTORY_SCHEMA,
            "captured_at": captured_at,
            "companion": {
                "version": APP_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "data_schema_version": DATA_SCHEMA_VERSION,
                "config_access": "READ_ONLY",
            },
            "status": "UNAVAILABLE",
            "stats": {
                "files_analyzed": 0,
                "files_recorded": 0,
                "files_skipped": 0,
                "secret_files_excluded": 0,
                "include_edges": 0,
                "entity_id_candidates": 0,
                "template_observations": 0,
                "custom_integrations": 0,
                "issues": 1,
            },
            "files": [],
            "includes": [],
            "entity_id_candidates": [],
            "template_observations": [],
            "custom_integrations": [],
            "coverage": [
                self._coverage("filesystem_yaml", "NOT_AVAILABLE", "Home Assistant config root is unavailable.", True)
            ],
            "issues": [self._issue(code, path, "Home Assistant configuration root is unavailable.")],
        }
