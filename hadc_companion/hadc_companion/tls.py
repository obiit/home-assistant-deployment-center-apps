from __future__ import annotations

import hashlib
import os
import shutil
import ssl
import subprocess
from pathlib import Path


def ensure_tls_material(data_root: Path) -> tuple[Path, Path, str]:
    tls_root = data_root / "tls"
    cert_path = tls_root / "cert.pem"
    key_path = tls_root / "key.pem"
    tls_root.mkdir(parents=True, exist_ok=True)

    if not cert_path.exists() or not key_path.exists():
        openssl = shutil.which("openssl")
        if openssl is None:
            raise RuntimeError("openssl is required to create the Companion TLS identity.")

        temporary_cert = tls_root / "cert.pem.tmp"
        temporary_key = tls_root / "key.pem.tmp"
        for path in (temporary_cert, temporary_key):
            if path.exists():
                path.unlink()

        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "3650",
                "-nodes",
                "-subj",
                "/CN=HADC Companion",
                "-addext",
                "subjectAltName=DNS:hadc-companion,DNS:homeassistant.local,IP:127.0.0.1",
                "-keyout",
                str(temporary_key),
                "-out",
                str(temporary_cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.chmod(temporary_key, 0o600)
        os.chmod(temporary_cert, 0o644)
        os.replace(temporary_key, key_path)
        os.replace(temporary_cert, cert_path)

    os.chmod(key_path, 0o600)
    fingerprint = certificate_sha256(cert_path)
    return cert_path, key_path, fingerprint


def certificate_sha256(cert_path: Path) -> str:
    pem = cert_path.read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()
