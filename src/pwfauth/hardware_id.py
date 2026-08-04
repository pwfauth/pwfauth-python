"""A stable per-machine identifier.

Mirrors the .NET and Node clients exactly, so the same machine produces the same
HWID under any of the three SDKs. That parity is not cosmetic: a licence counts
distinct hardware IDs against its device limit, so a mismatch would burn a second
seat the moment a customer switched SDKs.

Windows reads the cryptography MachineGuid through ``reg.exe`` -- deliberately not
``wmic``, which Windows 11 24H2 removed. Linux reads ``/etc/machine-id``, macOS the
IOPlatformUUID. Anything that fails falls back to the host name.
"""

from __future__ import annotations

import os
import platform
import re
import socket
import subprocess

_cached: str | None = None


def get_hardware_id() -> str:
    """Return this machine's hardware ID, computing it once per process."""
    global _cached
    if _cached is not None:
        return _cached

    value = ""
    try:
        value = _resolve()
    except Exception:
        # Any probe failure falls through to the host-name fallback.
        pass

    _cached = (value or _safe_hostname()).strip()
    return _cached


def reset_hardware_id_cache() -> None:
    """Clear the cache. Only useful in tests."""
    global _cached
    _cached = None


def _resolve() -> str:
    system = platform.system()
    if system == "Windows":
        return _windows_machine_guid()
    if system == "Darwin":
        return _mac_platform_uuid()
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
    return ""


def _windows_machine_guid() -> str:
    out = _run(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
    # "    MachineGuid    REG_SZ    2f5a1c8e-..."
    marker = out.upper().find("REG_SZ")
    return "" if marker < 0 else out[marker + len("REG_SZ"):].strip()


def _mac_platform_uuid() -> str:
    out = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
    return m.group(1) if m else ""


def _run(args: list[str]) -> str:
    try:
        # CREATE_NO_WINDOW keeps a console from flashing over a GUI app, the same
        # concern as windowsHide in the Node client.
        flags = 0x08000000 if platform.system() == "Windows" else 0
        out = subprocess.run(
            args,
            capture_output=True,
            timeout=5,
            creationflags=flags,
            check=False,
        )
        return out.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _safe_hostname() -> str:
    try:
        return socket.gethostname() or "unknown-host"
    except Exception:
        return "unknown-host"
