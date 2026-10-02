"""
scanner.py — fast extension/MIME filter plus ClamAV for allowed files.

Dangerous types (.exe, .rar, .zip, .z, …) are blocked from Telegram
metadata only — never downloaded.

Allowed types (photos, PDFs, Office docs, …) are downloaded to a random
temp path and streamed to clamd with INSTREAM. Temp files are always
deleted afterward.
"""

from __future__ import annotations

import asyncio
import os
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import clamd

from config import CONFIG

HARD_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({
    ".rar", ".zip", ".7z", ".tar", ".gz", ".tgz", ".bz2",
    ".xz", ".cab", ".ace", ".iso", ".img", ".z", ".zst",
    ".lz", ".lzma", ".sz", ".arj",
})

# Always blocked, even if a group turns the custom blocklist off.
HARD_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".pif", ".com", ".cpl",
    ".msi", ".msp", ".msix", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".js", ".jse", ".src", ".wsf", ".wsh", ".hta", ".jar", ".apk",
    ".reg", ".lnk", ".gadget", ".msc",
}) | HARD_ARCHIVE_EXTENSIONS

DANGEROUS_MIME_TYPES: frozenset[str] = frozenset({
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-ms-dos-executable",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-unix-executable",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/x-bat",
    "application/x-msdos-batch",
    "text/x-msdos-batch",
    "application/x-sh",
    "application/x-powershell",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "application/vnd.rar",
    "application/x-rar-compressed",
    "application/x-rar",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-7z-compressed",
    "application/x-tar",
    "application/gzip",
    "application/x-compress",
    "application/x-compressed",
    "application/zstd",
})


def sanitize_filename(original_name: str) -> str:
    """Return a display-safe version of a filename.

    Allows Khmer and other letters. Strips path components and control
    characters. Used only for display/logging — never as a disk path.
    """
    if not original_name:
        return "unnamed_file"
    base = os.path.basename(original_name)
    base = base.replace("\x00", "")
    cleaned: list[str] = []
    for ch in base:
        if ch.isalpha() or ch.isdigit() or ch in "._- ()[]":
            cleaned.append(ch)
        else:
            cleaned.append("_")
    base = "".join(cleaned).strip(" .")
    if not base:
        base = "unnamed_file"
    return base[:200]


def get_extension(filename: str) -> str:
    _, ext = os.path.splitext(filename.lower())
    return ext


def all_extensions(filename: str) -> list[str]:
    """Every suffix, so document.pdf.exe is treated as .exe (and .pdf)."""
    name = filename.lower()
    exts: list[str] = []
    while True:
        name, ext = os.path.splitext(name)
        if not ext:
            break
        exts.append(ext)
    return exts


def blocked_reason(
    filename: str,
    mime_type: Optional[str],
    extra_blocked: list[str],
    extra_blocking_enabled: bool,
) -> Optional[tuple[str, str]]:
    """Return (kind, value) if the file must be blocked without download."""
    exts = all_extensions(filename)
    extra = {e.lower() for e in extra_blocked} if extra_blocking_enabled else set()

    for ext in exts:
        if ext in HARD_ARCHIVE_EXTENSIONS:
            return ("archive", ext)
        if ext in HARD_DANGEROUS_EXTENSIONS:
            return ("executable", ext)
        if ext in extra:
            return ("policy", ext)

    mime = (mime_type or "").strip().lower()
    if mime in DANGEROUS_MIME_TYPES:
        if "rar" in mime or "zip" in mime or "7z" in mime or "tar" in mime or "gzip" in mime or "compress" in mime:
            return ("mime_archive", mime)
        return ("mime_exe", mime)

    return None


def make_temp_path(extension: str) -> str:
    os.makedirs(CONFIG.temp_dir, exist_ok=True)
    safe_ext = re.sub(r"[^a-z0-9]", "", extension.lower())[:10]
    name = f"{uuid.uuid4().hex}.{safe_ext}" if safe_ext else uuid.uuid4().hex
    return os.path.join(CONFIG.temp_dir, name)


class ScanOutcome(str, Enum):
    SAFE = "safe"
    INFECTED = "infected"
    ERROR = "error"


@dataclass
class ScanResult:
    outcome: ScanOutcome
    signature: Optional[str] = None
    detail: Optional[str] = None


def _sync_ping(host: str, port: int, timeout: int) -> bool:
    try:
        cd = clamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)
        return cd.ping() == "PONG"
    except Exception:
        return False


async def is_clamav_available(
    host: str = CONFIG.clamav_host,
    port: int = CONFIG.clamav_port,
    timeout: int = CONFIG.clamav_timeout,
) -> bool:
    return await asyncio.to_thread(_sync_ping, host, port, min(timeout, 10))


def _sync_scan_file(path: str, host: str, port: int, timeout: int) -> ScanResult:
    try:
        cd = clamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)
    except Exception as exc:
        return ScanResult(ScanOutcome.ERROR, detail=f"Could not connect to ClamAV: {exc}")

    try:
        with open(path, "rb") as fh:
            response = cd.instream(fh)
    except clamd.ConnectionError as exc:
        return ScanResult(ScanOutcome.ERROR, detail=f"ClamAV connection error: {exc}")
    except TimeoutError as exc:
        return ScanResult(ScanOutcome.ERROR, detail=f"ClamAV scan timed out: {exc}")
    except OSError as exc:
        return ScanResult(ScanOutcome.ERROR, detail=f"Could not read temp file: {exc}")
    except Exception as exc:
        return ScanResult(ScanOutcome.ERROR, detail=f"Unexpected scan error: {exc}")

    try:
        status, signature = response["stream"]
    except (KeyError, ValueError, TypeError):
        return ScanResult(ScanOutcome.ERROR, detail=f"Unexpected ClamAV response: {response}")

    if status == "OK":
        return ScanResult(ScanOutcome.SAFE)
    if status == "FOUND":
        return ScanResult(ScanOutcome.INFECTED, signature=signature)
    return ScanResult(ScanOutcome.ERROR, detail=f"ClamAV returned status={status}")


async def scan_file(
    path: str,
    host: str = CONFIG.clamav_host,
    port: int = CONFIG.clamav_port,
    timeout: int = CONFIG.clamav_timeout,
) -> ScanResult:
    """Scan a file via clamd INSTREAM. Never returns SAFE unless ClamAV said OK."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_sync_scan_file, path, host, port, timeout),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        return ScanResult(ScanOutcome.ERROR, detail="Scan timed out")


def cleanup_temp_file(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
