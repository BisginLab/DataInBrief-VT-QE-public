from __future__ import annotations

import csv
import os
import pickle
import re
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path

import json_repair as jr
import msgspec

from config import (
    APK_DIR,
    CACHE_DIR,
    HASH_FILE,
    PAPER_FILE,
    PKG_MAP_FILE,
    QUARK_RESCAN_DIR,
    QUARK_SCAN_DIR,
    VT_FIRST_TIME_BENIGN_DIR,
    VT_LEGACY_JSON_DIR,
    VT_RELIABLE_JSON_DIR,
)

PAPER_STATUS_INDEX = 34
ApkScanJob = tuple[str, str, str]


def path2names(paths: set[Path] | list[Path]) -> set[str]:
    """Convert file paths to filenames."""
    return {path.name for path in paths}


def _json_files(root: Path) -> set[Path]:
    return set(root.rglob("*.json")) if root.exists() else set()


def get_qk_files() -> set[Path]:
    """Return Quark-Engine JSON response files from first scan and rescan roots."""
    return _json_files(QUARK_SCAN_DIR) | _json_files(QUARK_RESCAN_DIR)


def get_all_vt_ai_files() -> set[Path]:
    """Return VirusTotal v3 JSON response files used for feature extraction."""
    return _json_files(VT_RELIABLE_JSON_DIR) | _json_files(VT_FIRST_TIME_BENIGN_DIR)


def get_reliable_vt_ai_files() -> set[Path]:
    """Return VirusTotal v3 JSON files retained after reliability filtering."""
    return _json_files(VT_RELIABLE_JSON_DIR)


def get_vt_og_files() -> set[Path]:
    """Return legacy VirusTotal JSON response files, if available."""
    return _json_files(VT_LEGACY_JSON_DIR)


def load_json_path_repair(path: Path) -> dict | None:
    """Load a JSON file, attempting a syntax repair for malformed responses."""
    raw = path.read_bytes().decode("utf-8-sig", errors="replace")
    try:
        return msgspec.json.decode(raw)
    except msgspec.DecodeError:
        cleaned = jr.repair_json(raw, skip_json_loads=True).strip()
        try:
            repaired = msgspec.json.decode(cleaned)
        except msgspec.DecodeError:
            return None
        return repaired[0] if isinstance(repaired, list) else repaired


class FeatureError(Exception):
    def __init__(self, msg: str, err_feature: str, err_path: Path):
        super().__init__(msg)
        self.err_feature = err_feature
        self.err_path = err_path


class SkipFileError(FeatureError):
    pass


class JSONParseError(FeatureError):
    pass


@contextmanager
def error_tracker(err_feature: str, err_file: Path, i: int):
    try:
        yield
    except KeyError as exc:
        msg = f"Skipping row {i} due to missing {err_feature!r} in {err_file}"
        raise SkipFileError(msg, err_feature, err_file) from exc
    except Exception as exc:
        msg = f"Skipping row {i} due to {type(exc).__name__} in {err_file}: {exc}"
        raise SkipFileError(msg, err_feature, err_file) from exc


def _cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / name


def _load_pickle(path: Path):
    if path.exists():
        with path.open("rb") as file:
            return pickle.load(file)
    return None


def _save_pickle(path: Path, value) -> None:
    with path.open("wb") as file:
        pickle.dump(value, file)


def load_pkg2hash() -> dict[str, str]:
    cache_path = _cache_path("pkg2hash.pkl")
    if cached := _load_pickle(cache_path):
        return cached

    pkg2hash = {}
    with PKG_MAP_FILE.open(newline="") as map_file:
        reader = csv.reader(map_file)
        next(reader, None)
        for row in reader:
            pkg_name = row[1]
            if pkg_name.endswith(".apk"):
                pkg_name = pkg_name[:-4]
            pkg2hash[pkg_name] = row[2]

    _save_pickle(cache_path, pkg2hash)
    return pkg2hash


def load_hash2malicious() -> dict[str, int | None]:
    cache_path = _cache_path("hash2malicious.pkl")
    if cached := _load_pickle(cache_path):
        return cached

    hash2malicious = {}
    for json_file in get_all_vt_ai_files():
        vt_report = load_json_path_repair(json_file)
        if vt_report is None:
            continue
        attrs = vt_report.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        hash2malicious[json_file.stem] = stats.get("malicious")

    _save_pickle(cache_path, hash2malicious)
    return hash2malicious


def load_hash2risk() -> dict[str, str]:
    cache_path = _cache_path("hash2risk.pkl")
    if cached := _load_pickle(cache_path):
        return cached

    hash2risk = {}
    for json_file in get_qk_files():
        threat_level = re.search(r'"threat_level":\s*"([^"]+)"', json_file.read_text(errors="replace"))
        if threat_level:
            hash2risk[json_file.stem] = threat_level.group(1).split()[0].lower()

    _save_pickle(cache_path, hash2risk)
    return hash2risk


def load_apk_files() -> list[str]:
    cache_path = _cache_path("apk_files.pkl")
    if cached := _load_pickle(cache_path):
        return cached

    apk_files = []
    for subfolder in APK_DIR.glob("eapks*"):
        if "_" in subfolder.name:
            continue
        for file_path in subfolder.glob("*.apk"):
            apk_files.append(os.path.join(subfolder.name, file_path.name))

    _save_pickle(cache_path, apk_files)
    return apk_files


def build_apk_scan_jobs(
    apk_files: Iterable[str],
    pkg2hash: dict[str, str],
    *,
    allowed_hashes: set[str] | None = None,
    seen_hashes: set[str] | None = None,
) -> list[ApkScanJob]:
    """Resolve APK paths to scan jobs, filtering in the parent process."""
    seen = seen_hashes or set()
    queued: set[str] = set()
    jobs: list[ApkScanJob] = []

    for apk_file in apk_files:
        apk_path = Path(apk_file)
        if len(apk_path.parts) != 2 or apk_path.suffix != ".apk":
            continue

        subfolder = apk_path.parts[0]
        md5 = pkg2hash.get(apk_path.stem)
        if not md5 or md5 in seen or md5 in queued:
            continue
        if allowed_hashes is not None and md5 not in allowed_hashes:
            continue

        jobs.append((apk_file, subfolder, md5))
        queued.add(md5)

    return jobs


def load_hash2folder() -> dict[str, str]:
    cache_path = _cache_path("hash2folder.pkl")
    if cached := _load_pickle(cache_path):
        return cached

    hash2folder = {}
    with HASH_FILE.open(newline="") as file:
        reader = csv.reader(file)
        next(reader, None)
        for folder, _, md5 in reader:
            hash2folder[md5] = folder

    _save_pickle(cache_path, hash2folder)
    return hash2folder
