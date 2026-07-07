from __future__ import annotations

import os
from pathlib import Path


def env_path(name: str, default: str | Path) -> Path:
    """Return a path from an environment variable, falling back to default."""
    return Path(os.environ.get(name, default)).expanduser()


def require_env(name: str) -> str:
    """Read a required value from the environment."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} is required.")
    return value


DATA_ROOT = env_path("DIB_DATA_ROOT", "data")

APK_DIR = env_path("APK_DIR", DATA_ROOT / "APKs")
HASH_FILE = env_path("HASH_FILE", DATA_ROOT / "hashes.csv")
PKG_MAP_FILE = env_path("PKG_MAP_FILE", DATA_ROOT / "md5_hashes.csv")
PAPER_FILE = env_path("PAPER_FILE", DATA_ROOT / "corrected_permacts.csv")

VT_JSON_DIR = env_path("VT_JSON_DIR", DATA_ROOT / "virustotal_v3_json")
VT_RELIABLE_JSON_DIR = env_path("VT_RELIABLE_JSON_DIR", VT_JSON_DIR)
VT_FIRST_TIME_BENIGN_DIR = env_path(
    "VT_FIRST_TIME_BENIGN_DIR", DATA_ROOT / "virustotal_first_time_benign_json"
)
VT_LEGACY_JSON_DIR = env_path("VT_LEGACY_JSON_DIR", DATA_ROOT / "virustotal_v2_json")

QUARK_SCAN_DIR = env_path("QUARK_SCAN_DIR", DATA_ROOT / "quark_first_scan_json")
QUARK_RESCAN_DIR = env_path("QUARK_RESCAN_DIR", DATA_ROOT / "quark_rescan_json")
QK_RESCANNED_DIR = env_path("QK_RESCANNED_DIR", QUARK_RESCAN_DIR)
QUARK_RULE_DIR = env_path("QUARK_RULE_DIR", DATA_ROOT / "quark-rules" / "rules")

DATASET_DIR = env_path("DATASET_DIR", DATA_ROOT / "derived")
CACHE_DIR = env_path("CACHE_DIR", DATA_ROOT / "cache")
FIGURE_DIR = env_path("FIGURE_DIR", DATA_ROOT / "figures")

VT_LIGHTWEIGHT_CSV = env_path("VT_LIGHTWEIGHT_CSV", DATASET_DIR / "vt_lightweight.csv")
QK_EXTENSIVE_CSV = env_path("QK_EXTENSIVE_CSV", DATASET_DIR / "qk_extensive_features.csv")
SUMMARY_DATASET_CSV = env_path("SUMMARY_DATASET_CSV", DATASET_DIR / "summary_dataset.csv")
PAPER_SUMMARY_DATASET_CSV = env_path(
    "PAPER_SUMMARY_DATASET_CSV", DATASET_DIR / "paper_summary_dataset.csv"
)
AGGREGATED_REPORT_CSV = env_path("AGGREGATED_REPORT_CSV", DATASET_DIR / "aggregated_report.csv")
