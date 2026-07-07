from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


def run_quark_scan(
    apk_path: Path,
    rule_dir: Path,
    output_dir: Path,
    subfolder: str,
    timeout_seconds: int,
) -> tuple[str, float]:
    """Run Quark-Engine in a subprocess and return status plus elapsed seconds."""
    inline_code = f"""
import json
import os
from quark.report import Report

apk_path = {str(apk_path)!r}
rule_dir = {str(rule_dir)!r}
output_dir = {str(output_dir)!r}
subfolder = {subfolder!r}

report = Report()
report.analysis(apk_path, rule_dir)
json_report = report.get_report("json")
report_path = os.path.join(output_dir, subfolder, json_report["md5"] + ".json")
os.makedirs(os.path.dirname(report_path), exist_ok=True)
with open(report_path, "w") as file:
    json.dump(json_report, file, indent=4)
"""
    started = time.monotonic()
    try:
        subprocess.run([sys.executable, "-c", inline_code], timeout=timeout_seconds, check=True)
        return "scanned", time.monotonic() - started
    except subprocess.TimeoutExpired:
        return "timeout", time.monotonic() - started
    except subprocess.CalledProcessError:
        return "error", time.monotonic() - started
