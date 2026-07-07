from __future__ import annotations

import multiprocessing as mp
import sys
from pathlib import Path

from config import APK_DIR, QUARK_RULE_DIR, QUARK_SCAN_DIR
from quark_runner import run_quark_scan
from utility import load_apk_files, load_pkg2hash

CHECKPOINT_FILE = QUARK_SCAN_DIR / "quark_checkpoint.txt"
TIMEOUT_FILE = QUARK_SCAN_DIR / "quark_timeout.txt"
ERROR_FILE = QUARK_SCAN_DIR / "quark_error.txt"
TIMEOUT_SECONDS = 90

pkg2hash: dict[str, str] = {}
seen: set[str] = set()


def _hash_for_apk(apk_file: str) -> tuple[str, str, str] | None:
    try:
        subfolder, pkg_name = apk_file.removesuffix(".apk").split("/", 1)
    except ValueError:
        return None

    md5 = pkg2hash.get(pkg_name)
    return (subfolder, pkg_name, md5) if md5 else None


def process_apk(apk_file: str) -> tuple[str, str, float] | None:
    apk_info = _hash_for_apk(apk_file)
    if apk_info is None:
        return None

    subfolder, _, md5 = apk_info
    if md5 in seen:
        return None

    status, elapsed = run_quark_scan(
        APK_DIR / apk_file,
        QUARK_RULE_DIR,
        QUARK_SCAN_DIR,
        subfolder,
        TIMEOUT_SECONDS,
    )
    return md5, status, elapsed


def main() -> None:
    global pkg2hash, seen
    pkg2hash = load_pkg2hash()
    seen = set(CHECKPOINT_FILE.read_text().splitlines()) if CHECKPOINT_FILE.exists() else set()

    QUARK_SCAN_DIR.mkdir(parents=True, exist_ok=True)
    scanned = timeouts = errors = 0
    workers = max(1, (mp.cpu_count() or 1) // 2)

    with mp.Pool(processes=workers) as pool:
        try:
            for result in pool.imap_unordered(process_apk, load_apk_files()):
                if result is None:
                    continue

                md5, status, elapsed = result
                seen.add(md5)
                with CHECKPOINT_FILE.open("a") as file:
                    file.write(f"{md5}\n")

                if status == "scanned":
                    scanned += 1
                    print(f"[S] {md5} scanned")
                elif status == "timeout":
                    timeouts += 1
                    with TIMEOUT_FILE.open("a") as file:
                        file.write(f"{md5},{elapsed:.3f}\n")
                    print(f"[T] {md5} timed out")
                else:
                    errors += 1
                    with ERROR_FILE.open("a") as file:
                        file.write(f"{md5},{elapsed:.3f}\n")
                    print(f"[E] {md5} failed")
        except KeyboardInterrupt:
            pool.terminate()
            pool.join()
            sys.exit(1)

    print(f"[Summary] Scanned: {scanned}; Timeouts: {timeouts}; Errors: {errors}")


if __name__ == "__main__":
    main()
