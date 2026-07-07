from __future__ import annotations

import csv

from config import AGGREGATED_REPORT_CSV
from utility import PAPER_FILE, PAPER_STATUS_INDEX, load_hash2malicious, load_hash2risk, load_pkg2hash


def vt_verdict(malicious_count: int | None) -> str | None:
    if malicious_count is None:
        return None
    if malicious_count == 0:
        return "benign"
    if malicious_count == 1:
        return "borderline"
    return "malicious"


def create_aggregated_report() -> None:
    pkg2hash = load_pkg2hash()
    hash2malicious = load_hash2malicious()
    hash2risk = load_hash2risk()

    AGGREGATED_REPORT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with (
        PAPER_FILE.open(newline="") as paper_file,
        AGGREGATED_REPORT_CSV.open("w", newline="") as report_file,
    ):
        paper_reader = csv.reader((line.replace("\0", "") for line in paper_file))
        next(paper_reader, None)

        writer = csv.DictWriter(
            report_file,
            fieldnames=["md5_hash", "pkg_name", "quark_verdict", "vt_verdict", "paper_verdict"],
        )
        writer.writeheader()

        failed = written = 0
        for row in paper_reader:
            pkg_name = row[1]
            md5_hash = pkg2hash.get(pkg_name)
            if not md5_hash:
                failed += 1
                continue

            verdict = vt_verdict(hash2malicious.get(md5_hash))
            quark_verdict = hash2risk.get(md5_hash)
            if verdict is None or quark_verdict is None:
                failed += 1
                continue

            writer.writerow(
                {
                    "md5_hash": md5_hash,
                    "pkg_name": pkg_name,
                    "quark_verdict": quark_verdict,
                    "vt_verdict": verdict,
                    "paper_verdict": "non-removed" if row[PAPER_STATUS_INDEX] == "0" else "removed",
                }
            )
            written += 1

    print(f"Wrote {written} rows to {AGGREGATED_REPORT_CSV}.")
    print(f"Skipped {failed} rows without complete cross-source data.")


if __name__ == "__main__":
    create_aggregated_report()
