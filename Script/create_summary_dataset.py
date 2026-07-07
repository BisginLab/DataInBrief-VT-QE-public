from __future__ import annotations

import csv
import multiprocessing as mp
from datetime import datetime
from pathlib import Path

from tqdm import tqdm

from config import QK_RESCANNED_DIR, SUMMARY_DATASET_CSV
from utility import JSONParseError, get_all_vt_ai_files, get_qk_files, load_json_path_repair

FEATURES = (
    "md5",
    "malicious_count",
    "undetected_count",
    "certificate_life_days",
    "file_duration_days",
    "times_submitted",
    "threat_level",
    "aggregated_risk_score",
    "weighted_conf_sum",
    "permission_n",
    "avg_weight",
)


def parse_cert_date(value: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%I:%M %p %m/%d/%Y"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unknown certificate date format: {value!r}")


def preferred_qk_file(qk_file: Path) -> Path:
    rescanned = QK_RESCANNED_DIR / "/".join(qk_file.parts[-2:])
    return rescanned if rescanned.exists() else qk_file


def parse_confidence(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return float(value.rstrip("%")) / 100
    except ValueError:
        return 0.0


def process_pair(args: tuple[tuple[Path, Path], int]) -> tuple[str, list | str]:
    (vt_file, qk_file), _ = args
    vt_res = load_json_path_repair(vt_file)
    qk_res = load_json_path_repair(preferred_qk_file(qk_file))

    try:
        if vt_res is None:
            raise JSONParseError(f"VirusTotal file {vt_file.name} failed to load", "vt_json", vt_file)
        if qk_res is None:
            raise JSONParseError(f"Quark-Engine file {qk_file.name} failed to load", "qk_json", qk_file)

        attrs = vt_res.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", -1)
        undetected_count = stats.get("undetected", -1)

        cert = attrs.get("androguard", {}).get("certificate", {})
        valid_from = cert.get("validfrom")
        valid_to = cert.get("validto")
        certificate_life_days = (
            (parse_cert_date(valid_to) - parse_cert_date(valid_from)).days
            if valid_from and valid_to
            else -1
        )

        first_ts = attrs.get("first_submission_date")
        last_ts = attrs.get("last_analysis_date")
        file_duration_days = (
            (datetime.fromtimestamp(last_ts) - datetime.fromtimestamp(first_ts)).days
            if first_ts is not None and last_ts is not None
            else -1
        )

        weighted_conf_sum = 0.0
        weights = []
        permission_n = 0
        for crime in qk_res.get("crimes", []):
            if not isinstance(crime, dict):
                continue
            weight = crime.get("weight")
            if isinstance(weight, (int, float)):
                weights.append(weight)
                weighted_conf_sum += weight * parse_confidence(crime.get("confidence"))
            if crime.get("permissions"):
                permission_n += 1

        avg_weight = sum(weights) / len(weights) if weights else -1
        return (
            "SUCCESS",
            [
                qk_res.get("md5"),
                malicious_count,
                undetected_count,
                certificate_life_days,
                file_duration_days,
                attrs.get("times_submitted", -1),
                qk_res.get("threat_level", -1),
                qk_res.get("total_score", -1),
                weighted_conf_sum,
                permission_n,
                avg_weight,
            ],
        )
    except JSONParseError as exc:
        return ("JSON_ERROR", exc.err_feature)


def common_file_pairs() -> set[tuple[Path, Path]]:
    vt_files = {path.stem: path for path in get_all_vt_ai_files()}
    qk_files = {path.stem: path for path in get_qk_files()}
    common_hashes = vt_files.keys() & qk_files.keys()

    print(f"There are {len(vt_files)} VirusTotal v3 responses.")
    print(f"There are {len(qk_files)} Quark-Engine responses.")
    print(f"There are {len(common_hashes)} common files.")

    return {(vt_files[hash_value], qk_files[hash_value]) for hash_value in common_hashes}


def create_csv() -> None:
    pairs = common_file_pairs()
    SUMMARY_DATASET_CSV.parent.mkdir(parents=True, exist_ok=True)

    correct_file_n = 0
    with (
        mp.Pool(processes=min(16, mp.cpu_count() or 1)) as pool,
        SUMMARY_DATASET_CSV.open("w", newline="") as csvfile,
    ):
        writer = csv.writer(csvfile)
        writer.writerow(FEATURES)

        tasks = [(file_pair, index) for index, file_pair in enumerate(pairs, start=1)]
        results = pool.imap_unordered(process_pair, tasks)
        for status, payload in tqdm(results, total=len(tasks), desc="Processing files"):
            if status == "SUCCESS":
                correct_file_n += 1
                writer.writerow(payload)

    total = len(pairs) or 1
    print(f"Processed {len(pairs)} common files.")
    print(f"Created {correct_file_n} rows.")
    print(f"Error rate: {(1 - correct_file_n / total):.4%}")


if __name__ == "__main__":
    create_csv()
