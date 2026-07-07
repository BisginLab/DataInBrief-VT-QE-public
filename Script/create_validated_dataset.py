from __future__ import annotations

import csv

from tqdm import tqdm

from config import DATASET_DIR, PAPER_SUMMARY_DATASET_CSV
from utility import get_reliable_vt_ai_files, load_hash2malicious, load_hash2risk, load_pkg2hash

STATUS_INDEX = 34
THRESHOLDS = range(1, 6)


def create_validated_dataset(threshold: int) -> None:
    reliable_vt_hashes = {file.stem for file in get_reliable_vt_ai_files()}
    pkg2hash = load_pkg2hash()
    hash2risk = load_hash2risk()
    hash2malicious = load_hash2malicious()

    dataset_path = DATASET_DIR / f"val_dataset_t{threshold}.csv"
    dataset_path.parent.mkdir(parents=True, exist_ok=True)

    valid_count = benign_count = malicious_count = 0
    with (
        PAPER_SUMMARY_DATASET_CSV.open(newline="") as paper_summary,
        dataset_path.open("w", newline="") as dataset,
    ):
        reader = csv.reader(paper_summary)
        writer = csv.writer(dataset)
        writer.writerow(next(reader) + ["verdict"])

        for row in tqdm(reader, desc=f"Compiling threshold {threshold}", unit="row"):
            md5_hash = pkg2hash.get(row[1])
            malicious_detections = hash2malicious.get(md5_hash)
            if malicious_detections is None or md5_hash not in hash2risk or md5_hash not in reliable_vt_hashes:
                continue

            valid_count += 1
            benign_by_paper = row[STATUS_INDEX] == "0"
            benign_by_vt = malicious_detections < threshold
            benign_by_qk = hash2risk[md5_hash] == "low"

            if benign_by_paper and benign_by_vt and benign_by_qk:
                benign_count += 1
                writer.writerow(row + ["benign"])
            elif not benign_by_paper and not benign_by_vt and not benign_by_qk:
                malicious_count += 1
                writer.writerow(row + ["malicious"])

    denominator = valid_count or 1
    print(f"Threshold {threshold}: {valid_count} valid files")
    print(f"Definitely benign: {benign_count} ({benign_count / denominator:.3%})")
    print(f"Definitely malicious: {malicious_count} ({malicious_count / denominator:.3%})")


if __name__ == "__main__":
    for threshold in THRESHOLDS:
        create_validated_dataset(threshold)
