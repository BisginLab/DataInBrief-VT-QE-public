from __future__ import annotations

import csv
import random

from config import DATASET_DIR

THRESHOLD = 5
RANDOM_SEED = 2026


def create_balanced_dataset(threshold: int = THRESHOLD) -> None:
    source_path = DATASET_DIR / f"val_dataset_t{threshold}.csv"
    output_path = DATASET_DIR / f"balanced_val_dataset_t{threshold}.csv"

    with source_path.open(newline="") as source:
        reader = csv.reader(source)
        header = next(reader)
        benign_rows = []
        malicious_rows = []
        for row in reader:
            if row[-1] == "benign":
                benign_rows.append(row)
            elif row[-1] == "malicious":
                malicious_rows.append(row)

    sample_size = min(len(benign_rows), len(malicious_rows))
    rng = random.Random(RANDOM_SEED)
    rng.shuffle(benign_rows)
    rng.shuffle(malicious_rows)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(header)
        writer.writerows(benign_rows[:sample_size])
        writer.writerows(malicious_rows[:sample_size])

    print(f"Wrote {sample_size * 2} balanced rows to {output_path}.")


if __name__ == "__main__":
    create_balanced_dataset()
