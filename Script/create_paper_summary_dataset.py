from __future__ import annotations

import csv

import pandas as pd
from tqdm import tqdm

from config import PAPER_SUMMARY_DATASET_CSV, SUMMARY_DATASET_CSV
from utility import PAPER_FILE, load_pkg2hash


def create_paper_summary_dataset() -> None:
    pkg2hash = load_pkg2hash()

    hash2features = {}
    with SUMMARY_DATASET_CSV.open(newline="") as file:
        summary_reader = csv.reader(file)
        summary_header = next(summary_reader)
        for row in summary_reader:
            hash2features[row[0]] = row[1:]

    PAPER_SUMMARY_DATASET_CSV.parent.mkdir(parents=True, exist_ok=True)
    with (
        PAPER_SUMMARY_DATASET_CSV.open("w", newline="") as ps_file,
        PAPER_FILE.open(newline="") as paper_file,
    ):
        ps_writer = csv.writer(ps_file)
        paper_reader = csv.reader((line.replace("\0", "") for line in paper_file))

        paper_header = next(paper_reader)
        ps_writer.writerow(paper_header + summary_header[1:])

        row_count = match_count = 1
        for row in tqdm(paper_reader, desc="Merging paper and summary rows"):
            row_count += 1
            pkg_name = row[1]
            hash_value = pkg2hash.get(pkg_name)
            if hash_value and (features := hash2features.get(hash_value)):
                match_count += 1
                ps_writer.writerow(row + features)

    ps_dataset = pd.read_csv(PAPER_SUMMARY_DATASET_CSV)
    print(f"All {row_count} rows have been processed.")
    print(f"Created CSV file with {match_count} rows.")
    print(f"Number of rows: {len(ps_dataset)}")
    print(f"Number of columns: {len(ps_dataset.columns)}")


if __name__ == "__main__":
    create_paper_summary_dataset()
