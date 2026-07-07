from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

from config import APK_DIR, HASH_FILE


def calculate_md5(file_path: Path) -> str:
    hash_md5 = hashlib.md5()
    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def load_processed_files(csv_file: Path) -> set[tuple[str, str]]:
    if not csv_file.exists() or csv_file.stat().st_size == 0:
        return set()

    with csv_file.open(newline="") as file:
        reader = csv.DictReader(file)
        return {(row["folder"], row["filename"]) for row in reader}


def process_apks(base_dir: Path, output_csv: Path) -> None:
    processed_files = load_processed_files(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    with output_csv.open("a", newline="") as csvfile:
        fieldnames = ["folder", "filename", "md5"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if output_csv.stat().st_size == 0:
            writer.writeheader()

        for apk_file in sorted(base_dir.glob("eapks*/*.apk")):
            folder = apk_file.parent.name
            filename = apk_file.name
            if (folder, filename) in processed_files:
                continue

            try:
                md5_hash = calculate_md5(apk_file)
            except OSError as exc:
                print(f"[E] Could not read {apk_file}: {exc}")
                continue

            writer.writerow({"folder": folder, "filename": filename, "md5": md5_hash})
            processed_files.add((folder, filename))
            print(f"[S] Processed {folder}/{filename}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute MD5 hashes for APK files.")
    parser.add_argument("--apk-dir", type=Path, default=APK_DIR)
    parser.add_argument("--output-csv", type=Path, default=HASH_FILE)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    process_apks(args.apk_dir, args.output_csv)
