import os
import csv
from pathlib import Path
from multiprocessing import Pool
from collections import Counter

from tqdm import tqdm
from utility import get_qk_files, load_json_path_repair
from config import QK_EXTENSIVE_CSV

OUTPUT_CSV    = QK_EXTENSIVE_CSV
NUM_PROCESSES = max(1, (os.cpu_count() or 1) // 2)
qk_files      = get_qk_files()

# --- Field definitions: simple JSON paths and defaults ---
FIELDS = [
    ("md5",             ["md5"],               ""),
    ("apk_filename",    ["apk_filename"],      ""),
    ("size_bytes",      ["size_bytes"],        -1),
    ("threat_level",    ["threat_level"],      ""),
    ("total_score",     ["total_score"],       -1),
    ("crimes.rule",        ["crimes"],           None),
    ("crimes.crime",       ["crimes"],           None),
    ("crimes.label",       ["crimes"],           None),
    ("crimes.score",       ["crimes"],           None),
    ("crimes.weight",      ["crimes"],           None),
    ("crimes.confidence",  ["crimes"],           None),
    ("crimes.permissions", ["crimes"],           None),
]

def extract_value(data, path, default):
    """
    Safely walk through nested dicts/lists in `data` following `path`.
    Returns the found value or `default` if any step is missing.
    """
    curr = data
    for key in path:
        if isinstance(key, str) and isinstance(curr, dict) and key in curr:
            curr = curr[key]
        else:
            return default
    return curr

def process_file(json_path: Path):
    parsed = load_json_path_repair(json_path)
    if parsed is None:
        return

    attrs = parsed  # top-level JSON object

    row = []
    missing = Counter()

    for name, path, default in FIELDS:
        # flag to mark this field missing once per file
        field_missing = False

        if name.startswith("crimes."):
            subkey = name.split('.')[-1]
            items = []
            crimes_list = attrs.get("crimes", [])
            if not isinstance(crimes_list, list):
                crimes_list = []

            for c in crimes_list:
                # Malformed response could have string as a crime, so check for that
                if isinstance(c, dict):
                    val = c.get(subkey, default)
                else:
                    val = default

                # mark missing if default used (default is None for all crimes.*)
                if val == default:
                    field_missing = True

                # flatten lists and primitives
                if isinstance(val, list):
                    items.append("|".join(str(x) for x in val))
                else:
                    items.append(str(val))

            cell = ";".join(items)
            row.append(cell)
        else:
            val = extract_value(attrs, path, default)
            # mark missing if default used
            if val == default:
                field_missing = True
            row.append(val)

        # count missing once per field per file
        if field_missing:
            missing[name] += 1

    well_defined = 1 if not missing else 0
    return row, missing, well_defined

def main():
    missing_counter = Counter()
    well_defined_count = 0
    parse_fail_count = 0

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline='', encoding='utf-8') as fp:
        writer = csv.writer(fp)
        writer.writerow([name for name, *_ in FIELDS])

        with Pool(NUM_PROCESSES) as pool:
            for result in tqdm(
                pool.imap_unordered(process_file, qk_files, chunksize=100),
                total=len(qk_files),
                desc="Processing QK files",
                unit="file",
            ):
                if result is None:
                    parse_fail_count += 1
                    continue

                row, miss_ctr, is_well = result
                writer.writerow(row)
                missing_counter.update(miss_ctr)
                well_defined_count += is_well

    print(f"\nDone. {well_defined_count:,}/{len(qk_files):,} files had all {len(FIELDS)} fields.")
    print(f"Skipped {parse_fail_count:,} files due to parse/load failure.")
    print("Missing counts per attribute:")
    for field, cnt in missing_counter.most_common():
        print(f"  {field}: {cnt}")

if __name__ == "__main__":
    main()
