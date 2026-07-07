# VirusTotal and Quark-Engine Enrichment for an Android Application Dataset

This repository contains the Python source code used to collect VirusTotal metadata, run Quark-Engine analysis, merge the resulting features, and create validated Android application dataset subsets for the associated Data in Brief submission:

**Validated and Enriched Android Application Dataset: Integration of VirusTotal and Quark-Engine Intelligence**

Associated dataset DOI: <https://doi.org/10.34894/XV84Z8>

Tagged source-code release: <https://github.com/BisginLab/DataInBrief-VT-QE-public/releases/tag/v1.0.0-dib-source>

## Repository Contents

| Path | Purpose |
| --- | --- |
| `Script/config.py` | Central path and environment-variable configuration |
| `Script/utility.py` | Shared JSON parsing, cache, and mapping helpers |
| `Script/calculate_hash.py` | Compute APK MD5 hashes |
| `Script/submit_to_virustotal.py` | Download VirusTotal v3 reports from hashes |
| `Script/quark_files.py` | Run the first Quark-Engine scan |
| `Script/qk_rescan.py` | Rescan APKs missing from the first Quark-Engine pass |
| `Script/create_vt_extensive_dataset.py` | Create `vt_lightweight.csv` |
| `Script/create_qk_extensive_dataset.py` | Create `qk_extensive_features.csv` |
| `Script/create_summary_dataset.py` | Merge VirusTotal and Quark-Engine summary features |
| `Script/create_paper_summary_dataset.py` | Merge summary features with the paper replication manifest |
| `Script/create_validated_dataset.py` | Create thresholded validated datasets |
| `Script/create_balanced_dataset.py` | Optionally create a balanced subset |
| `Script/compute_summary_stats.py` | Report extraction completeness statistics |
| `Script/qk_vt_cs_create_file.py` | Create cross-source comparison table |
| `Script/qk_vt_cs_visualize.py` | Create cross-source contingency heatmaps |
| `*_columns.txt` | Column dictionaries for released CSV files |

Generated CSVs, JSON responses, figures, checkpoints, pickles, and local credentials are intentionally excluded from source control.

## Configuration

Create an environment from `requirements.txt`, then set paths and secrets with environment variables. A template is provided in `.env.example`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Set VT_API_KEY in your shell before running the VirusTotal collection script.
export DIB_DATA_ROOT="/path/to/data"
export APK_DIR="/path/to/APKs"
export HASH_FILE="/path/to/hashes.csv"
export PKG_MAP_FILE="/path/to/md5_hashes.csv"
export PAPER_FILE="/path/to/corrected_permacts.csv"
```

No API keys are stored in this repository. `VT_API_KEY` is required only for VirusTotal collection.

## Reproduction Pipeline

Run scripts from the repository root.

```bash
# 1. APK hashes
python3 Script/calculate_hash.py

# 2. VirusTotal collection
python3 Script/submit_to_virustotal.py

# 3. Quark-Engine collection
python3 Script/quark_files.py
python3 Script/qk_rescan.py

# 4. Feature extraction
python3 Script/create_vt_extensive_dataset.py
python3 Script/create_qk_extensive_dataset.py
python3 Script/create_summary_dataset.py

# 5. Paper-level and validated datasets
python3 Script/create_paper_summary_dataset.py
python3 Script/create_validated_dataset.py
python3 Script/create_balanced_dataset.py

# 6. Quality checks and comparison figures
python3 Script/compute_summary_stats.py
python3 Script/qk_vt_cs_create_file.py
python3 Script/qk_vt_cs_visualize.py
```

## Key Outputs

| Output | Description |
| --- | --- |
| `vt_lightweight.csv` | VirusTotal metadata and analysis features |
| `qk_extensive_features.csv` | Quark-Engine features |
| `summary_dataset.csv` | Shared VirusTotal and Quark-Engine summary features |
| `paper_summary_dataset.csv` | Paper manifest plus enrichment features |
| `val_dataset_t1.csv` ... `val_dataset_t5.csv` | Validated datasets by VirusTotal threshold |
| `balanced_val_dataset_t5.csv` | Optional balanced dataset |
| `aggregated_report.csv` | Cross-source comparison table |

Column dictionaries for released CSV files are tracked at the repository root.

## Data in Brief Release Notes

For Data in Brief, publish the dataset in a repository with a persistent identifier and cite both the dataset DOI and a tagged source-code release. After pushing this repository to GitHub, archive the tagged release with Zenodo or another DOI-providing repository. Add the resulting source-code DOI to `CITATION.cff`, and cite the code in the article's Specifications Table/Data Accessibility section and reference list.

Credentials exposed during earlier development should remain revoked or rotated. This public repository was recreated from the cleaned source tree so that the release history does not contain those credentials.

## Licenses

Source code is released under the MIT License. See `LICENSE`.

Released datasets, column dictionaries, and non-code documentation are released under CC BY 4.0. See `LICENSE-DATA.md`.
