from __future__ import annotations
from collections import Counter
import multiprocessing as mp
from pathlib import Path
from typing import Dict, Tuple
from tqdm import tqdm

from config import QK_RESCANNED_DIR
from utility import get_all_vt_ai_files, get_qk_files, load_json_path_repair

# ------------------------------ helpers ------------------------------ #

def _prefer_rescanned_qk(qk_file: Path) -> Path:
    if not QK_RESCANNED_DIR:
        return qk_file
    candidate = QK_RESCANNED_DIR / "/".join(qk_file.parts[-2:])
    return candidate if candidate.exists() else qk_file


def _flags_for_pair(vt_file: Path, qk_file: Path) -> Dict[str, bool]:
    """Return boolean flags for JSON failures and missing attributes (existence‑only)."""
    f = {k: False for k in (
        # JSON failures
        "vt_json", "qk_json",
        # VT missingness (existence)
        "attributes", "last_analysis_stats", "certificate",
        "validfrom", "validto", "first_submission_date",
        "last_analysis_date", "times_submitted",
        # Derived VT feature existence
        "certificate_life_days_missing",
        # QK missingness (existence)
        "md5", "threat_level", "total_score",
        "crimes_missing", "weight", "confidence",
        # Derived QK feature existence
        "weighted_conf_sum_missing",
    )}

    vt = load_json_path_repair(vt_file)
    if not isinstance(vt, dict):
        f["vt_json"] = True
        vt = None

    qk = load_json_path_repair(_prefer_rescanned_qk(qk_file))
    if not isinstance(qk, dict):
        f["qk_json"] = True
        qk = None

    # ---- VT checks ----
    if vt is not None:
        attrs = (vt.get("data") or {}).get("attributes")
        if not isinstance(attrs, dict):
            f["attributes"] = True
        else:
            if not isinstance(attrs.get("last_analysis_stats"), dict):
                f["last_analysis_stats"] = True

            cert = ((attrs.get("androguard") or {}).get("certificate"))
            if not isinstance(cert, dict):
                f["certificate"] = True
            else:
                if cert.get("validfrom") is None:
                    f["validfrom"] = True
                if cert.get("validto") is None:
                    f["validto"] = True

            if attrs.get("first_submission_date") is None:
                f["first_submission_date"] = True
            if attrs.get("last_analysis_date") is None:
                f["last_analysis_date"] = True
            if attrs.get("times_submitted") is None:
                f["times_submitted"] = True

            # certificate_life_days exists iff both validfrom & validto exist
            if (not isinstance(cert, dict) or
                cert.get("validfrom") is None or cert.get("validto") is None):
                f["certificate_life_days_missing"] = True

    # ---- QK checks ----
    any_pair_for_weighted_sum = False
    if qk is not None:
        if qk.get("md5") is None:
            f["md5"] = True
        if qk.get("threat_level") is None:
            f["threat_level"] = True
        if qk.get("total_score") is None:
            f["total_score"] = True

        crimes = qk.get("crimes")
        if not isinstance(crimes, list) or len(crimes) == 0:
            f["crimes_missing"] = True
        else:
            saw_any_weight = False
            for c in crimes:
                if not isinstance(c, dict):
                    continue
                w_present = (c.get("weight") is not None)
                c_present = (c.get("confidence") is not None)
                if not w_present:
                    f["weight"] = True
                else:
                    saw_any_weight = True
                if not c_present:
                    f["confidence"] = True
                if w_present and c_present:
                    any_pair_for_weighted_sum = True
            if not saw_any_weight:
                # no crime provides a weight → avg_weight not derivable (signaled via `weight`)
                pass

        # weighted_conf_sum exists iff ≥1 crime has BOTH weight & confidence present
        if not any_pair_for_weighted_sum:
            f["weighted_conf_sum_missing"] = True

    return f


def _process(pair: Tuple[Path, Path]) -> Dict[str, bool]:
    vt_file, qk_file = pair
    return _flags_for_pair(vt_file, qk_file)


# ------------------------------- main -------------------------------- #

def main() -> None:
    vt = {p.stem: p for p in get_all_vt_ai_files()}
    qk = {p.stem: p for p in get_qk_files()}
    pairs = [(vt[s], qk[s]) for s in (vt.keys() & qk.keys())]

    print(f"There are {len(vt)} VirusTotal (v3) responses.")
    print(f"There are {len(qk)} Quark‑Engine responses.")
    print(f"There are {len(pairs)} common files.")

    counters: Counter = Counter()
    both_ok = vt5_ok = qk5_ok = all11_ok = 0

    with mp.Pool(processes=min(16, mp.cpu_count() or 1)) as pool:
        for flags in tqdm(pool.imap_unordered(_process, pairs), total=len(pairs), desc="Processing files"):
            counters.update({k: 1 for k, v in flags.items() if v})

            ok_json = not flags["vt_json"] and not flags["qk_json"]
            if ok_json:
                both_ok += 1

            # Existence‑based completeness
            vt_complete = ok_json and not any(flags[k] for k in (
                "attributes", "last_analysis_stats",
                "certificate_life_days_missing",  # proxy for validfrom&validto
                "first_submission_date", "last_analysis_date", "times_submitted",
            ))
            if vt_complete:
                vt5_ok += 1

            qk_complete = ok_json and not any(flags[k] for k in (
                "md5", "threat_level", "total_score",
                "crimes_missing", "weighted_conf_sum_missing",
            ))
            if qk_complete:
                qk5_ok += 1

            if vt_complete and qk_complete:
                all11_ok += 1

    total = len(pairs) or 1
    pct = lambda n: 100.0 * n / total
    pct_ok = lambda n: (100.0 * n / (both_ok or 1))

    # ---- Report ----
    print("\nErrors with parsing JSON files:")
    print(f"Fail to parse VirusTotal response (even after attempting to repair the JSON file): {counters['vt_json']} cases")
    print(f"Fail to parse QuarkEngine response (even after attempting to repair the JSON file): {counters['qk_json']} cases")

    print("\nErrors when extracting VirusTotal attributes:")
    for k, lbl in (
        ("attributes", "Missing attributes field"),
        ("last_analysis_stats", "Missing last_analysis_stats field"),
        ("certificate", "Missing certificate field"),
        ("validfrom", "Missing validfrom field"),
        ("validto", "Missing validto field"),
        ("first_submission_date", "Missing first_submission_date field"),
        ("last_analysis_date", "Missing last_analysis_date field"),
        ("certificate_life_days_missing", "Missing certificate_life_days field"),
    ):
        print(f"{lbl}: {counters[k]} cases")

    print("\nErrors when extracting Quark‑engine attributes:")
    for k, lbl in (
        ("md5", "Missing md5 field"),
        ("threat_level", "Missing threat_level field"),
        ("times_submitted", "Missing times_submitted field"),  # VT‑sourced, kept here per layout
        ("total_score", "Missing total_score field"),
        ("confidence", "Missing confidence field"),
        ("weight", "Missing weight field"),
        ("crimes_missing", "Missing or empty crimes list"),
        ("weighted_conf_sum_missing", "Missing weighted_conf_sum field"),
    ):
        print(f"{lbl}: {counters[k]} cases")

    print("\nCompleteness summary:")
    print(f"Parsed both JSONs successfully: {both_ok} of {total} ({pct(both_ok):.3f}%)")
    print(f"Files with ALL VT 5 features present: {vt5_ok} of {total} ({pct(vt5_ok):.3f}%) | of both‑OK: {pct_ok(vt5_ok):.3f}%")
    print(f"Files with ALL QK 5 features present: {qk5_ok} of {total} ({pct(qk5_ok):.3f}%) | of both‑OK: {pct_ok(qk5_ok):.3f}%")
    print(f"Files with ALL 11 features present: {all11_ok} of {total} ({pct(all11_ok):.3f}%) | of both‑OK: {pct_ok(all11_ok):.3f}%")


if __name__ == "__main__":
    main()
    
