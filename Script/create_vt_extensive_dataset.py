import os
import csv
import json
from pathlib import Path
from multiprocessing import Pool
from collections import Counter

from tqdm import tqdm
from utility import get_all_vt_ai_files, load_json_path_repair
from config import VT_LIGHTWEIGHT_CSV

OUTPUT_CSV    = VT_LIGHTWEIGHT_CSV
NUM_PROCESSES =  max(1, os.cpu_count() // 2)

vt_files = get_all_vt_ai_files()

# --- Field definitions (name, path‐list, default) ---
FIELDS = [
    ("type_extension",   ["type_extension"],   None),
    ("size",             ["size"],             -1),
    ("reputation",       ["reputation"],       -1),
    ("vhash",            ["vhash"],            None),
    ("first_submission_date",  ["first_submission_date"],  -1),
    ("last_submission_date",   ["last_submission_date"],   -1),
    ("last_modification_date", ["last_modification_date"], -1),
    ("times_submitted",        ["times_submitted"],        -1),
    ("unique_sources",         ["unique_sources"],         -1),
    ("sha256",          ["sha256"],          None),
    ("sha1",            ["sha1"],            None),
    ("md5",             ["md5"],             None),
    ("meaningful_name", ["meaningful_name"], None),

    ("last_analysis_stats.malicious",         ["last_analysis_stats","malicious"],          -1),
    ("last_analysis_stats.suspicious",        ["last_analysis_stats","suspicious"],         -1),
    ("last_analysis_stats.undetected",        ["last_analysis_stats","undetected"],         -1),
    ("last_analysis_stats.harmless",          ["last_analysis_stats","harmless"],           -1),
    ("last_analysis_stats.timeout",           ["last_analysis_stats","timeout"],            -1),
    ("last_analysis_stats.confirmed-timeout", ["last_analysis_stats","confirmed-timeout"], -1),
    ("last_analysis_stats.failure",           ["last_analysis_stats","failure"],            -1),
    ("last_analysis_stats.type-unsupported",  ["last_analysis_stats","type-unsupported"],   -1),

    ("total_votes.harmless",  ["total_votes","harmless"],  -1),
    ("total_votes.malicious", ["total_votes","malicious"], -1),

    ("bundle_info.type",             ["bundle_info","type"],            None),
    ("bundle_info.uncompressed_size",["bundle_info","uncompressed_size"],-1),
    
    ("androguard.Activities",             ["androguard","Activities"],             None),
    ("androguard.AndroidVersionCode",     ["androguard","AndroidVersionCode"],     None),
    ("androguard.AndroidVersionName",     ["androguard","AndroidVersionName"],     None),
    ("androguard.MinSdkVersion",          ["androguard","MinSdkVersion"],          None),
    ("androguard.TargetSdkVersion",       ["androguard","TargetSdkVersion"],       None),
    ("androguard.AndroguardVersion",      ["androguard","AndroguardVersion"],      None),
    ("androguard.AndroidApplication",     ["androguard","AndroidApplication"],     -1),
    ("androguard.AndroidApplicationError",["androguard","AndroidApplicationError"], None),
    ("androguard.main_activity",          ["androguard","main_activity"],          None),

    
    ("androguard.VTAndroidInfo", ["androguard","VTAndroidInfo"], -1),

    ("androguard.certificate.Subject.C",  ["androguard","certificate","Subject","C"],  None),
    ("androguard.certificate.Subject.CN", ["androguard","certificate","Subject","CN"], None),
    ("androguard.certificate.Subject.L",  ["androguard","certificate","Subject","L"],  None),
    ("androguard.certificate.Subject.O",  ["androguard","certificate","Subject","O"],  None),
    ("androguard.certificate.Subject.ST", ["androguard","certificate","Subject","ST"], None),
    ("androguard.certificate.Subject.DN", ["androguard","certificate","Subject","DN"], None),

    ("androguard.certificate.Issuer.C",  ["androguard","certificate","Issuer","C"],  None),
    ("androguard.certificate.Issuer.CN", ["androguard","certificate","Issuer","CN"], None),
    ("androguard.certificate.Issuer.L",  ["androguard","certificate","Issuer","L"],  None),
    ("androguard.certificate.Issuer.O",  ["androguard","certificate","Issuer","O"],  None),
    ("androguard.certificate.Issuer.ST", ["androguard","certificate","Issuer","ST"], None),
    ("androguard.certificate.Issuer.DN", ["androguard","certificate","Issuer","DN"], None),

    ("androguard.certificate.serialnumber", ["androguard","certificate","serialnumber"], None),
    ("androguard.certificate.thumbprint",   ["androguard","certificate","thumbprint"],   None),
    ("androguard.certificate.validfrom",    ["androguard","certificate","validfrom"],    None),
    ("androguard.certificate.validto",      ["androguard","certificate","validto"],      None),
    
    # [Note] Unfortunately, we found that the formats may vary, so we handle RiskIndicator individually as well
    # ("androguard.RiskIndicator.APK_DEX",            ["androguard","RiskIndicator","APK","DEX"],             -1),
    # ("androguard.RiskIndicator.APK_SHARED LIBRARIES",["androguard","RiskIndicator","APK","SHARED LIBRARIES"],-1),
    
    # [Note] We found that not all apps have Unity and some Unity-based apps have UnityPlayerNativeActivity.
    # Therefore, instead of hard-coding the activity like below, we used main_activity to track the source of intents.
    
    # ("androguard.intent_filters.Unity.action[0]",
    #     ["androguard","intent_filters","Activities",
    #      "com.unity3d.player.UnityPlayerProxyActivity","action",0], None),
    # ("androguard.intent_filters.Unity.category[0]",
    #     ["androguard","intent_filters","Activities",
    #      "com.unity3d.player.UnityPlayerProxyActivity","category",0], None),
]

def extract_value(data: dict, path: list, default):
    """
    Safely walk through nested dicts/lists in data following path.
    Returns the found value or default if any step is missing.
    
    return: (found, value)
    """
    curr = data
    for key in path:
        if isinstance(key, int):
            # list index lookup
            if isinstance(curr, list) and len(curr) > key:
                curr = curr[key]
            else:
                return (False, default)
        else:
            # dict key lookup
            if isinstance(curr, dict) and key in curr:
                curr = curr[key]
            else:
                return (False, default)
    return (True, curr)

def process_file(json_path: Path):
    parsed = load_json_path_repair(json_path)
    if parsed is None:
        return None

    attrs = parsed.get("data", {}).get("attributes", {})
    missing = Counter()
    row = []

    for col_name, path, default in FIELDS:
        found, value = extract_value(attrs, path, default)
        if not found:
            missing[col_name] += 1
        row.append(value)
    
    # We manually handled the case with intent_filters and RiskIndicator now
    andro = attrs.get('androguard', {})
    
    # main_activity is the 34th entry
    main_activity = row[33]
    intents = andro.get('intent_filters', {})
    
    launcher_actions = None
    launcher_categories = None
    is_launcher = False
    
    if (
        (act := intents.get('Activities', {}).get(main_activity, {})) or
        (act := intents.get(f'Activities_{main_activity}'))
    ):
        actions = act.get('action', [])
        categories = act.get('category', [])
        
        # Check if the activity represents a launcher program
        if ("android.intent.action.MAIN" in actions and
            ("android.intent.category.LAUNCHER" in categories or  # handheld
            "android.intent.category.LEANBACK_LAUNCHER" in categories)):  # TV
            
            is_launcher = True
            launcher_actions = actions
            launcher_categories = categories
            
    if not is_launcher:
        # Not a launcher program, or the fields are missing
        missing['androguard.intent_filters.Activities.action'] += 1
        missing['androguard.intent_filters.Activities.category'] += 1
        
    row.append(launcher_actions)
    row.append(launcher_categories)
    
    # We retrieve RiskIndicator attributes
    apk_dex = -1
    apk_shared_library = -1
    ri = andro.get('RiskIndicator', {})
    
    # Check nested form
    if apk := ri.get('APK', {}):
        apk_dex = apk.get('DEX', -1)
        apk_shared_library = apk.get('SHARED LIBRARIES', -1)
    else:
        # Check flat form
        apk_dex = ri.get('APK_DEX', -1)
        apk_shared_library = ri.get('APK_SHARED LIBRARIES', -1)
    
    if apk_dex == -1:
        missing['androguard.RiskIndicator.APK_DEX'] += 1
    if apk_shared_library == -1:
        missing['androguard.RiskIndicator.APK_SHARED LIBRARIES'] += 1
        
    row.append(apk_dex)
    row.append(apk_shared_library)
    
    assert len(row) == 55
    
    for i in range(55):
        # Ideally, this will trigger for 3 attributes:
        # launcher_action, launcher_category, and Activities
        if isinstance(row[i], (list, dict)):
            row[i] = json.dumps(row[i], separators=(',', ':'))
            
    well_defined = 1 if not missing else 0
    return row, missing, well_defined

def main():
    missing_counter = Counter()
    well_defined_count = 0
    parse_fail_count = 0

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow([col for col, *_ in FIELDS] +
                        ['androguard.intent_filters.Activities.action',
                         'androguard.intent_filters.Activities.category',
                         'androguard.RiskIndicator.APK_DEX',
                         "androguard.RiskIndicator.APK_SHARED LIBRARIES"])

        with Pool(NUM_PROCESSES) as pool:
            for result in tqdm(
                pool.imap_unordered(process_file, vt_files, chunksize=100),
                total=len(vt_files),
                desc="Processing VT files",
                unit="file",
            ):
                if result is None:
                    parse_fail_count += 1
                    continue

                row, miss_ctr, is_well = result
                writer.writerow(row)
                missing_counter.update(miss_ctr)
                well_defined_count += is_well

    print(f"\nDone. {well_defined_count:,}/{len(vt_files):,} files had all 55 attrs.")
    print(f"Skipped {parse_fail_count:,} files due to parse/repair failure.")
    print("Missing counts per attribute:")
    
    for field, cnt in missing_counter.most_common():
        print(f"  {field}: {cnt}")

if __name__ == "__main__":
    main()
