from __future__ import annotations

import asyncio
import csv
import json
from datetime import datetime, timedelta, timezone

import aiofiles
import aiohttp

from config import DATASET_DIR, HASH_FILE, VT_JSON_DIR, require_env

QUOTA_URL = "https://www.virustotal.com/api/v3/users/{id}/overall_quotas"
REPORT_URL = "https://www.virustotal.com/api/v3/files/{id}"
CHECKPOINT_FILE = DATASET_DIR / "virustotal_processed_hashes.txt"
REQUEST_DELAY_SECONDS = 4.32


def next_reset_time() -> datetime:
    """Return the next VirusTotal daily reset window at 00:01 UTC."""
    now = datetime.now(timezone.utc)
    tomorrow = now.date() + timedelta(days=1)
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day, 0, 1, tzinfo=timezone.utc)


async def read_checkpoint() -> set[str]:
    processed = set()
    try:
        async with aiofiles.open(CHECKPOINT_FILE, mode="r") as file:
            async for line in file:
                processed.add(line.strip())
    except FileNotFoundError:
        pass
    return processed


async def write_checkpoint(md5: str) -> None:
    CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(CHECKPOINT_FILE, mode="a") as file:
        await file.write(f"{md5}\n")


async def save_json_report(report: dict, folder: str, md5: str) -> None:
    folder_path = VT_JSON_DIR / folder
    folder_path.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(folder_path / f"{md5}.json", mode="w") as file:
        await file.write(json.dumps(report))


async def wait_for_quota(session: aiohttp.ClientSession, api_key: str) -> None:
    async with session.get(QUOTA_URL.format(id=api_key)) as response:
        quota_data = await response.json()
    daily_quota = quota_data["data"]["api_requests_daily"]["user"]
    if daily_quota["used"] < daily_quota["allowed"]:
        return

    reset_dt = next_reset_time()
    sleep_seconds = (reset_dt - datetime.now(timezone.utc)).total_seconds()
    if sleep_seconds > 0:
        print(f"[I] Daily quota reached. Sleeping {sleep_seconds:.0f}s until {reset_dt.isoformat()}.")
        await asyncio.sleep(sleep_seconds)


async def fetch_report(session: aiohttp.ClientSession, md5: str) -> dict | None:
    async with session.get(REPORT_URL.format(id=md5)) as response:
        if response.status != 200:
            print(f"[E] HTTP {response.status} for {md5}")
            return None
        report = await response.json()

    if "error" not in report:
        return report

    code = report["error"].get("code", "Unknown")
    message = report["error"].get("message", "")
    print(f"[E] VirusTotal returned {code} for {md5}: {message}")
    return None


async def process_hash(session: aiohttp.ClientSession, folder: str, md5: str, api_key: str) -> bool:
    await wait_for_quota(session, api_key)
    report = await fetch_report(session, md5)
    if report is None:
        return False
    await save_json_report(report, folder, md5)
    print(f"[S] Saved {md5}")
    return True


async def read_and_process() -> None:
    api_key = require_env("VT_API_KEY")
    processed = await read_checkpoint()
    async with aiofiles.open(HASH_FILE, mode="r") as file:
        lines = await file.read()

    rows = lines.splitlines()
    reader = csv.DictReader(rows)
    if not reader.fieldnames or not {"folder", "filename", "md5"}.issubset(reader.fieldnames):
        reader = csv.DictReader(rows, fieldnames=["folder", "filename", "md5"])

    async with aiohttp.ClientSession(headers={"x-apikey": api_key}) as session:
        for index, row in enumerate(reader, start=1):
            folder = row["folder"]
            md5 = row["md5"]
            filename = row["filename"]

            if md5 in processed:
                print(f"[I] Skipping {md5}")
                continue

            print(f"[P] Row {index}: {filename} ({md5})")
            if await process_hash(session, folder, md5, api_key):
                await write_checkpoint(md5)
                processed.add(md5)

            await asyncio.sleep(REQUEST_DELAY_SECONDS)


if __name__ == "__main__":
    asyncio.run(read_and_process())
