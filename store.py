import json
import os
from datetime import datetime, timedelta, timezone

store_file = "store.json"
keep_days = 14

def empty_store():
    return {"last_digest": None, "kev_cves": [], "items": {}}

def load_store(path=store_file):
    if not os.path.exists(path):
        return empty_store()
    with open(path, "r", encoding = "utf-8") as f:
        return json.load(f)

def save_store(store, path=store_file):
    temp_path = path+".temp"
    with open(temp_path, "w", encoding= "utf-8") as f:
        json.dump(store, f, ensure_ascii = False, indent=2)
    os.replace(temp_path, path)

def add_items(store, items, now = None):
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=keep_days)
    added = 0
    for item in items:
        if item["id"] in store["items"]:
            continue
        if item["published"] is None:
            continue
        if datetime.fromisoformat(item["published"]) < cutoff:
            continue
        store["items"][item["id"]] = {**item, "first_seen": now.isoformat()}
        added += 1
    return added
def prune(store, now=None):
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=keep_days)
    old_ids = [
        item_id
        for item_id, item in store["items"].items()
        if datetime.fromisoformat(item["published"]) < cutoff               
    ]
    for item_id in old_ids:
        del store["items"][item_id]
    return len(old_ids)