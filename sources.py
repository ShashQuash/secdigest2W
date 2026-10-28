import html
import re

import tomllib
from datetime import datetime, timezone

import feedparser
import requests

CONFIG_FILE = "feeds.toml"
HEADERS = {"User-Agent": "secdigest/0.1 (personal Discord security news digest)"}

TAG_RE = re.compile(r"<[^>]+>")
SPACE_RE = re.compile(r"\s+")
MAX_SUMMARY = 280


def clean_summary(raw):
    text = TAG_RE.sub(" ", raw or "")
    text = html.unescape(text)
    text = SPACE_RE.sub(" ", text).strip()
    text = text.removesuffix("[...]").strip()
    if len(text) > MAX_SUMMARY:
        text = text[:MAX_SUMMARY].rsplit(" ", 1)[0] + "..."
    return text

def load_feeds(path=CONFIG_FILE):
    with open(path, "rb") as f:
        config = tomllib.load(f)
    return config["feeds"]


def fetch_feed(url):
    response = requests.get(url, headers=HEADERS, timeout=15)
    response.raise_for_status()
    return feedparser.parse(response.content)


def to_utc(entry):
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed is None:
        return None
    return datetime(*parsed[:6], tzinfo=timezone.utc)


def normalize_entry(entry, feed):
    published = to_utc(entry)
    raw_id = entry.get("id") or entry.get("link")
    return {
        "id": f"{feed['url']}|{raw_id}",
        "title": entry.get("title", "").strip(),
        "link": entry.get("link", ""),
        "summary": clean_summary(entry.get("summary", "")),
        "published": published.isoformat() if published else None,
        "source": feed["name"],
        "language": feed.get("language", "en"),
    }


def fetch_all(feeds):
    items = []
    for feed in feeds:
        name = feed["name"]
        try:
            parsed = fetch_feed(feed["url"])
        except requests.RequestException as error:
            print(f"[ERROR] {name}: {type(error).__name__}: {error}")
            continue
        if parsed.bozo:
            print(f"[WARN] {name}: feed is not perfectly formed ({parsed.bozo_exception})")
        print(f"[OK] {name}: {len(parsed.entries)} items")
        for entry in parsed.entries:
            if not entry.get("link"):
                continue
            items.append(normalize_entry(entry, feed))
    return items


if __name__ == "__main__":
    items = fetch_all(load_feeds())
    unique_ids = {item["id"] for item in items}
    print(f"\nTotal items: {len(items)}, unique ids: {len(unique_ids)}\n")

    shown = set()
    for item in items:
        if item["source"] in shown:
            continue
        shown.add(item["source"])
        print(f"== {item['source']} ==")
        print("  id:       ", item["id"])
        print("  title:    ", item["title"])
        print("  published:", item["published"])
        print("  summary:  ", item["summary"])
        print()