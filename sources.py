import tomllib

import feedparser
import requests

CONFIG_FILE = "feeds.toml"
HEADERS = {"User-Agent": "secdigest/0.1 (personal Discord security news digest)"}


def load_feeds(path=CONFIG_FILE):
    with open(path, "rb") as f:
        config = tomllib.load(f)
    return config["feeds"]


def fetch_feed(url):
    response = requests.get(url, headers=HEADERS, timeout=15)
    response.raise_for_status()
    return feedparser.parse(response.content)


def fetch_all(feeds):
    results = {}
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
        results[name] = parsed
    return results


if __name__ == "__main__":
    feeds = load_feeds()
    results = fetch_all(feeds)
    print()
    for name, parsed in results.items():
        print(f"== {name} ==")
        for entry in parsed.entries[:3]:
            print("  ", entry.get("published", "no date"), "|", entry.get("title", "no title"))