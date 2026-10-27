import feedparser
import requests

FEED_URL = "https://www.bleepingcomputer.com/feed/"
HEADERS = {"User-Agent": "secdigest/0.1 (personal Discord security news digest)"}

def fetch_feed(url):
    response = requests.get(url, headers=HEADERS, timeout=15)
    response.raise_for_status()
    return feedparser.parse(response.content)

if __name__ == "__main__":
    feed = fetch_feed(FEED_URL)
    print("Feed title:", feed.feed.get("title"))
    print("Item found:", len(feed.entries))
    print()
    for entry in feed.entries[:5]:
        print(entry.get("published", "no date"), "|", entry.get("title", "no title"))
        print("     id:", entry.get("id", "no id"))
