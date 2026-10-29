import time

from sources import fetch_all, fetch_kev, is_sponsored, load_feeds
from store import add_items, load_store, prune, save_store

SPONSORED_CHECK_DELAY = 1


def mark_sponsored(items, store, feeds):
    markers = {feed["name"]: feed["sponsored_marker"] for feed in feeds if feed.get("sponsored_marker")}
    checked = 0
    for item in items:
        marker = markers.get(item["source"])
        if not marker or item["id"] in store["items"]:
            continue
        item["sponsored"] = is_sponsored(item["link"], marker)
        checked += 1
        time.sleep(SPONSORED_CHECK_DELAY)
    return checked


def main():
    feeds = load_feeds()
    kev_items = fetch_kev()
    items = fetch_all(feeds) + kev_items
    store = load_store()
    if kev_items:
        store["kev_cves"] = {
            item["cves"][0]: {"vendor": item["vendor"], "product": item["product"]}
            for item in kev_items
        }
    checked = mark_sponsored(items, store, feeds)
    added = add_items(store, items)
    pruned = prune(store)
    save_store(store)
    print(f"\nFetched {len(items)} items, checked {checked} pages for sponsorship, "
          f"added {added} new, pruned {pruned} old, store now holds {len(store['items'])}")


if __name__ == "__main__":
    main()