from sources import fetch_all, load_feeds
from store import add_items, load_store, prune, save_store
from sources import fetch_all, fetch_kev, load_feeds

def main():
    kev_items = fetch_kev()
    items = fetch_all(load_feeds()) + kev_items
    store = load_store()
    if kev_items:
        store["kev_cves"] = {
            item["cves"][0]: {"vendor": item["vendor"], "product": item["product"]}
            for item in kev_items
        }
    added = add_items(store, items)
    pruned = prune(store)
    save_store(store)
    print(f"\nFetched {len(items)} items, added {added} new, pruned {pruned} old, store now holds {len(store['items'])}")

if __name__ == "__main__":
    main()