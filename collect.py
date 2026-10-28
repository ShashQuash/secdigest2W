from sources import fetch_all, load_feeds
from store import add_items, load_store, prune, save_store

def main():
    items = fetch_all(load_feeds())
    store = load_store()
    added = add_items(store, items)
    pruned = prune(store)
    save_store(store)

    print(f"\nFetched{len(items)} items, added {added} new, pruned {pruned} old, store now holds {len(store['items'])}")

if __name__ == "__main__":
    main()