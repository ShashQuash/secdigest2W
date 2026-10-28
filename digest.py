import re
from collections import Counter

from store import load_store

REPORTED_WORDS = ["exploited", "exploiting", "in the wild", "zero-day", "0-day", "ausgenutzt"]
AVAILABLE_WORDS = ["proof-of-concept", "proof of concept", "poc", "exploit code", "public exploit"]

CATEGORIES = {
    "breach": ["breach", "breaches", "data leak", "leaked", "stolen", "steal", "steals",
               "stealing", "ransomware", "datenleck", "datenpanne", "cyberangriff"],
    "vulnerability": ["flaw", "flaws", "vulnerability", "vulnerabilities", "cve",
                      "schwachstelle", "schwachstellen", "sicherheitslücke", "sicherheitslücken",
                      "lücke", "lücken", "leck",
                      "angreifer können", "angreifer könnten",
                      "could allow an attacker", "could allow attackers",
                      "allows an attacker", "allows attackers",
                      "allow an attacker", "allow attackers"],
    "ai": ["ai", "llm", "llms", "chatgpt", "openai", "copilot", "gemini",
           "prompt injection", "deepfake", "ki"],
    "regulation": ["nis2", "nis-2", "cyber resilience act", "cra", "gdpr", "dsgvo",
                   "ai act", "dora", "enisa", "regulation", "directive", "richtlinie"],
    "patch": ["patch", "patches", "patched", "fix", "fixes", "fixed", "update", "updates",
              "patchday", "sicherheitsupdate", "stopft", "aktualisieren"],
    "threats": ["phishing", "malware", "campaign", "campaigns", "hijack", "hijacks", "hijacked",
                "botnet", "spyware", "infostealer", "backdoor", "seizes", "seized"],
}


def build_pattern(words):
    return re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b", re.IGNORECASE)


REPORTED_RE = build_pattern(REPORTED_WORDS)
AVAILABLE_RE = build_pattern(AVAILABLE_WORDS)
PATTERNS = {name: build_pattern(words) for name, words in CATEGORIES.items()}

SKIP_TITLE_RE = re.compile(
    r"^CISA Adds .+ Known Exploited Vulnerabilit|^\W*Passwort\W* Folge \d+",
    re.IGNORECASE,
)


def is_noise(item):
    return bool(SKIP_TITLE_RE.search(item["title"]))

def item_text(item):
    return f"{item['title']} {item['summary']}"


def exploit_level(item, kev_cves):
    if "kev" in item["tags"] or set(item["cves"]) & kev_cves:
        return "exploit_confirmed"
    text = item_text(item)
    if REPORTED_RE.search(text):
        return "exploit_reported"
    if AVAILABLE_RE.search(text):
        return "exploit_available"
    return None


def categorize(item, kev_cves):
    tags = set(item["tags"])
    level = exploit_level(item, kev_cves)
    if level:
        tags.add(level)
    text = item_text(item)
    for name, pattern in PATTERNS.items():
        if pattern.search(text):
            tags.add(name)
    return tags


if __name__ == "__main__":
    store = load_store()
    kev_cves = set(store["kev_cves"])
    all_items = list(store["items"].values())
    items = [item for item in all_items if not is_noise(item)]
    print(f"Skipped {len(all_items) - len(items)} noise items")
    tagged = [(item, categorize(item, kev_cves)) for item in items]

    counts = Counter(tag for _, tags in tagged for tag in tags)
    print("Tag counts:", dict(counts))
    print("Untagged:", sum(1 for _, tags in tagged if not tags), "of", len(items))

    print("\n-- News promoted to confirmed via KEV match --")
    for item, tags in tagged:
        if "exploit_confirmed" in tags and item["source"] != "CISA KEV":
            matched = sorted(set(item["cves"]) & kev_cves)
            print(f"   [{item['source']}] {item['title'][:70]}  {matched}")

    print("\n-- 8 untagged titles --")
    for item, tags in [t for t in tagged if not t[1]][:8]:
        print("  ", item["title"])