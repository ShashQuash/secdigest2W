import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from sources import load_feeds

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

WORD_RE = re.compile(r"[a-zA-ZäöüÄÖÜß0-9]+")
STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "into", "over", "after",
    "new", "now", "more", "than", "how", "why", "what", "its", "can", "but", "via",
    "der", "die", "das", "und", "für", "mit", "auf", "bei", "von", "aus", "wieder",
    "auch", "nicht", "sondern", "nur", "version", "ist", "ins", "über",
}
GENERIC_WORDS = {
    "million", "data", "users", "user", "attack", "attacks", "attacker", "attackers",
    "hacker", "hackers", "hacking", "using", "used", "uses", "could", "other", "days",
    "public", "online", "found", "exposed", "researchers", "security", "critical",
    "gets", "web", "cvss", "cisa", "warns", "urges", "two", "five", "four",
    "sicherheit", "angreifer", "angriffe",
}
CATEGORY_WORDS = (
    {w for words in CATEGORIES.values() for w in words}
    | set(REPORTED_WORDS)
    | set(AVAILABLE_WORDS)
)
MAX_TITLES_FOR_RARE = 3
MIN_SHARED_RARE = 2
MIN_NAME_TOKEN_LEN = 5

FIRST_DIGEST_DAYS = 4
BACKLOG_SLACK_DAYS = 3


def select_new(items, last_digest, now=None):
    now = now or datetime.now(timezone.utc)
    if last_digest:
        since = datetime.fromisoformat(last_digest)
        oldest_allowed = since - timedelta(days=BACKLOG_SLACK_DAYS)
    else:
        since = now - timedelta(days=FIRST_DIGEST_DAYS)
        oldest_allowed = since
    return [
        item for item in items
        if datetime.fromisoformat(item["first_seen"]) > since
        and datetime.fromisoformat(item["published"]) > oldest_allowed
    ]

SECTIONS = [
    ("exploit_confirmed", "✅ Known exploited (CISA KEV)"),
    ("exploit_reported", "⚠️ Reported exploited"),
    ("breach", "🔓 Breaches & ransomware"),
    ("regulation", "📜 EU & German regulation"),
    ("ai", "🤖 AI security"),
    ("vulnerability", "🐛 Vulnerabilities"),
    ("patch", "🩹 Patches"),
    ("threats", "🎣 Threats & campaigns"),
]
SECTION_ORDER = {key: n for n, (key, _) in enumerate(SECTIONS)}
def section_rank(section):
    if section is None:
        return len(SECTIONS)
    return SECTION_ORDER[section]

def pick_section(tags):
    tags = set(tags)
    if tags & {"exploit_component", "exploit_available"}:
        tags.add("vulnerability")
    return next((key for key, _ in SECTIONS if key in tags), None)

def build_entry(group, kev_cves, source_rank):
    item_tags = [categorize(item, kev_cves) for item in group]
    all_tags = set().union(*item_tags)
    section = pick_section(all_tags)

    def lead_rank(pair):
        item, tags = pair
        own_section = pick_section(tags)
        return (
            section_rank(own_section),
            item["language"] != "en",
            source_rank.get(item["source"], 99),
        )

    ordered = [item for item, _ in sorted(zip(group, item_tags), key=lead_rank)]
    return {"section": section, "lead": ordered[0], "others": ordered[1:], "tags": all_tags, "size": len(group)}

def title_words(item):
    words = {w.lower() for w in WORD_RE.findall(item["title"])}
    words = {w for w in words if len(w) >= 3 and not w.isdigit()}
    return words - STOPWORDS - GENERIC_WORDS - CATEGORY_WORDS


def rare_words(items):
    counts = Counter(word for item in items for word in title_words(item))
    return {word for word, n in counts.items() if n <= MAX_TITLES_FOR_RARE}

def name_tokens(item):
    words = {w.lower() for w in WORD_RE.findall(item["title"])}
    return {
        w for w in words
        if len(w) >= MIN_NAME_TOKEN_LEN
        and any(c.isdigit() for c in w)
        and any(c.isalpha() for c in w)
    }


def same_story_by_name(a, b, names_a, names_b):
    if not (names_a & names_b):
        return False
    gap = abs(datetime.fromisoformat(a["published"]) - datetime.fromisoformat(b["published"]))
    return gap <= timedelta(days=3)

def is_noise(item):
    return bool(SKIP_TITLE_RE.search(item["title"]))

def item_text(item):
    return f"{item['title']} {item['summary']}"


def mentions_product(item, info):
    text = item["title"].lower()
    return any(name and name.lower() in text for name in (info["vendor"], info["product"]))


def exploit_level(item, kev_cves):
    if "kev" in item["tags"]:
        return "exploit_confirmed"
    matched = [kev_cves[cve] for cve in item["cves"] if cve in kev_cves]
    if any(mentions_product(item, info) for info in matched):
        return "exploit_confirmed"
    text = item_text(item)
    if REPORTED_RE.search(text):
        return "exploit_reported"
    if matched:
        return "exploit_component"
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

def same_story_by_cves(a, b):
    cves_a, cves_b = set(a["cves"]), set(b["cves"])
    if not cves_a or not cves_b:
        return False
    return len(cves_a & cves_b) / len(cves_a | cves_b) >= 0.5


def same_story_by_words(a, b, words_a, words_b, rare):
    if a["source"] == b["source"]:
        return False
    if len(words_a & words_b & rare) < MIN_SHARED_RARE:
        return False
    gap = abs(datetime.fromisoformat(a["published"]) - datetime.fromisoformat(b["published"]))
    return gap <= timedelta(days=3)


def group_items(items):
    captain = list(range(len(items)))

    def find(i):
        while captain[i] != i:
            i = captain[i]
        return i

    rare = rare_words(items)
    words = [title_words(item) for item in items]
    names = [name_tokens(item) for item in items]
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            if (same_story_by_cves(a, b)
                    or same_story_by_words(a, b, words[i], words[j], rare)
                    or same_story_by_name(a, b, names[i], names[j])):
                captain[find(j)] = find(i)

    groups = {}
    for index, item in enumerate(items):
        groups.setdefault(find(index), []).append(item)
    return list(groups.values())

if __name__ == "__main__":
    store = load_store()
    kev_cves = store["kev_cves"]
    all_items = list(store["items"].values())
    items = [item for item in all_items if not is_noise(item)]
    print(f"Skipped {len(all_items) - len(items)} noise items")
    tagged = [(item, categorize(item, kev_cves)) for item in items]

    counts = Counter(tag for _, tags in tagged for tag in tags)
    print("Tag counts:", dict(counts))
    print("Untagged:", sum(1 for _, tags in tagged if not tags), "of", len(items))

    print("\n-- News items with a KEV CVE match --")
    for item, tags in tagged:
        if item["source"] == "CISA KEV":
            continue
        matched = [cve for cve in item["cves"] if cve in kev_cves]
        if not matched:
            continue
        level = next(t for t in tags if t.startswith("exploit_"))
        products = sorted({f"{kev_cves[c]['vendor']} {kev_cves[c]['product']}" for c in matched})
        print(f"   {level:18} [{item['source']}] {item['title'][:50]}  KEV: {products}")

    print("\n-- 8 untagged titles --")
    for item, tags in [t for t in tagged if not t[1]][:8]:
        print("  ", item["title"])

    groups = group_items(items)
    rare = rare_words(items)
    multi = [g for g in groups if len(g) > 1]
    print(f"\n-- {len(items)} items formed {len(groups)} groups, {len(multi)} with more than one item --")
    for group in sorted(multi, key=len, reverse=True):
        print(f"\n   Group of {len(group)}:")
        for item in group:
            print(f"     [{item['source']}] {item['title'][:55]}  cves={len(item['cves'])} rare={sorted(title_words(item) & rare)}")

    print("\n========== DIGEST PREVIEW ==========")
    source_rank = {feed["name"]: n for n, feed in enumerate(load_feeds())}
    new_items = select_new(items, store["last_digest"])
    entries = [build_entry(g, kev_cves, source_rank) for g in group_items(new_items)]
    entries = [e for e in entries if e["section"]]
    print(f"{len(new_items)} new items -> {len(entries)} digest entries")
    for key, title in SECTIONS:
        in_section = [e for e in entries if e["section"] == key]
        if not in_section:
            continue
        print(f"\n{title}  ({len(in_section)})")
        for entry in in_section:
            others = ", ".join(sorted({i["source"] for i in entry["others"]}))
            extra = f"  + {others}" if others else ""
            print(f"   [{entry['lead']['source']}] {entry['lead']['title'][:70]}{extra}")