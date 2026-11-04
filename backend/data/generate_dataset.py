import argparse
import json
import random
import numpy as np
import pandas as pd

SEED = 42
CATEGORIES = [
    "Communication", "Photography", "Finance", "Games", "Productivity",
    "Health & Fitness", "Shopping", "Education", "Music & Audio", "Travel",
]
CATEGORY_PERMISSIONS = {
    "Communication": ["INTERNET", "READ_CONTACTS", "RECORD_AUDIO", "CAMERA", "VIBRATE", "POST_NOTIFICATIONS"],
    "Photography": ["INTERNET", "CAMERA", "READ_MEDIA_IMAGES", "WRITE_EXTERNAL_STORAGE"],
    "Finance": ["INTERNET", "USE_BIOMETRIC", "POST_NOTIFICATIONS", "CAMERA"],
    "Games": ["INTERNET", "VIBRATE", "WAKE_LOCK", "BILLING"],
    "Productivity": ["INTERNET", "READ_MEDIA_IMAGES", "POST_NOTIFICATIONS", "WRITE_EXTERNAL_STORAGE"],
    "Health & Fitness": ["INTERNET", "ACTIVITY_RECOGNITION", "BODY_SENSORS", "ACCESS_FINE_LOCATION"],
    "Shopping": ["INTERNET", "POST_NOTIFICATIONS", "ACCESS_COARSE_LOCATION", "CAMERA"],
    "Education": ["INTERNET", "WRITE_EXTERNAL_STORAGE", "POST_NOTIFICATIONS"],
    "Music & Audio": ["INTERNET", "WAKE_LOCK", "READ_MEDIA_AUDIO", "BLUETOOTH"],
    "Travel": ["INTERNET", "ACCESS_FINE_LOCATION", "CAMERA", "POST_NOTIFICATIONS"],
}
DANGEROUS_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "CALL_PHONE",
    "READ_CONTACTS", "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO",
    "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES",
    "READ_PHONE_STATE", "BIND_ACCESSIBILITY_SERVICE", "RECEIVE_BOOT_COMPLETED",
]
POPULAR_BRANDS = [
    "WhatsApp", "Instagram", "Telegram", "PhonePe", "Paytm", "Google Pay",
    "Netflix", "Spotify", "Amazon", "Flipkart", "Zoom", "TikTok", "Snapchat",
    "PUBG Mobile", "Free Fire", "Truecaller", "Swiggy", "Zomato", "Uber", "Gmail",
]
GENUINE_NAME_PARTS = [
    ("Pixel", "Lens", "Studio", "Craft", "Forge", "Nest", "Loop", "Vault", "Atlas", "Beacon"),
    ("Notes", "Cam", "Pay", "Fit", "Chat", "Store", "Learn", "Tunes", "Trips", "Tasks"),
]
TYPO_MAP = {"a": "@", "i": "1", "o": "0", "l": "I", "e": "3", "s": "5", "m": "rn"}
FAKE_SUFFIXES = ["Pro", "Plus", "Mod", "Premium", "Gold", "VIP", "Free", "Unlocked",
                 "2024", "Latest", "New Version", "Official", "MOD APK"]
SPAM_TOKENS = [
    "free", "unlimited", "hack", "mod", "cracked", "unlocked", "no ads", "100% working",
    "earn money", "cash prize", "instant loan", "double your money", "guaranteed",
    "best app ever", "download now", "click here", "limited offer", "trusted by millions",
    "get rich", "win daily", "no kyc", "fastest approval", "lifetime premium",
]
GENUINE_DESC_TEMPLATES = [
    "{name} helps you {verb} {object} with a clean, distraction-free interface. "
    "Sync across devices, organise your work into projects, and pick up exactly where you left off. "
    "Built-in search finds anything in milliseconds. All data is encrypted in transit and at rest. "
    "We publish a full changelog with every release and never sell user data to third parties.",
    "Manage {object} the simple way. {name} gives you {verb} tools that stay out of your way: "
    "offline access, customisable reminders, and export to standard formats so your data is never locked in. "
    "Accessibility support includes screen reader labels and dynamic text sizing. "
    "Read our privacy policy for details on what we store and why.",
    "{name} is a focused {category} app for people who want to {verb} {object} without clutter. "
    "Features include folder organisation, batch actions, dark mode, and a widget for quick capture. "
    "Optional cloud backup is end-to-end encrypted. Support is handled by a real team, usually within 24 hours.",
]
GENUINE_VERBS = ["track", "organise", "capture", "plan", "edit", "share", "review", "schedule"]
GENUINE_OBJECTS = ["your daily notes", "team projects", "receipts and invoices", "workouts",
                   "photos and albums", "travel itineraries", "study material", "playlists"]
FAKE_DESC_TEMPLATES = [
    "{spam} {brandish} {spam2}!!! Download now and get {spam3}. Best app 2024. {spam4} {spam5}. "
    "No registration required. Works on all devices. {spam6}!!!",
    "{brandish} - {spam} version. {spam2}, {spam3}, {spam4}. Install now!!! "
    "Thousands of users already earning. {spam5}. Hurry limited time offer!!!",
    "{spam} {spam2} {spam3} {spam4} {spam5} {spam6} {brandish} download free apk latest version 2024 working 100%",
]

GENERIC_REVIEWS = [
    "Nice app", "Good app", "Very useful", "Thanks developer", "5 star",
    "Best app", "Working fine", "Please add more features", "Good", "Love it",
    "Awesome app", "Very nice", "Helpful app", "Great work", "Superb",
]
DETAILED_REVIEWS = [
    "Been using this for about eight months now. The offline mode saved me on a flight last week.",
    "Solid app. The last update fixed the sync bug I reported, support actually replied.",
    "Does what it says. Interface takes a day to get used to but then it's fast.",
    "Good value. I'd like a tablet layout but the phone version is well built.",
    "Battery usage is reasonable compared to the alternative I was using before.",
    "Crashed twice on my old Redmi but has been stable since 3.2.1. Dropping a star for that.",
    "The export to CSV is the reason I stayed. Most competitors lock your data in.",
    "Not perfect - search could be smarter - but it's reliable and that matters more to me.",
    "Dark mode is properly done, not just an inverted theme. Big difference at night.",
    "Customer support answered in a day and actually understood the problem.",
    "Sync between my tablet and phone works but takes a few seconds to catch up.",
    "Been through three of these apps, this is the only one that didn't lose my data.",
]
MILD_COMPLAINTS = [
    "Too many ads in the free version", "Keeps logging me out every few days",
    "Was good before the last update, now it lags", "Subscription is overpriced for what you get",
    "Notifications don't always arrive on time", "Wish it had a widget",
]
SCAM_REVIEWS = [
    "Fake app, took my money and did nothing", "This is not the real app, it stole my OTP",
    "Asked for my UPI PIN, dont install", "Downloaded and my phone started showing popups everywhere",
    "Not the official app, be careful", "Charged me without asking, cannot get refund",
]


def _typosquat(brand, rng):
    mode = rng.choice(["char", "suffix", "space", "both"])
    name = brand
    if mode in ("char", "both"):
        chars = list(name)
        idxs = [i for i, c in enumerate(chars) if c.lower() in TYPO_MAP]
        if idxs:
            i = rng.choice(idxs)
            chars[i] = TYPO_MAP[chars[i].lower()]
        name = "".join(chars)
    if mode in ("suffix", "both"):
        name = f"{name} {rng.choice(FAKE_SUFFIXES)}"
    if mode == "space":
        name = name.replace(" ", "") + " " + rng.choice(FAKE_SUFFIXES)
    return name


def _genuine_name(rng):
    a = rng.choice(GENUINE_NAME_PARTS[0]); b = rng.choice(GENUINE_NAME_PARTS[1])
    return f"{a}{b}" if rng.random() < 0.5 else f"{a} {b}"


def _package_name(app_name, rng, fake):
    slug = "".join(ch for ch in app_name.lower() if ch.isalnum())[:14] or "app"
    if fake:
        tld = rng.choice(["com", "net", "xyz", "top", "app"])
        vendor = rng.choice(["freeapps", "modstore", "apkhub", "bestapp", slug])
        return f"{tld}.{vendor}.{slug}{rng.randint(1, 999)}"
    return f"com.{slug}.android"


def _make_genuine(rng, np_rng):
    category = rng.choice(CATEGORIES)
    name = _genuine_name(rng)
    base_perms = CATEGORY_PERMISSIONS[category]
    n_perms = rng.randint(3, min(7, len(base_perms) + 2))
    perms = set(rng.sample(base_perms, min(len(base_perms), max(2, n_perms - 1))))
    perms.add("INTERNET")
    if rng.random() < 0.25:
        perms.add(rng.choice(["READ_EXTERNAL_STORAGE", "CAMERA", "ACCESS_COARSE_LOCATION"]))
    desc = rng.choice(GENUINE_DESC_TEMPLATES).format(
        name=name, verb=rng.choice(GENUINE_VERBS), object=rng.choice(GENUINE_OBJECTS), category=category.lower())
    if rng.random() < 0.35:
        promo = rng.choice([
            " Download now and try Premium free for 30 days!",
            " 100% free to start. Unlock Pro features anytime.",
            " Trusted by millions of users worldwide. Get the latest version today!",
            " Limited offer: annual plan at 40% off. No ads, ever.",
        ])
        desc += promo
    installs = int(10 ** np_rng.uniform(4.0, 8.3))
    rating = float(np.clip(np_rng.normal(4.15, 0.42), 2.6, 5.0))
    rating_count = max(50, int(installs / np_rng.uniform(60, 400)))
    reviews = rng.sample(DETAILED_REVIEWS, k=rng.randint(2, 5))
    reviews += [rng.choice(GENERIC_REVIEWS) for _ in range(rng.randint(1, 4))]
    if rng.random() < 0.55:
        reviews += rng.sample(MILD_COMPLAINTS, k=rng.randint(1, 2))
    rng.shuffle(reviews)
    return dict(
        app_name=name, package_name=_package_name(name, rng, fake=False), category=category,
        description=desc, reviews=" || ".join(reviews), permissions=";".join(sorted(perms)),
        rating=round(rating, 2), rating_count=rating_count, installs=installs,
        size_mb=round(np_rng.uniform(8, 180), 1), price=0.0 if rng.random() < 0.85 else round(np_rng.uniform(0.99, 9.99), 2),
        days_since_update=int(np.clip(np_rng.exponential(70), 1, 900)),
        app_age_days=int(np_rng.uniform(400, 3600)), developer_app_count=rng.randint(2, 40),
        has_developer_website=1, has_privacy_policy=1,
        content_rating=rng.choice(["Everyone", "Teen", "Everyone 10+"]), label=0,
    )


def _make_fake(rng, np_rng):
    category = rng.choice(CATEGORIES)
    impersonates = rng.random() < 0.7
    name = _typosquat(rng.choice(POPULAR_BRANDS), rng) if impersonates \
        else f"{_genuine_name(rng)} {rng.choice(FAKE_SUFFIXES)}"
    n_dangerous = rng.randint(6, 14)
    perms = set(rng.sample(DANGEROUS_PERMISSIONS, n_dangerous))
    perms.add("INTERNET")
    perms |= set(rng.sample(CATEGORY_PERMISSIONS[category], rng.randint(1, 2)))
    spam = rng.sample(SPAM_TOKENS, 6)
    if rng.random() < 0.30:
        desc = rng.choice(GENUINE_DESC_TEMPLATES).format(
            name=name, verb=rng.choice(GENUINE_VERBS), object=rng.choice(GENUINE_OBJECTS),
            category=category.lower()) + f" {spam[0].title()} {spam[1]}!"
    else:
        desc = rng.choice(FAKE_DESC_TEMPLATES).format(
            brandish=name, spam=spam[0], spam2=spam[1], spam3=spam[2], spam4=spam[3], spam5=spam[4], spam6=spam[5])
    installs = int(10 ** np_rng.uniform(2.5, 6.0))
    if rng.random() < 0.65:
        rating = float(np.clip(np_rng.normal(4.85, 0.15), 4.3, 5.0))
        rating_count = max(20, int(installs / np_rng.uniform(2, 25)))
        farm = rng.sample(GENERIC_REVIEWS, k=rng.randint(1, 3))
        reviews = [rng.choice(farm) for _ in range(rng.randint(5, 9))]
        if rng.random() < 0.25:
            reviews.append(rng.choice(DETAILED_REVIEWS))
    else:
        rating = float(np.clip(np_rng.normal(2.3, 0.7), 1.0, 3.4))
        rating_count = max(10, int(installs / np_rng.uniform(20, 200)))
        reviews = rng.sample(SCAM_REVIEWS, k=rng.randint(2, 4))
        reviews += [rng.choice(GENERIC_REVIEWS) for _ in range(rng.randint(1, 3))]
        if rng.random() < 0.4:
            reviews += rng.sample(MILD_COMPLAINTS, k=1)
    return dict(
        app_name=name, package_name=_package_name(name, rng, fake=True), category=category,
        description=desc, reviews=" || ".join(reviews), permissions=";".join(sorted(perms)),
        rating=round(rating, 2), rating_count=rating_count, installs=installs,
        size_mb=round(np_rng.uniform(1.5, 28), 1), price=0.0,
        days_since_update=int(np.clip(np_rng.exponential(200), 1, 1400)),
        app_age_days=int(np_rng.uniform(3, 260)), developer_app_count=rng.randint(1, 3),
        has_developer_website=int(rng.random() < 0.15), has_privacy_policy=int(rng.random() < 0.2),
        content_rating=rng.choice(["Everyone", "Teen", "Mature 17+", "Unrated"]), label=1,
    )


def _make_sophisticated_fake(rng, np_rng):
    row = _make_genuine(rng, np_rng)
    brand = rng.choice(POPULAR_BRANDS)
    row["app_name"] = brand if rng.random() < 0.3 else _typosquat(brand, rng)
    row["package_name"] = _package_name(row["app_name"], rng, fake=rng.random() < 0.5)
    perms = set(row["permissions"].split(";"))
    perms |= set(rng.sample(["READ_SMS", "READ_PHONE_STATE", "GET_ACCOUNTS",
                             "SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES"], rng.randint(1, 3)))
    row["permissions"] = ";".join(sorted(perms))
    row["app_age_days"] = int(np_rng.uniform(60, 700))
    row["developer_app_count"] = rng.randint(1, 6)
    row["rating"] = round(float(np.clip(np_rng.normal(4.5, 0.25), 3.8, 5.0)), 2)
    row["rating_count"] = max(40, int(row["installs"] / np_rng.uniform(25, 90)))
    soph = rng.sample(DETAILED_REVIEWS, k=rng.randint(1, 3))
    farm = rng.sample(GENERIC_REVIEWS, k=rng.randint(2, 3))
    soph += [rng.choice(farm) for _ in range(rng.randint(3, 5))]
    if rng.random() < 0.35:
        soph += rng.sample(SCAM_REVIEWS, k=1)
    rng.shuffle(soph)
    row["reviews"] = " || ".join(soph)
    row["has_privacy_policy"] = int(rng.random() < 0.6)
    row["label"] = 1
    return row


def _make_scruffy_genuine(rng, np_rng):
    row = _make_genuine(rng, np_rng)
    row["developer_app_count"] = rng.randint(1, 2)
    row["has_developer_website"] = int(rng.random() < 0.3)
    row["has_privacy_policy"] = int(rng.random() < 0.5)
    row["app_age_days"] = int(np_rng.uniform(30, 500))
    row["installs"] = int(10 ** np_rng.uniform(2.0, 4.5))
    row["rating"] = round(float(np.clip(np_rng.normal(3.6, 0.6), 2.0, 4.9)), 2)
    row["rating_count"] = max(5, int(row["installs"] / np_rng.uniform(15, 60)))
    row["size_mb"] = round(np_rng.uniform(2.0, 22.0), 1)
    if rng.random() < 0.5:
        row["app_name"] = f"{row['app_name']} {rng.choice(['Free', 'Pro', 'Lite'])}"
        row["description"] = row["description"] + " Free to use, no ads, premium unlock available."
    row["label"] = 0
    return row


def _add_label_noise(df, rate, rng):
    n = int(len(df) * rate)
    idx = rng.sample(range(len(df)), n)
    df.loc[idx, "label"] = 1 - df.loc[idx, "label"]
    return df


def generate(n=6000, fake_ratio=0.35, noise=0.03):
    rng = random.Random(SEED)
    np_rng = np.random.default_rng(SEED)
    n_fake = int(n * fake_ratio)
    n_genuine = n - n_fake
    n_hard_fake = int(n_fake * 0.30)
    n_hard_genuine = int(n_genuine * 0.25)
    rows = [_make_fake(rng, np_rng) for _ in range(n_fake - n_hard_fake)]
    rows += [_make_sophisticated_fake(rng, np_rng) for _ in range(n_hard_fake)]
    rows += [_make_genuine(rng, np_rng) for _ in range(n_genuine - n_hard_genuine)]
    rows += [_make_scruffy_genuine(rng, np_rng) for _ in range(n_hard_genuine)]
    rng.shuffle(rows)
    df = pd.DataFrame(rows)
    df.insert(0, "app_id", [f"APP{i:06d}" for i in range(len(df))])
    df = _add_label_noise(df, noise, rng)
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--fake-ratio", type=float, default=0.35)
    ap.add_argument("--noise", type=float, default=0.03)
    ap.add_argument("--out", default="apps_dataset.csv")
    args = ap.parse_args()
    df = generate(args.n, args.fake_ratio, args.noise)
    df.to_csv(args.out, index=False)
    print(json.dumps({"rows": len(df), "fake": int(df.label.sum()), "genuine": int((df.label == 0).sum()),
                      "columns": list(df.columns), "out": args.out}, indent=2))
