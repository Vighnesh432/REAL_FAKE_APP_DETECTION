import re
from functools import lru_cache

STOPWORDS = {
    "a", "about", "above", "after", "again", "all", "am", "an", "and", "any", "are",
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
    "but", "by", "can", "did", "do", "does", "doing", "don", "down", "during", "each",
    "few", "for", "from", "further", "had", "has", "have", "having", "he", "her", "here",
    "hers", "him", "his", "how", "i", "if", "in", "into", "is", "it", "its", "itself",
    "just", "me", "more", "most", "my", "no", "nor", "not", "now", "of", "off", "on",
    "once", "only", "or", "other", "our", "out", "over", "own", "s", "same", "she",
    "should", "so", "some", "such", "t", "than", "that", "the", "their", "them", "then",
    "there", "these", "they", "this", "those", "through", "to", "too", "under", "until",
    "up", "very", "was", "we", "were", "what", "when", "where", "which", "while", "who",
    "whom", "why", "will", "with", "you", "your", "yours",
}

_TOKEN_RE = re.compile(r"[a-z0-9']+")
_URL_RE = re.compile(r"https?://\S+|www\.\S+")
_EMOJI_RE = re.compile(
    "[" "\U0001F300-\U0001FAFF" "\U00002600-\U000027BF" "\U0001F1E0-\U0001F1FF" "]+"
)

SPAM_LEXICON = {
    "free", "unlimited", "hack", "hacked", "mod", "modded", "crack", "cracked",
    "unlocked", "premium", "vip", "pro", "gold", "guaranteed", "instant", "earn",
    "cash", "money", "prize", "win", "winner", "bonus", "reward", "loan", "rich",
    "click", "download", "hurry", "limited", "offer", "urgent", "official", "latest",
    "working", "apk", "100", "trusted", "millions", "best", "no", "kyc", "fastest",
}
URGENCY_LEXICON = {"now", "hurry", "today", "instant", "immediately", "limited", "fast", "quick"}
NEGATIVE_LEXICON = {
    "fake", "scam", "fraud", "steal", "stole", "stolen", "virus", "malware", "spam",
    "popup", "popups", "ads", "useless", "worst", "waste", "money", "refund", "otp",
    "pin", "hacked", "blocked", "cheat", "dont", "avoid", "warning", "danger",
}
POSITIVE_LEXICON = {
    "good", "great", "nice", "love", "excellent", "awesome", "amazing", "perfect",
    "best", "helpful", "smooth", "reliable", "solid", "recommend", "useful",
}


@lru_cache(maxsize=50_000)
def stem(word: str) -> str:
    if len(word) <= 3:
        return word
    for suf in ("ational", "ization", "iveness", "fulness", "ousness", "ement",
                "ation", "ingly", "edly", "ally", "ance", "ence", "able", "ible",
                "ness", "ment", "ies", "ing", "ers", "est", "ed", "ly", "er", "s"):
        if word.endswith(suf) and len(word) - len(suf) >= 3:
            base = word[: -len(suf)]
            if suf == "ies":
                return base + "y"
            if suf in ("ing", "ed") and len(base) > 2 and base[-1] == base[-2]:
                base = base[:-1]
            return base
    return word


def clean_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = _URL_RE.sub(" url ", text)
    text = _EMOJI_RE.sub(" ", text)
    text = re.sub(r"[^a-z0-9\s']", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def tokenize(text: str, remove_stopwords: bool = True, do_stem: bool = True) -> list[str]:
    tokens = _TOKEN_RE.findall(clean_text(text))
    if remove_stopwords:
        tokens = [t for t in tokens if t not in STOPWORDS and len(t) > 1]
    if do_stem:
        tokens = [stem(t) for t in tokens]
    return tokens


def preprocess(text: str) -> str:
    return " ".join(tokenize(text))


def split_reviews(reviews_blob: str) -> list[str]:
    if not isinstance(reviews_blob, str) or not reviews_blob.strip():
        return []
    return [r.strip() for r in reviews_blob.split("||") if r.strip()]


def lexicon_ratio(tokens: list[str], lexicon: set[str]) -> float:
    if not tokens:
        return 0.0
    stemmed_lex = {stem(w) for w in lexicon}
    hits = sum(1 for t in tokens if t in lexicon or t in stemmed_lex)
    return hits / len(tokens)


def sentiment_score(text: str) -> float:
    tokens = tokenize(text, remove_stopwords=True, do_stem=False)
    if not tokens:
        return 0.0
    pos = sum(1 for t in tokens if t in POSITIVE_LEXICON)
    neg = sum(1 for t in tokens if t in NEGATIVE_LEXICON)
    if pos + neg == 0:
        return 0.0
    return (pos - neg) / (pos + neg)
