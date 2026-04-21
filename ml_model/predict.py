import joblib
import warnings
import numpy as np
import pandas as pd
import re
import math
import os
import socket
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

_BASE = os.path.dirname(os.path.abspath(__file__))

MODEL_PATHS = [
    os.path.join(_BASE, "phishing_model.pkl"),
    os.path.join(_BASE, "phishing_model_2.pkl"),
    os.path.join(_BASE, "phishing_model_combined.pkl"),
]
_cache = {}

SHORTENING_SERVICES = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|shorte\.st"
PHISH_HINTS = r"login|verify|secure|account|update|banking|confirm|password|signin|ebayisapi|webscr"
SUSPICIOUS_TLDS = r"\.(tk|ml|ga|cf|gq|xyz|top|club|online|site|info|biz)$"
BRANDS = r"paypal|ebay|amazon|google|microsoft|apple|facebook|instagram|twitter|netflix|bank"

_KNOWN_BRANDS = [
    "paypal", "ebay", "amazon", "google", "microsoft", "apple",
    "facebook", "instagram", "twitter", "netflix", "bank", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays",
]


def _load():
    if "models" not in _cache:
        loaded = []
        for path in MODEL_PATHS:
            try:
                loaded.append(joblib.load(path))
            except FileNotFoundError:
                pass  # second model optional — only use if trained
        if not loaded:
            raise FileNotFoundError(
                "No trained model found. Train the models with ml_model/phishing_train_colab.ipynb and place the .pkl files in ml_model/."
            )
        _cache["models"] = loaded
    return _cache["models"]


# ── New feature helpers ───────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _min_brand_distance(hostname: str) -> int:
    parts = hostname.split(".")
    sld = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")
    return min(_levenshtein(sld, brand) for brand in _KNOWN_BRANDS)


def _consonant_ratio(s: str) -> float:
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return len([c for c in letters if c not in "aeiou"]) / len(letters)


def _add_engineered_features(features: dict) -> dict:
    """Mirror the engineered features added during training."""
    length_url = features.get("length_url", 1)
    special = (features.get("nb_at", 0) + features.get("nb_percent", 0)
               + features.get("nb_tilde", 0) + features.get("nb_dollar", 0))
    features["ratio_special_chars"] = special / max(length_url, 1)
    features["subdomain_hyphen"]    = features.get("nb_subdomains", 0) * features.get("nb_hyphens", 0)
    features["ext_link_dominance"]  = features.get("ratio_extHyperlinks", 0) - features.get("ratio_intHyperlinks", 0)
    features["null_login_combo"]    = features.get("ratio_nullHyperlinks", 0) * features.get("login_form", 0)
    features["obfuscation_score"]   = (
        features.get("punycode", 0) * 3
        + features.get("shortening_service", 0) * 2
        + features.get("http_in_path", 0)
        + features.get("https_token", 0)
    )
    features["digit_ratio_host"]  = features.get("ratio_digits_host", 0)
    features["query_param_count"] = features.get("nb_eq", 0)
    features["hint_density"]      = features.get("phish_hints", 0) / max(length_url / 10, 1)
    return features


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()
    hostname_lower = hostname.lower()

    digits_url  = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)

    words_raw  = [w for w in re.split(r"[\W_]+", full) if w]
    words_host = [w for w in re.split(r"[\W_]+", hostname_lower) if w]
    words_path = [w for w in re.split(r"[\W_]+", path.lower()) if w]

    parts = hostname_lower.split(".")
    nb_subdomains = max(len(parts) - 2, 0)
    tld = parts[-1] if parts else ""

    char_repeat = max((len(list(g)) for _, g in __import__("itertools").groupby(full)), default=0)

    # HTML features (best-effort)
    nb_hyperlinks = nb_extCSS = login_form = sfh = submit_email = 0
    iframe = popup_window = onmouseover = right_clic = external_favicon = 0
    empty_title = 1
    domain_in_title = domain_with_copyright = 0
    ratio_intHyperlinks = ratio_extHyperlinks = ratio_nullHyperlinks = 0.0
    ratio_intRedirection = ratio_extRedirection = 0.0
    ratio_intErrors = ratio_extErrors = 0.0
    ratio_intMedia = ratio_extMedia = links_in_tags = safe_anchor = 0.0
    nb_redirection = 0

    try:
        resp = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0"})
        html_text = resp.text
        soup = BeautifulSoup(html_text, "lxml")

        anchors = soup.find_all("a", href=True)
        nb_hyperlinks = len(anchors)
        if nb_hyperlinks:
            int_links  = sum(1 for a in anchors if hostname_lower in (a["href"] or ""))
            null_links = sum(1 for a in anchors if (a["href"] or "").strip() in ("", "#", "javascript:void(0)"))
            ext_links  = nb_hyperlinks - int_links - null_links
            ratio_intHyperlinks  = int_links / nb_hyperlinks
            ratio_extHyperlinks  = ext_links / nb_hyperlinks
            ratio_nullHyperlinks = null_links / nb_hyperlinks
            safe_anchor = int_links / nb_hyperlinks

        nb_extCSS = len([l for l in soup.find_all("link", rel="stylesheet")
                         if hostname_lower not in (l.get("href") or "")])

        forms = soup.find_all("form")
        login_form    = int(bool(soup.find("input", {"type": "password"})))
        sfh           = int(any(f.get("action", "").strip() in ("", "#") for f in forms))
        submit_email  = int(any("mailto:" in (f.get("action", "") or "") for f in forms))

        iframe        = int(bool(soup.find("iframe")))
        popup_window  = int("window.open" in html_text)
        onmouseover   = int("onmouseover" in html_text.lower())
        right_clic    = int("event.button==2" in html_text or "contextmenu" in html_text.lower())

        favicon = soup.find("link", rel=lambda r: r and "icon" in r)
        external_favicon = int(bool(favicon and favicon.get("href") and hostname_lower not in favicon["href"]))

        title_tag   = soup.find("title")
        title_text  = title_tag.get_text().lower() if title_tag else ""
        empty_title = int(not title_text.strip())
        domain_in_title = int(parts[0] in title_text if parts else False)
        domain_with_copyright = int(bool(re.search(r"©|copyright", html_text, re.I)) and hostname_lower in html_text.lower())

        media_tags = soup.find_all(["img", "video", "audio"])
        if media_tags:
            int_media = sum(1 for m in media_tags if hostname_lower in (m.get("src") or ""))
            ratio_intMedia = int_media / len(media_tags)
            ratio_extMedia = 1 - ratio_intMedia

        tag_links = soup.find_all(["meta", "script", "link"])
        if tag_links:
            int_tag = sum(1 for t in tag_links
                          if hostname_lower in (t.get("href") or t.get("src") or t.get("content") or ""))
            links_in_tags = int_tag / len(tag_links)

        nb_redirection = len(resp.history)

    except Exception:
        pass

    dns_record = 0
    try:
        socket.gethostbyname(hostname)
        dns_record = 1
    except Exception:
        pass

    # ── New features ──────────────────────────────────────────────────────────
    url_entropy      = _entropy(url)
    hostname_entropy = _entropy(hostname)
    min_brand_dist   = _min_brand_distance(hostname)
    sld = parts[0] if parts else hostname
    consonant_ratio  = _consonant_ratio(sld)

    features = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))),
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_tilde": url.count("~"),
        "nb_percent": url.count("%"),
        "nb_slash": url.count("/"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" "),
        "nb_www": url.lower().count("www"),
        "nb_com": url.lower().count(".com"),
        "nb_dslash": url.count("//"),
        "http_in_path": int("http" in path.lower()),
        "https_token": int("https" in hostname_lower),
        "ratio_digits_url": digits_url / len(url) if url else 0,
        "ratio_digits_host": digits_host / len(hostname) if hostname else 0,
        "punycode": int("xn--" in hostname_lower),
        "port": int(parsed.port is not None),
        "tld_in_path": int(tld in path.lower()),
        "tld_in_subdomain": int(tld in ".".join(parts[:-2]) if len(parts) > 2 else False),
        "abnormal_subdomain": int(bool(re.search(r"^(w[0-9]+|ww[^w])", hostname_lower))),
        "nb_subdomains": nb_subdomains,
        "prefix_suffix": int("-" in hostname_lower),
        "random_domain": int(bool(re.search(r"[0-9]{4,}", hostname_lower))),
        "shortening_service": int(bool(re.search(SHORTENING_SERVICES, full))),
        "path_extension": int(bool(re.search(r"\.(php|html|htm|asp|aspx|jsp)$", path.lower()))),
        "nb_redirection": nb_redirection,
        "nb_external_redirection": 0,
        "length_words_raw": len(words_raw),
        "char_repeat": char_repeat,
        "shortest_words_raw": min((len(w) for w in words_raw), default=0),
        "shortest_word_host": min((len(w) for w in words_host), default=0),
        "shortest_word_path": min((len(w) for w in words_path), default=0),
        "longest_words_raw": max((len(w) for w in words_raw), default=0),
        "longest_word_host": max((len(w) for w in words_host), default=0),
        "longest_word_path": max((len(w) for w in words_path), default=0),
        "avg_words_raw": sum(len(w) for w in words_raw) / len(words_raw) if words_raw else 0,
        "avg_word_host": sum(len(w) for w in words_host) / len(words_host) if words_host else 0,
        "avg_word_path": sum(len(w) for w in words_path) / len(words_path) if words_path else 0,
        "phish_hints": int(bool(re.search(PHISH_HINTS, full))),
        "domain_in_brand": int(bool(re.search(BRANDS, hostname_lower))),
        "brand_in_subdomain": int(bool(re.search(BRANDS, ".".join(parts[:-2]))) if len(parts) > 2 else False),
        "brand_in_path": int(bool(re.search(BRANDS, path.lower()))),
        "suspecious_tld": int(bool(re.search(SUSPICIOUS_TLDS, hostname_lower))),
        "statistical_report": 0,
        "nb_hyperlinks": nb_hyperlinks,
        "ratio_intHyperlinks": ratio_intHyperlinks,
        "ratio_extHyperlinks": ratio_extHyperlinks,
        "ratio_nullHyperlinks": ratio_nullHyperlinks,
        "nb_extCSS": nb_extCSS,
        "ratio_intRedirection": ratio_intRedirection,
        "ratio_extRedirection": ratio_extRedirection,
        "ratio_intErrors": ratio_intErrors,
        "ratio_extErrors": ratio_extErrors,
        "login_form": login_form,
        "external_favicon": external_favicon,
        "links_in_tags": links_in_tags,
        "submit_email": submit_email,
        "ratio_intMedia": ratio_intMedia,
        "ratio_extMedia": ratio_extMedia,
        "sfh": sfh,
        "iframe": iframe,
        "popup_window": popup_window,
        "safe_anchor": safe_anchor,
        "onmouseover": onmouseover,
        "right_clic": right_clic,
        "empty_title": empty_title,
        "domain_in_title": domain_in_title,
        "domain_with_copyright": domain_with_copyright,
        "whois_registered_domain": dns_record,
        "domain_registration_length": 0,  # filled by enrich_features() if WHOIS data is available
        "domain_age": 0,
        "web_traffic": 0,
        "dns_record": dns_record,
        "google_index": 0,
        "page_rank": 0,
        # New features
        "url_entropy":        url_entropy,
        "hostname_entropy":   hostname_entropy,
        "min_brand_distance": min_brand_dist,
        "consonant_ratio":    consonant_ratio,
    }
    return _add_engineered_features(features)


def enrich_features(features: dict, whoisfreaks: dict = None, whoisxml: dict = None) -> dict:
    """Overwrite the hardcoded-zero domain features with WHOIS-derived values."""
    if whoisfreaks and not whoisfreaks.get("error"):
        age_days = whoisfreaks.get("domain_age_days", -1)
        if age_days >= 0:
            features["domain_age"]                = age_days
            features["domain_registration_length"] = age_days
        if whoisfreaks.get("registered"):
            features["whois_registered_domain"] = 1
    if whoisxml and not whoisxml.get("error"):
        age_days = whoisxml.get("domain_age_days", -1)
        if age_days >= 0 and features.get("domain_age", 0) == 0:
            features["domain_age"]                = age_days
            features["domain_registration_length"] = age_days
        if whoisxml.get("registered"):
            features["whois_registered_domain"] = 1
    return features


def predict(url: str, whoisfreaks: dict = None, whoisxml: dict = None) -> dict:
    try:
        models = _load()
    except FileNotFoundError as e:
        raise RuntimeError(str(e))

    features = extract_url_features(url)
    if whoisfreaks or whoisxml:
        features = enrich_features(features, whoisfreaks, whoisxml)

    all_proba = []
    for bundle in models:
        feature_cols = bundle["features"]
        model        = bundle["model"]
        row = pd.DataFrame([[features.get(f, 0) for f in feature_cols]], columns=feature_cols)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            proba = model.predict_proba(row)[0]
        all_proba.append((bundle["label_encoder"], proba))

    # Pool: average probabilities across all loaded models
    # All models must share the same label encoding (phishing / legitimate)
    le_ref   = all_proba[0][0]
    avg_prob = np.mean([p for _, p in all_proba], axis=0)

    pred_idx   = int(np.argmax(avg_prob))
    label      = le_ref.inverse_transform([pred_idx])[0]
    confidence = round(float(avg_prob[pred_idx]) * 100, 2)

    return {
        "url":           url,
        "label":         label,
        "confidence":    confidence,
        "probabilities": dict(zip(le_ref.classes_, avg_prob.tolist())),
        "models_used":   len(models),
    }
