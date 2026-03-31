import joblib
import numpy as np
import re
import socket
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

MODEL_PATH = "ml_model/phishing_model.pkl"
_cache = {}

SHORTENING_SERVICES = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|shorte\.st"
PHISH_HINTS = r"login|verify|secure|account|update|banking|confirm|password|signin|ebayisapi|webscr"
SUSPICIOUS_TLDS = r"\.(tk|ml|ga|cf|gq|xyz|top|club|online|site|info|biz)$"
BRANDS = r"paypal|ebay|amazon|google|microsoft|apple|facebook|instagram|twitter|netflix|bank"


def _load():
    if "model" not in _cache:
        _cache.update(joblib.load(MODEL_PATH))
    return _cache


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()
    hostname_lower = hostname.lower()

    # digit ratios
    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)

    # words
    words_raw = re.split(r"[\W_]+", full)
    words_raw = [w for w in words_raw if w]
    words_host = re.split(r"[\W_]+", hostname_lower)
    words_host = [w for w in words_host if w]
    words_path = re.split(r"[\W_]+", path.lower())
    words_path = [w for w in words_path if w]

    # subdomains
    parts = hostname_lower.split(".")
    nb_subdomains = max(len(parts) - 2, 0)

    # tld
    tld = parts[-1] if parts else ""

    # char repeat: max consecutive repeated chars
    char_repeat = max((len(list(g)) for _, g in __import__("itertools").groupby(full)), default=0)

    # try to get page features via HTTP
    html_text = ""
    nb_hyperlinks = 0
    ratio_intHyperlinks = 0.0
    ratio_extHyperlinks = 0.0
    ratio_nullHyperlinks = 0.0
    nb_extCSS = 0
    ratio_intRedirection = 0.0
    ratio_extRedirection = 0.0
    ratio_intErrors = 0.0
    ratio_extErrors = 0.0
    login_form = 0
    external_favicon = 0
    links_in_tags = 0.0
    submit_email = 0
    ratio_intMedia = 0.0
    ratio_extMedia = 0.0
    sfh = 0
    iframe = 0
    popup_window = 0
    safe_anchor = 0.0
    onmouseover = 0
    right_clic = 0
    empty_title = 1
    domain_in_title = 0
    domain_with_copyright = 0

    try:
        resp = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0"})
        html_text = resp.text
        soup = BeautifulSoup(html_text, "lxml")

        # hyperlinks
        anchors = soup.find_all("a", href=True)
        nb_hyperlinks = len(anchors)
        if nb_hyperlinks:
            int_links = sum(1 for a in anchors if hostname_lower in (a["href"] or ""))
            null_links = sum(1 for a in anchors if (a["href"] or "").strip() in ("", "#", "javascript:void(0)"))
            ext_links = nb_hyperlinks - int_links - null_links
            ratio_intHyperlinks = int_links / nb_hyperlinks
            ratio_extHyperlinks = ext_links / nb_hyperlinks
            ratio_nullHyperlinks = null_links / nb_hyperlinks

        # CSS
        nb_extCSS = len([l for l in soup.find_all("link", rel="stylesheet") if hostname_lower not in (l.get("href") or "")])

        # login form
        forms = soup.find_all("form")
        login_form = int(bool(soup.find("input", {"type": "password"})))
        sfh = int(any(f.get("action", "").strip() in ("", "#") for f in forms))
        submit_email = int(any("mailto:" in (f.get("action", "") or "") for f in forms))

        # iframe
        iframe = int(bool(soup.find("iframe")))
        popup_window = int("window.open" in html_text)
        onmouseover = int("onmouseover" in html_text.lower())
        right_clic = int("event.button==2" in html_text or "contextmenu" in html_text.lower())

        # favicon
        favicon = soup.find("link", rel=lambda r: r and "icon" in r)
        external_favicon = int(bool(favicon and favicon.get("href") and hostname_lower not in favicon["href"]))

        # title
        title_tag = soup.find("title")
        title_text = title_tag.get_text().lower() if title_tag else ""
        empty_title = int(not title_text.strip())
        domain_in_title = int(parts[0] in title_text if parts else False)

        # copyright
        domain_with_copyright = int(bool(re.search(r"©|copyright", html_text, re.I)) and hostname_lower in html_text.lower())

        # media
        media_tags = soup.find_all(["img", "video", "audio"])
        if media_tags:
            int_media = sum(1 for m in media_tags if hostname_lower in (m.get("src") or ""))
            ratio_intMedia = int_media / len(media_tags)
            ratio_extMedia = 1 - ratio_intMedia

        # links in tags
        tag_links = soup.find_all(["meta", "script", "link"])
        if tag_links:
            int_tag = sum(1 for t in tag_links if hostname_lower in (t.get("href") or t.get("src") or t.get("content") or ""))
            links_in_tags = int_tag / len(tag_links)

        # safe anchor
        if nb_hyperlinks:
            safe = sum(1 for a in anchors if hostname_lower in (a["href"] or ""))
            safe_anchor = safe / nb_hyperlinks

        # redirections
        nb_redirection = len(resp.history)

    except Exception:
        pass

    # DNS / WHOIS approximations
    dns_record = 0
    try:
        socket.gethostbyname(hostname)
        dns_record = 1
    except Exception:
        pass

    return {
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
        "nb_redirection": locals().get("nb_redirection", 0),
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
        "domain_registration_length": 0,
        "domain_age": 0,
        "web_traffic": 0,
        "dns_record": dns_record,
        "google_index": 0,
        "page_rank": 0,
    }


def predict(url: str) -> dict:
    bundle = _load()
    model = bundle["model"]
    feature_cols = bundle["features"]
    le = bundle["label_encoder"]

    features = extract_url_features(url)
    row = np.array([[features.get(f, 0) for f in feature_cols]])
    proba = model.predict_proba(row)[0]
    pred_idx = int(np.argmax(proba))
    label = le.inverse_transform([pred_idx])[0]
    confidence = round(float(proba[pred_idx]) * 100, 2)

    return {"url": url, "label": label, "confidence": confidence, "probabilities": dict(zip(le.classes_, proba.tolist()))}
