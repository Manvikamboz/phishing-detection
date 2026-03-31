import re

# Known brands for impersonation detection
_BRANDS = re.compile(r"paypal|ebay|amazon|google|microsoft|apple|facebook|instagram|twitter|netflix|bank|chase|wellsfargo|citibank|hsbc|barclays", re.I)
_SUSPICIOUS_TLDS = re.compile(r"\.(tk|ml|ga|cf|gq|xyz|top|club|online|site|info|biz|work|click|link|live|stream|download)$", re.I)
_SHORTENERS = re.compile(r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|shorte\.st|cutt\.ly|rb\.gy", re.I)


# ── individual scorers ────────────────────────────────────────────────────────

def _score_ml(ml: dict) -> tuple[int, list[str], bool]:
    """Returns (score, reasons, is_hard_phishing).
    is_hard_phishing=True triggers an override regardless of total score."""
    label = ml.get("label", "")
    conf  = ml.get("confidence", 0)
    if label == "phishing":
        if conf >= 90:
            return 40, [f"ML model: HIGH confidence phishing ({conf:.1f}%)"], True
        if conf >= 70:
            return 32, [f"ML model flagged as phishing ({conf:.1f}% confidence)"], False
        return 18, [f"ML model flagged as phishing ({conf:.1f}% confidence)"], False
    # Even if label=legitimate, penalise low confidence (model is unsure)
    if label == "legitimate" and conf < 60:
        return 8, [f"ML model uncertain — low legitimate confidence ({conf:.1f}%)"], False
    return 0, [], False


def _score_virustotal(vt: dict) -> tuple[int, list[str], bool]:
    malicious  = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    total      = malicious + suspicious + vt.get("harmless", 0) + vt.get("undetected", 0)
    if malicious >= 3:
        ratio = malicious / total if total else 0
        score = min(35, max(malicious * 4, int(ratio * 60)))
        return score, [f"VirusTotal: {malicious}/{total} engines flagged malicious"], True
    if malicious > 0:
        return 20, [f"VirusTotal: {malicious}/{total} engines flagged malicious"], False
    if suspicious >= 3:
        return 14, [f"VirusTotal: {suspicious} engines flagged suspicious"], False
    if suspicious > 0:
        return 7, [f"VirusTotal: {suspicious} engines flagged suspicious"], False
    return 0, [], False


def _score_abuseipdb(abuse: dict) -> tuple[int, list[str]]:
    s         = abuse.get("abuse_score", 0)
    reports   = abuse.get("total_reports", 0)
    is_tor    = abuse.get("is_tor", False)
    cdn_masked= abuse.get("cdn_masked", False)
    isp       = abuse.get("isp", "")

    score, reasons = 0, []

    if is_tor:
        score += 10
        reasons.append("AbuseIPDB: IP is a TOR exit node")
    if s > 75 or reports > 10:
        score += 12
        reasons.append(f"AbuseIPDB: high abuse score {s}% ({reports} reports)")
    elif s > 50:
        score += 8
        reasons.append(f"AbuseIPDB: abuse score {s}%")
    elif s > 20:
        score += 4
        reasons.append(f"AbuseIPDB: moderate abuse score {s}%")
    if cdn_masked and score == 0:
        # Don't penalise but inform — CDN masks real IP
        reasons.append(f"AbuseIPDB: IP behind CDN ({isp}) — score may be unreliable")

    return min(score, 15), reasons


def _score_ipstack(ip: dict) -> tuple[int, list[str]]:
    if not ip or ip.get("error"):
        return 0, []
    if ip.get("is_attacker"):
        return 13, ["IPStack: IP flagged as attacker"]
    if ip.get("is_tor") or ip.get("is_proxy"):
        return 9,  ["IPStack: IP is TOR node or proxy"]
    if ip.get("is_anonymous"):
        return 5,  ["IPStack: IP is anonymous"]
    return 0, []


def _score_html(html: dict) -> tuple[int, list[str]]:
    score, reasons = 0, []
    if html.get("has_login_form") and html.get("has_password_field"):
        score += 5
        reasons.append("Login form with password field detected")
    if html.get("form_action_empty"):
        score += 4
        reasons.append("Form with empty/null action attribute")
    if html.get("iframe_count", 0) > 2:
        score += 3
        reasons.append(f"Multiple hidden iframes ({html['iframe_count']})")
    if html.get("external_script_count", 0) > 10:
        score += 3
        reasons.append(f"High external script count ({html['external_script_count']})")
    if html.get("hidden_element_count", 0) > 3:
        score += 2
        reasons.append(f"Hidden elements detected ({html['hidden_element_count']})")
    return min(score, 15), reasons


def _score_url_heuristics(url: str) -> tuple[int, list[str]]:
    score, reasons = 0, []
    if not url:
        return 0, []
    url_lower = url.lower()
    from urllib.parse import urlparse
    parsed   = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path     = (parsed.path or "").lower()
    parts    = hostname.split(".")
    tld      = parts[-1] if parts else ""

    # Brand name in subdomain but not as the real domain (typosquatting)
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    if _BRANDS.search(subdomain):
        score += 20
        reasons.append(f"Brand name '{_BRANDS.search(subdomain).group()}' found in subdomain (typosquatting)")

    # Brand name in path (e.g. paypal.com.evil.com/paypal-login)
    if _BRANDS.search(path):
        score += 10
        reasons.append(f"Brand name in URL path — possible impersonation")

    # Brand name in domain itself with action keywords (netflix-billing, amazon-update)
    brand_in_domain = _BRANDS.search(hostname)
    action_keywords = re.search(r"billing|update|verify|secure|login|signin|account|confirm|suspend|locked|alert|support", hostname)
    if brand_in_domain and action_keywords:
        score += 22
        reasons.append(f"Brand '{brand_in_domain.group()}' + action keyword '{action_keywords.group()}' in domain — high-confidence phishing pattern")

    # Suspicious TLD
    if _SUSPICIOUS_TLDS.search(hostname):
        score += 8
        reasons.append(f"Suspicious TLD (.{tld}) commonly used in phishing")

    # URL shortener — hides real destination
    if _SHORTENERS.search(url_lower):
        score += 12
        reasons.append("URL shortener detected — real destination hidden")

    # IP address as hostname
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 15
        reasons.append("IP address used as hostname instead of domain name")

    # Punycode / homograph attack (xn--)
    if "xn--" in hostname:
        score += 18
        reasons.append("Punycode/homograph domain detected — visual spoofing attack")

    # @ symbol in URL (tricks browser into ignoring real host)
    if "@" in url:
        score += 15
        reasons.append("@ symbol in URL — browser ignores everything before it")

    # Multiple subdomains (e.g. secure.login.verify.evil.com)
    nb_sub = max(len(parts) - 2, 0)
    if nb_sub >= 4:
        score += 12
        reasons.append(f"Excessive subdomains ({nb_sub}) — common evasion technique")
    elif nb_sub == 3:
        score += 5
        reasons.append(f"Multiple subdomains ({nb_sub})")

    # Hyphen in domain (e.g. paypal-secure-login.com)
    if hostname.count("-") >= 2:
        score += 8
        reasons.append(f"Multiple hyphens in domain ({hostname.count('-')}) — evasion pattern")

    # HTTP (not HTTPS) with login-related path
    if parsed.scheme == "http" and re.search(r"login|signin|account|verify|secure|password", path):
        score += 12
        reasons.append("HTTP (not HTTPS) used on a login/sensitive page")

    # Very long URL (obfuscation)
    if len(url) > 150:
        score += 6
        reasons.append(f"Unusually long URL ({len(url)} chars) — possible obfuscation")

    # Digits in domain (e.g. paypa1.com, amaz0n.com)
    if re.search(r"[0-9]", hostname.split(".")[0] if parts else ""):
        score += 7
        reasons.append("Digits in domain name — possible character substitution attack")

    return min(score, 40), reasons


# ── multi-signal correlation ──────────────────────────────────────────────────

def _correlate(ml_score, vt_score, abuse_score, ip_score, html_score, url_score) -> tuple[int, list[str]]:
    """
    If multiple independent sources agree → amplify score.
    This catches smart phishing that scores low on each individual source.
    """
    positive_sources = sum([
        ml_score >= 15,
        vt_score >= 7,
        abuse_score >= 4,
        ip_score >= 5,
        html_score >= 5,
        url_score >= 8,
    ])
    if positive_sources >= 4:
        return 20, [f"Multi-source correlation: {positive_sources}/6 independent sources flagged this URL"]
    if positive_sources == 3:
        return 10, [f"Multi-source correlation: {positive_sources}/6 sources raised concerns"]
    if positive_sources == 2:
        return 5,  [f"Multi-source correlation: {positive_sources}/6 sources raised concerns"]
    return 0, []


# ── main decide function ──────────────────────────────────────────────────────

def decide(ml_result: dict, vt_result: dict, abuse_result: dict,
           html_features: dict, ipstack_result: dict = None) -> dict:

    ml_score,    ml_reasons,    ml_hard    = _score_ml(ml_result)
    vt_score,    vt_reasons,    vt_hard    = _score_virustotal(vt_result)
    abuse_score, abuse_reasons             = _score_abuseipdb(abuse_result)
    ip_score,    ip_reasons                = _score_ipstack(ipstack_result or {})
    html_score,  html_reasons              = _score_html(html_features)
    url_score,   url_reasons               = _score_url_heuristics(ml_result.get("url", ""))
    corr_bonus,  corr_reasons              = _correlate(ml_score, vt_score, abuse_score, ip_score, html_score, url_score)

    total = min(
        ml_score + vt_score + abuse_score + ip_score + html_score + url_score + corr_bonus,
        100
    )

    all_reasons = ml_reasons + vt_reasons + abuse_reasons + ip_reasons + html_reasons + url_reasons + corr_reasons

    # ── Hard override rules ───────────────────────────────────────────────────
    # These force phishing label regardless of total score
    override_reason = None

    if ml_hard and vt_hard:
        override_reason = "OVERRIDE: Both ML model and VirusTotal independently confirmed phishing"

    elif ml_hard and url_score >= 15:
        override_reason = "OVERRIDE: ML high-confidence phishing + strong URL heuristic signals"

    elif vt_hard and url_score >= 15:
        override_reason = "OVERRIDE: VirusTotal confirmed malicious + strong URL heuristic signals"

    elif vt_score >= 20 and abuse_score >= 8:
        override_reason = "OVERRIDE: VirusTotal malicious + high IP abuse score"

    elif url_score >= 30:
        # URL alone has extremely strong phishing signals (e.g. punycode + brand impersonation)
        override_reason = "OVERRIDE: Extreme URL-level phishing signals detected"

    if override_reason:
        total = max(total, 85)
        all_reasons.insert(0, f"🚨 {override_reason}")

    # ── Final label ───────────────────────────────────────────────────────────
    if total >= 65:
        label = "phishing"
    elif total >= 35:
        label = "suspicious"
    else:
        label = "benign"

    return {
        "score": total,
        "label": label,
        "reasons": all_reasons or ["No significant threats detected"],
        "source_scores": {
            "ML Model":       ml_score,
            "VirusTotal":     vt_score,
            "AbuseIPDB":      abuse_score,
            "IPStack":        ip_score,
            "HTML Analysis":  html_score,
            "URL Heuristics": url_score,
            "Correlation":    corr_bonus,
        },
    }
