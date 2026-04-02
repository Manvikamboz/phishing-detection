import re
import math
from urllib.parse import urlparse

_BRANDS = re.compile(r"paypal|ebay|amazon|google|microsoft|apple|facebook|instagram|twitter|netflix|bank|chase|wellsfargo|citibank|hsbc|barclays", re.I)
_SUSPICIOUS_TLDS = re.compile(r"\.(tk|ml|ga|cf|gq|xyz|top|club|online|site|info|biz|work|click|link|live|stream|download)$", re.I)
_SHORTENERS = re.compile(r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|shorte\.st|cutt\.ly|rb\.gy", re.I)

# ── Bayesian fusion ───────────────────────────────────────────────────────────
# Each source emits a likelihood ratio (LR): how much more likely is phishing
# given this evidence vs. not. Prior = 0.5 (balanced dataset).
# Posterior = sigmoid(log-prior + sum(log(LR_i)))
# Sources are treated as conditionally independent given the class.

_LOG_PRIOR = math.log(0.5 / 0.5)  # 0 — balanced prior


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _lr_to_log(lr: float) -> float:
    """Convert likelihood ratio to log-odds contribution. Clipped for stability."""
    lr = max(lr, 1e-6)
    return math.log(lr)


# ── Source evidence extractors ────────────────────────────────────────────────

def _evidence_ml(ml: dict) -> tuple[float, list[str], bool]:
    """Returns (log_odds_contribution, reasons, hard_override)."""
    label = ml.get("label", "")
    conf  = ml.get("confidence", 0)
    if label == "phishing":
        if conf >= 90:
            return _lr_to_log(18.0), [f"ML model: HIGH confidence phishing ({conf:.1f}%)"], True
        if conf >= 70:
            return _lr_to_log(9.0),  [f"ML model flagged as phishing ({conf:.1f}%)"], False
        return _lr_to_log(4.0),      [f"ML model flagged as phishing ({conf:.1f}%)"], False
    if label == "legitimate" and conf < 60:
        return _lr_to_log(1.8),      [f"ML model uncertain ({conf:.1f}% legitimate confidence)"], False
    # Strong legitimate signal — negative contribution
    return _lr_to_log(0.15),         [], False


def _evidence_virustotal(vt: dict) -> tuple[float, list[str], bool]:
    malicious  = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    total      = malicious + suspicious + vt.get("harmless", 0) + vt.get("undetected", 0)
    if malicious >= 3:
        lr = min(50.0, malicious * 6.0)
        return _lr_to_log(lr), [f"VirusTotal: {malicious}/{total} engines flagged malicious"], True
    if malicious > 0:
        return _lr_to_log(8.0),  [f"VirusTotal: {malicious}/{total} engines flagged malicious"], False
    if suspicious >= 3:
        return _lr_to_log(4.0),  [f"VirusTotal: {suspicious} engines flagged suspicious"], False
    if suspicious > 0:
        return _lr_to_log(2.0),  [f"VirusTotal: {suspicious} engines flagged suspicious"], False
    # Clean VT result — negative contribution
    return _lr_to_log(0.3), [], False


def _evidence_abuseipdb(abuse: dict) -> tuple[float, list[str]]:
    s        = abuse.get("abuse_score", 0)
    reports  = abuse.get("total_reports", 0)
    is_tor   = abuse.get("is_tor", False)
    cdn      = abuse.get("cdn_masked", False)
    isp      = abuse.get("isp", "")
    log_odds, reasons = 0.0, []

    if is_tor:
        log_odds += _lr_to_log(4.0)
        reasons.append("AbuseIPDB: IP is a TOR exit node")
    if s > 75 or reports > 10:
        log_odds += _lr_to_log(5.0)
        reasons.append(f"AbuseIPDB: high abuse score {s}% ({reports} reports)")
    elif s > 50:
        log_odds += _lr_to_log(3.0)
        reasons.append(f"AbuseIPDB: abuse score {s}%")
    elif s > 20:
        log_odds += _lr_to_log(1.8)
        reasons.append(f"AbuseIPDB: moderate abuse score {s}%")
    if cdn and log_odds == 0.0:
        reasons.append(f"AbuseIPDB: IP behind CDN ({isp}) — score may be unreliable")
    return log_odds, reasons


def _evidence_ipstack(ip: dict) -> tuple[float, list[str]]:
    if not ip or ip.get("error"):
        return 0.0, []
    if ip.get("is_attacker"):
        return _lr_to_log(6.0), ["IPStack: IP flagged as attacker"]
    if ip.get("is_tor") or ip.get("is_proxy"):
        return _lr_to_log(3.5), ["IPStack: IP is TOR node or proxy"]
    if ip.get("is_anonymous"):
        return _lr_to_log(2.0), ["IPStack: IP is anonymous"]
    return 0.0, []


def _evidence_html(html: dict) -> tuple[float, list[str]]:
    log_odds, reasons = 0.0, []
    if html.get("has_login_form") and html.get("has_password_field"):
        log_odds += _lr_to_log(2.5)
        reasons.append("Login form with password field detected")
    if html.get("form_action_empty"):
        log_odds += _lr_to_log(2.0)
        reasons.append("Form with empty/null action attribute")
    if html.get("iframe_count", 0) > 2:
        log_odds += _lr_to_log(1.8)
        reasons.append(f"Multiple hidden iframes ({html['iframe_count']})")
    if html.get("external_script_count", 0) > 10:
        log_odds += _lr_to_log(1.6)
        reasons.append(f"High external script count ({html['external_script_count']})")
    if html.get("hidden_element_count", 0) > 3:
        log_odds += _lr_to_log(1.4)
        reasons.append(f"Hidden elements detected ({html['hidden_element_count']})")
    return log_odds, reasons


def _evidence_url(url: str) -> tuple[float, list[str]]:
    if not url:
        return 0.0, []
    log_odds, reasons = 0.0, []
    url_lower = url.lower()
    parsed    = urlparse(url)
    hostname  = (parsed.hostname or "").lower()
    path      = (parsed.path or "").lower()
    parts     = hostname.split(".")
    tld       = parts[-1] if parts else ""
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    if _BRANDS.search(subdomain):
        log_odds += _lr_to_log(25.0)
        reasons.append(f"Brand '{_BRANDS.search(subdomain).group()}' in subdomain (typosquatting)")

    if _BRANDS.search(path):
        log_odds += _lr_to_log(5.0)
        reasons.append("Brand name in URL path — possible impersonation")

    brand_m  = _BRANDS.search(hostname)
    action_m = re.search(r"billing|update|verify|secure|login|signin|account|confirm|suspend|locked|alert|support", hostname)
    if brand_m and action_m:
        log_odds += _lr_to_log(30.0)
        reasons.append(f"Brand '{brand_m.group()}' + action keyword '{action_m.group()}' in domain")

    if _SUSPICIOUS_TLDS.search(hostname):
        log_odds += _lr_to_log(3.5)
        reasons.append(f"Suspicious TLD (.{tld}) commonly used in phishing")

    if _SHORTENERS.search(url_lower):
        log_odds += _lr_to_log(5.0)
        reasons.append("URL shortener detected — real destination hidden")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        log_odds += _lr_to_log(8.0)
        reasons.append("IP address used as hostname instead of domain name")

    if "xn--" in hostname:
        log_odds += _lr_to_log(12.0)
        reasons.append("Punycode/homograph domain detected — visual spoofing attack")

    if "@" in url:
        log_odds += _lr_to_log(8.0)
        reasons.append("@ symbol in URL — browser ignores everything before it")

    nb_sub = max(len(parts) - 2, 0)
    if nb_sub >= 4:
        log_odds += _lr_to_log(5.0)
        reasons.append(f"Excessive subdomains ({nb_sub}) — common evasion technique")
    elif nb_sub == 3:
        log_odds += _lr_to_log(2.0)
        reasons.append(f"Multiple subdomains ({nb_sub})")

    if hostname.count("-") >= 2:
        log_odds += _lr_to_log(3.0)
        reasons.append(f"Multiple hyphens in domain ({hostname.count('-')}) — evasion pattern")

    if parsed.scheme == "http" and re.search(r"login|signin|account|verify|secure|password", path):
        log_odds += _lr_to_log(5.0)
        reasons.append("HTTP (not HTTPS) used on a login/sensitive page")

    if len(url) > 150:
        log_odds += _lr_to_log(2.2)
        reasons.append(f"Unusually long URL ({len(url)} chars) — possible obfuscation")

    if re.search(r"[0-9]", parts[0] if parts else ""):
        log_odds += _lr_to_log(2.5)
        reasons.append("Digits in domain name — possible character substitution attack")

    return log_odds, reasons


# ── Main decide function ──────────────────────────────────────────────────────

def decide(ml_result: dict, vt_result: dict, abuse_result: dict,
           html_features: dict, ipstack_result: dict = None) -> dict:

    ml_log,    ml_reasons,  ml_hard  = _evidence_ml(ml_result)
    vt_log,    vt_reasons,  vt_hard  = _evidence_virustotal(vt_result)
    abuse_log, abuse_reasons         = _evidence_abuseipdb(abuse_result)
    ip_log,    ip_reasons            = _evidence_ipstack(ipstack_result or {})
    html_log,  html_reasons          = _evidence_html(html_features)
    url_log,   url_reasons           = _evidence_url(ml_result.get("url", ""))

    # Weighted fusion: ML and VT are most reliable, URL heuristics next
    weights = {"ml": 1.4, "vt": 1.3, "abuse": 0.9, "ip": 0.8, "html": 0.9, "url": 1.1}
    total_log_odds = (
        _LOG_PRIOR
        + weights["ml"]    * ml_log
        + weights["vt"]    * vt_log
        + weights["abuse"] * abuse_log
        + weights["ip"]    * ip_log
        + weights["html"]  * html_log
        + weights["url"]   * url_log
    )

    # Convert posterior probability → 0-100 score
    posterior = _sigmoid(total_log_odds)
    score = int(round(posterior * 100))

    all_reasons = ml_reasons + vt_reasons + abuse_reasons + ip_reasons + html_reasons + url_reasons

    # ── Hard override rules ───────────────────────────────────────────────────
    override_reason = None
    if ml_hard and vt_hard:
        override_reason = "OVERRIDE: Both ML model and VirusTotal independently confirmed phishing"
    elif ml_hard and url_log > _lr_to_log(5.0):
        override_reason = "OVERRIDE: ML high-confidence phishing + strong URL heuristic signals"
    elif vt_hard and url_log > _lr_to_log(5.0):
        override_reason = "OVERRIDE: VirusTotal confirmed malicious + strong URL heuristic signals"
    elif vt_log > _lr_to_log(8.0) and abuse_log > _lr_to_log(3.0):
        override_reason = "OVERRIDE: VirusTotal malicious + high IP abuse score"
    elif url_log > _lr_to_log(20.0):
        override_reason = "OVERRIDE: Extreme URL-level phishing signals detected"

    if override_reason:
        score = max(score, 85)
        all_reasons.insert(0, f"🚨 {override_reason}")

    # ── Final label ───────────────────────────────────────────────────────────
    if score >= 65:
        label = "phishing"
    elif score >= 35:
        label = "suspicious"
    else:
        label = "benign"

    # Per-source scores mapped back to 0-100 for UI display
    def _log_to_display(log_val: float) -> int:
        return min(100, max(0, int(round(_sigmoid(log_val) * 100))))

    return {
        "score": score,
        "label": label,
        "reasons": all_reasons or ["No significant threats detected"],
        "source_scores": {
            "ML Model":       _log_to_display(ml_log * weights["ml"]),
            "VirusTotal":     _log_to_display(vt_log * weights["vt"]),
            "AbuseIPDB":      _log_to_display(abuse_log * weights["abuse"]),
            "IPStack":        _log_to_display(ip_log * weights["ip"]),
            "HTML Analysis":  _log_to_display(html_log * weights["html"]),
            "URL Heuristics": _log_to_display(url_log * weights["url"]),
        },
    }
