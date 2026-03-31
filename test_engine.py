import sys
sys.path.append(".")
from decision.engine import decide

cases = [
    {
        "name": "PayPal phishing — APIs confirm it",
        "ml":   {"url": "http://paypal.com.secure-login.verify-account.tk/webscr", "label": "phishing", "confidence": 94},
        "vt":   {"malicious": 5, "suspicious": 2, "harmless": 40, "undetected": 20},
        "ab":   {"abuse_score": 0, "total_reports": 0, "is_tor": False, "cdn_masked": True, "isp": "Cloudflare"},
        "html": {"has_login_form": 1, "has_password_field": 1, "form_action_empty": 0, "iframe_count": 1, "external_script_count": 8, "hidden_element_count": 2},
        "ip":   {"is_tor": False, "is_proxy": False, "is_anonymous": False, "is_attacker": False},
    },
    {
        "name": "Smart phishing — scores 0 on ALL APIs (new domain)",
        "ml":   {"url": "https://netflix-billing-update.com/account/payment", "label": "legitimate", "confidence": 52},
        "vt":   {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 72},
        "ab":   {"abuse_score": 0, "total_reports": 0, "is_tor": False, "cdn_masked": False, "isp": "Namecheap"},
        "html": {"has_login_form": 1, "has_password_field": 1, "form_action_empty": 0, "iframe_count": 0, "external_script_count": 2, "hidden_element_count": 0},
        "ip":   {"is_tor": False, "is_proxy": False, "is_anonymous": False, "is_attacker": False},
    },
    {
        "name": "Evasive phishing — punycode homograph attack",
        "ml":   {"url": "https://xn--pypal-4ve.com/signin", "label": "legitimate", "confidence": 61},
        "vt":   {"malicious": 0, "suspicious": 1, "harmless": 5, "undetected": 60},
        "ab":   {"abuse_score": 10, "total_reports": 1, "is_tor": False, "cdn_masked": False, "isp": "OVH"},
        "html": {"has_login_form": 1, "has_password_field": 1, "form_action_empty": 0, "iframe_count": 0, "external_script_count": 3, "hidden_element_count": 0},
        "ip":   {"is_tor": False, "is_proxy": False, "is_anonymous": False, "is_attacker": False},
    },
    {
        "name": "Legitimate Google",
        "ml":   {"url": "https://www.google.com", "label": "legitimate", "confidence": 98},
        "vt":   {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 2},
        "ab":   {"abuse_score": 0, "total_reports": 0, "is_tor": False, "cdn_masked": False, "isp": "Google"},
        "html": {"has_login_form": 0, "has_password_field": 0, "form_action_empty": 0, "iframe_count": 0, "external_script_count": 2, "hidden_element_count": 0},
        "ip":   {"is_tor": False, "is_proxy": False, "is_anonymous": False, "is_attacker": False},
    },
    {
        "name": "Legitimate GitHub login",
        "ml":   {"url": "https://github.com/login", "label": "legitimate", "confidence": 95},
        "vt":   {"malicious": 0, "suspicious": 0, "harmless": 75, "undetected": 1},
        "ab":   {"abuse_score": 0, "total_reports": 0, "is_tor": False, "cdn_masked": False, "isp": "GitHub"},
        "html": {"has_login_form": 1, "has_password_field": 1, "form_action_empty": 0, "iframe_count": 0, "external_script_count": 4, "hidden_element_count": 0},
        "ip":   {"is_tor": False, "is_proxy": False, "is_anonymous": False, "is_attacker": False},
    },
]

print("=" * 65)
for t in cases:
    r = decide(t["ml"], t["vt"], t["ab"], t["html"], t["ip"])
    label = r["label"].upper()
    score = r["score"]
    icon  = "PASS" if (
        ("phishing" in t["name"].lower() or "evasive" in t["name"].lower() or "smart" in t["name"].lower()) and label == "PHISHING"
        or "legitimate" in t["name"].lower() and label in ("BENIGN", "SUSPICIOUS")
    ) else "FAIL"
    print(f"[{icon}] {t['name']}")
    print(f"      Label: {label} | Score: {score}")
    print(f"      Sources: {r['source_scores']}")
    print()
print("=" * 65)
