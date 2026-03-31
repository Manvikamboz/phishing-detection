import requests
from bs4 import BeautifulSoup


def scrape(url: str) -> dict:
    features = {
        "has_login_form": 0,
        "has_password_field": 0,
        "external_script_count": 0,
        "iframe_count": 0,
        "hidden_element_count": 0,
        "link_count": 0,
        "image_count": 0,
        "has_favicon": 0,
        "form_action_empty": 0,
        "error": None,
    }
    try:
        resp = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, "lxml")

        forms = soup.find_all("form")
        features["has_login_form"] = int(len(forms) > 0)
        features["form_action_empty"] = int(
            any(f.get("action", "").strip() in ("", "#") for f in forms)
        )
        features["has_password_field"] = int(
            bool(soup.find("input", {"type": "password"}))
        )
        features["external_script_count"] = len(
            [s for s in soup.find_all("script", src=True) if url not in (s.get("src") or "")]
        )
        features["iframe_count"] = len(soup.find_all("iframe"))
        features["hidden_element_count"] = len(
            soup.find_all(style=lambda v: v and "display:none" in v.replace(" ", ""))
        )
        features["link_count"] = len(soup.find_all("a"))
        features["image_count"] = len(soup.find_all("img"))
        features["has_favicon"] = int(
            bool(soup.find("link", rel=lambda r: r and "icon" in r))
        )
    except Exception as e:
        features["error"] = str(e)

    return features
