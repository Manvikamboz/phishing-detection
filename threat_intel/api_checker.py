import os
import asyncio
import socket
import ipaddress
import httpx
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY")
IPSTACK_KEY     = os.getenv("IPSTACK_API_KEY")
FETCHSERP_KEY   = os.getenv("FETCHSERP_API_KEY")
IPQS_KEY        = os.getenv("IPQUALITYSCORE_API_KEY")

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_BLOCKED_PREFIXES = ("192.168.", "10.", "172.16.", "169.254.")


def _is_safe_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        if not host:
            return False
        # Block explicitly known internal hostnames
        if host in _BLOCKED_HOSTS:
            return False
        if any(host.startswith(p) for p in _BLOCKED_PREFIXES):
            return False
        # Only block if DNS resolves to a private/loopback address
        # If DNS fails (unresolvable domain) → allow through for analysis
        try:
            ip = socket.gethostbyname(host)
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
        except socket.gaierror:
            pass  # Unresolvable domain — still allow, URL heuristics will score it
        return True
    except Exception:
        return True  # Default allow — don't block on unexpected errors


def _resolve_ip(url: str) -> str:
    try:
        return socket.gethostbyname(urlparse(url).hostname or "")
    except Exception:
        return ""


async def _check_virustotal(url: str) -> dict:
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        async with httpx.AsyncClient(timeout=90) as client:
            # Step 1: submit URL
            resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}
            )
            analysis_id = resp.json()["data"]["id"]

            # Step 2: poll until status is completed (max 15 attempts x 4s = 60s)
            rjson = {}
            for _ in range(15):
                result = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers
                )
                rjson  = result.json()
                status = rjson.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    break
                await asyncio.sleep(4)

            stats = rjson.get("data", {}).get("attributes", {}).get("stats", {})
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "error": None,
        }
    except httpx.HTTPStatusError as e:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "error": str(e)}


async def _check_abuseipdb(url: str) -> dict:
    try:
        ip = _resolve_ip(url)
        if not ip:
            # DNS failed — return zeros but flag it so UI knows
            return {"ip": "", "abuse_score": 0, "total_reports": 0, "country": "",
                    "error": "DNS resolution failed — domain may not exist or is newly registered"}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
        data = resp.json().get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        is_tor = data.get("isTor", False)
        usage_type = data.get("usageType", "")
        isp = data.get("isp", "")

        # Flag shared hosting / CDN masking phishing sites
        cdn_masked = any(cdn in isp.lower() for cdn in ["cloudflare", "fastly", "akamai", "amazon", "google"])

        return {
            "ip":           ip,
            "abuse_score":  abuse_score,
            "total_reports":total_reports,
            "country":      data.get("countryCode", ""),
            "isp":          isp,
            "usage_type":   usage_type,
            "is_tor":       is_tor,
            "cdn_masked":   cdn_masked,
            "note":         "IP behind CDN — abuse score may be 0 even for phishing" if cdn_masked else None,
            "error":        None,
        }
    except httpx.HTTPStatusError as e:
        return {"ip": "", "abuse_score": 0, "total_reports": 0, "country": "", "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"ip": "", "abuse_score": 0, "total_reports": 0, "country": "", "error": str(e)}


async def _check_ipstack(url: str) -> dict:
    try:
        ip = _resolve_ip(url)
        if not ip:
            return {"ip": "", "country": "", "error": "DNS resolution failed"}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"http://api.ipstack.com/{ip}",
                params={"access_key": IPSTACK_KEY},
            )
        data = resp.json()
        threat = data.get("threat") or {}
        return {
            "ip":           ip,
            "country":      data.get("country_name", ""),
            "country_code": data.get("country_code", ""),
            "region":       data.get("region_name", ""),
            "city":         data.get("city", ""),
            "latitude":     data.get("latitude"),
            "longitude":    data.get("longitude"),
            "is_tor":       threat.get("is_tor", False),
            "is_proxy":     threat.get("is_proxy", False),
            "is_anonymous": threat.get("is_anonymous", False),
            "is_attacker":  threat.get("is_attacker", False),
            "error":        None,
        }
    except httpx.HTTPStatusError as e:
        return {"ip": "", "country": "", "is_tor": False, "is_proxy": False, "is_anonymous": False, "is_attacker": False, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"ip": "", "country": "", "is_tor": False, "is_proxy": False, "is_anonymous": False, "is_attacker": False, "error": str(e)}



async def _check_fetchserp(url: str) -> dict:
    """Fetch domain age, google index status, and page rank via FetchSERP."""
    empty = {"domain_age_days": -1, "google_index": 0, "page_rank": 0, "error": None}
    if not FETCHSERP_KEY:
        return {**empty, "error": "FETCHSERP_API_KEY not set"}
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.fetchserp.com/v1/domain_info",
                params={"domain": hostname, "api_key": FETCHSERP_KEY},
            )
        resp.raise_for_status()
        data = resp.json()
        return {
            "domain_age_days":  data.get("domain_age_days", -1),
            "google_index":     int(data.get("google_indexed", False)),
            "page_rank":        data.get("page_rank", 0),
            "error":            None,
        }
    except httpx.HTTPStatusError as e:
        return {**empty, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {**empty, "error": str(e)}


async def _check_ipqualityscore(url: str) -> dict:
    """Check URL fraud score, proxy/VPN/bot signals via IPQualityScore."""
    empty = {"fraud_score": 0, "is_proxy": False, "is_vpn": False,
             "is_bot": False, "phishing": False, "malware": False,
             "suspicious": False, "risk_score": 0, "error": None}
    if not IPQS_KEY:
        return {**empty, "error": "IPQUALITYSCORE_API_KEY not set"}
    try:
        import urllib.parse
        encoded = urllib.parse.quote(url, safe="")
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.ipqualityscore.com/api/json/url/{IPQS_KEY}/{encoded}"
            )
        resp.raise_for_status()
        data = resp.json()
        age_days = -1
        domain_age = data.get("domain_age", {})
        if isinstance(domain_age, dict) and domain_age.get("timestamp"):
            import time
            age_days = int((time.time() - domain_age["timestamp"]) / 86400)
        return {
            "fraud_score":    data.get("risk_score", 0),
            "is_proxy":       data.get("proxy", False),
            "is_vpn":         data.get("vpn", False),
            "is_bot":         data.get("bot_status", False),
            "phishing":       data.get("phishing", False),
            "malware":        data.get("malware", False),
            "suspicious":     data.get("suspicious", False),
            "risk_score":     data.get("risk_score", 0),
            "domain_rank":    data.get("domain_rank", 0),
            "dns_valid":      data.get("dns_valid", True),
            "domain_age_days": age_days,
            "error":          None,
        }
    except httpx.HTTPStatusError as e:
        return {**empty, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {**empty, "error": str(e)}



async def check_all(url: str) -> tuple:
    """Run all API checks concurrently — returns (vt, abuse, ipstack, fetchserp, ipqs)."""
    return await asyncio.gather(
        _check_virustotal(url),
        _check_abuseipdb(url),
        _check_ipstack(url),
        _check_fetchserp(url),
        _check_ipqualityscore(url),
    )
