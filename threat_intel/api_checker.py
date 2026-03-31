import os
import socket
import ipaddress
import httpx
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY")
IPSTACK_KEY    = os.getenv("IPSTACK_API_KEY")

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
        async with httpx.AsyncClient(timeout=30) as client:
            # Step 1: submit URL
            resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}
            )
            analysis_id = resp.json()["data"]["id"]

            # Step 2: poll until status is completed (max 6 attempts x 3s)
            for _ in range(6):
                result = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers
                )
                rjson  = result.json()
                status = rjson.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    break
                await asyncio.sleep(3)

        stats = rjson["data"]["attributes"]["stats"]
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


# Public sync wrappers (kept for backward compat with non-async callers)
import asyncio


def _run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return loop.run_until_complete(coro)
    except Exception:
        return asyncio.run(coro)


def check_virustotal(url: str) -> dict:
    return _run(_check_virustotal(url))


def check_abuseipdb(url: str) -> dict:
    return _run(_check_abuseipdb(url))


def check_ipstack(url: str) -> dict:
    return _run(_check_ipstack(url))


async def check_all(url: str) -> tuple:
    """Run all three API checks concurrently."""
    import asyncio
    return await asyncio.gather(
        _check_virustotal(url),
        _check_abuseipdb(url),
        _check_ipstack(url),
    )
