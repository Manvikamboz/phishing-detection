import os
import asyncio
import socket
import ipaddress
from datetime import datetime, timezone
import httpx
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()


def _env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


VIRUSTOTAL_KEY  = _env("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY   = _env("ABUSEIPDB_API_KEY")
IPSTACK_KEY     = _env("IPSTACK_API_KEY")
WHOISFREAKS_KEY = _env("WHOISFREAKS_API_KEY")
WHOISXML_KEY    = _env("WHOISXML_API_KEY")

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_BLOCKED_PREFIXES = ("192.168.", "10.", "172.16.", "169.254.")


def _is_safe_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        if not host:
            return False
        # Block explicitly known internal hostnames and raw private IPs typed directly
        if host in _BLOCKED_HOSTS:
            return False
        if any(host.startswith(p) for p in _BLOCKED_PREFIXES):
            return False
        # Only block raw IP addresses that are private — not domain names
        # A real domain like bennett.edu.in may resolve to a private IP on some networks
        # but it's still a legitimate domain that should be analyzed
        try:
            ipaddress.ip_address(host)  # raises if host is a domain name, not an IP
            addr = ipaddress.ip_address(host)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
        except ValueError:
            pass  # host is a domain name — always allow
        return True
    except Exception:
        return True  # Default allow — don't block on unexpected errors


def _resolve_ip(url: str) -> str:
    try:
        return socket.gethostbyname(urlparse(url).hostname or "")
    except Exception:
        return ""


def _days_since_iso(date_str: str | None) -> int:
    if not date_str:
        return -1
    try:
        cleaned = date_str.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - dt).total_seconds() // 86400))
    except Exception:
        return -1


def _looks_private(text: str | None) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(token in lowered for token in ("privacy", "redacted", "withheld", "proxy"))


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
    empty = {
        "ip": "",
        "abuse_score": 0,
        "total_reports": 0,
        "country": "",
        "isp": "",
        "usage_type": "",
        "is_tor": False,
        "cdn_masked": False,
        "note": None,
        "error": None,
    }
    if not ABUSEIPDB_KEY:
        return {**empty, "error": "ABUSEIPDB_API_KEY not set or empty"}
    try:
        ip = _resolve_ip(url)
        if not ip:
            # DNS failed — return zeros but flag it so UI knows
            return {
                **empty,
                "error": "DNS resolution failed — domain may not exist or is newly registered",
            }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
        resp.raise_for_status()
        payload = resp.json()
        errors = payload.get("errors") or []
        if errors:
            detail = errors[0].get("detail") if isinstance(errors[0], dict) else str(errors[0])
            return {**empty, "ip": ip, "error": detail or "AbuseIPDB returned an error"}

        data = payload.get("data")
        if not isinstance(data, dict):
            return {**empty, "ip": ip, "error": "Unexpected AbuseIPDB response"}

        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        is_tor = data.get("isTor", False)
        usage_type = data.get("usageType", "")
        isp = data.get("isp") or ""

        # Flag shared hosting / CDN masking phishing sites
        cdn_masked = any(cdn in isp.lower() for cdn in ["cloudflare", "fastly", "akamai", "amazon", "google"])

        return {
            **empty,
            "ip":            ip,
            "abuse_score":   abuse_score,
            "total_reports": total_reports,
            "country":       data.get("countryCode", ""),
            "isp":           isp,
            "usage_type":    usage_type,
            "is_tor":        is_tor,
            "cdn_masked":    cdn_masked,
            "note":          "IP behind CDN — abuse score may be 0 even for phishing" if cdn_masked else None,
        }
    except httpx.HTTPStatusError as e:
        return {**empty, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {**empty, "error": str(e)}


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



async def _check_whoisfreaks(url: str) -> dict:
    """Fetch live WHOIS registration details via WhoisFreaks."""
    empty = {
        "domain_age_days": -1,
        "registered": False,
        "registrar": "",
        "privacy_protected": False,
        "nameserver_count": 0,
        "created_date": None,
        "expires_date": None,
        "error": None,
    }
    if not WHOISFREAKS_KEY:
        return {**empty, "error": "WHOISFREAKS_API_KEY not set or empty"}
    try:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return {**empty, "error": "Invalid URL hostname"}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.whoisfreaks.com/v1.0/whois",
                params={
                    "apiKey": WHOISFREAKS_KEY,
                    "whois": "live",
                    "domainName": hostname,
                },
                headers={"Accept": "application/json"},
            )
        resp.raise_for_status()
        payload = resp.json()
        data = payload[0] if isinstance(payload, list) and payload else payload
        if not isinstance(data, dict):
            return {**empty, "error": "Unexpected WhoisFreaks response"}
        created_date = data.get("create_date")
        registrant = data.get("registrant_contact") or {}
        registry_data = data.get("registry_data") or {}
        age_days = _days_since_iso(created_date)
        nameservers = data.get("name_servers") or registry_data.get("name_servers") or []
        nameserver_count = len(nameservers) if isinstance(nameservers, list) else 0
        privacy = _looks_private(registrant.get("name")) or _looks_private(registrant.get("company"))

        return {
            "domain_age_days":  age_days,
            "registered":       str(data.get("domain_registered", "")).lower() == "yes",
            "registrar":        (data.get("domain_registrar") or {}).get("registrar_name", ""),
            "privacy_protected": privacy,
            "nameserver_count": nameserver_count,
            "created_date":     created_date,
            "expires_date":     data.get("expiry_date"),
            "error":            None,
        }
    except httpx.HTTPStatusError as e:
        return {**empty, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {**empty, "error": str(e)}


async def _check_whoisxml(url: str) -> dict:
    """Fetch WHOIS registration details via WhoisXML API."""
    empty = {
        "domain_age_days": -1,
        "estimated_domain_age": -1,
        "registrar": "",
        "registrant_country": "",
        "privacy_protected": False,
        "nameserver_count": 0,
        "created_date": None,
        "expires_date": None,
        "registered": False,
        "error": None,
    }
    if not WHOISXML_KEY:
        return {**empty, "error": "WHOISXML_API_KEY not set or empty"}
    try:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return {**empty, "error": "Invalid URL hostname"}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "apiKey": WHOISXML_KEY,
                    "domainName": hostname,
                    "outputFormat": "JSON",
                },
                headers={"Accept": "application/json"},
            )
        resp.raise_for_status()
        data = resp.json()
        whois = data.get("WhoisRecord") or {}
        registry = whois.get("registryData") or {}
        created_date = whois.get("createdDate") or registry.get("createdDate")
        expires_date = whois.get("expiresDate") or registry.get("expiresDate")
        registrant = whois.get("registrant") or registry.get("registrant") or {}
        estimated_age = whois.get("estimatedDomainAge", -1)
        if isinstance(estimated_age, str) and estimated_age.isdigit():
            estimated_age = int(estimated_age)
        age_days = estimated_age if isinstance(estimated_age, int) and estimated_age >= 0 else _days_since_iso(created_date)
        name_servers = (whois.get("nameServers") or {}).get("hostNames") or (registry.get("nameServers") or {}).get("hostNames") or []
        raw_segments = [
            registrant.get("name"),
            registrant.get("organization"),
            whois.get("rawText"),
            registry.get("rawText"),
        ]
        return {
            "domain_age_days":      age_days,
            "estimated_domain_age": estimated_age if isinstance(estimated_age, int) else -1,
            "registrar":            whois.get("registrarName") or registry.get("registrarName", ""),
            "registrant_country":   registrant.get("country") or registrant.get("countryCode", ""),
            "privacy_protected":    any(_looks_private(text) for text in raw_segments),
            "nameserver_count":     len(name_servers) if isinstance(name_servers, list) else 0,
            "created_date":         created_date,
            "expires_date":         expires_date,
            "registered":           whois.get("dataError") != "MISSING_WHOIS_DATA",
            "error":                None,
        }
    except httpx.HTTPStatusError as e:
        return {**empty, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {**empty, "error": str(e)}



async def check_all(url: str) -> tuple:
    """Run all API checks concurrently — returns (vt, abuse, ipstack, whoisfreaks, whoisxml)."""
    return await asyncio.gather(
        _check_virustotal(url),
        _check_abuseipdb(url),
        _check_ipstack(url),
        _check_whoisfreaks(url),
        _check_whoisxml(url),
    )
