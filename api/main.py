import sys
import os
import time
import asyncio
from functools import lru_cache
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ml_model.predict import predict
from scraper.html_scraper import scrape
from threat_intel.api_checker import check_all, _is_safe_url
from decision.engine import decide

app = FastAPI(title="Phishing Detection API", version="2.0.0")


class URLRequest(BaseModel):
    url: str


class AlertRequest(BaseModel):
    url: str
    label: str
    score: int
    reasons: list[str]
    source: str = "n8n"


alerts_log: list[dict] = []

# Simple TTL cache: {url: (result, timestamp)}
_cache: dict = {}
_CACHE_TTL = 300  # seconds


def _get_cache(url: str):
    if url in _cache:
        result, ts = _cache[url]
        if time.time() - ts < _CACHE_TTL:
            return result
        del _cache[url]
    return None


def _set_cache(url: str, result: dict):
    _cache[url] = (result, time.time())


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


async def _analyze(url: str) -> dict:
    cached = _get_cache(url)
    if cached:
        return {**cached, "cached": True}

    if not _is_safe_url(url):
        raise HTTPException(status_code=400, detail="URL targets a private/reserved address (SSRF blocked)")

    try:
        ml_result = predict(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML prediction failed: {e}")

    # Run all external API calls + HTML scrape in parallel
    html_features, (vt_result, abuse_result, ipstack_result) = await asyncio.gather(
        asyncio.to_thread(scrape, url),
        check_all(url),
    )

    final = decide(ml_result, vt_result, abuse_result, html_features, ipstack_result)

    result = {
        "url":           url,
        "score":         final["score"],
        "label":         final["label"],
        "reasons":       final["reasons"],
        "source_scores": final["source_scores"],
        "ml":            ml_result,
        "virustotal":    vt_result,
        "abuseipdb":     abuse_result,
        "ipstack":       ipstack_result,
        "html_features": html_features,
        "cached":        False,
    }
    _set_cache(url, result)
    return result


@app.get("/")
def root():
    return {"status": "Phishing Detection API is running"}


@app.get("/health")
def health():
    return {"status": "ok", "cache_size": len(_cache)}


@app.post("/predict")
async def predict_url(req: URLRequest):
    return await _analyze(_normalize_url(req.url))


@app.get("/webhook")
@app.post("/webhook")
async def webhook(url: str = None, req: URLRequest = None):
    target = _normalize_url(req.url if req else url or "")
    if not target or target in ("http://", "https://"):
        raise HTTPException(status_code=400, detail="url is required")
    return await _analyze(target)


@app.post("/alert")
def receive_alert(alert: AlertRequest):
    alerts_log.append(alert.model_dump())
    return {"status": "received", "total_alerts": len(alerts_log)}


@app.get("/alerts")
def get_alerts():
    return alerts_log


@app.delete("/cache")
def clear_cache():
    _cache.clear()
    return {"status": "cache cleared"}


@app.get("/cache/logs")
def cache_logs():
    now = time.time()
    return [
        {
            "url":        url,
            "label":      result.get("label"),
            "score":      result.get("score"),
            "cached_at":  time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
            "expires_in": f"{max(0, int(_CACHE_TTL - (now - ts)))}s",
        }
        for url, (result, ts) in _cache.items()
    ]
