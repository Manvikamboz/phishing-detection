# 🛡️ Phishing Detection System

A hybrid phishing detection system that analyzes URLs using Machine Learning, HTML analysis, URL heuristics, and 5 threat intelligence APIs — fused together using a Bayesian log-odds engine to produce a single risk score.

---

## 🧱 Architecture

```
User → Streamlit UI → FastAPI → ┌─ ML Model (XGBoost x2)
                                ├─ HTML Scraper (BeautifulSoup)
                                ├─ VirusTotal API
                                ├─ AbuseIPDB API
                                ├─ IPStack API
                                ├─ IPQualityScore API
                                ├─ FetchSERP API
                                └─ URL Heuristics
                                        ↓
                               Bayesian Decision Engine
                                        ↓
                              Score (0–100) + Label + Reasons
```

---

## 🔄 Data Flow

1. **User** enters a URL in the Streamlit UI
2. **FastAPI** normalizes the URL, checks the 5-minute TTL cache, and runs SSRF protection
3. **In parallel**, the following run simultaneously:
   - HTML scraper fetches and parses the live page
   - All 5 external API checks (VirusTotal, AbuseIPDB, IPStack, FetchSERP, IPQualityScore)
4. **ML model** extracts ~87 features from the URL + page, enriched with FetchSERP/IPQS domain data, then averages predictions from 2 XGBoost models
5. **Decision Engine** applies Bayesian log-odds fusion across all 8 sources with weights, runs URL heuristic checks, applies hard override rules, and maps the posterior probability to a 0–100 score
6. **Result** is returned to the UI and cached — includes score, label, per-source scores, and reasons

---

## 📊 Detection Sources & Weights

| Source | Weight | What it checks |
|---|---|---|
| ML Model | 1.4 | ~87 URL + HTML features via 2 XGBoost models |
| IPQualityScore | 1.4 | Fraud score, phishing/malware flags, proxy/VPN |
| VirusTotal | 1.3 | ~90 antivirus engines scan the URL |
| FetchSERP | 1.2 | Domain age, Google index status, page rank |
| URL Heuristics | 1.1 | Brand impersonation, typosquatting, suspicious TLDs, punycode |
| HTML Analysis | 0.9 | Login forms, password fields, iframes, hidden elements |
| AbuseIPDB | 0.9 | IP abuse history, TOR exit node, CDN masking |
| IPStack | 0.8 | IP geolocation, TOR/proxy/attacker flags |

**Score thresholds:** `≥ 65 → phishing` | `35–64 → suspicious` | `< 35 → benign`

---

## 📦 Tech Stack

| Layer | Technology |
|---|---|
| UI | Streamlit + Plotly |
| API | FastAPI |
| ML | XGBoost + scikit-learn (2 models, ensemble averaged) |
| Scraping | BeautifulSoup + requests |
| Threat Intel | VirusTotal, AbuseIPDB, IPStack, FetchSERP, IPQualityScore |
| Async | asyncio + httpx |

---

## 🚀 Quick Start (Local)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Set up API keys
Edit `.env` and add your keys:
```
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
IPSTACK_API_KEY=your_key
FETCHSERP_API_KEY=your_key
IPQUALITYSCORE_API_KEY=your_key
```

### 3. Download dataset
- Download from: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
- Place the CSV file at: `ml_model/dataset.csv`

### 4. Train the model
```bash
python ml_model/train.py
```

### 5. Start the API
```bash
uvicorn api.main:app --reload
```

### 6. Start the UI (new terminal)
```bash
python -m streamlit run ui/app.py
```

---

## 🔑 Environment Variables

| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `IPSTACK_API_KEY` | IPStack geolocation + threat API key |
| `FETCHSERP_API_KEY` | FetchSERP domain age/index API key |
| `IPQUALITYSCORE_API_KEY` | IPQualityScore fraud/phishing API key |

---

## 📊 Example Output

```json
{
  "score": 95,
  "label": "phishing",
  "reasons": [
    "🚨 OVERRIDE: Both ML model and VirusTotal independently confirmed phishing",
    "ML model: HIGH confidence phishing (99.1%)",
    "VirusTotal: 7/90 engines flagged malicious",
    "IPQualityScore: URL flagged as phishing (fraud score 98)",
    "Domain is very new (3 days old) — high phishing risk",
    "Login form with password field detected"
  ],
  "source_scores": {
    "ML Model": 97,
    "VirusTotal": 89,
    "AbuseIPDB": 55,
    "IPStack": 50,
    "HTML Analysis": 72,
    "URL Heuristics": 81,
    "IPQualityScore": 99,
    "FetchSERP": 88
  }
}
```

---

## ⚠️ Limitations

- Depends on external APIs (rate limits apply on free tiers)
- Cannot detect highly obfuscated or zero-day attacks
- Domain age and page rank default to 0 if FetchSERP/IPQS keys are not set
- CDN-hosted phishing sites (Cloudflare, etc.) may show 0 AbuseIPDB score

---

## 🔮 Future Scope

- Deep learning-based URL analysis (LSTM/Transformer)
- Browser extension for real-time protection
- Email security system integration
- Image-based phishing detection (screenshot similarity)
- Automated retraining pipeline with new phishing feeds
