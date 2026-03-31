# 🛡️ Phishing Detection System

A hybrid phishing detection system using Machine Learning, HTML analysis, and threat intelligence APIs.

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
streamlit run ui/app.py
```

---

## ☁️ Deploy to Render

1. Push this repo to GitHub
2. Go to https://render.com → New → Blueprint
3. Connect your GitHub repo (it will detect `render.yaml`)
4. Add environment variables in Render dashboard:
   - `VIRUSTOTAL_API_KEY`
   - `ABUSEIPDB_API_KEY`
   - `API_URL` → set to your deployed FastAPI service URL
5. Deploy both services

> ⚠️ Make sure `ml_model/phishing_model.pkl` is committed to the repo before deploying (train locally first).

---

## 🤖 n8n Automation

### What it does
- Exposes a webhook (`POST /check-url`) that n8n listens on
- n8n calls your FastAPI `/webhook` with the URL
- Routes result by label: **phishing → log alert + Slack**, **suspicious → Slack warning**
- All alerts are stored via `POST /alert` and viewable at `GET /alerts`

### Setup
1. Install & start n8n:
```bash
npx n8n
```
2. Open http://localhost:5678 → **Import workflow** → select `n8n/phishing_detection_workflow.json`
3. In the Slack nodes, add your Slack credential and set the target channel
4. Activate the workflow — your n8n webhook URL will be:
```
http://localhost:5678/webhook/check-url
```
5. Test it:
```bash
curl -X POST http://localhost:5678/webhook/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-site.com"}'
```

### New API Endpoints
| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/webhook?url=` | n8n-friendly predict endpoint |
| POST | `/alert` | Receive alert from n8n |
| GET | `/alerts` | View all logged alerts |

---

## 🧱 Architecture

```
User → Streamlit UI → FastAPI → ML Model
                             → HTML Scraper
                             → VirusTotal API
                             → AbuseIPDB API
                             → Decision Engine → Score + Label + Reasons
```

---

## 📦 Tech Stack

| Layer | Technology |
|---|---|
| UI | Streamlit |
| API | FastAPI |
| ML | XGBoost + scikit-learn |
| Scraping | BeautifulSoup |
| Threat Intel | VirusTotal, AbuseIPDB |
| Deployment | Render |
