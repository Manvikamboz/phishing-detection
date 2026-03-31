# 🛡️ Phishing Detection System

A hybrid phishing detection system using Machine Learning, HTML analysis, and threat intelligence APIs.

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
| Deployment | Railway |

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
python -m streamlit run ui/app.py
```

---

## ☁️ Deploy to Railway

### Deploy API
1. Go to https://railway.app → Login with GitHub
2. Click **New Project** → **Deploy from GitHub repo**
3. Select `phishing-detection` repo
4. Go to **Variables** tab and add:
   - `VIRUSTOTAL_API_KEY` → your key
   - `ABUSEIPDB_API_KEY` → your key
5. Go to **Settings** → **Domains** → **Generate Domain**
6. Copy your API URL (e.g. `https://phishing-detection.up.railway.app`)

### Deploy UI
1. Click **New Service** in the same Railway project
2. Select the same GitHub repo
3. Go to **Settings** → **Start Command** and set:
   ```
   python -m streamlit run ui/app.py --server.port $PORT --server.address 0.0.0.0
   ```
4. Go to **Variables** tab and add:
   - `API_URL` → your Railway API URL from above
5. Go to **Settings** → **Domains** → **Generate Domain**

> ⚠️ Make sure `ml_model/phishing_model.pkl` is committed to the repo before deploying (train locally first).

---

## 🔑 Environment Variables

| Variable | Service | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | API | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | API | AbuseIPDB API key |
| `API_URL` | UI | Deployed FastAPI URL |

---

## 📊 Example Output

```json
{
  "score": 95,
  "label": "phishing",
  "reasons": [
    "ML model flagged as phishing (99.9% confidence)",
    "VirusTotal: 5 engines flagged as malicious",
    "Login form with password field detected"
  ]
}
```

---

## ⚠️ Limitations

- Depends on external APIs (VirusTotal, AbuseIPDB)
- Cannot detect highly obfuscated attacks
- Some features (domain age, page rank) default to 0 without paid APIs

---

## 🔮 Future Scope

- Deep learning-based URL analysis
- Browser extension for real-time protection
- Email security system integration
- Image-based phishing detection
