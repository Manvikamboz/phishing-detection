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

> ⚠️ You need **two separate Railway services** from the same GitHub repo — one for the API, one for the UI.

### Step 1 — Deploy the API service
1. Go to https://railway.app → Login with GitHub
2. Click **New Project** → **Deploy from GitHub repo** → select your repo
3. Railway will auto-detect `railway.json` and use: `uvicorn api.main:app --host 0.0.0.0 --port $PORT`
4. Go to **Variables** tab and add:
   - `VIRUSTOTAL_API_KEY` → your key
   - `ABUSEIPDB_API_KEY` → your key
   - `IPSTACK_API_KEY` → your key
5. Go to **Settings** → **Networking** → **Generate Domain**
6. Copy the API URL (e.g. `https://your-api.up.railway.app`)

### Step 2 — Deploy the UI service
1. In the **same Railway project**, click **+ New** → **GitHub Repo** → select the same repo
2. Go to **Settings** → **Deploy** → **Custom Start Command** and set:
   ```
   python -m streamlit run ui/app.py --server.port $PORT --server.address 0.0.0.0
   ```
3. Go to **Variables** tab and add:
   - `API_URL` → the API URL from Step 1 (e.g. `https://your-api.up.railway.app`)
4. Go to **Settings** → **Networking** → **Generate Domain**

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
