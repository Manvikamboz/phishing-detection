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

## 🔑 Environment Variables

| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |

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
