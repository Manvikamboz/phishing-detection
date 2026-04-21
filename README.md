# Phishing Detection System

A hybrid phishing detection system that scores a URL using:

- a stacked ML ensemble
- live HTML/page analysis
- URL heuristics
- VirusTotal, AbuseIPDB, IPStack, WhoisFreaks, and WhoisXML
- a Bayesian fusion engine that combines all signals into one `0-100` risk score

## Architecture

```text
Streamlit UI -> FastAPI API -> parallel analysis
                           -> HTML scraper
                           -> ML predictor
                           -> VirusTotal
                           -> AbuseIPDB
                           -> IPStack
                           -> WhoisFreaks
                           -> WhoisXML
                           -> Bayesian decision engine
                           -> score + label + reasons
```

## Labels

- `0-34`: `benign`
- `35-64`: `suspicious`
- `65-100`: `phishing`

## Project Structure

```text
api/              FastAPI app and endpoints
decision/         Bayesian fusion / rule engine
ml_model/         training, prediction, datasets, saved models
scraper/          HTML feature extraction
threat_intel/     external API integrations + SSRF checks
ui/               Streamlit frontend
test_engine.py    local decision-engine smoke test
```

## Requirements

- Python 3.10+
- `pip`
- API keys for any threat-intel providers you want to enable

Install dependencies:

```bash
pip install -r requirements.txt
```

## Environment Variables

Create a `.env` file in the project root.

```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
IPSTACK_API_KEY=
WHOISFREAKS_API_KEY=
WHOISXML_API_KEY=
API_URL=http://localhost:8000
```

Notes:

- `API_URL` is used by the Streamlit UI and defaults to `http://localhost:8000`.
- If a provider key is missing, that source returns an error payload and the rest of the system still runs.
- WHOIS enrichment improves model features like domain age but is optional.

## Datasets And Training

The project supports up to three saved models:

- `ml_model/phishing_model.pkl` from `ml_model/dataset.csv`
- `ml_model/phishing_model_2.pkl` from `ml_model/dataset2.csv`
- `ml_model/phishing_model_combined.pkl` from both datasets together

This repo already contains `ml_model/dataset2.csv`.

If you also want the first dataset, download it from Kaggle and place it here:

```text
ml_model/dataset.csv
```

Suggested source:

- <https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset>

Train the models in Colab with `ml_model/phishing_train_colab.ipynb`, then download the generated `.pkl` files and place them in `ml_model/`.

The app can run with one or more trained model files present, but prediction will fail if none of the model files exist.

## Running Locally

Start the API:

```bash
uvicorn api.main:app --reload
```

Start the UI in a second terminal:

```bash
python3 -m streamlit run ui/app.py
```

## API Endpoints

Base URL: `http://localhost:8000`

- `GET /` health-style welcome response
- `GET /health` API status and cache size
- `POST /predict` analyze a URL
- `GET /webhook` analyze via query param
- `POST /webhook` analyze via JSON body
- `POST /alert` store alert payloads
- `GET /alerts` list received alerts
- `DELETE /cache` clear in-memory cache
- `GET /cache/logs` inspect cached analyses

Example request:

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Example response:

```json
{
  "url": "https://example.com",
  "score": 42,
  "label": "suspicious",
  "reasons": [
    "ML model uncertain (52.0% legitimate confidence)"
  ],
  "source_scores": {
    "ML Model": 60,
    "VirusTotal": 23,
    "AbuseIPDB": 50,
    "IPStack": 50,
    "HTML Analysis": 50,
    "URL Heuristics": 41,
    "WhoisFreaks": 50,
    "WhoisXML": 50
  },
  "cached": false
}
```

## How Detection Works

1. The API normalizes the incoming URL and blocks obvious SSRF targets like localhost and private IPs.
2. HTML scraping and all threat-intel API checks run concurrently.
3. The predictor extracts URL and page-derived features, then averages probabilities across every trained model file it can load.
4. The decision engine combines ML, WHOIS, HTML, IP, VirusTotal, and URL-heuristic evidence using weighted Bayesian log-odds.
5. Hard overrides raise the final score for especially strong phishing evidence.
6. Results are cached in memory for 5 minutes.

## Tech Stack

- FastAPI
- Streamlit
- scikit-learn
- XGBoost
- LightGBM
- pandas / numpy
- requests / httpx
- BeautifulSoup / lxml
- Plotly

## Notes And Limitations

- External API calls can be slow and are subject to rate limits.
- The cache is in-memory only and resets when the API restarts.
- `IPStack` is called over `http` in the current implementation because that is how the code is written.
- HTML analysis depends on the target page being reachable from the machine running the app.
- Some phishing sites hidden behind CDNs can appear clean in IP reputation services.

## Quick Check

You can run the decision-engine smoke test with:

```bash
python3 test_engine.py
```
