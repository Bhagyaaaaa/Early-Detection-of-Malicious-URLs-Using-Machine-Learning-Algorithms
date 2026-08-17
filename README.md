# Early Detection of Malicious URLs Using Machine Learning

An 8th-semester project on detecting phishing / malicious URLs, combining a trained XGBoost model with a live Flask web app that scores URLs in real time using URL-structure and lexical features.

## Overview

The project has two parts:

1. **Model training** – an XGBoost classifier (`xgb_model.json`) trained on engineered URL features to distinguish malicious from benign URLs.
2. **Live web app** (`XGBOOST_8TH_Sem_Project/app.py`) – a Flask application with a browser UI where you paste in a URL and get an instant verdict. It extracts 30+ features per URL (entropy, suspicious keywords, TLD reputation, IP-in-URL, brand impersonation in subdomain, redirect patterns, etc.) and scores risk with a transparent, weighted rule-based engine, returning a verdict plus a breakdown of which risk factors triggered.

> **Note:** the shipped web app (`app.py`) currently uses the rule-based scoring engine rather than loading `xgb_model.json` directly — wiring the trained XGBoost model into the live endpoint is a natural next step (see Future Work).

## Features Extracted

URL length, hostname/path length, counts of dots/hyphens/digits/special characters, Shannon entropy of the URL and hostname, presence of an IP address in the URL, suspicious TLDs (`.xyz`, `.tk`, `.top`, etc.), suspicious keywords (`login`, `verify`, `secure`, `paypal`, ...), brand names appearing in the subdomain or path, HTTPS usage, and more.

## Tech Stack

- **Model:** XGBoost, pandas, NumPy
- **Backend:** Flask, tldextract
- **Frontend:** Single-page HTML/CSS/JS served directly from Flask

## Project Structure

```
Early-Detection-of-Malicious-URLs-Using-Machine-Learning-Algorithms/
├── IEEE PAPER .docx                    # IEEE-format research paper
├── report_merged.pdf                   # Consolidated project report
└── XGBOOST_8TH_Sem_Project/
    ├── app.py                          # Flask app: feature extraction + risk scoring + UI
    ├── requirements.txt
    └── xgb_model.json                  # Trained XGBoost model artifact
```

## Getting Started

```bash
git clone https://github.com/Bhagyaaaaa/Early-Detection-of-Malicious-URLs-Using-Machine-Learning-Algorithms.git
cd Early-Detection-of-Malicious-URLs-Using-Machine-Learning-Algorithms/XGBOOST_8TH_Sem_Project
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser and enter a URL to analyze.

## API

**POST** `/predict`
```json
{ "url": "https://example.com/login" }
```
Response:
```json
{
  "prediction": "Malicious" | "Benign",
  "confidence": 72.5,
  "risk_factors": [ { "factor": "Brand Name in Subdomain", "severity": "critical", "weight": 35 } ]
}
```

## Future Work

- Load `xgb_model.json` directly in `/predict` so the live app scores using the trained model rather than the rule-based fallback
- Compare rule-based vs. model-based verdicts on a held-out test set
- Add a training script/notebook to the repo so the model is reproducible from raw data

## Documentation

Full methodology and results are written up in `IEEE PAPER .docx` and `report_merged.pdf`.

## Author

**Bhagyaaaaa** — [GitHub](https://github.com/Bhagyaaaaa)
