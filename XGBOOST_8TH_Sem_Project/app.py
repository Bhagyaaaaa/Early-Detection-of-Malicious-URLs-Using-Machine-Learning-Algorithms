from flask import Flask, request, jsonify, render_template_string
import xgboost as xgb
import pandas as pd
import numpy as np
import re, math
import tldextract
from urllib.parse import urlparse

app = Flask(__name__)

# ── Load trained model ────────────────────────────────────────
model = xgb.XGBClassifier()
model.load_model("xgb_model.json")   # we'll save this from Colab

# ── Feature extractor (same function as before) ───────────────
def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url)
        ext    = tldextract.extract(url)
    except:
        return None

    hostname = parsed.netloc or ""
    path     = parsed.path    or ""

    def shannon_entropy(s):
        if not s: return 0
        prob = [s.count(c)/len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    suspicious_words = ["login","verify","secure","account","update",
                        "banking","confirm","password","signin","paypal",
                        "ebay","amazon","apple","microsoft","free","lucky"]
    suspicious_tlds  = ["xyz","tk","ml","ga","cf","gq","top","club",
                        "work","date","racing","download","stream","gdn"]

    features["url_length"]          = len(url)
    features["hostname_length"]     = len(hostname)
    features["path_length"]         = len(path)
    features["num_dots"]            = url.count(".")
    features["num_hyphens"]         = url.count("-")
    features["num_underscores"]     = url.count("_")
    features["num_slashes"]         = url.count("/")
    features["num_at"]              = url.count("@")
    features["num_question"]        = url.count("?")
    features["num_equals"]          = url.count("=")
    features["num_ampersand"]       = url.count("&")
    features["num_percent"]         = url.count("%")
    features["num_digits"]          = sum(c.isdigit() for c in url)
    features["digit_ratio"]         = features["num_digits"] / (len(url) + 1)
    features["num_params"]          = len(parsed.query.split("&")) if parsed.query else 0
    features["hostname_entropy"]    = shannon_entropy(hostname)
    features["url_entropy"]         = shannon_entropy(url)
    features["suspicious_keywords"] = sum(w in url.lower() for w in suspicious_words)
    features["has_ip_in_url"]       = 1 if re.match(r"http[s]?://(\d{1,3}\.){3}\d{1,3}", url) else 0
    features["subdomain_depth"]     = len(ext.subdomain.split(".")) if ext.subdomain else 0
    features["domain_length"]       = len(ext.domain) if ext.domain else 0
    features["tld_length"]          = len(ext.suffix)  if ext.suffix  else 0
    features["suspicious_tld"]      = 1 if ext.suffix in suspicious_tlds else 0
    features["is_https"]            = 1 if parsed.scheme == "https" else 0
    features["has_port"]            = 1 if parsed.port else 0
    features["has_login_keyword"]   = 1 if re.search(r"login|signin|logon|authenticate", url, re.I) else 0
    features["has_redirect"]        = 1 if re.search(r"redirect|redir|url=|link=", url, re.I) else 0
    features["has_double_slash"]    = 1 if "//" in path else 0
    features["has_hex_encoding"]    = 1 if "%" in url else 0
    features["path_depth"]          = path.count("/")
    features["has_exe_extension"]   = 1 if re.search(r"\.(exe|php|js|zip|rar|docm|xlsm)$", path, re.I) else 0
    features["domain_has_digits"]   = 1 if re.search(r"\d", ext.domain) else 0
    features["has_subdomain"]       = 1 if ext.subdomain else 0
    features["tld_in_subdomain"]    = 1 if re.search(r"\.(com|net|org|gov|edu)", ext.subdomain, re.I) else 0
    features["brand_in_subdomain"]  = 1 if re.search(r"paypal|google|apple|amazon|microsoft|facebook", ext.subdomain, re.I) else 0
    features["brand_in_path"]       = 1 if re.search(r"paypal|google|apple|amazon|microsoft|facebook", path, re.I) else 0

    return features

# ── HTML Template ─────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Malicious URL Detector</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; }
    body { background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: #1e293b; border-radius: 16px; padding: 40px; width: 640px; box-shadow: 0 25px 50px rgba(0,0,0,0.4); }
    h1 { font-size: 22px; margin-bottom: 6px; color: #f8fafc; }
    .subtitle { font-size: 13px; color: #94a3b8; margin-bottom: 28px; }
    input { width: 100%; padding: 14px 16px; border-radius: 10px; border: 1px solid #334155;
            background: #0f172a; color: #f1f5f9; font-size: 14px; margin-bottom: 14px; outline: none; }
    input:focus { border-color: #6366f1; }
    button { width: 100%; padding: 14px; border-radius: 10px; border: none;
             background: #6366f1; color: white; font-size: 15px; font-weight: 600; cursor: pointer; }
    button:hover { background: #4f46e5; }
    .result { margin-top: 24px; padding: 20px; border-radius: 12px; display: none; }
    .malicious { background: #450a0a; border: 1px solid #dc2626; }
    .benign    { background: #052e16; border: 1px solid #16a34a; }
    .verdict   { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
    .confidence{ font-size: 13px; color: #94a3b8; margin-bottom: 16px; }
    .features  { font-size: 12px; }
    .feat-row  { display: flex; justify-content: space-between; padding: 5px 0;
                 border-bottom: 1px solid rgba(255,255,255,0.07); }
    .feat-name { color: #94a3b8; }
    .feat-val  { color: #f1f5f9; font-weight: 500; }
    .tag { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; margin-bottom: 12px; }
    .tag-mal { background: #dc2626; color: white; }
    .tag-ben { background: #16a34a; color: white; }
    .loading { text-align: center; color: #94a3b8; font-size: 13px; display: none; margin-top: 16px; }
  </style>
</head>
<body>
<div class="card">
  <h1>🔍 Malicious URL Detector</h1>
  <p class="subtitle">Powered by XGBoost · 382,985 URLs trained · AUC-ROC 0.9992</p>

  <input type="text" id="urlInput" placeholder="Enter any URL e.g. http://suspicious-login.xyz/verify"
         onkeydown="if(event.key==='Enter') analyse()"/>
  <button onclick="analyse()">Analyse URL</button>

  <div class="loading" id="loading">Analysing...</div>

  <div class="result" id="result">
    <div class="tag" id="tag"></div>
    <div class="verdict" id="verdict"></div>
    <div class="confidence" id="confidence"></div>
    <div class="features" id="features"></div>
  </div>
</div>

<script>
async function analyse() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) return;

  document.getElementById("loading").style.display = "block";
  document.getElementById("result").style.display  = "none";

  const resp = await fetch("/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  const data = await resp.json();

  document.getElementById("loading").style.display = "none";

  const box = document.getElementById("result");
  box.className = "result " + (data.prediction === "Malicious" ? "malicious" : "benign");
  box.style.display = "block";

  document.getElementById("tag").className    = "tag " + (data.prediction === "Malicious" ? "tag-mal" : "tag-ben");
  document.getElementById("tag").textContent  = data.prediction.toUpperCase();
  document.getElementById("verdict").textContent    = data.prediction === "Malicious"
    ? "⚠️ This URL appears to be malicious" : "✅ This URL appears to be safe";
  document.getElementById("confidence").textContent = `Confidence: ${data.confidence}%`;

  let html = "<div style='margin-bottom:8px;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;'>Top signals detected</div>";
  data.top_features.forEach(f => {
    html += `<div class="feat-row"><span class="feat-name">${f.feature}</span><span class="feat-val">${f.value}</span></div>`;
  });
  document.getElementById("features").innerHTML = html;
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url  = data.get("url", "")

    feats = extract_features(url)
    if feats is None:
        return jsonify({"error": "Could not parse URL"}), 400

    df_input = pd.DataFrame([feats])

    # Align columns with training data (drop port_number)
    expected_cols = model.get_booster().feature_names
    df_input = df_input.reindex(columns=expected_cols, fill_value=0)

    prob       = model.predict_proba(df_input)[0][1]
    prediction = "Malicious" if prob >= 0.5 else "Benign"
    confidence = round(float(prob if prediction == "Malicious" else 1 - prob) * 100, 1)

    # Top features by value (simple display)
    top_feats = sorted(feats.items(), key=lambda x: abs(x[1]), reverse=True)[:8]
    top_features = [{"feature": k, "value": round(v, 3)} for k, v in top_feats]

    return jsonify({
        "prediction"  : prediction,
        "confidence"  : confidence,
        "top_features": top_features
    })

if __name__ == "__main__":
    app.run(debug=True)

# Run this in Colab as the final cell
xgb_model.save_model("xgb_model.json")
print("Model saved! Download this file and put it next to app.py")