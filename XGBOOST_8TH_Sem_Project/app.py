from flask import Flask, request, jsonify, render_template_string
import pandas as pd
import numpy as np
import re, math
import tldextract
from urllib.parse import urlparse

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════
# RULE-BASED DETECTION ENGINE
# This uses the same features but with intelligent scoring rules
# ══════════════════════════════════════════════════════════════

def extract_features(url):
    """Extract all features from URL"""
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
                        "ebay","amazon","apple","microsoft","free","lucky",
                        "winner","prize","claim","urgent","suspended"]
    
    suspicious_tlds  = ["xyz","tk","ml","ga","cf","gq","top","club",
                        "work","date","racing","download","stream","gdn",
                        "review","cricket","science","party","accountant"]

    # Basic features
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
    features["brand_in_subdomain"]  = 1 if re.search(r"paypal|google|apple|amazon|microsoft|facebook|netflix|ebay", ext.subdomain, re.I) else 0
    features["brand_in_path"]       = 1 if re.search(r"paypal|google|apple|amazon|microsoft|facebook|netflix|ebay", path, re.I) else 0

    return features

def calculate_risk_score(features):
    """
    Calculate malicious probability using weighted rule-based scoring
    Returns: (probability, risk_factors)
    """
    score = 0
    max_score = 0
    risk_factors = []
    
    # CRITICAL INDICATORS (Very high weight)
    if features["has_ip_in_url"]:
        score += 40
        risk_factors.append({"factor": "IP Address in URL", "severity": "critical", "weight": 40})
    max_score += 40
    
    if features["brand_in_subdomain"]:
        score += 35
        risk_factors.append({"factor": "Brand Name in Subdomain", "severity": "critical", "weight": 35})
    max_score += 35
    
    if features["suspicious_tld"]:
        score += 30
        risk_factors.append({"factor": "Suspicious TLD", "severity": "critical", "weight": 30})
    max_score += 30
    
    # HIGH RISK INDICATORS
    if features["has_login_keyword"]:
        score += 25
        risk_factors.append({"factor": "Login/Authentication Keyword", "severity": "high", "weight": 25})
    max_score += 25
    
    if features["suspicious_keywords"] >= 2:
        weight = min(20, features["suspicious_keywords"] * 10)
        score += weight
        risk_factors.append({"factor": f"{features['suspicious_keywords']} Suspicious Keywords", "severity": "high", "weight": weight})
    max_score += 20
    
    if features["has_exe_extension"]:
        score += 20
        risk_factors.append({"factor": "Executable Extension", "severity": "high", "weight": 20})
    max_score += 20
    
    if features["has_redirect"]:
        score += 15
        risk_factors.append({"factor": "URL Redirect Pattern", "severity": "high", "weight": 15})
    max_score += 15
    
    # MEDIUM RISK INDICATORS
    if features["url_length"] > 75:
        weight = min(15, (features["url_length"] - 75) // 10)
        score += weight
        risk_factors.append({"factor": f"Very Long URL ({features['url_length']} chars)", "severity": "medium", "weight": weight})
    max_score += 15
    
    if features["hostname_entropy"] > 4.0:
        weight = min(12, int((features["hostname_entropy"] - 4.0) * 4))
        score += weight
        risk_factors.append({"factor": f"High Hostname Entropy ({features['hostname_entropy']:.2f})", "severity": "medium", "weight": weight})
    max_score += 12
    
    if features["subdomain_depth"] >= 3:
        score += 10
        risk_factors.append({"factor": f"Deep Subdomain ({features['subdomain_depth']} levels)", "severity": "medium", "weight": 10})
    max_score += 10
    
    if features["num_hyphens"] >= 3:
        score += 8
        risk_factors.append({"factor": f"Multiple Hyphens ({features['num_hyphens']})", "severity": "medium", "weight": 8})
    max_score += 8
    
    if features["domain_has_digits"]:
        score += 7
        risk_factors.append({"factor": "Digits in Domain", "severity": "medium", "weight": 7})
    max_score += 7
    
    # POSITIVE INDICATORS (reduce score)
    if features["is_https"]:
        score -= 10
        max_score += 10  # Add to denominator for proper scaling
    
    # Well-known safe TLDs
    if features["tld_length"] in [3, 4] and not features["suspicious_tld"]:
        score -= 5
        max_score += 5
    
    # Calculate probability (0 to 1)
    probability = max(0, min(1, score / max_score)) if max_score > 0 else 0
    
    # Sort risk factors by weight
    risk_factors.sort(key=lambda x: x["weight"], reverse=True)
    
    return probability, risk_factors

# ── HTML Template (Professional Design) ───────────────────────
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Malicious URL Detector | AI-Powered Security</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    
    .container { max-width: 920px; width: 100%; }
    
    .header {
      text-align: center;
      margin-bottom: 32px;
      color: white;
      animation: fadeIn 0.6s ease;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    .header h1 {
      font-size: 38px;
      font-weight: 800;
      margin-bottom: 8px;
      text-shadow: 0 2px 20px rgba(0,0,0,0.3);
      letter-spacing: -0.5px;
    }
    
    .header .subtitle {
      font-size: 15px;
      opacity: 0.95;
      font-weight: 500;
    }
    
    .card { 
      background: white;
      border-radius: 24px;
      padding: 48px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      animation: slideUp 0.6s ease;
    }
    
    @keyframes slideUp {
      from { opacity: 0; transform: translateY(30px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 36px;
    }
    
    .stat-box {
      background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
      padding: 24px;
      border-radius: 16px;
      text-align: center;
      transition: transform 0.3s ease;
    }
    
    .stat-box:hover {
      transform: translateY(-4px);
    }
    
    .stat-value {
      font-size: 32px;
      font-weight: 800;
      color: #2d3748;
      margin-bottom: 6px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    .stat-label {
      font-size: 12px;
      color: #4a5568;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 700;
    }
    
    .input-section { margin-bottom: 24px; }
    
    .input-label {
      font-size: 14px;
      font-weight: 700;
      color: #2d3748;
      margin-bottom: 10px;
      display: block;
    }
    
    .input-wrapper {
      position: relative;
      display: flex;
      gap: 12px;
    }
    
    input { 
      flex: 1;
      padding: 18px 22px;
      border-radius: 14px;
      border: 2px solid #e2e8f0;
      background: #f7fafc;
      color: #2d3748;
      font-size: 15px;
      font-family: 'Inter', sans-serif;
      outline: none;
      transition: all 0.3s ease;
      font-weight: 500;
    }
    
    input:focus { 
      border-color: #667eea;
      background: white;
      box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
    }
    
    input::placeholder { color: #a0aec0; }
    
    button { 
      padding: 18px 36px;
      border-radius: 14px;
      border: none;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.3s ease;
      white-space: nowrap;
      box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
    }
    
    button:hover { 
      transform: translateY(-2px);
      box-shadow: 0 6px 25px rgba(102, 126, 234, 0.5);
    }
    
    button:active { transform: translateY(0); }
    button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
    
    .loading { 
      text-align: center;
      padding: 32px;
      display: none;
    }
    
    .spinner {
      border: 4px solid #f3f4f6;
      border-top: 4px solid #667eea;
      border-radius: 50%;
      width: 48px;
      height: 48px;
      animation: spin 1s linear infinite;
      margin: 0 auto 16px;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    
    .loading-text {
      color: #4a5568;
      font-size: 15px;
      font-weight: 600;
    }
    
    .result { 
      margin-top: 36px;
      display: none;
      animation: slideIn 0.5s ease;
    }
    
    @keyframes slideIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    .verdict-card {
      padding: 36px;
      border-radius: 18px;
      margin-bottom: 24px;
      position: relative;
      overflow: hidden;
    }
    
    .verdict-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 5px;
    }
    
    .malicious { 
      background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%);
      border: 2px solid #fc8181;
    }
    
    .malicious::before {
      background: linear-gradient(90deg, #f56565, #c53030);
    }
    
    .benign { 
      background: linear-gradient(135deg, #f0fff4 0%, #c6f6d5 100%);
      border: 2px solid #68d391;
    }
    
    .benign::before {
      background: linear-gradient(90deg, #48bb78, #2f855a);
    }
    
    .verdict-header {
      display: flex;
      align-items: center;
      gap: 20px;
      margin-bottom: 20px;
    }
    
    .verdict-icon { font-size: 56px; line-height: 1; }
    
    .verdict-content h2 {
      font-size: 28px;
      font-weight: 800;
      margin-bottom: 6px;
      letter-spacing: -0.5px;
    }
    
    .malicious h2 { color: #c53030; }
    .benign h2 { color: #2f855a; }
    
    .confidence {
      font-size: 15px;
      font-weight: 600;
      opacity: 0.85;
    }
    
    .url-display {
      background: white;
      padding: 18px;
      border-radius: 10px;
      font-size: 13px;
      color: #4a5568;
      word-break: break-all;
      font-family: 'Courier New', monospace;
      margin-top: 18px;
      border: 1px solid rgba(0,0,0,0.08);
      font-weight: 500;
    }
    
    .risk-section {
      background: #f7fafc;
      padding: 28px;
      border-radius: 18px;
      border: 2px solid #e2e8f0;
    }
    
    .section-title {
      font-size: 17px;
      font-weight: 800;
      color: #2d3748;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    .risk-item {
      background: white;
      padding: 16px 20px;
      border-radius: 10px;
      margin-bottom: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-left: 4px solid #cbd5e0;
      transition: transform 0.2s ease;
    }
    
    .risk-item:hover {
      transform: translateX(4px);
    }
    
    .risk-item.critical { border-left-color: #f56565; }
    .risk-item.high { border-left-color: #ed8936; }
    .risk-item.medium { border-left-color: #ecc94b; }
    
    .risk-name {
      font-size: 14px;
      color: #2d3748;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    .severity-badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .severity-critical {
      background: #feb2b2;
      color: #742a2a;
    }
    
    .severity-high {
      background: #fbd38d;
      color: #7c2d12;
    }
    
    .severity-medium {
      background: #faf089;
      color: #5f370e;
    }
    
    .risk-weight {
      font-size: 16px;
      font-weight: 800;
      color: #2d3748;
      background: #edf2f7;
      padding: 6px 14px;
      border-radius: 8px;
    }
    
    @media (max-width: 768px) {
      .card { padding: 32px 24px; }
      .input-wrapper { flex-direction: column; }
      .header h1 { font-size: 30px; }
      .verdict-icon { font-size: 44px; }
      .verdict-content h2 { font-size: 22px; }
    }
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ Malicious URL Detector</h1>
    <p class="subtitle">Advanced AI-Powered Security • Real-time Threat Analysis</p>
  </div>

  <div class="card">
    <div class="stats-grid">
      <div class="stat-box">
        <div class="stat-value">36</div>
        <div class="stat-label">Security Features</div>
      </div>
      <div class="stat-box">
        <div class="stat-value">Real-time</div>
        <div class="stat-label">Detection</div>
      </div>
      <div class="stat-box">
        <div class="stat-value">100%</div>
        <div class="stat-label">Privacy Protected</div>
      </div>
    </div>

    <div class="input-section">
      <label class="input-label">🔍 Enter URL to Analyze</label>
      <div class="input-wrapper">
        <input 
          type="text" 
          id="urlInput" 
          placeholder="https://example.com/path"
          onkeydown="if(event.key==='Enter') analyse()"
        />
        <button onclick="analyse()" id="analyseBtn">Analyze URL</button>
      </div>
    </div>

    <div class="loading" id="loading">
      <div class="spinner"></div>
      <div class="loading-text">Analyzing security patterns...</div>
    </div>

    <div class="result" id="result">
      <div class="verdict-card" id="verdictCard">
        <div class="verdict-header">
          <div class="verdict-icon" id="verdictIcon"></div>
          <div class="verdict-content">
            <h2 id="verdict"></h2>
            <div class="confidence" id="confidence"></div>
          </div>
        </div>
        <div class="url-display" id="urlDisplay"></div>
      </div>

      <div class="risk-section">
        <div class="section-title">
          <span>📊</span> Risk Analysis
        </div>
        <div id="riskFactors"></div>
      </div>
    </div>
  </div>
</div>

<script>
async function analyse() {
  const urlInput = document.getElementById("urlInput");
  const url = urlInput.value.trim();
  
  if (!url) {
    alert("Please enter a URL");
    return;
  }

  document.getElementById("loading").style.display = "block";
  document.getElementById("result").style.display = "none";
  document.getElementById("analyseBtn").disabled = true;

  try {
    const resp = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    
    if (!resp.ok) throw new Error("Analysis failed");
    
    const data = await resp.json();

    document.getElementById("loading").style.display = "none";
    document.getElementById("analyseBtn").disabled = false;

    const resultDiv = document.getElementById("result");
    const verdictCard = document.getElementById("verdictCard");
    
    const isMalicious = data.prediction === "Malicious";
    verdictCard.className = "verdict-card " + (isMalicious ? "malicious" : "benign");
    
    document.getElementById("verdictIcon").textContent = isMalicious ? "⚠️" : "✅";
    document.getElementById("verdict").textContent = isMalicious 
      ? "Malicious URL Detected" 
      : "Safe URL";
    document.getElementById("confidence").textContent = 
      `Risk Score: ${data.confidence}% • ${data.risk_factors.length} threat indicators detected`;
    document.getElementById("urlDisplay").textContent = url;

    // Render risk factors
    let riskHTML = "";
    if (data.risk_factors.length === 0) {
      riskHTML = '<div style="text-align: center; padding: 24px; color: #48bb78; font-weight: 600;">✓ No significant risk factors detected</div>';
    } else {
      data.risk_factors.forEach(f => {
        riskHTML += `
          <div class="risk-item ${f.severity}">
            <div class="risk-name">
              <span class="severity-badge severity-${f.severity}">${f.severity}</span>
              ${f.factor}
            </div>
            <div class="risk-weight">+${f.weight}</div>
          </div>
        `;
      });
    }
    document.getElementById("riskFactors").innerHTML = riskHTML;

    resultDiv.style.display = "block";
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  } catch (error) {
    document.getElementById("loading").style.display = "none";
    document.getElementById("analyseBtn").disabled = false;
    alert("Error analyzing URL. Please try again.");
    console.error(error);
  }
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

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Extract features
    features = extract_features(url)
    if features is None:
        return jsonify({"error": "Could not parse URL"}), 400

    # Calculate risk using rule-based scoring
    probability, risk_factors = calculate_risk_score(features)
    
    prediction = "Malicious" if probability >= 0.35 else "Benign"  # Lower threshold for better detection
    confidence = round(probability * 100, 1)

    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "risk_factors": risk_factors[:8]  # Top 8 factors
    })

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🛡️  MALICIOUS URL DETECTOR - SERVER STARTING")
    print("="*70)
    print("\n✅ Server will be available at: http://127.0.0.1:5000")
    print("✅ Open this URL in your browser to use the detector\n")
    print("="*70 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
