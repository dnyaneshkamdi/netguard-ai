# 🛡️ NetGuard AI — Intelligent Cloud Network Threat Detection System

![Python](https://img.shields.io/badge/Python-3.14-blue)
![AWS](https://img.shields.io/badge/Cloud-AWS-orange)
![ML](https://img.shields.io/badge/AI-Isolation%20Forest-green)
![Flask](https://img.shields.io/badge/Dashboard-Flask-red)

## 🔥 Problem Statement
Small businesses deploy cloud infrastructure on AWS without proper network monitoring.
They can't afford enterprise security tools (Splunk costs ₹1Cr+/year), and manual log 
analysis is slow. This leaves them vulnerable to port scans, DDoS, and brute force attacks.

**NetGuard AI solves this — free, automatic, and explains threats in plain English.**

---

## 🚀 What Makes This Unique
| Feature | Existing Tools | NetGuard AI |
|---|---|---|
| Real AWS VPC Logs | ❌ | ✅ |
| AI Anomaly Detection | Partial | ✅ Isolation Forest |
| Plain English Explanation | ❌ | ✅ LLM-powered |
| Live Email Alerts | Paid only | ✅ AWS SNS (free tier) |
| Web Dashboard | Paid only | ✅ Flask |
| Open Source | ❌ | ✅ |

---

## 🏗️ Architecture
```
AWS VPC Flow Logs
       ↓
  S3 Bucket (storage)
       ↓
  Python Log Collector
       ↓
  Isolation Forest (AI anomaly detection)
       ↓
  Threat Classifier (PORT_SCAN / DDOS / BRUTE_FORCE)
       ↓
  LLM Explainer (plain English report)
       ↓
  AWS SNS Email Alert + Flask Dashboard
```

---

## 🛠️ Tech Stack
- **Python** — Core pipeline, log parsing, ML
- **AWS** — VPC Flow Logs, S3, SNS (Email Alerts)
- **scikit-learn** — Isolation Forest anomaly detection
- **Flask** — Live web dashboard
- **boto3** — AWS SDK for Python

---

## 📁 Project Structure
```
netguard-ai/
├── main.py                  # Single command startup
├── config.py                # AWS + API settings
├── modules/
│   ├── parse_vpc_logs.py    # AWS S3 log collector
│   ├── log_simulator.py     # Attack traffic simulator
│   ├── detector.py          # AI detection engine
│   ├── explainer.py         # LLM threat explainer
│   └── alerter.py           # SNS + Slack alerts
├── web/
│   ├── app.py               # Flask dashboard
│   └── templates/
│       └── dashboard.html   # Live UI
└── requirements.txt
```

---

## ⚡ Quick Start
```bash
# 1. Clone karo
git clone https://github.com/YOURUSERNAME/netguard-ai.git
cd netguard-ai

# 2. Virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt

# 3. AWS configure karo
aws configure

# 4. .env setup karo
AWS_REGION=ap-south-1
S3_BUCKET_NAME=your-bucket-name

# 5. Run karo!
python main.py
```

---

## 🎯 Detected Threat Types
- **PORT_SCAN** — Reconnaissance attack detection
- **DDOS_ATTEMPT** — High volume traffic detection  
- **BRUTE_FORCE** — Multiple failed connection detection
- **SUSPICIOUS_TRAFFIC** — Anomaly based detection

---

## 📊 Live Dashboard
Run `python main.py` → Choose option 3 → Open `http://localhost:5000`

---

## 👨‍💻 Built By
**Dnyanesh Kamdi** — Walchand College of Engineering, Sangli  
AWS Certified | Azure Certified | Cloud & Security Enthusiast

---

## 🔮 Version 2 Roadmap
- [ ] Docker containerization
- [ ] Azure NSG logs support
- [ ] Local LLM (Ollama) integration
- [ ] Real-time packet capture
