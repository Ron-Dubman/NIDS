# 🛡️ Lightweight NIDS
Python 3 Intrusion Detection System that sniffs live traffic, extracts flow features and raises signature + anomaly based alerts in JSON logs.

![CI](https://github.com/Ron-Dubman/NIDS/workflows/CI/badge.svg)

## Quick Start
```bash
#1. clone
git clone https://github.com/Ron-Dubman/NIDS.git
cd NIDS

#2. dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

#3. collect normal traffic data from live traffic for Isolation Forest ML model (reccomended learning time > 15 minutes (900 seconds))
sudo ~/NIDS/.venv/bin/python3 -m src.main --learn 900

#4. train the ML model on collected data and start the IDS
sudo ~/NIDS/.venv/bin/python3 -m src.main --train
```
#### Open streamlit dashboard to view alerts and analytics:
```bash
streamlit run src/streamlit_app.py
```
#### Open a new tab and open a http server on port 8000:
```bash 
python3 -m http.server 8000
```
#### Open a new tab and generate test traffic:
```bash
sudo python3 mock_traffic_generator.py normal/anomalous/syn-flood/port-scan
```

## Architecture
| Component | Purpose |
|-----------|---------|
| `PacketCapture` | Thread-safe live capture with Scapy |
| `TrafficAnalyzer` | Per-flow feature extractor |
| `DetectionEngine` | Signature rules + `IsolationForest` |
| `AlertSystem` | JSON logger |
|`intrusion_detection_system`| initializes and connects all components|
| `main.py` | entry point, passes command line arguments |

## ✅ Tests
```bash 
python -m pytest tests/ -v
```

## 📦 Requirements
- Python ≥ 3.10
- Root for live capture
- see `requirements.txt`

## ⚠️ Disclaimer
Proof of concept only, not production grade.
