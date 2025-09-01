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

#3. train and run
sudo ~/NIDS_proj/NIDS/.venv/bin/python3 -m src.main --train
```
#### Open a new tab and watch alerts:
```bash
tail -f ids_alerts.log
```
#### Open a new tab and open a http server on port 8000:
```bash 
python3 -m http.server 8000
```
#### Open a new tab and generate test traffic:
| Attack type | Command (second terminal) |
|:-----------:|:-------------------------:|
| Normal HTTP | `curl -s http://localhost:8000 > /dev/null` |
| SYN flood   | `sudo hping3 -S -p 8000 -s 12345 -k -i u100 127.0.0.1` |
| Port scan   | `sudo hping3 -A -p 8000 -s 12345 -k -i u100 127.0.0.1` |

## Architecture
| Component | Purpose |
|-----------|---------|
| `PacketCapture` | Thread-safe live capture with Scapy |
| `TrafficAnalyzer` | Per-flow feature extractor |
| `DetectionEngine` | Signature rules + `IsolationForest` |
| `AlertSystem` | JSON logger |
| `main.py` | CLI glue |

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
