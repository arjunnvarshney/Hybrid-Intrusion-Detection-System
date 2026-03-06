# Hybrid Intrusion Detection System (HIDS)

A modular Intrusion Detection System combining Signature-based detection and Machine Learning Anomaly detection.

## Features
- **Signature-based Detection**: Matches network traffic against known attack patterns.
- **ML Anomaly Detection**: Uses a Random Forest model trained on the NSL-KDD dataset to detect zero-day or unknown attacks.
- **Packet Capture**: Real-time packet sniffing using Scapy.
- **Web Dashboard**: Simple Flask-based interface to monitor alerts and system logs.

## Project Structure
- `src/packet_capture`: Handles live network traffic ingestion.
- `src/signature_detection`: Rule-based engine for known patterns.
- `src/anomaly_detection`: ML-based inference for anomaly detection.
- `src/model_training`: Scripts for preprocessing NSL-KDD and training the Random Forest model.
- `src/dashboard`: Flask web application for visualization.

## Setup Instructions

### 1. Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Data Preparation
Run the training script to fetch the NSL-KDD dataset and train the model:
```bash
python src/model_training/train.py
```

### 3. Run the IDS
```bash
python main.py
```

### 4. Open Dashboard
Visit `http://127.0.0.1:5000` in your browser.
