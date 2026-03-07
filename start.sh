#!/bin/bash
echo "🛡️ Preparing Hybrid IDS for Deployment..."

# 1. Ensure data directory exists
mkdir -p data

# 2. Run Database Migration
python migrate_db.py

# 3. Check for Models, train if missing
if [ ! -f "random_forest.pkl" ]; then
    echo "[*] Training AI models..."
    python src/model_training/train.py
fi

# 4. Start the Hybrid IDS (Web + Engine)
# We force 0.0.0.0 and use the PORT environment variable provided by the cloud
echo "[*] Initializing Secure Uplink..."
python main.py
