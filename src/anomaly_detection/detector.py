import joblib
import numpy as np
import os

MODEL_PATH = "models/model.pkl"
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/encoders.pkl"

class AnomalyDetector:
    def __init__(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.encoders = joblib.load(ENCODER_PATH)
            self.ready = True
        else:
            print("Anomaly Detection model not found. Please run training script first.")
            self.ready = False

    def predict(self, feature_vector):
        """
        Predicts if a feature vector is malicious (1) or benign (0).
        Expected Features (41 total): 
        [duration, protocol_type, service, flag, src_bytes, dst_bytes, ...]
        """
        if not self.ready:
            return None
        
        try:
            # Ensure feature vector is 2D and matches expected 41 features
            if feature_vector.ndim == 1:
                feature_vector = feature_vector.reshape(1, -1)
            
            if feature_vector.shape[1] != 41:
                print(f"[ERROR] Feature vector shape mismatch: expected 41, got {feature_vector.shape[1]}")
                return None

            print("[DEBUG] Triggering ML Inference Brain...")
            prediction = self.model.predict(feature_vector)
            probabilities = self.model.predict_proba(feature_vector)
            
            # Predict malicious (1) if prob > target threshold
            # Returns (IsMalicious, MaliciousProbability)
            return int(prediction[0]), float(probabilities[0][1])
            
        except Exception as e:
            print(f"[!] Inference Error: {e}")
            return None
