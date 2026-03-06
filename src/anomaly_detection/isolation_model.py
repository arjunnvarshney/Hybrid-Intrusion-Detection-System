import joblib
import os
import numpy as np

ISO_MODEL_PATH = "models/isolation_forest.pkl"

class IsolationForestDetector:
    def __init__(self):
        if os.path.exists(ISO_MODEL_PATH):
            self.model = joblib.load(ISO_MODEL_PATH)
            self.ready = True
        else:
            print("[!] Isolation Forest model not found. Run training script first.")
            self.ready = False

    def predict(self, feature_vector):
        """
        Predicts if a feature vector is an outlier/anomaly.
        Isolation Forest outputs -1 for anomalies and 1 for normal.
        """
        if not self.ready:
            return None
        
        try:
            if feature_vector.ndim == 1:
                feature_vector = feature_vector.reshape(1, -1)
            
            # IsolationForest decision_function returns signed distance from the boundary.
            # predict returns -1 for outliers and 1 for inliers.
            prediction = self.model.predict(feature_vector)
            score = self.model.decision_function(feature_vector)
            
            # Convert -1 (outlier) to 1 (attack) and 1 (normal) to 0 (benign)
            is_anomaly = 1 if prediction[0] == -1 else 0
            
            # Score is normalized such that negative values are anomalies.
            # We transform it to a mock probability or confidence.
            # Higher score = more normal. Lower/Negative = more anomalous.
            confidence = float(1.0 - (score[0] + 0.5)) # Rough normalization to 0-1 range
            confidence = max(0.0, min(1.0, confidence))

            return is_anomaly, confidence
            
        except Exception as e:
            print(f"[!] Isolation Forest Inference Error: {e}")
            return None
