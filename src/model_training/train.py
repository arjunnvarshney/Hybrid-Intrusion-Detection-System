import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
import os
import requests

# Column names for NSL-KDD
COL_NAMES = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty_level"]

DATA_URL = "https://raw.githubusercontent.com/Jehuty4949/NSL_KDD/master/KDDTrain%2B.csv"
DATA_PATH = "data/nsl_kdd.csv"
MODEL_PATH = "models/model.pkl"
ISO_MODEL_PATH = "models/isolation_forest.pkl"
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/encoders.pkl"

def get_data():
    """Download and prepare data if not exists."""
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(DATA_PATH):
        print(f"Downloading dataset to {DATA_PATH}...")
        response = requests.get(DATA_URL)
        with open(DATA_PATH, 'wb') as f:
            f.write(response.content)
        print("Download complete.")

def preprocess_data(df):
    """Clean and preprocess the dataset."""
    print("Preprocessing data...")
    if 'difficulty_level' in df.columns:
        df = df.drop('difficulty_level', axis=1)
    
    df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
    
    categorical_cols = ['protocol_type', 'service', 'flag']
    encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    return X_scaled, y, scaler, encoders

def run_training():
    get_data()
    
    df = pd.read_csv(DATA_PATH, header=None, names=COL_NAMES)
    X, y, scaler, encoders = preprocess_data(df)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 1. Train Random Forest (Supervised)
    print(f"Training Random Forest on {len(X_train)} samples...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # 2. Train Isolation Forest (Anomaly Detection) on Normal traffic only
    print("Training Isolation Forest on Normal traffic...")
    X_normal_train = X_train[y_train == 0]
    iso_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    iso_forest.fit(X_normal_train)
    
    # Evaluate
    y_pred_rf = clf.predict(X_test)
    y_pred_iso = iso_forest.predict(X_test)
    y_pred_iso = [1 if x == -1 else 0 for x in y_pred_iso]
    
    print("\n" + "="*30)
    print("      MODEL EVALUATION")
    print("="*30)
    print(f"Random Forest Accuracy: {accuracy_score(y_test, y_pred_rf):.4f}")
    print(f"Isolation Forest 'Accuracy' (vs true labels): {accuracy_score(y_test, y_pred_iso):.4f}")
    print("="*30)
    
    if not os.path.exists('models'):
        os.makedirs('models')
        
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(iso_forest, ISO_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(encoders, ENCODER_PATH)
    print(f"\nModels saved successfully.")

if __name__ == "__main__":
    run_training()
