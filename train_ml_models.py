#!/usr/bin/env python3
import os
import sys
import json
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import traceback

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import ML_MODELS_PATH, ML_DEBUG

def load_training_data(vuln_type):
    """Load training data for a specific vulnerability type"""
    data_file = f"training_data/{vuln_type}_training_data.json"
    if not os.path.exists(data_file):
        print(f"[!] Training data not found for {vuln_type}")
        return None, None
        
    try:
        with open(data_file, 'r') as f:
            data = json.load(f)
            
        X = np.array([sample['features'] for sample in data['samples']])
        y = np.array([sample['is_vulnerable'] for sample in data['samples']])
        
        # Verify feature count matches expected
        expected_features = {
            'xss': 40,  # 10 common + 30 XSS specific
            'sqli': 42,  # Updated from 35
            'csrf': 30,  # 10 common + 20 CSRF specific
            'ssrf': 33,  # Updated from 35
            'lfi': 35,  # 10 common + 25 LFI specific
            'rce': 21   # Updated from 40
        }
        
        if X.shape[1] != expected_features[vuln_type]:
            print(f"[!] Feature count mismatch for {vuln_type}. Expected {expected_features[vuln_type]}, got {X.shape[1]}")
            return None, None
            
        return X, y
    except Exception as e:
        print(f"[!] Error loading training data for {vuln_type}: {e}")
        if ML_DEBUG:
            print(f"[!] Stack trace: {traceback.format_exc()}")
        return None, None

def train_model(X, y, vuln_type):
    """Train and save ML model for vulnerability detection"""
    try:
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
            
        model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test_scaled)
        print(f"\n[*] Model performance for {vuln_type}:")
        print(classification_report(y_test, y_pred))
        
        # Save model, scaler and feature names
        os.makedirs(ML_MODELS_PATH, exist_ok=True)
        
        model_file = os.path.join(ML_MODELS_PATH, f"{vuln_type}_model.pkl")
        scaler_file = os.path.join(ML_MODELS_PATH, f"{vuln_type}_scaler.pkl")
        features_file = os.path.join(ML_MODELS_PATH, f"{vuln_type}_features.pkl")
        
        with open(model_file, 'wb') as f:
            pickle.dump(model, f)
        with open(scaler_file, 'wb') as f:
            pickle.dump(scaler, f)
        with open(features_file, 'wb') as f:
            pickle.dump(list(range(X.shape[1])), f)  # Save feature indices
            
        print(f"[✓] Saved model files for {vuln_type}")
        return True
        
    except Exception as e:
        print(f"[!] Error training model for {vuln_type}: {e}")
        if ML_DEBUG:
            print(f"[!] Stack trace: {traceback.format_exc()}")
        return False

def verify_model(vuln_type):
    """Verify that a model exists and can be loaded"""
    try:
        model_file = os.path.join(ML_MODELS_PATH, f"{vuln_type}_model.pkl")
        scaler_file = os.path.join(ML_MODELS_PATH, f"{vuln_type}_scaler.pkl")
        features_file = os.path.join(ML_MODELS_PATH, f"{vuln_type}_features.pkl")
        
        if not all(os.path.exists(f) for f in [model_file, scaler_file, features_file]):
            print(f"[!] Missing model files for {vuln_type}")
            return False
            
        # Try loading the model
        with open(model_file, 'rb') as f:
            model = pickle.load(f)
        with open(scaler_file, 'rb') as f:
            scaler = pickle.load(f)
        with open(features_file, 'rb') as f:
            features = pickle.load(f)
            
        # Verify model can make predictions
        expected_features = {
            'xss': 40,  # 10 common + 30 XSS specific
            'sqli': 42,  # Updated from 35
            'csrf': 30,  # 10 common + 20 CSRF specific
            'ssrf': 33,  # Updated from 35
            'lfi': 35,  # 10 common + 25 LFI specific
            'rce': 21   # Updated from 40
        }
        
        X_dummy = np.zeros((1, expected_features[vuln_type]))
        X_scaled = scaler.transform(X_dummy)
        model.predict_proba(X_scaled)
        
        print(f"[✓] Verified model for {vuln_type}")
        return True
        
    except Exception as e:
        print(f"[!] Error verifying model for {vuln_type}: {e}")
        if ML_DEBUG:
            print(f"[!] Stack trace: {traceback.format_exc()}")
        return False

def main():
    """Main function to verify and train ML models"""
    vuln_types = ['xss', 'sqli', 'csrf', 'ssrf', 'lfi', 'rce']
    
    print("[*] Starting ML model verification and training")
    print("-" * 50)
    
    for vuln_type in vuln_types:
        print(f"\n[*] Processing {vuln_type} model...")
        
        # First verify existing model
        if verify_model(vuln_type):
            continue
            
        # If verification fails, try training new model
        print(f"[*] Training new model for {vuln_type}...")
        X, y = load_training_data(vuln_type)
        
        if X is not None and y is not None:
            if train_model(X, y, vuln_type):
                print(f"[✓] Successfully trained new model for {vuln_type}")
            else:
                print(f"[!] Failed to train model for {vuln_type}")
        else:
            print(f"[!] Could not load training data for {vuln_type}")
            
    print("\n[*] Model verification and training complete")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Critical error: {e}")
        if ML_DEBUG:
            print(f"[!] Stack trace: {traceback.format_exc()}")
        sys.exit(1) 