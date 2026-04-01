import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

def engineer_features(df):
    """Raw logs se ML ke liye features banao"""
    
    features = pd.DataFrame()
    
    features['srcport']  = df['srcport'].fillna(0)
    features['dstport']  = df['dstport'].fillna(0)
    features['packets']  = df['packets'].fillna(1)
    features['bytes']    = df['bytes'].fillna(0)
    features['action_encoded'] = (df['action'] == 'ACCEPT').astype(int)
    
    # Port scan detection
    port_counts = df.groupby('srcaddr')['dstport'].nunique()
    features['unique_ports_per_src'] = df['srcaddr'].map(port_counts).fillna(0)
    
    # High volume detection
    pkt_counts = df.groupby('srcaddr')['packets'].sum()
    features['total_packets_per_src'] = df['srcaddr'].map(pkt_counts).fillna(0)
    
    # Suspicious ports
    suspicious_ports = [22, 23, 3389, 445, 1433, 3306]
    features['is_suspicious_port'] = df['dstport'].isin(suspicious_ports).astype(int)
    
    # Bytes per packet
    features['bytes_per_packet'] = (
        df['bytes'] / df['packets'].replace(0, 1)
    ).fillna(0)
    
    # Rejected connections per IP
    reject_counts = df[df['action']=='REJECT'].groupby('srcaddr').size()
    features['rejected_per_src'] = df['srcaddr'].map(reject_counts).fillna(0)
    
    # Connection rate
    features['connection_rate'] = features['total_packets_per_src'] / (features['unique_ports_per_src'] + 1)
    
    return features


def detect_anomalies_if(features):
    """Isolation Forest — unsupervised anomaly detection"""
    
    model = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=100
    )
    predictions = model.fit_predict(features)
    scores      = model.score_samples(features)
    return predictions, scores


def train_xgboost(features, if_predictions):
    """XGBoost — supervised classifier using IF labels"""
    
    # IF predictions ko labels banao
    labels = (if_predictions == -1).astype(int)  # 1=threat, 0=normal
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42
    )
    
    # Scale features
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)
    
    # XGBoost model
    xgb = XGBClassifier(
        n_estimators    = 100,
        max_depth       = 4,
        learning_rate   = 0.1,
        use_label_encoder = False,
        eval_metric     = 'logloss',
        random_state    = 42
    )
    xgb.fit(X_train, y_train)
    
    # Full dataset pe predict karo
    X_full = scaler.transform(features)
    xgb_predictions = xgb.predict(X_full)
    xgb_proba      = xgb.predict_proba(X_full)[:, 1]
    
    accuracy = xgb.score(X_test, y_test)
    print(f"[+] XGBoost Accuracy : {accuracy*100:.1f}%")
    
    return xgb_predictions, xgb_proba, scaler, xgb


def detect_anomalies(df):
    """Combined IF + XGBoost pipeline"""
    
    print("\n[*] Feature engineering chal raha hai...")
    features = engineer_features(df)
    
    print("[*] Isolation Forest chal raha hai...")
    if_predictions, if_scores = detect_anomalies_if(features)
    
    print("[*] XGBoost classifier train ho raha hai...")
    xgb_predictions, xgb_proba, scaler, xgb = train_xgboost(features, if_predictions)
    
    # Combined decision — dono agree kare toh threat
    df = df.copy()
    df['if_anomaly']    = if_predictions == -1
    df['xgb_anomaly']   = xgb_predictions == 1
    df['xgb_confidence']= (xgb_proba * 100).round(1)
    df['anomaly_score'] = if_scores
    
    # Final decision: IF ya XGBoost mein se koi bhi flag kare
    df['is_anomaly'] = df['if_anomaly'] | df['xgb_anomaly']
    
    anomaly_count = df['is_anomaly'].sum()
    total         = len(df)
    
    print(f"[+] Total entries analyzed : {total}")
    print(f"[+] IF anomalies           : {df['if_anomaly'].sum()}")
    print(f"[+] XGBoost anomalies      : {df['xgb_anomaly'].sum()}")
    print(f"[+] Combined threats       : {anomaly_count}")
    
    return df


def classify_threat(anomaly_df):
    """Anomaly ka type classify karo"""
    
    threats = []
    anomalies = anomaly_df[anomaly_df['is_anomaly'] == True]
    
    if anomalies.empty:
        print("\n✅ Koi threat nahi mila — traffic normal hai!")
        return []
    
    for src_ip, group in anomalies.groupby('srcaddr'):
        unique_ports  = group['dstport'].nunique()
        total_packets = group['packets'].sum()
        rejected      = (group['action'] == 'REJECT').sum()
        avg_confidence = group['xgb_confidence'].mean() if 'xgb_confidence' in group.columns else 0
        
        if unique_ports >= 5:
            threat_type = "PORT_SCAN"
            severity    = "HIGH"
            description = f"{unique_ports} alag ports scan kiye gaye ek hi IP se"
        elif total_packets > 500:
            threat_type = "DDOS_ATTEMPT"
            severity    = "CRITICAL"
            description = f"Unusually high traffic — {total_packets} packets"
        elif rejected > 10:
            threat_type = "BRUTE_FORCE"
            severity    = "HIGH"
            description = f"{rejected} rejected connections — brute force possible"
        else:
            threat_type = "SUSPICIOUS_TRAFFIC"
            severity    = "MEDIUM"
            description = "Unusual pattern detected"
        
        threat = {
            'src_ip'        : src_ip,
            'threat_type'   : threat_type,
            'severity'      : severity,
            'description'   : description,
            'unique_ports'  : unique_ports,
            'total_packets' : int(total_packets),
            'rejected_count': int(rejected),
            'affected_ports': sorted(group['dstport'].unique().tolist())[:10],
            'xgb_confidence': f"{avg_confidence:.1f}%"
        }
        threats.append(threat)
    
    return threats


def print_threat_report(threats):
    """Threats ko readable format mein print karo"""
    
    if not threats:
        return
    
    print("\n" + "="*55)
    print("   ⚠️  NETGUARD AI — THREAT REPORT")
    print("="*55)
    
    for i, t in enumerate(threats, 1):
        print(f"\n🚨 THREAT #{i}")
        print(f"   Source IP      : {t['src_ip']}")
        print(f"   Type           : {t['threat_type']}")
        print(f"   Severity       : {t['severity']}")
        print(f"   Description    : {t['description']}")
        print(f"   Ports hit      : {t['affected_ports']}")
        print(f"   Packets        : {t['total_packets']}")
        print(f"   XGBoost Conf.  : {t['xgb_confidence']}")
        print("-"*55)
    
    print(f"\n✅ Analysis complete — {len(threats)} threat(s) found!")


def run_detection(df):
    """Main function — detection pipeline"""
    
    print("\n" + "="*55)
    print("   NetGuard AI — Detection Engine v2")
    print("   Isolation Forest + XGBoost")
    print("="*55)
    
    analyzed_df = detect_anomalies(df)
    threats     = classify_threat(analyzed_df)
    print_threat_report(threats)
    
    return analyzed_df, threats


# Test
if __name__ == "__main__":
    from modules.log_simulator import generate_fake_logs
    print("[*] Fake logs generate ho rahe hain...")
    df = generate_fake_logs()
    analyzed_df, threats = run_detection(df)
    