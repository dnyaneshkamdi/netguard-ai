import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings('ignore')

def engineer_features(df):
    """Raw logs se ML ke liye features banao"""
    
    features = pd.DataFrame()
    
    # Basic numeric features
    features['srcport']  = df['srcport'].fillna(0)
    features['dstport']  = df['dstport'].fillna(0)
    features['packets']  = df['packets'].fillna(1)
    features['bytes']    = df['bytes'].fillna(0)
    
    # Action encode karo (ACCEPT=1, REJECT=0)
    features['action_encoded'] = (df['action'] == 'ACCEPT').astype(int)
    
    # Port scan detection feature — ek hi source se kitne alag ports hit hue?
    port_counts = df.groupby('srcaddr')['dstport'].nunique()
    features['unique_ports_per_src'] = df['srcaddr'].map(port_counts).fillna(0)
    
    # High volume detection — ek IP se kitne packets?
    pkt_counts = df.groupby('srcaddr')['packets'].sum()
    features['total_packets_per_src'] = df['srcaddr'].map(pkt_counts).fillna(0)
    
    # Suspicious port flag (common attack ports)
    suspicious_ports = [22, 23, 3389, 445, 1433, 3306]
    features['is_suspicious_port'] = df['dstport'].isin(suspicious_ports).astype(int)
    
    # Bytes per packet ratio (DoS indicator)
    features['bytes_per_packet'] = (
        df['bytes'] / df['packets'].replace(0, 1)
    ).fillna(0)
    
    return features


def detect_anomalies(df):
    """Isolation Forest se anomalies detect karo"""
    
    print("\n[*] Feature engineering chal raha hai...")
    features = engineer_features(df)
    
    print("[*] Isolation Forest model train ho raha hai...")
    model = IsolationForest(
        contamination=0.1,   # 10% traffic suspicious maano
        random_state=42,
        n_estimators=100
    )
    
    predictions = model.fit_predict(features)
    scores      = model.score_samples(features)
    
    # -1 = anomaly, 1 = normal
    df = df.copy()
    df['anomaly']       = predictions
    df['anomaly_score'] = scores
    df['is_anomaly']    = predictions == -1
    
    anomaly_count = (predictions == -1).sum()
    total         = len(predictions)
    
    print(f"[+] Total entries analyzed : {total}")
    print(f"[+] Anomalies detected     : {anomaly_count}")
    print(f"[+] Normal traffic         : {total - anomaly_count}")
    
    return df


def classify_threat(anomaly_df):
    """Anomaly ka type classify karo"""
    
    threats = []
    
    anomalies = anomaly_df[anomaly_df['is_anomaly'] == True]
    
    if anomalies.empty:
        print("\n✅ Koi threat nahi mila — traffic normal hai!")
        return []
    
    # IP wise group karo
    for src_ip, group in anomalies.groupby('srcaddr'):
        unique_ports  = group['dstport'].nunique()
        total_packets = group['packets'].sum()
        rejected      = (group['action'] == 'REJECT').sum()
        
        # Threat type decide karo
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
            'src_ip'      : src_ip,
            'threat_type' : threat_type,
            'severity'    : severity,
            'description' : description,
            'unique_ports': unique_ports,
            'total_packets': int(total_packets),
            'rejected_count': int(rejected),
            'affected_ports': sorted(group['dstport'].unique().tolist())[:10]
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
        print(f"   Source IP   : {t['src_ip']}")
        print(f"   Type        : {t['threat_type']}")
        print(f"   Severity    : {t['severity']}")
        print(f"   Description : {t['description']}")
        print(f"   Ports hit   : {t['affected_ports']}")
        print(f"   Packets     : {t['total_packets']}")
        print("-"*55)
    
    print(f"\n✅ Analysis complete — {len(threats)} threat(s) found!")


def run_detection(df):
    """Main function — detection pipeline"""
    
    print("\n" + "="*55)
    print("   NetGuard AI — Detection Engine")
    print("="*55)
    
    # Step 1: Anomaly detect karo
    analyzed_df = detect_anomalies(df)
    
    # Step 2: Classify threats
    threats = classify_threat(analyzed_df)
    
    # Step 3: Report print karo
    print_threat_report(threats)
    
    return analyzed_df, threats


# Test karne ke liye
if __name__ == "__main__":
    from modules.log_simulator import generate_fake_logs
    
    print("[*] Fake logs generate ho rahe hain...")
    df = generate_fake_logs()
    
    analyzed_df, threats = run_detection(df)
    