import pandas as pd
import random
from datetime import datetime, timedelta

def generate_fake_logs(num_entries=100):
    """Testing ke liye fake VPC logs generate karo"""
    
    normal_ips = ['10.0.1.5', '10.0.1.6', '10.0.1.10', '10.0.2.1']
    attack_ip = '45.33.32.156'  # Fake attacker IP
    
    logs = []
    base_time = int(datetime.now().timestamp())
    
    # Normal traffic — 85 entries
    for i in range(85):
        logs.append({
            'srcaddr': random.choice(normal_ips),
            'dstaddr': '10.0.0.1',
            'srcport': random.randint(1024, 65535),
            'dstport': random.choice([80, 443, 22]),
            'protocol': '6',
            'packets': random.randint(1, 10),
            'bytes': random.randint(100, 5000),
            'action': 'ACCEPT',
            'timestamp': datetime.fromtimestamp(base_time + i*10)
        })
    
    # Port scan attack — 15 entries (suspicious!)
    for port in range(20, 35):
        logs.append({
            'srcaddr': attack_ip,
            'dstaddr': '10.0.1.5',
            'srcport': 54321,
            'dstport': port,
            'protocol': '6',
            'packets': 1,
            'bytes': 40,
            'action': 'REJECT',
            'timestamp': datetime.fromtimestamp(base_time + port)
        })
    
    df = pd.DataFrame(logs)
    print(f"[+] {len(df)} fake log entries generate kiye")
    print(f"[+] Normal traffic: 85 entries")
    print(f"[+] Port scan attack: 15 entries from {attack_ip}")
    print(f"\n--- Sample Data ---")
    print(df[['srcaddr', 'dstaddr', 'dstport', 'action']].head(10))
    print("\n✅ Fake logs ready!")
    return df

if __name__ == "__main__":
    df = generate_fake_logs()
    