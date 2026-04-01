import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

# Real-world IP ranges
INTERNAL_IPS = [
    '10.0.1.5', '10.0.1.6', '10.0.1.10',
    '10.0.2.1', '10.0.2.5', '172.31.0.5'
]

KNOWN_ATTACKERS = [
    '45.33.32.156',   # Shodan scanner
    '192.241.213.46', # Known malicious
    '103.21.244.0',   # Suspicious Asia
    '185.220.101.45', # Tor exit node
]

LEGIT_EXTERNAL = [
    '13.232.0.1',   # AWS Mumbai
    '52.66.0.1',    # AWS India
    '8.8.8.8',      # Google DNS
    '1.1.1.1',      # Cloudflare
]

PROTOCOLS = {'TCP': 6, 'UDP': 17, 'ICMP': 1}

def generate_normal_traffic(num=80):
    """Normal business traffic simulate karo"""
    logs = []
    base_time = datetime.now() - timedelta(minutes=10)
    
    for i in range(num):
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(LEGIT_EXTERNAL + INTERNAL_IPS)
        logs.append({
            'srcaddr'  : src,
            'dstaddr'  : dst,
            'srcport'  : random.randint(1024, 65535),
            'dstport'  : random.choice([80, 443, 8080, 53, 22, 3306]),
            'protocol' : 6,
            'packets'  : random.randint(1, 50),
            'bytes'    : random.randint(100, 50000),
            'action'   : 'ACCEPT',
            'timestamp': base_time + timedelta(seconds=i*7)
        })
    return logs

def generate_port_scan(attacker_ip=None):
    """Realistic port scan attack simulate karo"""
    if not attacker_ip:
        attacker_ip = random.choice(KNOWN_ATTACKERS)
    
    logs = []
    target = random.choice(INTERNAL_IPS)
    base_time = datetime.now() - timedelta(minutes=3)
    
    # Sequential port scan
    ports = random.sample(range(1, 1024), random.randint(10, 20))
    
    for i, port in enumerate(ports):
        logs.append({
            'srcaddr'  : attacker_ip,
            'dstaddr'  : target,
            'srcport'  : 54321,
            'dstport'  : port,
            'protocol' : 6,
            'packets'  : 1,
            'bytes'    : 40,
            'action'   : 'REJECT',
            'timestamp': base_time + timedelta(seconds=i*0.5)
        })
    
    print(f"[SIM] Port Scan: {attacker_ip} → {target} ({len(ports)} ports)")
    return logs

def generate_brute_force(attacker_ip=None):
    """SSH Brute force attack simulate karo"""
    if not attacker_ip:
        attacker_ip = random.choice(KNOWN_ATTACKERS)
    
    logs = []
    target = random.choice(INTERNAL_IPS)
    base_time = datetime.now() - timedelta(minutes=5)
    
    # Multiple failed SSH attempts
    for i in range(random.randint(15, 25)):
        logs.append({
            'srcaddr'  : attacker_ip,
            'dstaddr'  : target,
            'srcport'  : random.randint(40000, 65535),
            'dstport'  : 22,
            'protocol' : 6,
            'packets'  : 3,
            'bytes'    : 180,
            'action'   : 'REJECT',
            'timestamp': base_time + timedelta(seconds=i*2)
        })
    
    print(f"[SIM] Brute Force: {attacker_ip} → {target}:22")
    return logs

def generate_ddos(attacker_ip=None):
    """DDoS attack simulate karo"""
    if not attacker_ip:
        attacker_ip = random.choice(KNOWN_ATTACKERS)
    
    logs = []
    target = random.choice(INTERNAL_IPS)
    base_time = datetime.now() - timedelta(minutes=2)
    
    for i in range(random.randint(20, 30)):
        logs.append({
            'srcaddr'  : attacker_ip,
            'dstaddr'  : target,
            'srcport'  : random.randint(1024, 65535),
            'dstport'  : random.choice([80, 443]),
            'protocol' : 6,
            'packets'  : random.randint(50, 200),
            'bytes'    : random.randint(50000, 200000),
            'action'   : random.choice(['ACCEPT', 'REJECT']),
            'timestamp': base_time + timedelta(seconds=i)
        })
    
    print(f"[SIM] DDoS: {attacker_ip} → {target}")
    return logs

def generate_fake_logs(num_entries=100, attack_scenario='mixed'):
    """
    Main function — realistic VPC Flow Logs generate karo
    
    attack_scenario options:
    - 'mixed'       : random attacks
    - 'port_scan'   : sirf port scan
    - 'brute_force' : sirf brute force
    - 'ddos'        : sirf ddos
    - 'all'         : sab attacks ek saath
    """
    
    print(f"\n[SIM] Generating realistic logs — scenario: {attack_scenario}")
    
    all_logs = []
    
    # Normal traffic always add karo
    normal_count = int(num_entries * 0.75)
    all_logs.extend(generate_normal_traffic(normal_count))
    
    # Attack scenario
    if attack_scenario == 'mixed':
        attack = random.choice(['port_scan', 'brute_force', 'ddos'])
        if attack == 'port_scan':
            all_logs.extend(generate_port_scan())
        elif attack == 'brute_force':
            all_logs.extend(generate_brute_force())
        else:
            all_logs.extend(generate_ddos())
            
    elif attack_scenario == 'port_scan':
        all_logs.extend(generate_port_scan())
        
    elif attack_scenario == 'brute_force':
        all_logs.extend(generate_brute_force())
        
    elif attack_scenario == 'ddos':
        all_logs.extend(generate_ddos())
        
    elif attack_scenario == 'all':
        all_logs.extend(generate_port_scan())
        all_logs.extend(generate_brute_force())
        all_logs.extend(generate_ddos())
    
    # DataFrame banao
    df = pd.DataFrame(all_logs)
    
    # Shuffle karo
    df = df.sample(frac=1).reset_index(drop=True)
    
    print(f"[SIM] Total entries  : {len(df)}")
    print(f"[SIM] Normal traffic : {(df['action']=='ACCEPT').sum()}")
    print(f"[SIM] Blocked traffic: {(df['action']=='REJECT').sum()}")
    print(f"[SIM] Unique IPs     : {df['srcaddr'].nunique()}")
    print(f"\n--- Sample ---")
    print(df[['srcaddr','dstaddr','dstport','action']].head(5))
    print("\n✅ Realistic logs ready!")
    
    return df


# Test
if __name__ == "__main__":
    print("=== Testing All Scenarios ===\n")
    
    print("1. Mixed scenario:")
    df1 = generate_fake_logs(100, 'mixed')
    
    print("\n2. All attacks scenario:")
    df2 = generate_fake_logs(100, 'all')
    