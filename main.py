import time
import threading
from datetime import datetime
from modules.log_simulator import generate_fake_logs
from modules.parse_vpc_logs import fetch_latest_logs
from modules.detector import run_detection
from modules.explainer import explain_threats
from modules.alerter import send_alerts
from config import AWS_REGION, S3_BUCKET_NAME

def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║                                                  ║
║         🛡️  NETGUARD AI v1.0                     ║
║     AI-Powered Cloud Security System             ║
║                                                  ║
║     Cloud   : AWS (ap-south-1)                   ║
║     AI      : Isolation Forest + LLM             ║
║     Alerts  : SNS Email                          ║
║     Dashboard: http://localhost:5000             ║
║                                                  ║
╚══════════════════════════════════════════════════╝
    """)

def run_single_scan(use_real_logs=False):
    """Ek baar scan karo"""
    
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 🔍 Scan shuru ho raha hai...")
    
    # Step 1: Logs lao
    if use_real_logs:
        print("[*] Real AWS VPC logs fetch ho rahe hain...")
        df = fetch_latest_logs()
        if df is None:
            print("[!] Real logs nahi mile — simulator use kar raha hai")
            df = generate_fake_logs()
    else:
        print("[*] Simulated logs generate ho rahe hain...")
        df = generate_fake_logs()
    
    if df is None or len(df) == 0:
        print("[!] Koi log data nahi mila")
        return
    
    # Step 2: AI Detection
    print("[*] AI detection chal rahi hai...")
    analyzed_df, threats = run_detection(df)
    
    # Step 3: LLM Explanation
    print("[*] Threats explain ho rahe hain...")
    explanations = explain_threats(threats)
    
    # Step 4: Alerts
    if threats:
        print(f"[*] {len(threats)} threat(s) ke liye alerts bhej rahe hain...")
        send_alerts(threats, explanations)
    else:
        print("[✅] Koi threat nahi mila — system safe hai!")
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Scan complete!\n")
    return threats


def run_continuous(interval=60, use_real_logs=False):
    """Continuous monitoring — har X seconds pe scan"""
    
    print(f"\n[*] Continuous monitoring shuru — har {interval} seconds pe scan")
    print("[*] Band karne ke liye Ctrl+C dabao\n")
    
    scan_count = 0
    total_threats = 0
    
    try:
        while True:
            scan_count += 1
            print(f"{'='*50}")
            print(f"  SCAN #{scan_count} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*50}")
            
            threats = run_single_scan(use_real_logs)
            if threats:
                total_threats += len(threats)
            
            print(f"[📊] Total scans: {scan_count} | Total threats: {total_threats}")
            print(f"[⏳] Next scan {interval} seconds mein...\n")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n[*] Monitoring band kiya")
        print(f"[📊] Final Stats:")
        print(f"     Total Scans   : {scan_count}")
        print(f"     Total Threats : {total_threats}")
        print(f"     Session End   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def start_dashboard():
    """Flask dashboard alag thread mein start karo"""
    from web.app import app, run_pipeline
    
    # Background scanner
    scanner = threading.Thread(target=run_pipeline, daemon=True)
    scanner.start()
    
    print("\n🚀 Dashboard starting: http://localhost:5000")
    app.run(debug=False, port=5000, use_reloader=False)


def main():
    print_banner()
    
    print("Kya karna hai?")
    print("1 — Single scan (ek baar)")
    print("2 — Continuous monitoring (auto repeat)")
    print("3 — Dashboard mode (browser mein dekho)")
    print("4 — Single scan with real AWS logs")
    
    choice = input("\nChoice (1/2/3/4): ").strip()
    
    if choice == '1':
        print("\n[*] Single scan mode...")
        run_single_scan(use_real_logs=False)
        
    elif choice == '2':
        interval = input("Scan interval (seconds, default 60): ").strip()
        interval = int(interval) if interval.isdigit() else 60
        run_continuous(interval=interval)
        
    elif choice == '3':
        start_dashboard()
        
    elif choice == '4':
        print("\n[*] Real AWS logs mode...")
        run_single_scan(use_real_logs=True)
        
    else:
        print("[!] Invalid choice — single scan chal raha hai")
        run_single_scan()


if __name__ == "__main__":
    main()
    