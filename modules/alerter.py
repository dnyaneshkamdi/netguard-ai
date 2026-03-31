import boto3
import json
import requests
from datetime import datetime
from config import AWS_REGION, SLACK_WEBHOOK_URL

def send_sns_alert(threat, explanation):
    """AWS SNS se email alert bhejo"""
    
    try:
        sns = boto3.client('sns', region_name=AWS_REGION)
        
        # SNS topic check karo
        topics = sns.list_topics()['Topics']
        topic_arn = None
        
        for topic in topics:
            if 'netguard' in topic['TopicArn'].lower():
                topic_arn = topic['TopicArn']
                break
        
        if not topic_arn:
            print("[!] SNS topic nahi mila — pehle banao (steps neeche hain)")
            return False
        
        # Message banao
        subject = f"🚨 NetGuard AI Alert — {threat['threat_type']} Detected!"
        message = f"""
NetGuard AI — Security Alert
{'='*40}

THREAT DETECTED: {threat['threat_type']}
Source IP      : {threat['src_ip']}
Severity       : {threat['severity']}
Time           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

DESCRIPTION:
{threat['description']}

PORTS TARGETED: {threat['affected_ports']}
TOTAL PACKETS : {threat['total_packets']}

EXPLANATION:
{explanation}

{'='*40}
NetGuard AI — Automated Security System
        """
        
        sns.publish(
            TopicArn = topic_arn,
            Subject  = subject,
            Message  = message
        )
        
        print(f"[+] ✅ SNS Email alert bheja gaya!")
        return True
        
    except Exception as e:
        print(f"[!] SNS error: {e}")
        return False


def send_slack_alert(threat):
    """Slack webhook se alert bhejo"""
    
    if not SLACK_WEBHOOK_URL:
        print("[!] Slack webhook URL nahi hai — .env mein add karo")
        return False
    
    # Severity ke hisaab se color
    colors = {
        'CRITICAL': '#FF0000',
        'HIGH'    : '#FF6600',
        'MEDIUM'  : '#FFAA00',
        'LOW'     : '#00AA00'
    }
    color = colors.get(threat['severity'], '#FFAA00')
    
    payload = {
        "attachments": [{
            "color": color,
            "title": f"🚨 NetGuard AI — {threat['threat_type']} Detected!",
            "fields": [
                {"title": "Source IP",  "value": threat['src_ip'],       "short": True},
                {"title": "Severity",   "value": threat['severity'],     "short": True},
                {"title": "Type",       "value": threat['threat_type'],  "short": True},
                {"title": "Packets",    "value": str(threat['total_packets']), "short": True},
                {"title": "Ports Hit",  "value": str(threat['affected_ports']), "short": False},
                {"title": "Description","value": threat['description'],  "short": False},
            ],
            "footer": "NetGuard AI Security System",
            "ts"    : int(datetime.now().timestamp())
        }]
    }
    
    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data        = json.dumps(payload),
            headers     = {'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            print("[+] ✅ Slack alert bheja gaya!")
            return True
        else:
            print(f"[!] Slack error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[!] Slack connection error: {e}")
        return False


def send_console_alert(threat, explanation):
    """Console pe formatted alert print karo (always works!)"""
    
    severity_icons = {
        'CRITICAL': '🔴',
        'HIGH'    : '🟠',
        'MEDIUM'  : '🟡',
        'LOW'     : '🟢'
    }
    icon = severity_icons.get(threat['severity'], '🟡')
    
    print("\n" + "🚨"*25)
    print(f"""
  NETGUARD AI — LIVE SECURITY ALERT
  {'='*45}
  {icon} SEVERITY    : {threat['severity']}
  📌 THREAT TYPE : {threat['threat_type']}
  🌐 SOURCE IP   : {threat['src_ip']}
  ⏰ TIME        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  📋 DESCRIPTION : {threat['description']}
  🔢 PORTS HIT   : {threat['affected_ports']}
  {'='*45}
""")
    print("🚨"*25 + "\n")


def create_sns_topic():
    """SNS topic banana — ek baar run karo"""
    
    try:
        sns       = boto3.client('sns', region_name=AWS_REGION)
        response  = sns.create_topic(Name='netguard-alerts')
        topic_arn = response['TopicArn']
        print(f"[+] ✅ SNS Topic created: {topic_arn}")
        return topic_arn
        
    except Exception as e:
        print(f"[!] SNS topic create error: {e}")
        return None


def subscribe_email(email, topic_arn):
    """Email ko SNS topic se subscribe karo"""
    
    try:
        sns = boto3.client('sns', region_name=AWS_REGION)
        sns.subscribe(
            TopicArn = topic_arn,
            Protocol = 'email',
            Endpoint = email
        )
        print(f"[+] ✅ Confirmation email bheja gaya: {email}")
        print("[!] Apna email check karo aur confirm karo!")
        
    except Exception as e:
        print(f"[!] Subscribe error: {e}")


def send_alerts(threats, explanations):
    """Saare threats ke liye alerts bhejo"""
    
    if not threats:
        print("✅ Koi threat nahi — alert ki zaroorat nahi!")
        return
    
    print(f"\n[*] {len(threats)} threat(s) ke liye alerts bhej rahe hain...")
    
    for i, threat in enumerate(threats):
        exp = explanations[i]['explanation'] if i < len(explanations) else ""
        
        # Console alert — hamesha kaam karta hai
        send_console_alert(threat, exp)
        
        # SNS alert
        send_sns_alert(threat, exp)
        
        # Slack alert
        send_slack_alert(threat)


# Test karne ke liye
if __name__ == "__main__":
    from modules.log_simulator import generate_fake_logs
    from modules.detector import run_detection
    from modules.explainer import explain_threats
    
    print("[*] Full pipeline test chal raha hai...")
    
    df                   = generate_fake_logs()
    analyzed_df, threats = run_detection(df)
    explanations         = explain_threats(threats)
    
    send_alerts(threats, explanations)
    