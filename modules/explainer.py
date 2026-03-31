import os
import json
from config import OPENAI_API_KEY

def build_prompt(threat):
    """Threat data se LLM prompt banao"""
    
    return f"""You are a cybersecurity expert analyzing network threats.

A threat has been detected in AWS cloud infrastructure. Analyze it and respond in simple, clear language that a non-technical person can understand.

THREAT DETAILS:
- Source IP: {threat['src_ip']}
- Threat Type: {threat['threat_type']}
- Severity: {threat['severity']}
- Description: {threat['description']}
- Ports Targeted: {threat['affected_ports']}
- Total Packets: {threat['total_packets']}
- Rejected Connections: {threat['rejected_count']}

Respond in exactly this format:

WHAT HAPPENED:
[2-3 lines explaining what the attacker did, in simple language]

WHY IT IS DANGEROUS:
[2-3 lines explaining the risk]

IMMEDIATE ACTION:
[3 bullet points — exactly what to do right now]

SEVERITY LEVEL: {threat['severity']}
"""


def explain_threat_local(threat):
    """OpenAI API ke bina — rule-based explanation (free, always works)"""
    
    threat_type = threat['threat_type']
    src_ip      = threat['src_ip']
    ports       = threat['affected_ports']
    severity    = threat['severity']
    
    explanations = {
        "PORT_SCAN": {
            "what": f"IP address {src_ip} ne tumhare server ke {len(ports)} alag ports ko scan kiya. Yeh ek reconnaissance attack hai — attacker pehle survey kar raha tha ki kaun se doors (ports) khule hain.",
            "why": "Port scan usually kisi bade attack ka pehla step hota hai. Attacker yeh pata karna chahta tha ki kaunsi services chal rahi hain taaki unhe exploit kar sake.",
            "actions": [
                f"AWS Security Group mein IP {src_ip} ko immediately block karo",
                "CloudTrail logs check karo — kya is IP ne aur kuch kiya?",
                "Unused ports band karo — sirf zaroori ports (443, 80) open rakho"
            ]
        },
        "DDOS_ATTEMPT": {
            "what": f"IP address {src_ip} se unusually high amount of traffic aa raha tha — {threat['total_packets']} packets ek saath. Yeh server ko overload karne ki koshish thi.",
            "why": "DDoS attack server ko slow ya completely down kar sakta hai. Agar yeh successful hota toh tumhara application sabke liye unavailable ho jaata.",
            "actions": [
                f"IP {src_ip} ko AWS Security Group mein turant block karo",
                "AWS Shield enable karo — yeh DDoS protection deta hai",
                "Rate limiting lagao — ek IP se max requests limit karo"
            ]
        },
        "BRUTE_FORCE": {
            "what": f"IP address {src_ip} ne {threat['rejected_count']} baar tumhare server pe login karne ki koshish ki aur har baar fail hua. Yeh automated password guessing attack hai.",
            "why": "Agar attacker sahi password guess kar leta toh tumhara server ka full control uske haath mein aata. SSH ya RDP brute force se server compromise ho sakta tha.",
            "actions": [
                f"IP {src_ip} ko AWS Security Group mein block karo",
                "SSH access sirf specific IPs tak limit karo (whitelist)",
                "Multi-factor authentication (MFA) enable karo"
            ]
        },
        "SUSPICIOUS_TRAFFIC": {
            "what": f"IP address {src_ip} se unusual network pattern detect hua. Normal traffic se alag behavior tha jo automated scanning ya probing indicate karta hai.",
            "why": "Suspicious traffic often kisi targeted attack ka indicator hota hai. Ignore karna risky ho sakta hai.",
            "actions": [
                f"IP {src_ip} ko monitor karo — agar dobara aaye toh block karo",
                "VPC Flow Logs review karo last 24 hours ke liye",
                "AWS GuardDuty enable karo for continuous monitoring"
            ]
        }
    }
    
    exp = explanations.get(threat_type, explanations["SUSPICIOUS_TRAFFIC"])
    
    report = f"""
{'='*55}
⚠️  NETGUARD AI — THREAT EXPLANATION
{'='*55}

🎯 THREAT TYPE : {threat_type}
📍 SOURCE IP   : {src_ip}
🔴 SEVERITY    : {severity}

📋 WHAT HAPPENED:
   {exp['what']}

⚡ WHY IT IS DANGEROUS:
   {exp['why']}

✅ IMMEDIATE ACTIONS:
"""
    for i, action in enumerate(exp['actions'], 1):
        report += f"   {i}. {action}\n"
    
    report += f"\n{'='*55}\n"
    return report


def explain_threat_openai(threat):
    """OpenAI API se explanation (API key chahiye)"""
    
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        
        prompt   = build_prompt(threat)
        response = client.chat.completions.create(
            model    = "gpt-3.5-turbo",
            messages = [{"role": "user", "content": prompt}],
            max_tokens = 400
        )
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"[!] OpenAI API error: {e}")
        print("[*] Falling back to local explanation...")
        return explain_threat_local(threat)


def explain_threats(threats):
    """Saare threats explain karo"""
    
    if not threats:
        print("✅ Koi threat nahi — explanation ki zaroorat nahi!")
        return []
    
    print(f"\n[*] {len(threats)} threat(s) explain ho rahe hain...")
    
    explanations = []
    for threat in threats:
        # API key hai toh OpenAI use karo, warna local
        if OPENAI_API_KEY and OPENAI_API_KEY != "sk-xxxxxxx":
            print(f"[*] OpenAI se explain ho raha hai: {threat['src_ip']}")
            exp = explain_threat_openai(threat)
        else:
            print(f"[*] Local explanation: {threat['src_ip']}")
            exp = explain_threat_local(threat)
        
        print(exp)
        explanations.append({
            'threat' : threat,
            'explanation': exp
        })
    
    return explanations


# Test karne ke liye
if __name__ == "__main__":
    from modules.log_simulator import generate_fake_logs
    from modules.detector import run_detection
    
    print("[*] Fake logs generate ho rahe hain...")
    df = generate_fake_logs()
    
    print("[*] Detection chal raha hai...")
    analyzed_df, threats = run_detection(df)
    
    print("[*] Explanation generate ho rahi hai...")
    explanations = explain_threats(threats)
    