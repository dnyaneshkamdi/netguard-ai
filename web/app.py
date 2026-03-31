from flask import Flask, render_template, jsonify
from datetime import datetime
import threading
import time
from modules.log_simulator import generate_fake_logs
from modules.detector import run_detection
from modules.explainer import explain_threats
from modules.alerter import send_alerts

app = Flask(__name__)

# Global state — live data store karne ke liye
dashboard_data = {
    'total_analyzed' : 0,
    'threats_found'  : 0,
    'last_scan'      : 'Never',
    'status'         : 'Starting...',
    'threats'        : [],
    'explanations'   : []
}

def run_pipeline():
    """Background mein har 30 seconds pe scan karo"""
    global dashboard_data
    
    while True:
        try:
            dashboard_data['status'] = 'Scanning...'
            
            # Step 1: Logs lao
            df = generate_fake_logs(num_entries=100)
            
            # Step 2: Detect karo
            analyzed_df, threats = run_detection(df)
            
            # Step 3: Explain karo
            explanations = explain_threats(threats)
            
            # Step 4: Alerts bhejo
            send_alerts(threats, explanations)
            
            # Dashboard update karo
            dashboard_data['total_analyzed'] += len(df)
            dashboard_data['threats_found']  += len(threats)
            dashboard_data['last_scan']       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            dashboard_data['status']          = 'Active — Monitoring'
            dashboard_data['threats']         = threats
            dashboard_data['explanations']    = explanations
            
        except Exception as e:
            dashboard_data['status'] = f'Error: {str(e)}'
        
        time.sleep(30)


@app.route('/')
def index():
    return render_template('dashboard.html', data=dashboard_data)


@app.route('/api/status')
def api_status():
    """Live data ke liye API endpoint"""
    return jsonify({
        'total_analyzed': dashboard_data['total_analyzed'],
        'threats_found' : dashboard_data['threats_found'],
        'last_scan'     : dashboard_data['last_scan'],
        'status'        : dashboard_data['status'],
        'threat_count'  : len(dashboard_data['threats']),
        'threats'       : dashboard_data['threats']
    })


@app.route('/api/scan')
def manual_scan():
    """Manual scan trigger karo"""
    try:
        df                   = generate_fake_logs(num_entries=100)
        analyzed_df, threats = run_detection(df)
        explanations         = explain_threats(threats)
        send_alerts(threats, explanations)
        
        dashboard_data['total_analyzed'] += len(df)
        dashboard_data['threats_found']  += len(threats)
        dashboard_data['last_scan']       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        dashboard_data['threats']         = threats
        dashboard_data['explanations']    = explanations
        
        return jsonify({'success': True, 'threats_found': len(threats)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


if __name__ == '__main__':
    # Background scanner thread shuru karo
    scanner = threading.Thread(target=run_pipeline, daemon=True)
    scanner.start()
    print("\n🚀 NetGuard AI Dashboard starting...")
    print("   Browser mein kholo: http://localhost:5000\n")
    app.run(debug=False, port=5000)
    