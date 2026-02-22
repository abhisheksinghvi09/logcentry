import time
import requests
import json
import uuid
from datetime import datetime

BASE_URL = "http://localhost:8005"

def wait_for_server():
    print("Waiting for server...")
    for _ in range(30):
        try:
            resp = requests.get(f"{BASE_URL}/api/v1/health")
            if resp.status_code == 200:
                print("Server is up!")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    return False

def setup_project():
    # Use demo key to create project
    headers = {"X-API-Key": "lc_dev_bypass_key"}
    
    # Check if project exists or ensure we have a key
    # For simplicity, let's just use the demo key for everything if it works, 
    # but the demo key is associated with the demo project.
    
    # Let's verify we can get the demo key
    resp = requests.get(f"{BASE_URL}/api/v1/demo-key")
    if resp.status_code != 200:
        print("Failed to get demo key")
        return None
        
    return "lc_dev_bypass_key"

def send_logs(api_key, logs):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    resp = requests.post(f"{BASE_URL}/api/v1/logs/batch", json={"logs": logs}, headers=headers)
    if resp.status_code == 200:
        print(f"Sent {len(logs)} logs")
        return True
    else:
        print(f"Failed to send logs: {resp.text}")
        return False

def verify_siem(api_key):
    headers = {"X-API-Key": api_key}
    
    # 1. Trigger Brute Force Rule
    print("\n--- Testing Brute Force Detection ---")
    attacker_ip = "192.168.1.100"
    logs = []
    for i in range(10):
        logs.append({
            "level": "warning",
            "message": f"Failed password for user root from {attacker_ip} port {5000+i} ssh2",
            "source": "sshd",
            "metadata": {"ip": attacker_ip, "user": "root"}
        })
    send_logs(api_key, logs)
    
    # Give it a moment for processing (if async) or just run manual evaluation
    time.sleep(2)
    
    # Trigger correlation/alert creation manually for testing
    print("Triggering correlation...")
    resp = requests.post(f"{BASE_URL}/api/v1/siem/alerts/from-correlation", headers=headers)
    print(f"Correlation response: {resp.json()}")
    
    # Check alerts
    resp = requests.get(f"{BASE_URL}/api/v1/siem/alerts", headers=headers)
    alerts = resp.json().get("alerts", [])
    print(f"Found {len(alerts)} alerts")
    
    brute_force_alert = next((a for a in alerts if "Brute Force" in a.get("rule_name", "") or "T1110" in str(a.get("mitre_techniques", ""))), None)
    if brute_force_alert:
        print("✅ Brute Force Alert Verified!")
    else:
        print("❌ Brute Force Alert NOT found")
        # Check rules evaluation
        resp = requests.post(f"{BASE_URL}/api/v1/siem/rules/evaluate", headers=headers)
        print(f"Rule evaluation: {resp.json()}")

    # 2. Test UEBA Anomaly
    print("\n--- Testing UEBA Anomaly ---")
    user = "jdoe"
    # Establish baseline (normal activity)
    project_id = "default"
    baseline_count = 50 

    # 1. Send baseline logs (Training Phase)
    print(f"Sending {baseline_count} baseline logs (9 AM)...")
    for _ in range(baseline_count):
        log = {
            "project_id": project_id,
            "timestamp": datetime.utcnow().replace(hour=9, minute=0).isoformat(), # Always at 9 AM
            "level": "info",
            "source": "web_server",
            "message": "User login successful",
            "metadata": {
                "user": "jdoe",
                "ip": "192.168.1.100",
                "action": "login"
            }
        }
        requests.post(f"{BASE_URL}/api/v1/logs/batch", json={"logs": [log]}, headers=headers)
    print(f"Sent {baseline_count} logs")

    # Trigger analysis to build baseline
    print("Triggering UEBA training...")
    requests.post(
        f"{BASE_URL}/api/v1/siem/entities/analyze", 
        params={"time_window_minutes": 60, "log_count": 100, "entity_type": "user"},
        headers=headers
    )

    # 2. Send anomaly log (Detection Phase)
    print("Sending anomaly log (3 AM)...")
    anomaly_log = {
        "project_id": project_id,
        "timestamp": datetime.utcnow().replace(hour=3, minute=0).isoformat(), # 3 AM (unusual)
        "level": "warning",
        "source": "vpn",
        "message": "VPN access detected",
        "metadata": {
            "user": "jdoe", # Same user
            "ip": "10.0.0.5", # New IP
            "action": "vpn_connect"
        }
    }
    requests.post(f"{BASE_URL}/api/v1/logs/batch", json={"logs": [anomaly_log]}, headers=headers)
    print("Sent 1 anomaly log")
    
    # 3. Analyze again to detect anomaly
    print("Triggering UEBA detection...")
    resp = requests.post(
        f"{BASE_URL}/api/v1/siem/entities/analyze", 
        params={"time_window_minutes": 60, "log_count": 100, "entity_type": "user"},
        headers=headers
    )
    analysis = resp.json()
    anomalies = analysis.get("anomalies", [])
    
    unusual_hour = next((a for a in anomalies if a["anomaly_type"] == "unusual_hour"), None)
    if unusual_hour:
        print("✅ UEBA Unusual Hour Anomaly Verified!")
    else:
        print("❌ UEBA Anomaly NOT found")
        print(f"Anomalies found: {anomalies}")

if __name__ == "__main__":
    if wait_for_server():
        key = setup_project()
        if key:
            verify_siem(key)
        else:
            print("Could not setup project/key")
    else:
        print("Server did not start")
