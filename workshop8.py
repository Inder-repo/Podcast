"""
STRIDE Threat Modeling - COMPLETE FINAL VERSION
All 4 Workshops | Hidden Unlock Codes | Enhanced Assessment with Threat Mapping
"""

import streamlit as st
import base64
import json
import os
import pandas as pd
from graphviz import Digraph
from datetime import datetime
import random

st.set_page_config(
    page_title="STRIDE Threat Modeling Learning Lab",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# UNLOCK CODES - NOT DISPLAYED IN UI
WORKSHOP_CODES = {"1": None, "2": "MICRO2025", "3": "TENANT2025", "4": "HEALTH2025"}

# CSS
st.markdown("""
<style>
    .stButton>button{width:100%;border-radius:4px;font-weight:500}
    .threat-critical{background-color:#B71C1C;color:white;padding:12px;border-radius:4px;border-left:5px solid #D32F2F;margin:8px 0}
    .threat-high{background-color:#FFE5E5;padding:12px;border-radius:4px;border-left:5px solid #F96167;margin:8px 0}
    .threat-medium{background-color:#FFF9E5;padding:12px;border-radius:4px;border-left:5px solid #FFC107;margin:8px 0}
    .threat-low{background-color:#E8F5E9;padding:12px;border-radius:4px;border-left:5px solid #2C5F2D;margin:8px 0}
    .correct-answer{background-color:#C8E6C9;padding:12px;border-radius:4px;border-left:5px solid #4CAF50;margin:8px 0}
    .incorrect-answer{background-color:#FFCDD2;padding:12px;border-radius:4px;border-left:5px solid #F44336;margin:8px 0}
    .partial-answer{background-color:#FFF9C4;padding:12px;border-radius:4px;border-left:5px solid #FFC107;margin:8px 0}
    .score-excellent{background-color:#4CAF50;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
    .badge-completed{background-color:#2C5F2D;color:white;padding:4px 12px;border-radius:12px;font-size:0.85em;font-weight:600}
    .badge-locked{background-color:#757575;color:white;padding:4px 12px;border-radius:12px;font-size:0.85em;font-weight:600}
    .info-box{background-color:#E3F2FD;padding:16px;border-radius:4px;border-left:4px solid #1976D2;margin:12px 0}
    .learning-box{background-color:#E8EAF6;padding:16px;border-radius:4px;border-left:4px solid #3F51B5;margin:12px 0}
    .component-card{background-color:#F5F5F5;padding:12px;border-radius:4px;border-left:3px solid #028090;margin:8px 0}
    .threat-detail-box{background-color:#FFF9E5;padding:15px;border-radius:6px;border-left:4px solid #FF9800;margin:10px 0}
</style>
""", unsafe_allow_html=True)

def init_session_state():
    defaults = {
        'selected_workshop': None, 'completed_workshops': set(), 'unlocked_workshops': set(['1']),
        'current_step': 1, 'threats': [], 'user_answers': [], 'total_score': 0, 'max_score': 0,
        'diagram_generated': None, 'detailed_diagram_generated': None, 'show_unlock_form': {}
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# COMPLETE THREAT DATABASE - ALL WORKSHOPS
PREDEFINED_THREATS = {
    "1": [
        {"id": "T-001", "stride": "Spoofing", "component": "Web Frontend → API Backend",
         "threat": "Session hijacking via XSS", "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["HttpOnly cookies", "CSP headers", "Input sanitization", "XSS prevention"],
         "incorrect_mitigations": ["Increase password complexity", "Add rate limiting", "Enable 2FA"],
         "explanation": "XSS allows stealing session cookies. HttpOnly prevents JavaScript access to cookies.",
         "compliance": "OWASP Top 10 A03:2021", "points": 10,
         "why_this_risk": "Medium likelihood - XSS still common. High impact - full account access.",
         "why_these_controls": "HttpOnly blocks cookie theft. CSP restricts scripts. Sanitization prevents injection.",
         "real_world": "British Airways fined £20M for XSS-based breach (2019)."},
        
        {"id": "T-002", "stride": "Tampering", "component": "API Backend → Database",
         "threat": "SQL injection", "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Parameterized queries", "Use ORM", "Input validation", "Least privilege"],
         "incorrect_mitigations": ["Encrypt database", "Add logging", "Strong passwords"],
         "explanation": "SQL injection exploits unsanitized input. Parameterized queries prevent it.",
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1", "points": 10,
         "why_this_risk": "Medium likelihood - still common. Critical impact - full database access.",
         "why_these_controls": "Parameterized queries treat input as data, not code.",
         "real_world": "Target breach (2013) started with SQL injection - 40M cards stolen."},
        
        {"id": "T-003", "stride": "Information Disclosure", "component": "Database",
         "threat": "Unencrypted PII", "likelihood": "Low", "impact": "Critical",
         "correct_mitigations": ["AES-256 encryption", "AWS RDS encryption", "Encrypt backups", "AWS KMS"],
         "incorrect_mitigations": ["Add firewall", "Increase password strength", "Add monitoring"],
         "explanation": "Unencrypted data at rest exposed if storage compromised.",
         "compliance": "GDPR Article 32, PCI-DSS 3.4", "points": 10,
         "why_this_risk": "Low likelihood - requires physical access. Critical - GDPR fines up to 4% revenue.",
         "why_these_controls": "Encryption makes stolen data unreadable without keys.",
         "real_world": "Equifax (2017) - 147M exposed. Encryption would have limited damage."}
    ],
    
    "2": [
        {"id": "T-101", "stride": "Information Disclosure", "component": "Mobile App → API Gateway",
         "threat": "BOLA - accessing other users' accounts", "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Object-level authorization", "Verify ownership", "JWT validation", "Resource-based permissions"],
         "incorrect_mitigations": ["Add encryption", "Use HTTPS", "Enable logging"],
         "explanation": "BOLA allows accessing resources without ownership check.",
         "compliance": "OWASP API Security Top 10 - API1", "points": 10,
         "why_this_risk": "High - common in APIs. Critical - access any user's data.",
         "why_these_controls": "Validate user owns requested resource on EVERY request.",
         "real_world": "Peloton API (2021) allowed accessing any user's data."},
        
        {"id": "T-102", "stride": "Tampering", "component": "Payment Service",
         "threat": "Vulnerable container image", "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["ECR image scanning", "Regular updates", "Minimal base images", "Scan on push"],
         "incorrect_mitigations": ["Add firewall", "Enable logging", "Use encryption"],
         "explanation": "Container images can contain CVEs. Scan and update regularly.",
         "compliance": "CIS Docker Benchmark", "points": 10,
         "why_this_risk": "Medium - images often outdated. High - container compromise.",
         "why_these_controls": "Automated scanning detects vulnerabilities. Updates patch them.",
         "real_world": "Many breaches via vulnerable container images."}
    ],
    
    "3": [
        {"id": "T-201", "stride": "Information Disclosure", "component": "Query Service → Data Warehouse",
         "threat": "Row-level security bypass", "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["RLS enforcement", "Query rewriting", "Tenant context validation", "Integration testing"],
         "incorrect_mitigations": ["Add encryption", "Use VPN", "Enable logging"],
         "explanation": "Multi-tenant systems must enforce RLS. Tenant A should never see Tenant B data.",
         "compliance": "SOC 2 CC6.1", "points": 10,
         "why_this_risk": "Medium - complex to implement. Critical - cross-tenant data leak.",
         "why_these_controls": "RLS enforces data isolation at database level.",
         "real_world": "Many SaaS platforms have had cross-tenant leaks."},
        
        {"id": "T-202", "stride": "Tampering", "component": "Kafka → Spark Processing",
         "threat": "Data pipeline poisoning", "likelihood": "Low", "impact": "High",
         "correct_mitigations": ["Schema validation", "Producer authentication", "Input sanitization", "Message signing"],
         "incorrect_mitigations": ["Add monitoring", "Increase storage", "Use encryption"],
         "explanation": "Data pipelines process untrusted data. Validate schema and sanitize.",
         "compliance": "ISO 27001 A.14.2.5", "points": 10,
         "why_this_risk": "Low - requires access. High - corrupts analytics.",
         "why_these_controls": "Schema validation enforces structure. Sanitization prevents injection.",
         "real_world": "Data pipeline attacks corrupt business intelligence."}
    ],
    
    "4": [
        {"id": "T-301", "stride": "Tampering", "component": "IoT Gateway → Device Data Svc",
         "threat": "MQTT message injection", "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["MQTT over TLS", "Client certificates", "Message signing", "Input validation"],
         "incorrect_mitigations": ["Add encryption", "Use HTTPS", "Enable logging"],
         "explanation": "Unprotected MQTT allows injecting false vitals. Could trigger wrong treatment.",
         "compliance": "FDA 21 CFR Part 11, HIPAA", "points": 10,
         "why_this_risk": "High - IoT often weak security. Critical - false vitals = patient harm.",
         "why_these_controls": "TLS encrypts. Certificates authenticate. Signing proves integrity.",
         "real_world": "FDA recalls for insecure medical devices."},
        
        {"id": "T-302", "stride": "Information Disclosure", "component": "Patient DB",
         "threat": "PHI exposure via unencrypted backups", "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Encrypt backups", "AWS KMS", "Backup access controls", "Audit logging"],
         "incorrect_mitigations": ["Rate limiting", "Enable logging", "Use firewall"],
         "explanation": "Database backups contain full PHI. Must be encrypted.",
         "compliance": "HIPAA 164.312(a)(2)(iv)", "points": 10,
         "why_this_risk": "Medium - backups often overlooked. Critical - HIPAA breach.",
         "why_these_controls": "Backup encryption protects data at rest. KMS manages keys.",
         "real_world": "Healthcare breaches often via unencrypted backups."}
    ]
}

# ALL 4 WORKSHOPS COMPLETE
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: E-Commerce",
        "level": "Foundation", "duration": "2 hours", "target_threats": 3,
        "scenario": {
            "title": "TechMart Store",
            "description": "E-commerce platform selling electronics",
            "business_context": "Series A startup, 50K monthly users, $2M revenue",
            "assets": ["Customer PII", "Payment data (via Stripe)", "User credentials", "Order history"],
            "objectives": ["Confidentiality: Protect customer PII", "Integrity: Ensure order accuracy", "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS Level 4", "GDPR", "CCPA"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA on CloudFront/S3"},
                {"name": "API Backend", "type": "process", "description": "Node.js/Express on ECS"},
                {"name": "Database", "type": "datastore", "description": "RDS PostgreSQL"},
                {"name": "Stripe", "type": "external_entity", "description": "Payment processing"},
                {"name": "S3 Storage", "type": "datastore", "description": "Product images"},
                {"name": "SendGrid", "type": "external_entity", "description": "Email notifications"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP requests", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database", "data": "SQL queries", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payment tokens", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "S3 Storage", "data": "Images", "protocol": "S3 API"},
                {"source": "API Backend", "destination": "SendGrid", "data": "Emails", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Internet Boundary", "description": "Untrusted users → Trusted AWS", "components": ["Customer", "Web Frontend"]},
                {"name": "Application Tier", "description": "Frontend → Backend", "components": ["Web Frontend", "API Backend"]},
                {"name": "Data Tier", "description": "App → Storage", "components": ["API Backend", "Database", "S3 Storage"]},
                {"name": "External Services", "description": "Internal → Third-party", "components": ["API Backend", "Stripe", "SendGrid"]}
            ]
        }
    },
    "2": {
        "name": "Workshop 2: Mobile Banking",
        "level": "Intermediate", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "CloudBank Mobile Banking",
            "description": "Microservices banking platform",
            "business_context": "Regional bank, 500K customers, $50B assets",
            "assets": ["Customer financial data", "Transaction history", "PII including SSN", "OAuth tokens"],
            "objectives": ["Confidentiality: Protect financial data", "Integrity: Prevent unauthorized transfers", "Availability: 99.95% uptime"],
            "compliance": ["PCI-DSS", "SOC 2", "GLBA"],
            "components": [
                {"name": "Mobile App", "type": "external_entity", "description": "iOS/Android apps"},
                {"name": "API Gateway", "type": "process", "description": "AWS API Gateway"},
                {"name": "User Service", "type": "process", "description": "Auth & profiles (ECS)"},
                {"name": "Payment Service", "type": "process", "description": "Transfers (ECS)"},
                {"name": "User DB", "type": "datastore", "description": "DynamoDB"},
                {"name": "Transaction DB", "type": "datastore", "description": "Aurora PostgreSQL"},
                {"name": "Plaid", "type": "external_entity", "description": "Bank account linking"}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS requests", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "User Service", "data": "Auth requests", "protocol": "HTTP/2"},
                {"source": "API Gateway", "destination": "Payment Service", "data": "Payments", "protocol": "HTTP/2"},
                {"source": "Payment Service", "destination": "Transaction DB", "data": "Transactions", "protocol": "PostgreSQL"},
                {"source": "User Service", "destination": "User DB", "data": "User data", "protocol": "DynamoDB"},
                {"source": "Payment Service", "destination": "Plaid", "data": "Account links", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Client Boundary", "description": "Mobile → Cloud", "components": ["Mobile App", "API Gateway"]},
                {"name": "Service Mesh", "description": "Microservices", "components": ["User Service", "Payment Service"]},
                {"name": "Data Layer", "description": "Services → Datastores", "components": ["User DB", "Transaction DB"]},
                {"name": "External", "description": "Platform → Third parties", "components": ["Plaid"]}
            ]
        }
    },
    "3": {
        "name": "Workshop 3: SaaS Analytics",
        "level": "Advanced", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "DataInsight Analytics Platform",
            "description": "Multi-tenant SaaS for business intelligence",
            "business_context": "B2B SaaS, 500 enterprise customers, 10TB daily",
            "assets": ["Customer business data", "Tenant metadata", "Data pipeline logic", "API keys"],
            "objectives": ["Confidentiality: Complete tenant isolation", "Integrity: Accurate analytics", "Availability: 99.99% SLA"],
            "compliance": ["SOC 2 Type II", "ISO 27001", "GDPR"],
            "components": [
                {"name": "Web Dashboard", "type": "external_entity", "description": "React SPA"},
                {"name": "API Gateway", "type": "process", "description": "Kong Gateway"},
                {"name": "Ingestion Service", "type": "process", "description": "Data ingestion API"},
                {"name": "Kafka", "type": "datastore", "description": "Amazon MSK streaming"},
                {"name": "Spark Processing", "type": "process", "description": "EMR transformation"},
                {"name": "Data Warehouse", "type": "datastore", "description": "Redshift with RLS"},
                {"name": "Query Service", "type": "process", "description": "Analytics queries"},
                {"name": "Salesforce", "type": "external_entity", "description": "CRM integration"}
            ],
            "data_flows": [
                {"source": "Web Dashboard", "destination": "API Gateway", "data": "Authenticated requests", "protocol": "HTTPS"},
                {"source": "Salesforce", "destination": "Ingestion Service", "data": "CRM data", "protocol": "HTTPS"},
                {"source": "Ingestion Service", "destination": "Kafka", "data": "Event streams", "protocol": "Kafka"},
                {"source": "Kafka", "destination": "Spark Processing", "data": "Raw events", "protocol": "Kafka"},
                {"source": "Spark Processing", "destination": "Data Warehouse", "data": "Processed data", "protocol": "Redshift"},
                {"source": "Query Service", "destination": "Data Warehouse", "data": "SQL queries", "protocol": "Redshift"}
            ],
            "trust_boundaries": [
                {"name": "Tenant A Isolation", "description": "Logical boundary Tenant A", "components": []},
                {"name": "Tenant B Isolation", "description": "Logical boundary Tenant B", "components": []},
                {"name": "Pipeline Ingestion", "description": "External → Processing", "components": ["Salesforce", "Ingestion Service", "Kafka"]},
                {"name": "Pipeline Storage", "description": "Processing → Storage", "components": ["Spark Processing", "Data Warehouse"]}
            ]
        }
    },
    "4": {
        "name": "Workshop 4: Healthcare IoT",
        "level": "Expert", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "HealthMonitor Connected Care",
            "description": "Remote patient monitoring with medical IoT devices",
            "business_context": "FDA-registered device, 10K patients, life-critical",
            "assets": ["Protected Health Information (PHI)", "Real-time vital signs (safety-critical)", "Device calibration data"],
            "objectives": ["Safety: Device data integrity (HIGHEST)", "Privacy: Protect PHI per HIPAA", "Availability: 99.99% for alerts"],
            "compliance": ["HIPAA", "HITECH", "FDA 21 CFR Part 11"],
            "components": [
                {"name": "Glucose Monitor", "type": "external_entity", "description": "CGM IoT device"},
                {"name": "BP Monitor", "type": "external_entity", "description": "Blood pressure cuff"},
                {"name": "IoT Gateway", "type": "process", "description": "Edge device in home"},
                {"name": "Device Data Svc", "type": "process", "description": "Telemetry ingestion"},
                {"name": "Alert Service", "type": "process", "description": "SAFETY-CRITICAL alerts"},
                {"name": "Patient DB", "type": "datastore", "description": "Aurora (HIPAA)"},
                {"name": "Mobile App", "type": "external_entity", "description": "Patient app"},
                {"name": "Web Portal", "type": "external_entity", "description": "Clinician portal"}
            ],
            "data_flows": [
                {"source": "Glucose Monitor", "destination": "IoT Gateway", "data": "Glucose readings", "protocol": "BLE"},
                {"source": "BP Monitor", "destination": "IoT Gateway", "data": "BP readings", "protocol": "BLE"},
                {"source": "IoT Gateway", "destination": "Device Data Svc", "data": "Vital signs", "protocol": "MQTT/TLS"},
                {"source": "Device Data Svc", "destination": "Alert Service", "data": "Vitals monitoring", "protocol": "HTTP/2"},
                {"source": "Alert Service", "destination": "Web Portal", "data": "Critical alerts", "protocol": "WebSocket"},
                {"source": "Mobile App", "destination": "Device Data Svc", "data": "Patient queries", "protocol": "HTTPS"},
                {"source": "Device Data Svc", "destination": "Patient DB", "data": "PHI storage", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Patient Home", "description": "Physical access risk", "components": ["Glucose Monitor", "BP Monitor", "IoT Gateway"]},
                {"name": "Patient WiFi", "description": "Untrusted network", "components": ["IoT Gateway", "Device Data Svc"]},
                {"name": "Cloud Platform", "description": "Trusted AWS", "components": ["Device Data Svc", "Alert Service"]},
                {"name": "Safety-Critical", "description": "Alert path", "components": ["Alert Service", "Web Portal"]}
            ]
        }
    }
}

def generate_high_level_architecture(workshop_config):
    try:
        dot = Digraph(format="png")
        dot.attr(rankdir="LR", size="10,6")
        
        scenario = workshop_config["scenario"]
        
        dot.node("Users", "Users/Clients", fillcolor="lightcoral", style="filled")
        dot.node("Application", f"{scenario['title']}\nApplication", fillcolor="lightblue", style="filled")
        dot.node("Data", "Data Layer", fillcolor="lightgreen", style="filled")
        
        dot.edge("Users", "Application", "HTTPS")
        dot.edge("Application", "Data", "Queries")
        
        path = dot.render("high_level", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except:
        return None

def generate_detailed_dfd(workshop_config, threats=[]):
    """Generate detailed DFD with threat mapping for assessment"""
    try:
        dot = Digraph(format="png")
        dot.attr(rankdir="TB", size="16,14", fontname="Arial", bgcolor="white", splines="polyline")
        dot.attr("node", fontname="Arial", fontsize="10")
        dot.attr("edge", fontname="Arial", fontsize="8")
        
        styles = {
            "external_entity": {"shape": "oval", "style": "filled", "fillcolor": "lightcoral", "color": "red", "penwidth": "2"},
            "process": {"shape": "box", "style": "filled,rounded", "fillcolor": "lightblue", "color": "blue", "penwidth": "2"},
            "datastore": {"shape": "cylinder", "style": "filled", "fillcolor": "lightgreen", "color": "green", "penwidth": "2"}
        }
        
        # Map threats to components/flows
        node_threats = {}
        edge_threats = {}
        
        for threat in threats:
            threat_id = threat.get("matched_threat_id", threat.get("id", ""))
            affected = threat.get("component", threat.get("affected_component", ""))
            stride = threat.get("stride", threat.get("stride_category", ""))
            
            threat_info = f"{threat_id}({stride[0]})"  # e.g., T-001(S)
            
            if "→" in affected:
                edge_threats.setdefault(affected, []).append(threat_info)
            else:
                node_threats.setdefault(affected, []).append(threat_info)
        
        # Add nodes with threat annotations
        for comp in workshop_config["scenario"]["components"]:
            name = comp["name"]
            threat_labels = node_threats.get(name, [])
            
            label = f"{name}\\n{comp['description']}"
            if threat_labels:
                label += f"\\n⚠ {', '.join(threat_labels)}"
            
            style = styles.get(comp["type"], styles["process"]).copy()
            if threat_labels:
                style["fillcolor"] = "#FFE082"  # Highlight threatened components
                style["penwidth"] = "3"
            
            dot.node(name, label, **style)
        
        # Add edges with threat annotations
        for flow in workshop_config["scenario"]["data_flows"]:
            edge_key = f"{flow['source']} → {flow['destination']}"
            threat_labels = edge_threats.get(edge_key, [])
            
            label = f"{flow['data']}\\n({flow['protocol']})"
            if threat_labels:
                label += f"\\n⚠ {', '.join(threat_labels)}"
            
            color = "#FF6F00" if threat_labels else "black"
            penwidth = "3" if threat_labels else "1.5"
            
            dot.edge(flow['source'], flow['destination'], label=label, color=color, penwidth=penwidth)
        
        # Add trust boundaries
        for idx, boundary in enumerate(workshop_config["scenario"]["trust_boundaries"]):
            with dot.subgraph(name=f"cluster_{idx}") as c:
                c.attr(label=f"🔒 {boundary['name']}", style="dashed", color="purple",
                       fontsize="12", penwidth="2.5", bgcolor="#F3E5F5")
                for comp_name in boundary.get("components", []):
                    c.node(comp_name)
        
        path = dot.render("detailed_dfd", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except:
        return None

def calculate_threat_score(user_threat, predefined_threat):
    score, max_score, feedback = 0, predefined_threat["points"], []
    
    if user_threat["component"] == predefined_threat["component"]:
        score += 2
        feedback.append("✓ Correct component")
    else:
        feedback.append(f"✗ Expected: {predefined_threat['component']}")
    
    if user_threat["stride"] == predefined_threat["stride"]:
        score += 2
        feedback.append("✓ Correct STRIDE")
    else:
        feedback.append(f"✗ Expected STRIDE: {predefined_threat['stride']}")
    
    if user_threat["likelihood"] == predefined_threat["likelihood"]:
        score += 1
        feedback.append("✓ Correct likelihood")
    
    if user_threat["impact"] == predefined_threat["impact"]:
        score += 1
        feedback.append("✓ Correct impact")
    
    correct_mits = set(predefined_threat["correct_mitigations"])
    user_mits = set(user_threat.get("selected_mitigations", []))
    correct_selected = user_mits & correct_mits
    
    if len(correct_selected) >= 3:
        score += 4
        feedback.append(f"✓ Excellent mitigations ({len(correct_selected)})")
    elif len(correct_selected) >= 2:
        score += 3
        feedback.append(f"✓ Good mitigations ({len(correct_selected)})")
    elif len(correct_selected) >= 1:
        score += 2
        feedback.append(f"⚠ Partial ({len(correct_selected)})")
    
    return max(0, score), max_score, feedback

def save_progress():
    try:
        with open("/tmp/threat_progress.json", "w") as f:
            json.dump({
                "completed_workshops": list(st.session_state.completed_workshops),
                "unlocked_workshops": list(st.session_state.unlocked_workshops),
                "selected_workshop": st.session_state.selected_workshop,
                "current_step": st.session_state.current_step,
                "threats": st.session_state.threats,
                "user_answers": st.session_state.user_answers,
                "total_score": st.session_state.total_score,
                "max_score": st.session_state.max_score
            }, f)
    except:
        pass

def load_progress():
    try:
        if os.path.exists("/tmp/threat_progress.json"):
            with open("/tmp/threat_progress.json") as f:
                p = json.load(f)
                st.session_state.completed_workshops = set(p.get("completed_workshops", []))
                st.session_state.unlocked_workshops = set(p.get("unlocked_workshops", ["1"]))
                st.session_state.selected_workshop = p.get("selected_workshop")
                st.session_state.current_step = p.get("current_step", 1)
                st.session_state.threats = p.get("threats", [])
                st.session_state.user_answers = p.get("user_answers", [])
                st.session_state.total_score = p.get("total_score", 0)
                st.session_state.max_score = p.get("max_score", 0)
    except:
        pass

load_progress()

# SIDEBAR
with st.sidebar:
    st.title("🔒 STRIDE Lab")
    st.markdown("### Workshops")
    
    if st.session_state.selected_workshop and st.session_state.max_score > 0:
        score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
        st.markdown("### 📊 Score")
        st.progress(score_pct / 100)
        st.markdown(f"**{st.session_state.total_score}/{st.session_state.max_score}** ({score_pct:.1f}%)")
        st.markdown("---")
    
    for ws_id, ws in WORKSHOPS.items():
        unlocked = ws_id in st.session_state.unlocked_workshops
        completed = ws_id in st.session_state.completed_workshops
        
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"Workshop {ws_id}", key=f"ws_{ws_id}", disabled=not unlocked):
                st.session_state.selected_workshop = ws_id
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                st.rerun()
        
        with col2:
            st.markdown("✅" if completed else "🔒" if not unlocked else "")
        
        # UNLOCK FORM - NO CODES DISPLAYED
        if not unlocked and ws_id != "1":
            unlock_key = f"unlock_{ws_id}"
            if unlock_key not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[unlock_key] = False
            
            if st.button(f"Unlock", key=f"unlock_btn_{ws_id}"):
                st.session_state.show_unlock_form[unlock_key] = not st.session_state.show_unlock_form[unlock_key]
            
            if st.session_state.show_unlock_form.get(unlock_key):
                code = st.text_input("Code from instructor", type="password", key=f"code_{ws_id}")
                if st.button("Submit", key=f"submit_{ws_id}"):
                    if code == WORKSHOP_CODES.get(ws_id):
                        st.session_state.unlocked_workshops.add(ws_id)
                        st.session_state.show_unlock_form[unlock_key] = False
                        save_progress()
                        st.success("Unlocked!")
                        st.rerun()
                    else:
                        st.error("Invalid code")
        
        st.caption(f"{ws['level']} | {ws['target_threats']} threats")
        st.markdown("---")

# MAIN
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling")
    st.markdown("Select a workshop from the sidebar to begin.")
    st.info("**Note:** Workshop unlock codes will be provided by your instructor.")
    st.stop()

current = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

st.title(current["name"])
st.caption(f"{current['level']} | {current['scenario']['title']}")

# Progress
cols = st.columns(5)
steps = ["Scope", "Decompose", "Threats", "Assess", "Complete"]
for idx, step in enumerate(steps):
    with cols[idx]:
        if idx + 1 < st.session_state.current_step:
            st.markdown(f"✅ {step}")
        elif idx + 1 == st.session_state.current_step:
            st.markdown(f"▶️ **{step}**")
        else:
            st.markdown(f"⭕ {step}")

st.markdown("---")

# STEP 1
if st.session_state.current_step == 1:
    st.header("Step 1: Scope")
    
    scenario = current["scenario"]
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown(f"**Context:** {scenario['business_context']}")
        st.markdown("### Objectives")
        for obj in scenario["objectives"]:
            st.markdown(f"- {obj}")
        st.markdown("### Assets")
        for asset in scenario["assets"]:
            st.markdown(f"- {asset}")
        st.markdown("### Compliance")
        for comp in scenario["compliance"]:
            st.markdown(f"- {comp}")
    
    with col2:
        st.info(f"**Goal:** {current['target_threats']} threats\n**Duration:** {current['duration']}")
    
    st.subheader("High-Level Architecture")
    diagram = generate_high_level_architecture(current)
    if diagram:
        st.image(f"data:image/png;base64,{diagram}")
    
    if st.button("Next ➡️", type="primary"):
        st.session_state.current_step = 2
        save_progress()
        st.rerun()

# STEP 2
elif st.session_state.current_step == 2:
    st.header("Step 2: Decompose")
    
    diagram = generate_detailed_dfd(current, st.session_state.threats)
    if diagram:
        st.image(f"data:image/png;base64,{diagram}")
        st.session_state.detailed_diagram_generated = diagram
    
    st.subheader("Data Flows")
    for flow in current["scenario"]["data_flows"]:
        st.markdown(f"- {flow['source']} → {flow['destination']}: {flow['data']} ({flow['protocol']})")
    
    st.subheader("Trust Boundaries")
    for boundary in current["scenario"]["trust_boundaries"]:
        st.markdown(f"**🔒 {boundary['name']}:** {boundary['description']}")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 1
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next ➡️", type="primary"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()

# STEP 3 - NO NESTED EXPANDERS
elif st.session_state.current_step == 3:
    st.header("Step 3: Identify Threats")
    st.info(f"Goal: {current['target_threats']} threats")
    
    with st.form("threat_form"):
        threat_options = {f"{t['id']}: {t['threat']}": t for t in workshop_threats}
        
        if not threat_options:
            st.error("No threats available")
            st.stop()
        
        selected_key = st.selectbox("Select threat:", list(threat_options.keys()))
        selected_predefined = threat_options[selected_key]
        
        col1, col2 = st.columns(2)
        
        with col1:
            all_components = [c["name"] for c in current["scenario"]["components"]]
            all_flows = [f"{f['source']} → {f['destination']}" for f in current["scenario"]["data_flows"]]
            
            user_component = st.selectbox("Component:", all_components + all_flows)
            user_stride = st.selectbox("STRIDE:", ["Spoofing", "Tampering", "Repudiation", 
                                                    "Information Disclosure", "Denial of Service", 
                                                    "Elevation of Privilege"])
            user_likelihood = st.select_slider("Likelihood:", ["Low", "Medium", "High", "Critical"])
            user_impact = st.select_slider("Impact:", ["Low", "Medium", "High", "Critical"])
        
        with col2:
            all_mits = selected_predefined["correct_mitigations"] + selected_predefined.get("incorrect_mitigations", [])
            random.shuffle(all_mits)
            user_mitigations = st.multiselect("Mitigations:", all_mits)
        
        if st.form_submit_button("Submit", type="primary"):
            user_answer = {
                "component": user_component,
                "stride": user_stride,
                "likelihood": user_likelihood,
                "impact": user_impact,
                "selected_mitigations": user_mitigations,
                "matched_threat_id": selected_predefined["id"]
            }
            
            score, max_score, feedback = calculate_threat_score(user_answer, selected_predefined)
            
            st.session_state.total_score += score
            st.session_state.max_score += max_score
            
            st.session_state.user_answers.append({
                **user_answer,
                "score": score,
                "max_score": max_score,
                "feedback": feedback,
                "predefined": selected_predefined
            })
            
            st.session_state.threats.append(user_answer)
            save_progress()
            st.rerun()
    
    # Display answers - NO NESTED EXPANDERS
    if st.session_state.user_answers:
        st.markdown("---")
        st.subheader(f"Answers ({len(st.session_state.user_answers)}/{current['target_threats']})")
        
        for idx, answer in enumerate(st.session_state.user_answers):
            score_pct = (answer["score"] / answer["max_score"]) * 100
            emoji = "✅" if score_pct >= 80 else "⚠️" if score_pct >= 50 else "❌"
            
            st.markdown(f"### {emoji} {answer['matched_threat_id']} ({score_pct:.0f}%)")
            
            for fb in answer["feedback"]:
                if "✓" in fb:
                    st.success(fb)
                elif "✗" in fb:
                    st.error(fb)
                else:
                    st.warning(fb)
            
            # Learning content - INLINE
            predefined = answer.get("predefined")
            if predefined:
                st.markdown("**📚 Learning:**")
                st.info(f"**Explanation:** {predefined['explanation']}")
                st.caption(f"**Why:** {predefined['why_these_controls']}")
                st.caption(f"**Example:** {predefined['real_world']}")
            
            st.markdown("---")
    
    progress = len(st.session_state.user_answers) / current['target_threats']
    st.progress(min(progress, 1.0))
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 2
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next ➡️", type="primary"):
            if st.session_state.user_answers:
                st.session_state.current_step = 4
                save_progress()
                st.rerun()
            else:
                st.error("Add at least one threat")

# STEP 4 - ENHANCED WITH THREAT-MAPPED DIAGRAM
elif st.session_state.current_step == 4:
    st.header("Step 4: Assessment")
    
    if not st.session_state.user_answers:
        st.warning("No answers")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
        st.stop()
    
    # THREAT-MAPPED DIAGRAM
    st.subheader("🗺️ Threat-Mapped Architecture")
    st.markdown("""
    <div class="info-box">
    This diagram shows all identified threats mapped to affected components and data flows.
    Orange highlights indicate threatened elements. Threat IDs are labeled with STRIDE categories.
    </div>
    """, unsafe_allow_html=True)
    
    with st.spinner("Generating threat-mapped diagram..."):
        threat_diagram = generate_detailed_dfd(current, st.session_state.threats)
    
    if threat_diagram:
        st.image(f"data:image/png;base64,{threat_diagram}",
                 caption="Architecture with Identified Threats Highlighted",
                 use_column_width=True)
    
    # THREAT DETAILS WITH MITIGATIONS
    st.subheader("📋 Threat Details with Mitigations")
    
    for idx, answer in enumerate(st.session_state.user_answers):
        predefined = answer.get("predefined", {})
        score_pct = (answer["score"] / answer["max_score"]) * 100
        
        st.markdown(f"""
        <div class="threat-detail-box">
        <strong>{answer['matched_threat_id']}</strong> - {predefined.get('threat', 'Unknown')}
        <br><strong>STRIDE:</strong> {answer['stride']}
        <br><strong>Component:</strong> {answer['component']}
        <br><strong>Risk:</strong> {answer['likelihood']} likelihood × {answer['impact']} impact
        <br><strong>Your Score:</strong> {answer['score']}/{answer['max_score']} ({score_pct:.0f}%)
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("**✅ Correct Mitigations:**")
        for mit in predefined.get('correct_mitigations', []):
            st.success(f"• {mit}")
        
        st.markdown(f"**📖 Why These Controls:** {predefined.get('why_these_controls', 'N/A')}")
        st.markdown(f"**🌍 Real-World Example:** {predefined.get('real_world', 'N/A')}")
        st.markdown(f"**📜 Compliance:** {predefined.get('compliance', 'N/A')}")
        st.markdown("---")
    
    # STATISTICS
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percent", f"{final_score_pct:.1f}%")
    col3.metric("Grade", "A" if final_score_pct >= 90 else "B" if final_score_pct >= 80 else "C")
    
    st.subheader("Results Table")
    df = pd.DataFrame([{
        "Threat": a["matched_threat_id"],
        "STRIDE": a["stride"],
        "Component": a["component"],
        "Score": f"{a['score']}/{a['max_score']}"
    } for a in st.session_state.user_answers])
    st.dataframe(df, hide_index=True, use_container_width=True)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
    with col2:
        if st.button("Complete ➡️", type="primary"):
            st.session_state.current_step = 5
            save_progress()
            st.rerun()

# STEP 5
elif st.session_state.current_step == 5:
    st.header("🎉 Complete!")
    
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    if final_score_pct >= 90:
        st.balloons()
        st.success(f"Excellent! {final_score_pct:.1f}%")
    else:
        st.info(f"Completed! {final_score_pct:.1f}%")
    
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()
    
    next_ws = str(int(st.session_state.selected_workshop) + 1)
    
    if next_ws in WORKSHOPS:
        st.info(f"Ready for Workshop {next_ws}? Ask your instructor for the unlock code.")
        if next_ws in st.session_state.unlocked_workshops:
            if st.button(f"Start Workshop {next_ws}", type="primary"):
                st.session_state.selected_workshop = next_ws
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                save_progress()
                st.rerun()
    
    if st.button("🏠 Home"):
        st.session_state.selected_workshop = None
        st.session_state.current_step = 1
        save_progress()
        st.rerun()

st.caption("STRIDE Threat Modeling Learning Lab")
