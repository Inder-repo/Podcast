"""
STRIDE Threat Modeling - COMPLETE FINAL VERSION
All 4 Workshops | Full Threat Database | No Nested Expanders | Scoring System
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

# Unlock codes
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
    .score-good{background-color:#8BC34A;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
    .score-fair{background-color:#FFC107;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
    .score-poor{background-color:#FF5722;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
    .badge-completed{background-color:#2C5F2D;color:white;padding:4px 12px;border-radius:12px;font-size:0.85em;font-weight:600}
    .badge-locked{background-color:#757575;color:white;padding:4px 12px;border-radius:12px;font-size:0.85em;font-weight:600}
    .info-box{background-color:#E3F2FD;padding:16px;border-radius:4px;border-left:4px solid #1976D2;margin:12px 0}
    .learning-box{background-color:#E8EAF6;padding:16px;border-radius:4px;border-left:4px solid #3F51B5;margin:12px 0}
    .component-card{background-color:#F5F5F5;padding:12px;border-radius:4px;border-left:3px solid #028090;margin:8px 0}
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

# COMPLETE THREAT DATABASE - ALL 15 FOR WORKSHOP 1
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
         "real_world": "Equifax (2017) - 147M exposed. Encryption would have limited damage."},
        
        {"id": "T-004", "stride": "Denial of Service", "component": "API Backend",
         "threat": "API flooding", "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Rate limiting", "AWS WAF", "Auto-scaling", "AWS Shield"],
         "incorrect_mitigations": ["Add more memory", "Enable logging", "Use encryption"],
         "explanation": "DoS overwhelms resources. Rate limiting and auto-scaling mitigate this.",
         "compliance": "OWASP Top 10 A05:2021", "points": 10,
         "why_this_risk": "High likelihood - DDoS cheap. Medium impact - revenue loss but no data breach.",
         "why_these_controls": "Rate limiting blocks floods. Auto-scaling adds capacity.",
         "real_world": "GitHub survived 1.35 Tbps DDoS (2018) with good protection."},
        
        {"id": "T-005", "stride": "Elevation of Privilege", "component": "API Backend",
         "threat": "Broken access control", "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["RBAC", "Validate permissions per request", "Least privilege", "Deny by default"],
         "incorrect_mitigations": ["Encrypt API", "Add logging", "Strong authentication"],
         "explanation": "Authorization determines access rights. RBAC ensures proper permissions.",
         "compliance": "OWASP Top 10 A01:2021, PCI-DSS 7.1", "points": 10,
         "why_this_risk": "Medium - developers forget checks. High - admin access = full control.",
         "why_these_controls": "Check authorization on EVERY request. Deny by default.",
         "real_world": "Instagram bug (2020) let users call admin endpoints."},
        
        {"id": "T-006", "stride": "Repudiation", "component": "API Backend",
         "threat": "Insufficient logging", "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Comprehensive logging", "Log auth events", "Log modifications", "CloudWatch", "Write-once storage"],
         "incorrect_mitigations": ["Add encryption", "Enable 2FA", "Use firewalls"],
         "explanation": "Logs provide proof of actions and enable forensics.",
         "compliance": "PCI-DSS 10, SOC 2 CC7.2", "points": 10,
         "why_this_risk": "Medium - can't investigate without logs. Average 207 days to detect breach.",
         "why_these_controls": "Logs record WHO, WHAT, WHEN, WHERE. Write-once prevents tampering.",
         "real_world": "Many breaches undetected for months due to no logging."},
        
        {"id": "T-007", "stride": "Tampering", "component": "Customer → Web Frontend",
         "threat": "Man-in-the-middle", "likelihood": "Low", "impact": "High",
         "correct_mitigations": ["TLS 1.3", "HSTS headers", "Certificate pinning", "HTTPS redirects"],
         "incorrect_mitigations": ["Database encryption", "Enable logging", "Strong passwords"],
         "explanation": "MITM intercepts traffic. TLS encrypts, HSTS prevents downgrades.",
         "compliance": "PCI-DSS 4.1", "points": 10,
         "why_this_risk": "Low - HTTPS default now. High - credentials/payment data stolen.",
         "why_these_controls": "TLS encrypts traffic. HSTS forces HTTPS always.",
         "real_world": "Public WiFi MITM attacks common. Firesheep (2010) showed ease."},
        
        {"id": "T-008", "stride": "Information Disclosure", "component": "API Backend",
         "threat": "Verbose errors", "likelihood": "High", "impact": "Low",
         "correct_mitigations": ["Generic errors for users", "Log details server-side", "Disable debug mode", "Custom error pages"],
         "incorrect_mitigations": ["Encrypt errors", "Add authentication", "Rate limiting"],
         "explanation": "Detailed errors reveal internals. Show generic to users, log details server-side.",
         "compliance": "OWASP Top 10 A05:2021, CWE-209", "points": 10,
         "why_this_risk": "High - very common mistake. Low - aids reconnaissance but not direct breach.",
         "why_these_controls": "Generic errors hide internals. Detailed logs help debugging.",
         "real_world": "Error messages fingerprint systems for targeted attacks."},
        
        {"id": "T-009", "stride": "Spoofing", "component": "Customer",
         "threat": "Weak passwords", "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["12+ char passwords", "MFA", "Account lockout", "CAPTCHA", "Breach detection"],
         "incorrect_mitigations": ["Encrypt passwords in DB", "Add logging", "Use HTTPS"],
         "explanation": "Weak passwords easily guessed. Strong policy + MFA makes brute force impractical.",
         "compliance": "OWASP ASVS V2.1.1, PCI-DSS 8.2.3", "points": 10,
         "why_this_risk": "High - 80% of breaches involve weak passwords. Medium - one account compromised.",
         "why_these_controls": "12+ chars = billions of combinations. MFA blocks even if password stolen.",
         "real_world": "773M passwords leaked (Collection #1). MFA stops credential stuffing."},
        
        {"id": "T-010", "stride": "Elevation of Privilege", "component": "API Backend → S3 Storage",
         "threat": "Misconfigured S3 bucket", "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["S3 Block Public Access", "Bucket policies", "IAM roles", "S3 logging", "Regular audits"],
         "incorrect_mitigations": ["Encrypt S3 objects", "Add CloudWatch", "Strong passwords"],
         "explanation": "Misconfigured buckets expose data. Block Public Access prevents this.",
         "compliance": "AWS Well-Architected, CIS AWS", "points": 10,
         "why_this_risk": "Medium - still common. High - public data breach.",
         "why_these_controls": "Block Public Access is global override. IAM roles rotate credentials.",
         "real_world": "Capital One (2019) - 100M exposed via S3 misconfiguration."},
        
        {"id": "T-011", "stride": "Tampering", "component": "Web Frontend",
         "threat": "DOM-based XSS", "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["React built-in protection", "Avoid dangerouslySetInnerHTML", "DOMPurify", "CSP"],
         "incorrect_mitigations": ["Server-side validation only", "Use HTTPS", "Database encryption"],
         "explanation": "DOM XSS occurs in browser. React escapes by default, but unsafe patterns bypass.",
         "compliance": "OWASP Top 10 A03:2021, CWE-79", "points": 10,
         "why_this_risk": "Medium - requires unsafe React patterns. Medium - session theft.",
         "why_these_controls": "React auto-escapes JSX. dangerouslySetInnerHTML bypasses - avoid it.",
         "real_world": "Tweetdeck (2014) DOM XSS created auto-retweeting worm."},
        
        {"id": "T-012", "stride": "Information Disclosure", "component": "API Backend → Stripe",
         "threat": "Hardcoded API keys", "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Publishable keys in frontend", "Secrets Manager for secret keys", "Never commit keys", "Rotate keys", "Environment variables"],
         "incorrect_mitigations": ["Encrypt keys in code", "Obfuscate JavaScript", "Rate limiting"],
         "explanation": "Frontend code is public. Use publishable keys client-side, secret keys server-side only.",
         "compliance": "PCI-DSS 6.5.3", "points": 10,
         "why_this_risk": "High - frontend code PUBLIC. Critical - direct financial fraud.",
         "why_these_controls": "Publishable keys safe for frontend. Secret keys server-side in Secrets Manager.",
         "real_world": "GitHub finds thousands of exposed keys daily. Bots exploit within minutes."},
        
        {"id": "T-013", "stride": "Denial of Service", "component": "Database",
         "threat": "Expensive queries", "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Pagination", "Query timeouts", "Connection pooling", "Index fields", "Complexity analysis"],
         "incorrect_mitigations": ["More storage", "Enable encryption", "Add logging"],
         "explanation": "Unbounded queries exhaust resources. Pagination limits results, timeouts kill runaway queries.",
         "compliance": "OWASP API Top 10 API4:2023", "points": 10,
         "why_this_risk": "Medium - legitimate users can trigger. Medium - DB slow affects all users.",
         "why_these_controls": "Pagination limits results. Timeouts kill runaway queries.",
         "real_world": "Reddit crashed multiple times due to expensive queries."},
        
        {"id": "T-014", "stride": "Spoofing", "component": "API Backend → SendGrid",
         "threat": "Email spoofing", "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["SPF records", "DKIM signing", "DMARC policy", "Secure API key", "Monitor sending"],
         "incorrect_mitigations": ["Encrypt email", "Rate limiting", "Strong passwords"],
         "explanation": "Email authentication proves origin. SPF, DKIM, DMARC prevent domain spoofing.",
         "compliance": "DMARC RFC 7489", "points": 10,
         "why_this_risk": "Medium - easy to spoof. Medium - brand damage, phishing.",
         "why_these_controls": "SPF lists authorized servers. DKIM signs emails. DMARC enforces policy.",
         "real_world": "BEC scams cost $2.4B in 2021. SPF/DKIM/DMARC make this harder."},
        
        {"id": "T-015", "stride": "Tampering", "component": "API Backend",
         "threat": "Mass assignment", "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Explicit allowed fields", "Use DTO", "Schema validation", "Blacklist sensitive fields", "ORM protection"],
         "incorrect_mitigations": ["Encrypt request", "Add authentication", "Enable logging"],
         "explanation": "Mass assignment lets attackers modify protected fields. Explicitly define allowed fields.",
         "compliance": "OWASP API Top 10 API6:2023, CWE-915", "points": 10,
         "why_this_risk": "Medium - frameworks auto-bind. High - can set isAdmin=true.",
         "why_these_controls": "Allow-lists define updateable fields. Anything else rejected.",
         "real_world": "GitHub (2012) mass assignment let anyone gain admin access."}
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
        
        {"id": "T-202", "stride": "Tampering", "component": "API Gateway → Query Service",
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
        {"id": "T-301", "stride": "Tampering", "component": "AI Agent → LLM API",
         "threat": "Prompt injection", "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Input sanitization", "Prompt templates", "Output validation", "Human-in-loop"],
         "incorrect_mitigations": ["Add encryption", "Use HTTPS", "Enable logging"],
         "explanation": "Prompt injection tricks AI into harmful actions. Sanitize inputs, validate outputs.",
         "compliance": "NIST AI Risk Management", "points": 10,
         "why_this_risk": "High - easy to exploit. Critical - AI makes harmful decisions.",
         "why_these_controls": "Input sanitization removes malicious instructions. Output validation catches bad responses.",
         "real_world": "Many LLM jailbreaks via prompt injection."},
        
        {"id": "T-302", "stride": "Information Disclosure", "component": "Vector DB",
         "threat": "RAG poisoning", "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Content signing", "Source verification", "Regular audits", "Access controls"],
         "incorrect_mitigations": ["Rate limiting", "Enable logging", "Use encryption"],
         "explanation": "Vector databases can be poisoned with false medical info. Verify sources.",
         "compliance": "FDA AI/ML Guidance", "points": 10,
         "why_this_risk": "Medium - requires DB access. Critical - false medical info = patient harm.",
         "why_these_controls": "Content signing proves authenticity. Source verification ensures trust.",
         "real_world": "RAG poisoning attacks demonstrated in research."}
    ]
}

# WORKSHOPS
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: E-Commerce",
        "level": "Foundation", "duration": "2 hours", "target_threats": 15,
        "scenario": {
            "title": "TechMart Store",
            "description": "E-commerce platform",
            "business_context": "Series A startup, 50K users",
            "assets": ["Customer PII", "Payment data", "Credentials"],
            "objectives": ["Confidentiality: Protect PII", "Integrity: Order accuracy", "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS", "GDPR"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA"},
                {"name": "API Backend", "type": "process", "description": "Node.js API"},
                {"name": "Database", "type": "datastore", "description": "PostgreSQL"},
                {"name": "Stripe", "type": "external_entity", "description": "Payments"},
                {"name": "S3 Storage", "type": "datastore", "description": "Images"},
                {"name": "SendGrid", "type": "external_entity", "description": "Email"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database", "data": "SQL", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payments", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "S3 Storage", "data": "Images", "protocol": "S3 API"},
                {"source": "API Backend", "destination": "SendGrid", "data": "Email", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Internet", "description": "Untrusted → Trusted", "components": ["Customer", "Web Frontend"]},
                {"name": "Application", "description": "Frontend → Backend", "components": ["Web Frontend", "API Backend"]},
                {"name": "Data", "description": "App → Storage", "components": ["API Backend", "Database", "S3 Storage"]},
                {"name": "External", "description": "Internal → Third-party", "components": ["API Backend", "Stripe", "SendGrid"]}
            ]
        }
    },
    "2": {
        "name": "Workshop 2: Mobile Banking",
        "level": "Intermediate", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "CloudBank",
            "description": "Mobile banking app",
            "business_context": "Regional bank, 500K users",
            "assets": ["Financial data", "Credentials", "Transactions"],
            "objectives": ["Confidentiality", "Integrity", "Availability"],
            "compliance": ["PCI-DSS", "GLBA"],
            "components": [
                {"name": "Mobile App", "type": "external_entity", "description": "iOS/Android app"},
                {"name": "API Gateway", "type": "process", "description": "Kong gateway"},
                {"name": "Payment Service", "type": "process", "description": "Microservice"},
                {"name": "Transaction DB", "type": "datastore", "description": "DynamoDB"}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "Payment Service", "data": "Payments", "protocol": "gRPC"},
                {"source": "Payment Service", "destination": "Transaction DB", "data": "Data", "protocol": "DynamoDB"}
            ],
            "trust_boundaries": [
                {"name": "Mobile", "description": "App → Gateway", "components": ["Mobile App", "API Gateway"]},
                {"name": "Services", "description": "Gateway → Services", "components": ["API Gateway", "Payment Service"]},
                {"name": "Data", "description": "Services → DB", "components": ["Payment Service", "Transaction DB"]}
            ]
        }
    },
    "3": {
        "name": "Workshop 3: SaaS Analytics",
        "level": "Advanced", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "DataInsight",
            "description": "Multi-tenant analytics",
            "business_context": "SaaS company, 1000 tenants",
            "assets": ["Customer data", "Business intelligence", "Tenant metadata"],
            "objectives": ["Multi-tenant isolation", "Data confidentiality", "Query performance"],
            "compliance": ["SOC 2", "ISO 27001"],
            "components": [
                {"name": "Web Portal", "type": "external_entity", "description": "Customer portal"},
                {"name": "API Gateway", "type": "process", "description": "API layer"},
                {"name": "Query Service", "type": "process", "description": "Query engine"},
                {"name": "Data Warehouse", "type": "datastore", "description": "Redshift"}
            ],
            "data_flows": [
                {"source": "Web Portal", "destination": "API Gateway", "data": "Queries", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "Query Service", "data": "SQL", "protocol": "HTTPS"},
                {"source": "Query Service", "destination": "Data Warehouse", "data": "Data", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Tenant", "description": "Tenant isolation", "components": ["Web Portal", "API Gateway"]},
                {"name": "Query", "description": "Query processing", "components": ["API Gateway", "Query Service"]},
                {"name": "Data", "description": "Data access", "components": ["Query Service", "Data Warehouse"]}
            ]
        }
    },
    "4": {
        "name": "Workshop 4: AI Healthcare",
        "level": "Expert", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "HealthAI",
            "description": "AI diagnostics platform",
            "business_context": "Healthcare AI startup, FDA regulated",
            "assets": ["PHI", "AI models", "Medical knowledge"],
            "objectives": ["Patient safety", "Data privacy", "Model integrity"],
            "compliance": ["HIPAA", "FDA 21 CFR Part 11"],
            "components": [
                {"name": "Clinician Portal", "type": "external_entity", "description": "Provider interface"},
                {"name": "AI Agent", "type": "process", "description": "AI orchestrator"},
                {"name": "LLM API", "type": "external_entity", "description": "GPT-4/Claude"},
                {"name": "Vector DB", "type": "datastore", "description": "Medical knowledge"},
                {"name": "Patient DB", "type": "datastore", "description": "EHR data"}
            ],
            "data_flows": [
                {"source": "Clinician Portal", "destination": "AI Agent", "data": "Queries", "protocol": "HTTPS"},
                {"source": "AI Agent", "destination": "LLM API", "data": "Prompts", "protocol": "HTTPS"},
                {"source": "AI Agent", "destination": "Vector DB", "data": "Embeddings", "protocol": "Vector"},
                {"source": "AI Agent", "destination": "Patient DB", "data": "PHI", "protocol": "HL7/FHIR"}
            ],
            "trust_boundaries": [
                {"name": "Clinical", "description": "Clinician → AI", "components": ["Clinician Portal", "AI Agent"]},
                {"name": "AI", "description": "AI → LLM", "components": ["AI Agent", "LLM API"]},
                {"name": "Data", "description": "AI → Data", "components": ["AI Agent", "Vector DB", "Patient DB"]}
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
    try:
        dot = Digraph(format="png")
        dot.attr(rankdir="TB", size="14,12")
        
        styles = {
            "external_entity": {"shape": "oval", "style": "filled", "fillcolor": "lightcoral"},
            "process": {"shape": "box", "style": "filled,rounded", "fillcolor": "lightblue"},
            "datastore": {"shape": "cylinder", "style": "filled", "fillcolor": "lightgreen"}
        }
        
        node_threats = {}
        edge_threats = {}
        for threat in threats:
            if threat.get("matched_threat_id"):
                affected = threat.get("component", "")
                threat_id = threat.get("matched_threat_id")
                if "→" in affected:
                    edge_threats.setdefault(affected, []).append(threat_id)
                else:
                    node_threats.setdefault(affected, []).append(threat_id)
        
        for comp in workshop_config["scenario"]["components"]:
            name = comp["name"]
            threat_label = node_threats.get(name, [])
            label = f"{name}\n{comp['description']}"
            if threat_label:
                label += f"\n✓ {', '.join(threat_label)}"
            
            style = styles.get(comp["type"], styles["process"]).copy()
            if threat_label:
                style["fillcolor"] = "#C8E6C9"
            
            dot.node(name, label, **style)
        
        for flow in workshop_config["scenario"]["data_flows"]:
            edge_key = f"{flow['source']} → {flow['destination']}"
            threat_label = edge_threats.get(edge_key, [])
            label = f"{flow['data']}\n({flow['protocol']})"
            if threat_label:
                label += f"\n✓ {', '.join(threat_label)}"
            
            color = "#4CAF50" if threat_label else "black"
            dot.edge(flow['source'], flow['destination'], label=label, color=color)
        
        for idx, boundary in enumerate(workshop_config["scenario"]["trust_boundaries"]):
            with dot.subgraph(name=f"cluster_{idx}") as c:
                c.attr(label=f"🔒 {boundary['name']}", style="dashed", color="purple")
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
        
        if not unlocked and ws_id != "1":
            unlock_key = f"unlock_{ws_id}"
            if unlock_key not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[unlock_key] = False
            
            if st.button(f"Unlock", key=f"unlock_btn_{ws_id}"):
                st.session_state.show_unlock_form[unlock_key] = not st.session_state.show_unlock_form[unlock_key]
            
            if st.session_state.show_unlock_form.get(unlock_key):
                code = st.text_input("Code", type="password", key=f"code_{ws_id}")
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
    st.markdown("Select a workshop from the sidebar.")
    st.markdown("**Codes:** Workshop 2: `MICRO2025`, Workshop 3: `TENANT2025`, Workshop 4: `HEALTH2025`")
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

# STEP 3 - FIXED NO NESTED EXPANDERS
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
            
            # Learning content - INLINE not in expander
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

# STEP 4
elif st.session_state.current_step == 4:
    st.header("Step 4: Assessment")
    
    if not st.session_state.user_answers:
        st.warning("No answers")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
        st.stop()
    
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percent", f"{final_score_pct:.1f}%")
    col3.metric("Grade", "A" if final_score_pct >= 90 else "B" if final_score_pct >= 80 else "C")
    
    st.subheader("Results")
    df = pd.DataFrame([{
        "Threat": a["matched_threat_id"],
        "Score": f"{a['score']}/{a['max_score']}"
    } for a in st.session_state.user_answers])
    st.dataframe(df, hide_index=True)
    
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
        st.info(f"Ready for Workshop {next_ws}?")
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
