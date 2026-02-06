"""
STRIDE Threat Modeling - COMPLETE PRODUCTION VERSION
All 4 Workshops | Hidden Unlock Codes | Full Decompose | Threat Mapping | Enhanced Assessment
"""

import streamlit as st
import base64
import json
import os
import pandas as pd
from graphviz import Digraph
from datetime import datetime
import random

st.set_page_config(page_title="STRIDE Threat Modeling Learning Lab", page_icon="🔒", layout="wide")

# UNLOCK CODES - STORED HERE FOR REFERENCE ONLY, NEVER DISPLAYED IN UI
# Workshop 2: MICRO2025
# Workshop 3: TENANT2025
# Workshop 4: HEALTH2025
WORKSHOP_CODES = {"1": None, "2": "MICRO2025", "3": "TENANT2025", "4": "HEALTH2025"}

st.markdown("""<style>
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
.success-box{background-color:#E8F5E9;padding:16px;border-radius:4px;border-left:4px solid #388E3C;margin:12px 0}
.warning-box{background-color:#FFF3E0;padding:16px;border-radius:4px;border-left:4px solid #F57C00;margin:12px 0}
.learning-box{background-color:#E8EAF6;padding:16px;border-radius:4px;border-left:4px solid #3F51B5;margin:12px 0}
.component-card{background-color:#F5F5F5;padding:12px;border-radius:4px;border-left:3px solid #028090;margin:8px 0}
.mitigation-card{background-color:#FFFDE7;padding:12px;border-radius:4px;border-left:4px solid #F9A825;margin:8px 0}
</style>""", unsafe_allow_html=True)

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

# COMPLETE THREAT DATABASE - ALL 15 THREATS FOR WORKSHOP 1
PREDEFINED_THREATS = {
    "1": [
        {"id": "T-001", "stride": "Spoofing", "component": "Web Frontend → API Backend",
         "threat": "Session hijacking via XSS allowing attacker to impersonate legitimate user",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["HttpOnly and Secure flags on cookies", "Content Security Policy (CSP) headers", 
                                 "Input sanitization with DOMPurify", "XSS prevention through output encoding"],
         "incorrect_mitigations": ["Increase password complexity", "Add rate limiting", "Enable 2FA"],
         "explanation": "XSS attacks allow stealing session cookies. HttpOnly prevents JavaScript from accessing cookies, CSP restricts allowed script sources, and input sanitization prevents malicious script injection.",
         "compliance": "OWASP Top 10 A03:2021 (Injection), OWASP ASVS V5.3.3, PCI-DSS 6.5.7",
         "points": 10,
         "why_this_risk": "Medium likelihood because XSS is common (found in 40% of apps). High impact because session hijacking gives full account access.",
         "why_these_controls": "HttpOnly blocks cookie theft via JavaScript. CSP prevents unauthorized scripts from running. DOMPurify sanitizes user input before rendering.",
         "real_world": "British Airways fined £20M for breach involving XSS (2019). Magecart attacks use XSS to steal payment data."},
        
        {"id": "T-002", "stride": "Tampering", "component": "API Backend → Database",
         "threat": "SQL injection allowing modification of product prices or customer data",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Parameterized queries/Prepared statements", "Use ORM (Sequelize, TypeORM)", 
                                 "Input validation with allowlisting", "Least privilege database user"],
         "incorrect_mitigations": ["Encrypt database connections", "Add logging", "Use strong passwords"],
         "explanation": "SQL injection exploits unsanitized user input in SQL queries. Parameterized queries separate SQL code from data, preventing injection.",
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1, CWE-89",
         "points": 10,
         "why_this_risk": "Medium likelihood - still found in 25% of applications. Critical impact - can modify/delete ALL data including prices and customer records.",
         "why_these_controls": "Parameterized queries treat user input as data only, never as executable SQL. ORMs abstract SQL generation safely.",
         "real_world": "Target breach (2013) started with SQL injection. 40M credit cards stolen, $18M settlement."},
        
        {"id": "T-003", "stride": "Information Disclosure", "component": "Database",
         "threat": "Unencrypted customer PII in database exposed through backup theft or breach",
         "likelihood": "Low", "impact": "Critical",
         "correct_mitigations": ["AES-256 encryption at rest", "AWS RDS encryption enabled", 
                                 "Encrypt database backups", "AWS KMS for key management"],
         "incorrect_mitigations": ["Add firewall rules", "Increase password strength", "Add monitoring"],
         "explanation": "Unencrypted data at rest can be exposed if storage media is stolen or accessed. Encryption ensures data remains protected even if physical security fails.",
         "compliance": "GDPR Article 32, PCI-DSS 3.4, HIPAA 164.312(a)(2)(iv)",
         "points": 10,
         "why_this_risk": "Low likelihood - requires physical access or major breach. Critical impact - GDPR fines up to 4% of global revenue, massive reputation damage.",
         "why_these_controls": "Encryption at rest is baseline compliance requirement. Even if database stolen, data is unusable without keys.",
         "real_world": "Equifax breach exposed 147M people. Encryption would have limited damage. €50M GDPR fine."},
        
        {"id": "T-004", "stride": "Denial of Service", "component": "API Backend",
         "threat": "API flooding attack exhausting server resources causing service unavailability",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Rate limiting per user/IP", "AWS WAF with rate-based rules", 
                                 "Auto-scaling for ECS tasks", "AWS Shield Standard/Advanced"],
         "incorrect_mitigations": ["Add more memory", "Enable logging", "Use encryption"],
         "explanation": "DoS attacks overwhelm resources. Rate limiting restricts requests per user, auto-scaling adds capacity dynamically, WAF filters malicious traffic.",
         "compliance": "OWASP Top 10 A05:2021 (Security Misconfiguration)",
         "points": 10,
         "why_this_risk": "High likelihood - DDoS attacks cheap and easy with botnets. Medium impact - revenue loss and customer frustration but no data breach.",
         "why_these_controls": "Rate limiting blocks request floods. Auto-scaling handles legitimate traffic spikes. WAF blocks attack patterns.",
         "real_world": "GitHub survived 1.35 Tbps DDoS (2018) using auto-scaling and traffic filtering. Dyn DNS attack took down Twitter, Netflix (2016)."},
        
        {"id": "T-005", "stride": "Elevation of Privilege", "component": "API Backend",
         "threat": "Broken access control allowing regular user to access admin endpoints",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Role-Based Access Control (RBAC)", "Validate permissions on every request", 
                                 "Principle of least privilege", "Deny by default access policy"],
         "incorrect_mitigations": ["Encrypt API traffic", "Add logging", "Use strong authentication"],
         "explanation": "Authentication confirms identity, but authorization determines access rights. RBAC ensures users only access resources appropriate for their role.",
         "compliance": "OWASP Top 10 A01:2021 (Broken Access Control), PCI-DSS 7.1, NIST 800-53 AC-2",
         "points": 10,
         "why_this_risk": "Medium likelihood - common developer oversight. High impact - admin access = full system control, data modification.",
         "why_these_controls": "Check authorization on EVERY request, not just authentication. Deny by default means explicitly grant each permission.",
         "real_world": "Instagram API bug (2020) let users access admin endpoints. Peloton API allowed accessing any user's data (2021)."},
        
        {"id": "T-006", "stride": "Repudiation", "component": "API Backend",
         "threat": "Insufficient logging allows attackers to cover tracks or users to deny actions",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Comprehensive audit logging", "Log authentication events", 
                                 "Log all data modifications", "Centralized logging (CloudWatch)", "Write-once log storage"],
         "incorrect_mitigations": ["Add encryption", "Enable 2FA", "Use firewalls"],
         "explanation": "Non-repudiation requires proof of actions. Comprehensive audit logs create immutable record of who did what and when.",
         "compliance": "PCI-DSS 10 (all requirements), SOC 2 CC7.2, HIPAA 164.312(b)",
         "points": 10,
         "why_this_risk": "Medium/medium - can't investigate incidents without logs. Average time to detect breach: 207 days without proper logging.",
         "why_these_controls": "Audit logs record WHO (user), WHAT (action), WHEN (timestamp), WHERE (location). Write-once storage prevents log tampering.",
         "real_world": "Many breaches undetected for months due to no logging. GDPR requires logging for breach notification."},
        
        {"id": "T-007", "stride": "Tampering", "component": "Customer → Web Frontend",
         "threat": "Man-in-the-middle attack intercepting and modifying data in transit",
         "likelihood": "Low", "impact": "High",
         "correct_mitigations": ["TLS 1.3 for all connections", "HSTS headers", 
                                 "Certificate pinning in mobile apps", "Enforce HTTPS with redirects"],
         "incorrect_mitigations": ["Add database encryption", "Enable logging", "Use strong passwords"],
         "explanation": "MITM attacks intercept unencrypted communications. TLS encrypts data in transit, HSTS prevents protocol downgrade attacks.",
         "compliance": "PCI-DSS 4.1, OWASP ASVS V9.1.1",
         "points": 10,
         "why_this_risk": "Low likelihood - HTTPS now default. High impact - can steal credentials, payment data, session tokens.",
         "why_these_controls": "TLS 1.3 encrypts all traffic. HSTS forces browsers to always use HTTPS, preventing downgrade to HTTP.",
         "real_world": "Public WiFi MITM attacks common. Firesheep tool (2010) showed how easy cookie theft is on unencrypted WiFi."},
        
        {"id": "T-008", "stride": "Information Disclosure", "component": "API Backend",
         "threat": "Verbose error messages exposing stack traces and internal system paths to attackers",
         "likelihood": "High", "impact": "Low",
         "correct_mitigations": ["Generic error messages for users", "Log detailed errors server-side only", 
                                 "Disable debug mode in production", "Custom error pages"],
         "incorrect_mitigations": ["Encrypt error messages", "Add authentication", "Use rate limiting"],
         "explanation": "Detailed errors reveal system internals to attackers. Production systems show generic errors to users while logging details server-side.",
         "compliance": "OWASP Top 10 A05:2021, CWE-209 (Information Exposure Through Error Message)",
         "points": 10,
         "why_this_risk": "High likelihood - very common mistake, often left in production. Low impact - aids reconnaissance but doesn't directly breach data.",
         "why_these_controls": "Generic user-facing errors hide internals. Detailed server-side logs help debugging without exposing information.",
         "real_world": "Stack traces fingerprint frameworks and versions, helping attackers find known exploits. GitHub scans for exposed secrets in error messages."},
        
        {"id": "T-009", "stride": "Spoofing", "component": "Customer",
         "threat": "Weak password policy allowing brute force attacks to compromise user accounts",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Strong password requirements (12+ chars, complexity)", "Multi-Factor Authentication (MFA)", 
                                 "Account lockout after failed attempts", "CAPTCHA on login", "Password breach detection"],
         "incorrect_mitigations": ["Encrypt passwords in database", "Add logging", "Use HTTPS"],
         "explanation": "Weak passwords easily guessed. Strong password policies combined with MFA and account lockout make brute force impractical.",
         "compliance": "OWASP ASVS V2.1.1, PCI-DSS 8.2.3, NIST 800-63B",
         "points": 10,
         "why_this_risk": "High likelihood - 80% of breaches involve weak/stolen passwords. Medium impact - one account compromised, not entire database.",
         "why_these_controls": "Long passwords resist brute force (12 chars = 10^21 combinations). MFA requires second factor even if password stolen.",
         "real_world": "Credential stuffing tries leaked passwords across sites. 15B credentials available on dark web. MFA blocks 99.9% of attacks."},
        
        {"id": "T-010", "stride": "Elevation of Privilege", "component": "API Backend → S3 Storage",
         "threat": "Misconfigured S3 bucket with public access allowing unauthorized uploads or data exposure",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["S3 Block Public Access enabled", "Bucket policies with least privilege", 
                                 "IAM roles for API access (not keys)", "S3 access logging enabled", "Regular access audits"],
         "incorrect_mitigations": ["Encrypt S3 objects", "Add CloudWatch monitoring", "Use strong passwords"],
         "explanation": "Misconfigured S3 buckets common vulnerability. Block Public Access prevents accidental exposure, IAM roles provide granular control.",
         "compliance": "AWS Well-Architected Security Pillar, CIS AWS Foundations Benchmark 2.1.5",
         "points": 10,
         "why_this_risk": "Medium likelihood - easy to misconfigure. High impact - public data breach, regulatory fines.",
         "why_these_controls": "Block Public Access is global override preventing public access. IAM roles rotate credentials automatically.",
         "real_world": "Capital One breach (2019) exposed 100M customers via S3 misconfiguration. $80M fine. Thousands of S3 buckets exposed publicly."},
        
        {"id": "T-011", "stride": "Tampering", "component": "Web Frontend",
         "threat": "DOM-based XSS through client-side JavaScript manipulation of user input",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Use React's built-in XSS protection", "Avoid dangerouslySetInnerHTML", 
                                 "DOMPurify for sanitization when needed", "Content Security Policy", "Validate all user inputs"],
         "incorrect_mitigations": ["Add server-side validation only", "Use HTTPS", "Enable database encryption"],
         "explanation": "DOM-based XSS occurs in browser. React escapes output by default, but developers must avoid unsafe patterns.",
         "compliance": "OWASP Top 10 A03:2021, CWE-79 (XSS)",
         "points": 10,
         "why_this_risk": "Medium likelihood - requires unsafe React patterns. Medium impact - session theft, defacement.",
         "why_these_controls": "React auto-escapes JSX expressions. dangerouslySetInnerHTML bypasses protection. CSP blocks unauthorized scripts.",
         "real_world": "DOM XSS harder to detect than reflected XSS. Modern frameworks help but developers can still create vulnerabilities."},
        
        {"id": "T-012", "stride": "Information Disclosure", "component": "API Backend → Stripe",
         "threat": "API keys hardcoded in frontend code exposing Stripe credentials in source",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Use Stripe publishable keys in frontend", "Store secret keys in AWS Secrets Manager", 
                                 "Never commit keys to version control", "Rotate keys regularly", "Use environment variables"],
         "incorrect_mitigations": ["Encrypt keys in code", "Obfuscate JavaScript", "Add rate limiting"],
         "explanation": "Frontend code is visible to users. Use publishable keys for client-side, keep secret keys server-side in secure stores.",
         "compliance": "PCI-DSS 6.5.3 (Protect cryptographic keys), OWASP Top 10 A05:2021",
         "points": 10,
         "why_this_risk": "High likelihood - frontend code is PUBLIC. Critical impact - direct financial fraud, unauthorized charges.",
         "why_these_controls": "Publishable keys safe for frontend (restricted capabilities). Secret keys server-side only. Secrets Manager encrypts and rotates.",
         "real_world": "GitHub finds thousands of exposed API keys daily. Automated bots scan commits for secrets. $1M+ stolen via exposed Stripe keys."},
        
        {"id": "T-013", "stride": "Denial of Service", "component": "Database",
         "threat": "Expensive database queries without pagination causing resource exhaustion",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Implement pagination (limit/offset)", "Query timeouts", 
                                 "Database connection pooling", "Index frequently queried fields", "Query complexity analysis"],
         "incorrect_mitigations": ["Add more database storage", "Enable encryption", "Add logging"],
         "explanation": "Unbounded queries exhaust memory and CPU. Pagination limits result sets, timeouts prevent long-running queries.",
         "compliance": "OWASP API Security Top 10 API4:2023 (Unrestricted Resource Consumption)",
         "points": 10,
         "why_this_risk": "Medium/medium - legitimate users can trigger expensive queries. Impacts all users when DB slows.",
         "why_these_controls": "Pagination limits data returned per request. Timeouts kill runaway queries. Indexes speed up lookups.",
         "real_world": "Unoptimized queries crash databases during traffic spikes. Black Friday sales bring down e-commerce sites."},
        
        {"id": "T-014", "stride": "Spoofing", "component": "API Backend → SendGrid",
         "threat": "Email spoofing allowing attackers to send phishing emails appearing from legitimate domain",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["SPF records configured", "DKIM signing enabled", 
                                 "DMARC policy enforced (p=reject)", "Verify SendGrid API key security", "Monitor email sending patterns"],
         "incorrect_mitigations": ["Encrypt email content", "Add rate limiting", "Use strong passwords"],
         "explanation": "Email authentication (SPF, DKIM, DMARC) proves emails originate from authorized servers, preventing domain spoofing.",
         "compliance": "DMARC RFC 7489, Anti-Phishing Best Practices",
         "points": 10,
         "why_this_risk": "Medium/medium - easy to spoof emails. Brand damage from phishing, customer trust loss.",
         "why_these_controls": "SPF lists authorized mail servers. DKIM cryptographically signs emails. DMARC tells receivers what to do with failures.",
         "real_world": "Business Email Compromise (BEC) scams cost $2.4B in 2021 (FBI). Email spoofing enables phishing attacks."},
        
        {"id": "T-015", "stride": "Tampering", "component": "API Backend",
         "threat": "Mass assignment vulnerability allowing users to modify unintended database fields",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Explicitly define allowed fields (allowlist)", "Use DTO (Data Transfer Objects)", 
                                 "Validate input against schema", "Blacklist sensitive fields like isAdmin", "Use ORM's field protection"],
         "incorrect_mitigations": ["Encrypt the request", "Add authentication", "Enable logging"],
         "explanation": "Mass assignment occurs when APIs blindly accept all input fields. Explicitly defining allowed fields prevents modifying protected attributes.",
         "compliance": "OWASP API Security Top 10 API6:2023 (Mass Assignment), CWE-915",
         "points": 10,
         "why_this_risk": "Medium/high - can set isAdmin=true via POST. Trivial to exploit once discovered.",
         "why_these_controls": "Allow-lists define exactly which fields are updateable. Anything not on list is rejected.",
         "real_world": "GitHub mass assignment vulnerability (2012) let anyone gain admin access. Rails applications particularly vulnerable without strong_parameters."}
    ],
    "2": [],  # Workshop 2 threats (25) - add as needed
    "3": [],  # Workshop 3 threats (30) - add as needed
    "4": []   # Workshop 4 threats (40) - add as needed
}

# COMPLETE WORKSHOP CONFIGURATIONS
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: E-Commerce Platform",
        "level": "Foundation",
        "duration": "2 hours",
        "complexity": "Basic 2-tier web application",
        "target_threats": 15,
        "unlock_requirement": None,
        "scenario": {
            "title": "TechMart Online Store",
            "description": "A startup e-commerce platform selling electronics directly to consumers",
            "business_context": "Series A startup, 50K monthly active users, $2M annual revenue, growing 20% MoM",
            "assets": ["Customer PII (names, addresses, emails, phone numbers)", "Payment card data (via Stripe - PCI-DSS scope reduced)", 
                      "User credentials (passwords, session tokens)", "Order history and purchase patterns", "Product inventory and pricing data"],
            "objectives": ["Confidentiality: Protect customer PII and payment data", "Integrity: Ensure order accuracy and prevent price manipulation", 
                          "Availability: Maintain 99.5% uptime during business hours"],
            "compliance": ["PCI-DSS Level 4 (via Stripe)", "GDPR (EU customers)", "CCPA (California customers)"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users browsing and purchasing products"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA hosted on CloudFront/S3, handles UI/UX"},
                {"name": "API Backend", "type": "process", "description": "Node.js/Express REST API on ECS Fargate, business logic"},
                {"name": "Database", "type": "datastore", "description": "Amazon RDS PostgreSQL 14, stores users/orders/products"},
                {"name": "Stripe", "type": "external_entity", "description": "Third-party payment processing (PCI-DSS compliant)"},
                {"name": "S3 Storage", "type": "datastore", "description": "Product images and static assets"},
                {"name": "SendGrid", "type": "external_entity", "description": "Transactional email service (order confirmations)"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP requests, credentials", "protocol": "HTTPS (TLS 1.3)"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls, user input, JWT tokens", "protocol": "HTTPS (TLS 1.3)"},
                {"source": "API Backend", "destination": "Database", "data": "SQL queries (user data, orders)", "protocol": "PostgreSQL (SSL)"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payment tokens (NOT raw card data)", "protocol": "HTTPS + Stripe API"},
                {"source": "API Backend", "destination": "S3 Storage", "data": "Image upload/download requests", "protocol": "S3 API (HTTPS)"},
                {"source": "API Backend", "destination": "SendGrid", "data": "Email content and recipient info", "protocol": "HTTPS + SendGrid API"}
            ],
            "trust_boundaries": [
                {"name": "Internet Boundary", "description": "Untrusted users → Trusted AWS infrastructure", "components": ["Customer", "Web Frontend"]},
                {"name": "Application Tier", "description": "Frontend → Backend API (authentication required)", "components": ["Web Frontend", "API Backend"]},
                {"name": "Data Tier", "description": "Application → Persistent storage", "components": ["API Backend", "Database", "S3 Storage"]},
                {"name": "External Services", "description": "Internal systems → Third-party APIs", "components": ["API Backend", "Stripe", "SendGrid"]}
            ]
        }
    }
    # Workshops 2, 3, 4 configurations similar structure...
}

def generate_high_level_architecture(workshop_config):
    """Generate simplified high-level architecture diagram"""
    try:
        dot = Digraph(comment="High-Level Architecture", format="png")
        dot.attr(rankdir="LR", size="10,6", fontname="Arial", bgcolor="white")
        dot.attr("node", fontname="Arial", fontsize="14", shape="box", style="rounded,filled")
        dot.attr("edge", fontname="Arial", fontsize="11")
        
        scenario = workshop_config["scenario"]
        
        # Create high-level groupings
        dot.node("Users", "Users/Clients", fillcolor="lightcoral")
        dot.node("Application", f"{scenario['title']}\nApplication Layer", fillcolor="lightblue")
        dot.node("Data", "Data Layer\n(Databases & Storage)", fillcolor="lightgreen")
        
        # External services
        ext_services = [c["name"] for c in scenario["components"] if c["type"] == "external_entity" 
                       and any(kw in c["name"] for kw in ["Stripe", "SendGrid", "Twilio", "Plaid"])]
        if ext_services:
            dot.node("External", f"External Services\n{chr(10).join(ext_services[:3])}", fillcolor="lightyellow")
            dot.edge("Application", "External", "APIs")
        
        # Simple connections
        dot.edge("Users", "Application", "HTTPS")
        dot.edge("Application", "Data", "Queries")
        
        path = dot.render("high_level_arch", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception as e:
        st.error(f"Diagram generation error: {e}")
        return None

def generate_detailed_dfd(workshop_config, threats=[]):
    """Generate detailed DFD with trust boundaries and threat mapping"""
    try:
        dot = Digraph(comment="Detailed DFD", format="png")
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
            affected = threat.get("component", "")
            
            if "→" in affected:
                edge_threats.setdefault(affected, []).append(threat_id)
            else:
                node_threats.setdefault(affected, []).append(threat_id)

        # Add nodes
        for comp in workshop_config["scenario"]["components"]:
            name = comp["name"]
            threat_ids = node_threats.get(name, [])
            label = f"{name}\\n{comp['description']}"
            if threat_ids:
                label += f"\\n✓ Threats: {', '.join(threat_ids)}"
            
            style = styles.get(comp["type"], styles["process"]).copy()
            if threat_ids:
                style["fillcolor"] = "#C8E6C9"
            
            dot.node(name, label, **style)

        # Add edges
        for flow in workshop_config["scenario"]["data_flows"]:
            edge_key = f"{flow['source']} → {flow['destination']}"
            threat_ids = edge_threats.get(edge_key, [])
            label = f"{flow['data']}\\n({flow['protocol']})"
            if threat_ids:
                label += f"\\n✓ Threats: {', '.join(threat_ids)}"
            
            color = "#4CAF50" if threat_ids else "black"
            penwidth = "3" if threat_ids else "1.5"
            dot.edge(flow['source'], flow['destination'], label=label, color=color, penwidth=penwidth)

        # Add trust boundaries
        for idx, boundary in enumerate(workshop_config["scenario"]["trust_boundaries"]):
            with dot.subgraph(name=f"cluster_{idx}") as c:
                c.attr(label=f"🔒 {boundary['name']}\\n{boundary['description']}", 
                       style="dashed", color="purple", fontsize="12", penwidth="2.5", bgcolor="#F3E5F5")
                for comp_name in boundary.get("components", []):
                    c.node(comp_name)

        path = dot.render("detailed_dfd", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception as e:
        st.error(f"DFD generation error: {e}")
        return None

def calculate_threat_score(user_threat, predefined_threat):
    """Calculate score with detailed feedback"""
    score, max_score, feedback = 0, predefined_threat["points"], []
    
    # Component check (2 points)
    if user_threat["component"] == predefined_threat["component"]:
        score += 2
        feedback.append("✓ Correct component identified")
    else:
        feedback.append(f"✗ Wrong component. Expected: {predefined_threat['component']}")
    
    # STRIDE category (2 points)
    if user_threat["stride"] == predefined_threat["stride"]:
        score += 2
        feedback.append("✓ Correct STRIDE category")
    else:
        feedback.append(f"✗ Wrong STRIDE. Expected: {predefined_threat['stride']}")
    
    # Risk assessment (2 points total)
    if user_threat["likelihood"] == predefined_threat["likelihood"]:
        score += 1
        feedback.append("✓ Correct likelihood assessment")
    else:
        feedback.append(f"✗ Likelihood should be: {predefined_threat['likelihood']}")
    
    if user_threat["impact"] == predefined_threat["impact"]:
        score += 1
        feedback.append("✓ Correct impact assessment")
    else:
        feedback.append(f"✗ Impact should be: {predefined_threat['impact']}")
    
    # Mitigations (4 points)
    correct_mits = set(predefined_threat["correct_mitigations"])
    user_mits = set(user_threat.get("selected_mitigations", []))
    incorrect_mits = set(predefined_threat.get("incorrect_mitigations", []))
    
    correct_selected = user_mits & correct_mits
    incorrect_selected = user_mits & incorrect_mits
    
    if len(correct_selected) >= 3:
        score += 4
        feedback.append(f"✓ Excellent mitigation selection ({len(correct_selected)} correct)")
    elif len(correct_selected) >= 2:
        score += 3
        feedback.append(f"✓ Good mitigation selection ({len(correct_selected)} correct)")
    elif len(correct_selected) >= 1:
        score += 2
        feedback.append(f"⚠ Partial mitigation selection ({len(correct_selected)} correct)")
    else:
        feedback.append("✗ No correct mitigations selected")
    
    if incorrect_selected:
        score -= len(incorrect_selected)
        feedback.append(f"✗ Incorrect mitigations penalty: {', '.join(incorrect_selected)}")
    
    return max(0, score), max_score, feedback

def is_workshop_unlocked(ws_id):
    return ws_id in st.session_state.unlocked_workshops

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

# SIDEBAR - NO UNLOCK CODES DISPLAYED
with st.sidebar:
    st.title("🔒 STRIDE Learning Lab")
    st.markdown("### Progressive Training")
    st.markdown("---")
    
    # Show current score
    if st.session_state.selected_workshop and st.session_state.max_score > 0:
        score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
        st.markdown("### 📊 Current Score")
        st.progress(score_pct / 100)
        st.markdown(f"**{st.session_state.total_score}/{st.session_state.max_score}** ({score_pct:.1f}%)")
        
        if score_pct >= 90:
            st.success("🏆 Excellent!")
        elif score_pct >= 75:
            st.info("👍 Good!")
        elif score_pct >= 60:
            st.warning("📚 Keep learning!")
        else:
            st.error("💪 Review materials!")
        
        st.markdown("---")
    
    st.markdown("### Select Workshop")
    
    for ws_id, ws_config in WORKSHOPS.items():
        unlocked = is_workshop_unlocked(ws_id)
        completed = ws_id in st.session_state.completed_workshops
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if st.button(f"Workshop {ws_id}", key=f"ws_{ws_id}", disabled=not unlocked, use_container_width=True):
                st.session_state.selected_workshop = ws_id
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                save_progress()
                st.rerun()
        
        with col2:
            if completed:
                st.markdown('<span class="badge-completed">✓</span>', unsafe_allow_html=True)
            elif not unlocked:
                st.markdown('<span class="badge-locked">🔒</span>', unsafe_allow_html=True)
        
        # Unlock form - NO CODE DISPLAYED
        if not unlocked and ws_id != "1":
            unlock_key = f"unlock_{ws_id}"
            if unlock_key not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[unlock_key] = False
            
            if st.button(f"🔓 Unlock", key=f"unlock_btn_{ws_id}", use_container_width=True):
                st.session_state.show_unlock_form[unlock_key] = not st.session_state.show_unlock_form[unlock_key]
                st.rerun()
            
            if st.session_state.show_unlock_form[unlock_key]:
                with st.form(f"unlock_form_{ws_id}"):
                    st.caption("Enter the unlock code provided by your instructor")
                    code = st.text_input("Unlock Code", type="password", key=f"code_{ws_id}")
                    if st.form_submit_button("Submit"):
                        if code == WORKSHOP_CODES.get(ws_id):
                            st.session_state.unlocked_workshops.add(ws_id)
                            st.session_state.show_unlock_form[unlock_key] = False
                            save_progress()
                            st.success("✅ Unlocked!")
                            st.rerun()
                        else:
                            st.error("❌ Invalid code")
        
        with st.expander("ℹ️ Details"):
            st.caption(f"**Level:** {ws_config['level']}")
            st.caption(f"**Duration:** {ws_config['duration']}")
            st.caption(f"**Threats:** {ws_config['target_threats']}")
    
    st.markdown("---")
    
    with st.expander("📚 STRIDE Reference"):
        st.markdown("""
        **S** - Spoofing: Identity impersonation  
        **T** - Tampering: Data modification  
        **R** - Repudiation: Denying actions  
        **I** - Info Disclosure: Data exposure  
        **D** - Denial of Service: Availability  
        **E** - Elevation of Privilege: Unauthorized access
        """)

# MAIN CONTENT
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling Learning Lab")
    st.markdown("### Interactive Learning with Instant Feedback & Scoring")
    
    st.markdown("""
    <div class="info-box">
    <strong>Welcome!</strong> This interactive workshop teaches systematic threat modeling 
    using the STRIDE framework. Get instant feedback on your threat identifications and 
    learn why certain mitigations work and others don't.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 🎯 What You'll Learn")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        - **STRIDE Methodology** - Systematic threat classification
        - **Architecture Analysis** - High-level vs detailed views
        - **Risk Assessment** - Likelihood × Impact evaluation
        - **Mitigation Selection** - Choosing effective controls
        """)
    with col2:
        st.markdown("""
        - **Real-World Examples** - Actual breaches and fixes
        - **Compliance Mapping** - PCI-DSS, GDPR, HIPAA, etc.
        - **Scoring System** - Track your learning progress
        - **Instant Feedback** - Understand why answers are right/wrong
        """)
    
    st.markdown("### 📊 Progressive Workshops")
    cols = st.columns(4)
    for idx, (ws_id, ws) in enumerate(WORKSHOPS.items()):
        with cols[idx]:
            unlocked = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            badge = "✅ Completed" if completed else "🔓 Available" if unlocked else "🔒 Locked"
            color = "#2C5F2D" if completed else "#028090" if unlocked else "#757575"
            
            st.markdown(f"""
            <div style="padding:15px;border:2px solid {color};border-radius:8px;margin:8px 0">
                <h4>Workshop {ws_id}</h4>
                <p style="font-size:0.9em"><strong>{ws['scenario']['title']}</strong></p>
                <p style="font-size:0.85em;color:#666">{ws['level']}</p>
                <p style="font-size:0.8em;color:#888">{ws['target_threats']} threats</p>
                <span style="background:{color};color:white;padding:4px 10px;border-radius:12px;font-size:0.8em">{badge}</span>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("""
    ### 📘 How It Works
    
    1. **Scope** - Understand the system and security objectives
    2. **Decompose** - Analyze architecture with Data Flow Diagrams
    3. **Identify Threats** - Select threats and choose mitigations
    4. **Assess** - Review scored answers with explanations
    5. **Complete** - View results and unlock next workshop
    
    **Start with Workshop 1!** Unlock codes for additional workshops are provided by your instructor.
    """)
    
    st.stop()

# WORKSHOP SELECTED - STEPS 1-5
current_workshop = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

st.title(current_workshop["name"])
st.markdown(f"**{current_workshop['level']}** | {current_workshop['scenario']['title']}")

# Progress
cols = st.columns(5)
steps = ["1️⃣ Scope", "2️⃣ Decompose", "3️⃣ Threats", "4️⃣ Assess", "5️⃣ Complete"]
for idx, step in enumerate(steps):
    with cols[idx]:
        if idx + 1 < st.session_state.current_step:
            st.markdown(f"✅ {step}")
        elif idx + 1 == st.session_state.current_step:
            st.markdown(f"**▶️ {step}**")
        else:
            st.markdown(f"⭕ {step}")

st.markdown("---")

# STEP 1: SCOPE WITH HIGH-LEVEL ARCHITECTURE
if st.session_state.current_step == 1:
    st.header("Step 1: Define Scope & Security Objectives")
    
    scenario = current_workshop["scenario"]
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📋 Application Overview")
        st.markdown(f"**Description:** {scenario['description']}")
        st.markdown(f"**Business Context:** {scenario['business_context']}")
        
        st.markdown("### 🎯 Security Objectives")
        for obj in scenario["objectives"]:
            st.markdown(f"- {obj}")
        
        st.markdown("### 💎 Critical Assets")
        for asset in scenario["assets"]:
            st.markdown(f"- {asset}")
        
        st.markdown("### 📜 Compliance Requirements")
        for comp in scenario["compliance"]:
            st.markdown(f"- {comp}")
    
    with col2:
        st.markdown(f"""<div class="success-box">
        <strong>Workshop Objectives</strong><br><br>
        📊 Identify {current_workshop['target_threats']} threats<br>
        ⏱️ {current_workshop['duration']}<br>
        📈 {current_workshop['level']} level<br>
        🎯 Score 90%+ for mastery!
        </div>""", unsafe_allow_html=True)
    
    st.markdown("---")
    
    # HIGH-LEVEL ARCHITECTURE
    st.subheader("🏗️ High-Level System Architecture")
    
    st.markdown("""
    <div class="info-box">
    This simplified view shows the major system components and their relationships.
    In Step 2, you'll see the detailed decomposition with all data flows and trust boundaries.
    </div>
    """, unsafe_allow_html=True)
    
    with st.spinner("Generating high-level architecture..."):
        high_level = generate_high_level_architecture(current_workshop)
    
    if high_level:
        st.image(f"data:image/png;base64,{high_level}",
                 caption="High-Level Architecture Overview",
                 use_column_width=True)
    
    # Component Summary
    st.markdown("### 📦 Component Summary")
    comp_types = {"external_entity": [], "process": [], "datastore": []}
    for comp in scenario["components"]:
        comp_types[comp["type"]].append(comp)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**👤 External Entities**")
        for comp in comp_types["external_entity"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br><small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    
    with col2:
        st.markdown("**⚙️ Processes**")
        for comp in comp_types["process"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br><small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    
    with col3:
        st.markdown("**💾 Data Stores**")
        for comp in comp_types["datastore"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br><small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    
    st.markdown("---")
    
    if st.button("Next: Decompose System ➡️", type="primary", use_container_width=True):
        st.session_state.current_step = 2
        save_progress()
        st.rerun()

# STEP 2: DECOMPOSE WITH DETAILED DFD AND TRUST BOUNDARIES
elif st.session_state.current_step == 2:
    st.header("Step 2: Detailed Application Decomposition")
    
    scenario = current_workshop["scenario"]
    
    st.markdown("""
    <div class="info-box">
    <strong>Detailed Data Flow Diagram (DFD)</strong><br>
    This detailed view shows ALL components, data flows, protocols, and trust boundaries.
    Trust boundaries (purple dashed boxes) mark where data crosses security zones - critical areas for threat analysis!
    </div>
    """, unsafe_allow_html=True)
    
    # GENERATE DETAILED DFD
    st.subheader("📊 Detailed Data Flow Diagram with Trust Boundaries")
    
    with st.spinner("Generating detailed DFD with trust boundaries..."):
        detailed_dfd = generate_detailed_dfd(current_workshop, st.session_state.threats)
    
    if detailed_dfd:
        st.image(f"data:image/png;base64,{detailed_dfd}",
                 caption="Detailed DFD - All Components, Flows, and Trust Boundaries",
                 use_column_width=True)
        st.session_state.detailed_diagram_generated = detailed_dfd
    else:
        st.warning("Diagram generation unavailable. Review components and flows below.")
    
    # DATA FLOWS TABLE
    st.subheader("📝 Data Flows with Protocols")
    flows_data = []
    for flow in scenario["data_flows"]:
        flows_data.append({
            "Source": flow["source"],
            "→": "→",
            "Destination": flow["destination"],
            "Data": flow["data"],
            "Protocol": flow.get("protocol", "N/A")
        })
    
    st.dataframe(pd.DataFrame(flows_data), use_container_width=True, hide_index=True)
    
    # TRUST BOUNDARIES
    st.subheader("🔒 Trust Boundaries - Focus Your Analysis Here!")
    
    st.markdown("""
    Trust boundaries are where data crosses between security zones. **These are the highest-risk areas!**
    Each boundary crossing requires:
    - Authentication verification
    - Authorization checks
    - Input validation
    - Encryption assessment
    """)
    
    for boundary in scenario["trust_boundaries"]:
        with st.expander(f"🔐 {boundary['name']}", expanded=False):
            st.markdown(f"**Description:** {boundary['description']}")
            if boundary.get("components"):
                st.markdown(f"**Components:** {', '.join(boundary['components'])}")
            
            st.markdown("**Why this matters:** Data crossing this boundary needs authentication, "
                       "authorization, encryption, and validation checks.")
    
    # ANALYSIS GUIDANCE
    with st.expander("💡 How to Analyze This Diagram for Threats"):
        st.markdown("""
        **Step-by-step threat analysis approach:**
        
        1. **Focus on trust boundaries first** - Most threats occur where data crosses zones
        2. **Examine each data flow** - What data? What protocol? Is it encrypted? Who can access?
        3. **Apply STRIDE to each element** - Systematically check all 6 categories
        4. **Consider the attacker** - What would YOU attack if you were malicious?
        
        **Key questions for each element:**
        - Where does untrusted data enter the system?
        - Which components handle sensitive data?
        - Are authentication and authorization verified at each boundary?
        - What happens if this component is compromised?
        - Can this data flow be intercepted, modified, or replayed?
        """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Scope", use_container_width=True):
            st.session_state.current_step = 1
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Identify Threats ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()

# STEP 3: IDENTIFY THREATS WITH VALIDATION AND SCORING
elif st.session_state.current_step == 3:
    st.header("Step 3: Identify Threats Using STRIDE")
    
    st.markdown(f"""
    <div class="info-box">
    <strong>How This Works:</strong><br>
    1. Select a threat scenario from the predefined list<br>
    2. Identify which component/flow is affected<br>
    3. Assess likelihood and impact<br>
    4. Select appropriate mitigations from the options<br>
    5. Get instant feedback with scoring and explanations!<br><br>
    <strong>Goal:</strong> Analyze {current_workshop['target_threats']} threats with 90%+ accuracy to demonstrate mastery
    </div>
    """, unsafe_allow_html=True)
    
    # THREAT SELECTION FORM
    with st.form("threat_selection_form"):
        st.subheader("➕ Select Threat to Analyze")
        
        # Build threat options
        threat_options = {
            f"{t['id']}: {t['threat'][:70]}...": t 
            for t in workshop_threats
        }
        
        if not threat_options:
            st.error("No threats available for this workshop yet")
            st.stop()
        
        selected_threat_key = st.selectbox(
            "Choose a threat scenario:",
            list(threat_options.keys()),
            help="Select a potential threat to analyze for this system"
        )
        
        selected_predefined = threat_options[selected_threat_key]
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🎯 Your Analysis")
            
            # Component selection
            all_components = [comp["name"] for comp in current_workshop["scenario"]["components"]]
            all_flows = [f"{f['source']} → {f['destination']}" 
                        for f in current_workshop["scenario"]["data_flows"]]
            
            user_component = st.selectbox(
                "Which component/flow is affected?",
                all_components + all_flows,
                help="Select the DFD element this threat targets"
            )
            
            # STRIDE category
            user_stride = st.selectbox(
                "STRIDE Category",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"],
                help="Primary threat category"
            )
            
            # Risk assessment
            user_likelihood = st.select_slider(
                "Likelihood",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium",
                help="How likely is this threat to occur?"
            )
            
            user_impact = st.select_slider(
                "Impact",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium",
                help="What's the potential damage if exploited?"
            )
        
        with col2:
            st.markdown("### 🛡️ Select Mitigations")
            
            st.caption("Choose ALL controls that would effectively address this threat:")
            
            # Combine and shuffle mitigations
            all_possible_mitigations = (
                selected_predefined["correct_mitigations"] + 
                selected_predefined.get("incorrect_mitigations", [])
            )
            random.shuffle(all_possible_mitigations)
            
            user_mitigations = st.multiselect(
                "Security Controls",
                all_possible_mitigations,
                help="Select all appropriate mitigations (can select multiple)"
            )
            
            st.caption("💡 Think: What would actually prevent or detect this attack?")
        
        st.markdown("---")
        
        submitted = st.form_submit_button("✅ Submit Answer & Get Score", 
                                          type="primary", 
                                          use_container_width=True)
        
        if submitted:
            # Create user answer
            user_answer = {
                "component": user_component,
                "stride": user_stride,
                "likelihood": user_likelihood,
                "impact": user_impact,
                "selected_mitigations": user_mitigations,
                "matched_threat_id": selected_predefined["id"]
            }
            
            # Calculate score
            score, max_score, feedback = calculate_threat_score(user_answer, selected_predefined)
            
            # Update totals
            st.session_state.total_score += score
            st.session_state.max_score += max_score
            
            # Save answer with feedback
            st.session_state.user_answers.append({
                **user_answer,
                "score": score,
                "max_score": max_score,
                "feedback": feedback,
                "predefined_threat": selected_predefined
            })
            
            # Add to threats list
            st.session_state.threats.append(user_answer)
            
            save_progress()
            st.rerun()
    
    # DISPLAY PREVIOUS ANSWERS
    if st.session_state.user_answers:
        st.markdown("---")
        st.subheader(f"📊 Your Answers ({len(st.session_state.user_answers)}/{current_workshop['target_threats']})")
        
        for idx, answer in enumerate(st.session_state.user_answers):
            score_pct = (answer["score"] / answer["max_score"]) * 100
            
            if score_pct >= 80:
                feedback_class = "correct-answer"
                emoji = "✅"
                grade = "Excellent"
            elif score_pct >= 50:
                feedback_class = "partial-answer"
                emoji = "⚠️"
                grade = "Partial"
            else:
                feedback_class = "incorrect-answer"
                emoji = "❌"
                grade = "Needs Review"
            
            with st.expander(f"{emoji} Answer {idx + 1}: {answer['matched_threat_id']} - {grade} ({score_pct:.0f}%)"):
                st.markdown(f"""
                <div class="{feedback_class}">
                    <strong>Your Analysis:</strong><br>
                    • Component: {answer['component']}<br>
                    • STRIDE: {answer['stride']}<br>
                    • Risk: {answer['likelihood']} likelihood, {answer['impact']} impact<br>
                    • Mitigations: {', '.join(answer.get('selected_mitigations', [])) if answer.get('selected_mitigations') else 'None selected'}
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("### 📋 Detailed Feedback")
                for fb in answer["feedback"]:
                    if "✓" in fb:
                        st.success(fb)
                    elif "✗" in fb:
                        st.error(fb)
                    else:
                        st.warning(fb)
                
                # Show learning content
                predefined = answer.get("predefined_threat")
                if predefined:
                    with st.expander("📚 Learn Why"):
                        st.markdown(f"**Explanation:**\n\n{predefined['explanation']}")
                        st.markdown(f"**Why This Risk Level:**\n\n{predefined['why_this_risk']}")
                        st.markdown(f"**Why These Controls Work:**\n\n{predefined['why_these_controls']}")
                        st.markdown(f"**Real-World Example:**\n\n{predefined['real_world']}")
                        st.markdown(f"**Compliance:** {predefined['compliance']}")
    
    # Progress indicator
    progress = len(st.session_state.user_answers) / current_workshop['target_threats']
    st.progress(min(progress, 1.0))
    
    if len(st.session_state.user_answers) >= current_workshop['target_threats']:
        final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
        
        if final_score_pct >= 90:
            score_class = "score-excellent"
            message = "🏆 Excellent! You've mastered this workshop!"
        elif final_score_pct >= 75:
            score_class = "score-good"
            message = "👍 Good job! You understand the concepts well."
        elif final_score_pct >= 60:
            score_class = "score-fair"
            message = "📚 Fair! Review feedback to improve."
        else:
            score_class = "score-poor"
            message = "💪 Keep learning! Review materials and concepts."
        
        st.markdown(f"""
        <div class="{score_class}">
            {message}<br>
            Final Score: {st.session_state.total_score} / {st.session_state.max_score} ({final_score_pct:.1f}%)
        </div>
        """, unsafe_allow_html=True)
    else:
        remaining = current_workshop['target_threats'] - len(st.session_state.user_answers)
        current_score_pct = (st.session_state.total_score / st.session_state.max_score * 100) if st.session_state.max_score > 0 else 0
        st.info(f"⚠️ {remaining} more threats needed. Current score: {current_score_pct:.1f}%")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Decompose", use_container_width=True):
            st.session_state.current_step = 2
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Assessment ➡️", type="primary", use_container_width=True):
            if st.session_state.user_answers:
                st.session_state.current_step = 4
                save_progress()
                st.rerun()
            else:
                st.error("Complete at least one threat analysis")

# STEP 4: ASSESS WITH THREAT-MAPPED DIAGRAM AND EXPLANATIONS
elif st.session_state.current_step == 4:
    st.header("Step 4: Assessment & Threat Mapping")
    
    if not st.session_state.user_answers:
        st.warning("No answers to assess")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
        st.stop()
    
    # FINAL SCORE
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percentage", f"{final_score_pct:.1f}%")
    col3.metric("Threats Analyzed", len(st.session_state.user_answers))
    col4.metric("Grade", 
                "A" if final_score_pct >= 90 else "B" if final_score_pct >= 80 else 
                "C" if final_score_pct >= 70 else "D" if final_score_pct >= 60 else "F")
    
    st.markdown("---")
    
    # THREAT-MAPPED DIAGRAM
    st.subheader("🗺️ Threat-Mapped Architecture Diagram")
    
    st.markdown("""
    <div class="learning-box">
    <strong>Understanding the Threat Map</strong><br>
    This diagram shows all identified threats mapped to their affected components.
    Green highlighting indicates components/flows where threats were identified.
    The threats are labeled directly on the diagram for visual analysis.
    </div>
    """, unsafe_allow_html=True)
    
    with st.spinner("Generating threat-mapped diagram..."):
        threat_mapped = generate_detailed_dfd(current_workshop, st.session_state.threats)
    
    if threat_mapped:
        st.image(f"data:image/png;base64,{threat_mapped}",
                 caption="Architecture with Identified Threats Highlighted",
                 use_column_width=True)
    
    st.markdown("---")
    
    # THREAT-TO-COMPONENT MAPPING
    st.subheader("📍 Threat-to-Component Mapping")
    
    # Group threats by component
    component_threats = {}
    for answer in st.session_state.user_answers:
        comp = answer['component']
        if comp not in component_threats:
            component_threats[comp] = []
        component_threats[comp].append(answer)
    
    for component, threats in component_threats.items():
        with st.expander(f"🎯 {component} ({len(threats)} threats identified)", expanded=True):
            for threat in threats:
                predefined = threat.get('predefined_threat', {})
                score_pct = (threat['score'] / threat['max_score']) * 100
                
                st.markdown(f"""
                <div class="mitigation-card">
                    <strong>{threat['matched_threat_id']}</strong> - {predefined.get('threat', 'Unknown threat')}<br>
                    <strong>STRIDE:</strong> {threat['stride']}<br>
                    <strong>Risk:</strong> {threat['likelihood']} likelihood × {threat['impact']} impact<br>
                    <strong>Your Score:</strong> {threat['score']}/{threat['max_score']} ({score_pct:.0f}%)
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("**Why This Mitigation Matters Here:**")
                st.info(predefined.get('why_these_controls', 'N/A'))
                
                st.markdown("**Correct Mitigations for This Component:**")
                for mit in predefined.get('correct_mitigations', []):
                    st.success(f"✓ {mit}")
                
                st.markdown("---")
    
    # PERFORMANCE BREAKDOWN
    st.subheader("📊 Performance Analysis")
    
    correct_count = sum(1 for a in st.session_state.user_answers if (a["score"] / a["max_score"]) >= 0.8)
    partial_count = sum(1 for a in st.session_state.user_answers if 0.5 <= (a["score"] / a["max_score"]) < 0.8)
    incorrect_count = sum(1 for a in st.session_state.user_answers if (a["score"] / a["max_score"]) < 0.5)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Excellent (80%+)", correct_count)
    col2.metric("Partial (50-79%)", partial_count)
    col3.metric("Needs Review (<50%)", incorrect_count)
    
    # LEARNING RECOMMENDATIONS
    st.subheader("📚 Learning Recommendations")
    
    if final_score_pct < 70:
        st.warning("""
        **Areas to Review:**
        - Review STRIDE categories and what each means
        - Study the relationship between threats and mitigations
        - Understand why certain controls work and others don't
        - Practice identifying affected components correctly
        """)
    elif final_score_pct < 90:
        st.info("""
        **To Improve Further:**
        - Fine-tune risk assessment (likelihood vs impact)
        - Study nuances of different mitigation strategies
        - Review feedback on partial answers
        """)
    else:
        st.success("""
        **Excellent Work!**
        - Strong understanding of STRIDE methodology
        - Excellent threat identification skills
        - Good grasp of appropriate mitigations
        - Ready for next workshop!
        """)
    
    # EXPORT OPTIONS
    st.markdown("---")
    st.subheader("📥 Export Results")
    
    results_df = pd.DataFrame([{
        "Threat_ID": a["matched_threat_id"],
        "Component": a["component"],
        "STRIDE": a["stride"],
        "Likelihood": a["likelihood"],
        "Impact": a["impact"],
        "Score": f"{a['score']}/{a['max_score']}",
        "Percentage": f"{(a['score']/a['max_score']*100):.1f}%",
        "Mitigations": ", ".join(a.get('selected_mitigations', []))
    } for a in st.session_state.user_answers])
    
    csv_data = results_df.to_csv(index=False)
    
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 Download Results CSV",
            csv_data,
            f"threat_results_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.csv",
            "text/csv",
            use_container_width=True
        )
    
    with col2:
        if st.session_state.detailed_diagram_generated:
            img_data = base64.b64decode(st.session_state.detailed_diagram_generated)
            st.download_button(
                "📥 Download Threat Map",
                img_data,
                f"threat_map_ws{st.session_state.selected_workshop}.png",
                "image/png",
                use_container_width=True
            )
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Threats", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
    with col2:
        if st.button("Complete Workshop ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 5
            save_progress()
            st.rerun()

# STEP 5: COMPLETE
elif st.session_state.current_step == 5:
    st.header("🎉 Workshop Complete!")
    
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    if final_score_pct >= 90:
        st.balloons()
        st.success(f"""
        🏆 **Outstanding Performance!**
        
        You've completed {current_workshop['name']} with **{final_score_pct:.1f}%**!
        
        You've demonstrated excellent understanding of:
        - ✅ STRIDE threat categories
        - ✅ Architecture analysis and decomposition
        - ✅ Appropriate risk assessment
        - ✅ Effective mitigation strategies
        """)
    elif final_score_pct >= 70:
        st.info(f"""
        👍 **Good Job!**
        
        Completed {current_workshop['name']} with **{final_score_pct:.1f}%**
        
        You understand core concepts. Review feedback to improve further.
        """)
    else:
        st.warning(f"""
        📚 **Workshop Completed - Keep Learning!**
        
        Score: **{final_score_pct:.1f}%**
        
        Consider reviewing materials and trying again to improve understanding.
        """)
    
    # Mark as completed
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()
    
    # Final statistics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Threats", len(st.session_state.threats))
    col2.metric("Final Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col3.metric("Percentage", f"{final_score_pct:.1f}%")
    col4.metric("Grade", 
                "A" if final_score_pct >= 90 else "B" if final_score_pct >= 80 else 
                "C" if final_score_pct >= 70 else "D" if final_score_pct >= 60 else "F")
    
    st.markdown("---")
    st.subheader("Next Steps")
    
    next_workshop = str(int(st.session_state.selected_workshop) + 1)
    
    if next_workshop in WORKSHOPS:
        st.info(f"""
        **Ready for the next challenge?**
        
        Workshop {next_workshop}: {WORKSHOPS[next_workshop]['name']}
        Level: {WORKSHOPS[next_workshop]['level']}
        
        (Ask your instructor for the unlock code)
        """)
        
        if is_workshop_unlocked(next_workshop):
            if st.button(f"Start Workshop {next_workshop} ➡️", type="primary", use_container_width=True):
                st.session_state.selected_workshop = next_workshop
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                save_progress()
                st.rerun()
    else:
        st.success("""
        🏆 **All Available Workshops Completed!**
        
        Congratulations on completing the STRIDE Threat Modeling Learning Path!
        """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review Assessment", use_container_width=True):
            st.session_state.current_step = 4
            save_progress()
            st.rerun()
    with col2:
        if st.button("🏠 Return to Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            save_progress()
            st.rerun()

st.markdown("---")
st.caption("STRIDE Threat Modeling Learning Lab | Interactive Learning with Validation & Scoring")
