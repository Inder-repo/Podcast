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
    "2": [  # Workshop 2: Microservices / API-Based (5 threats)
        {"id": "T-101", "stride": "Information Disclosure", "component": "API Gateway → Payment Service",
         "threat": "BOLA (Broken Object Level Authorization) - accessing other users' data",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Object-level authorization on every API call", "Resource ownership checks", "Use UUIDs not sequential IDs", "Validate user owns resource"],
         "incorrect_mitigations": ["Add authentication", "Encrypt account ID", "Add rate limiting"],
         "explanation": "BOLA = broken object authorization. API returns data based only on object ID without verifying ownership. Must verify user owns the specific resource being accessed.",
         "compliance": "OWASP API Security Top 10 - API1:2023",
         "points": 10,
         "why_this_risk": "High likelihood - trivial to exploit in banking apps. Critical impact - access to all customer financial data.",
         "why_these_controls": "Validate ownership on EVERY API call. Database query must include: WHERE id=? AND user_id=current_user",
         "real_world": "Peloton API (2021): Any user could access any other user's data by changing user ID. T-Mobile (2021): BOLA exposed customer data. First American leaked 885M docs via BOLA (2019)."},
        
        {"id": "T-102", "stride": "Spoofing", "component": "User Service → Payment Service",
         "threat": "Service Impersonation - rogue service in service mesh",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Mutual TLS (mTLS) for service mesh", "Service identity verification", "Certificate-based authentication", "SPIFFE IDs for services"],
         "incorrect_mitigations": ["Use API keys only", "Add logging", "Network firewall"],
         "explanation": "Without mutual authentication, services accept requests from imposter. Attacker deploys rogue service pretending to be legitimate Payment Service.",
         "compliance": "NIST 800-204, Zero Trust Architecture",
         "points": 10,
         "why_this_risk": "Medium/high - needs cluster access but enables lateral movement and data theft.",
         "why_these_controls": "mTLS means both client and server present certificates. Service mesh (Istio, Linkerd) automatically handles mTLS. Each service has unique identity certificate.",
         "real_world": "Service mesh breaches prevented by mTLS. Without it, lateral movement trivial once attacker enters network."},
        
        {"id": "T-103", "stride": "Repudiation", "component": "Payment Service",
         "threat": "Insufficient Logging - can't trace distributed requests",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Distributed tracing (OpenTelemetry)", "Centralized logging (ELK/Splunk)", "Correlation IDs across services", "Structured JSON logging"],
         "incorrect_mitigations": ["Local file logging only", "No correlation IDs", "Minimal logging"],
         "explanation": "Microservices don't log service-to-service calls. When breach discovered, can't trace attacker's path through system. No correlation IDs across services.",
         "compliance": "PCI-DSS 10, SOC 2 CC7.2",
         "points": 10,
         "why_this_risk": "High/medium - very common oversight. Can't investigate incidents or prove compliance without proper logging.",
         "why_these_controls": "Distributed tracing creates trace showing request path across ALL services. Correlation ID propagates through every service call.",
         "real_world": "Average breach detection: 207 days without centralized logging. With proper logging: detected in hours."},
        
        {"id": "T-104", "stride": "Denial of Service", "component": "API Gateway",
         "threat": "Rate Limiting Bypass - distributed botnet attack",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Global + Per-service rate limits", "Distributed rate limiting (Redis)", "Circuit breaker pattern", "WAF with geo-blocking"],
         "incorrect_mitigations": ["Per-IP limits only", "No distributed tracking", "Increase server capacity only"],
         "explanation": "Attacker uses distributed botnet with different IPs to bypass per-IP rate limits. Or discovers internal service endpoint that bypasses API gateway entirely.",
         "compliance": "OWASP API Top 10 API4:2023 (Unrestricted Resource Consumption)",
         "points": 10,
         "why_this_risk": "High/high - DDoS attacks cheap and easy. Service outage = revenue loss for banking app.",
         "why_these_controls": "Redis-backed rate limiting shared across ALL gateway instances. Circuit breaker prevents cascade failures.",
         "real_world": "GitHub API: 5000 req/hour per user. CloudFlare: Global rate limiting prevented Tbps DDoS attacks."},
        
        {"id": "T-105", "stride": "Tampering", "component": "User Service → Payment Service",
         "threat": "Insecure Service-to-Service Communication - unencrypted inter-service traffic",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["JWT validation on every service call", "Short token expiration (15min)", "Service mesh encryption (mTLS)", "TLS for all internal traffic"],
         "incorrect_mitigations": ["HTTP only for internal", "No token validation", "Long-lived tokens"],
         "explanation": "Services communicate over plain HTTP within cluster. Network sniffer captures credit card data in transit between services. Attacker performs ARP spoofing to intercept/modify traffic.",
         "compliance": "PCI-DSS 4.1, HIPAA 164.312(e)",
         "points": 10,
         "why_this_risk": "Medium/critical - needs network access but financial data exposed.",
         "why_these_controls": "Service mesh automatically encrypts all pod-to-pod traffic with mTLS. Network-level encryption layer prevents MITM.",
         "real_world": "Enterprises with mTLS prevented 100% of network-based lateral movement in red team exercises."}
    ],
    "3": [  # Workshop 3: Multi-Tenant SaaS (5 threats)
        {"id": "T-201", "stride": "Information Disclosure", "component": "Query Service → Data Warehouse",
         "threat": "Cross-Tenant Data Access - SQL missing tenant filter",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Row-Level Security (RLS) in PostgreSQL/Redshift", "Tenant context validation on every request", "WHERE tenant_id = :tenant_id in ALL queries", "Database-level enforcement"],
         "incorrect_mitigations": ["Application-level filtering only", "Trust tenant_id from request", "No RLS policies"],
         "explanation": "SQL query doesn't include tenant filter. Attacker from Tenant A crafts API request that returns Tenant B's data. Database doesn't enforce tenant isolation automatically.",
         "compliance": "SOC 2 CC6.1 (Logical Access), ISO 27001 A.9.4.1",
         "points": 10,
         "why_this_risk": "High/critical - THE multi-tenant SaaS vulnerability. One query returns data from ALL tenants.",
         "why_these_controls": "PostgreSQL RLS policies enforce tenant_id filter on ALL queries automatically at database level. Can't be bypassed by application bug.",
         "real_world": "GitHub Gist (2020): Cross-tenant data leak. SaaS platforms average 1-2 tenant isolation bugs per year. Complete business failure if exposed."},
        
        {"id": "T-202", "stride": "Elevation of Privilege", "component": "API Gateway",
         "threat": "Tenant Isolation Bypass - modifying tenant context",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Tenant context from JWT ONLY (never request body)", "Middleware validation before all routes", "Admin namespace isolation (separate domain)", "Tenant existence and active status checks"],
         "incorrect_mitigations": ["Accept tenant_id from request body", "No middleware validation", "Same domain for admin and tenant APIs"],
         "explanation": "Attacker discovers admin endpoint /internal/all-tenants that bypasses tenant context. Or exploits race condition in tenant context switching.",
         "compliance": "SOC 2 CC6.1",
         "points": 10,
         "why_this_risk": "Medium/critical - needs to find vulnerability but impact is catastrophic cross-tenant access.",
         "why_these_controls": "EVERY API request includes X-Tenant-ID header extracted from JWT. Backend validates before processing. No tenant context = automatic 403 rejection.",
         "real_world": "Salesforce: Strict namespace isolation. Multi-tenant architecture review catches 90% of isolation bugs before production."},
        
        {"id": "T-203", "stride": "Denial of Service", "component": "Query Service → Data Warehouse",
         "threat": "Noisy Neighbor Resource Exhaustion - one tenant impacts all",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Per-tenant resource quotas (CPU/memory/queries)", "Query timeout enforcement (30 seconds)", "Query complexity limits", "Priority queues for enterprise vs free tier"],
         "incorrect_mitigations": ["Unlimited resources per tenant", "No query timeouts", "Shared pool without limits"],
         "explanation": "Tenant A runs expensive analytics query consuming all database CPU. Tenant B's queries time out. Shared resource pool allows one tenant to degrade service for all tenants.",
         "compliance": "SLA commitments, Fair usage policies",
         "points": 10,
         "why_this_risk": "High/high - very common in shared infrastructure. Revenue loss when paying customers impacted.",
         "why_these_controls": "AWS Service Quotas or custom quota service. Tenant A: max 1000 req/min, 10 concurrent queries, 100GB data scanned/day.",
         "real_world": "AWS RDS: Per-instance IOPS limits. Heroku: Per-app dyno limits. Prevents noisy neighbor problems."},
        
        {"id": "T-204", "stride": "Information Disclosure", "component": "Data Lake → Data Warehouse",
         "threat": "Shared Secret Keys - all tenant data with same encryption key",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Per-tenant encryption keys (DEK per tenant)", "Separate backup files per tenant", "AWS KMS with tenant isolation", "Automatic key rotation"],
         "incorrect_mitigations": ["Single master key for all tenants", "Shared backups", "No key separation"],
         "explanation": "All tenants' data encrypted with same master key. If key leaked, ALL tenant data decryptable. Insider with access to key can decrypt any tenant's data.",
         "compliance": "GDPR Article 32 (Security of processing), SOC 2 CC6.1",
         "points": 10,
         "why_this_risk": "Medium/critical - needs key compromise but exposes EVERYTHING. Regulatory violation as tenants can't have separate keys.",
         "why_these_controls": "Each tenant has unique DEK. DEKs encrypted with tenant-specific KEK in AWS KMS. Tenant A's key can't decrypt Tenant B's data.",
         "real_world": "GDPR requires data isolation. Multi-tenant SaaS with single key failed audit. Per-tenant keys now standard for enterprise SaaS."},
        
        {"id": "T-205", "stride": "Tampering", "component": "API Gateway",
         "threat": "Insufficient Tenant Context Validation - accepting tenant_id from request",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Tenant-tagged logs with tenant_id in every log", "Isolation testing (automated tests with 2 tenants)", "Tenant context from JWT claims only", "Middleware enforcement"],
         "incorrect_mitigations": ["Trust request body tenant_id", "No isolation tests", "Optional tenant validation"],
         "explanation": "API accepts tenant_id from request body without validation. Attacker modifies POST body: {tenant_id: 'victim-tenant', data: {...}} to write data to victim's tenant.",
         "compliance": "SOC 2 CC7.2 (System Monitoring)",
         "points": 10,
         "why_this_risk": "High/high - extremely common mistake. Direct data integrity and isolation issues.",
         "why_these_controls": "NEVER trust tenant_id from request body/query params. Extract from JWT claims only. JWT signed by auth service, can't be forged.",
         "real_world": "Isolation testing caught 40% of tenant isolation bugs in major SaaS platforms before production deployment."}
    ],
    "4": [  # Workshop 4: IoT / Healthcare Systems (5 threats)
        {"id": "T-301", "stride": "Tampering", "component": "Glucose Monitor → IoT Gateway",
         "threat": "Device Tampering - firmware modification or physical access",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Secure boot with signature verification", "Firmware signing with manufacturer key", "TPM (Trusted Platform Module)", "Physical tamper detection sensors"],
         "incorrect_mitigations": ["No firmware verification", "Unsigned firmware allowed", "No tamper seals"],
         "explanation": "Attacker gains physical access to glucose monitor in patient's home. Reflashes firmware to report false readings (always shows 'normal'). Patient doesn't get alerts for dangerously high glucose.",
         "compliance": "FDA 21 CFR Part 11, IEC 62304 (medical device software)",
         "points": 10,
         "why_this_risk": "Medium/CRITICAL - needs physical access but LIFE-THREATENING. Patient could die from missed alerts.",
         "why_these_controls": "Secure boot verifies firmware signature before boot using hardware root of trust. Only signed firmware will execute. Prevents malicious firmware installation.",
         "real_world": "Medtronic insulin pump recall: Unencrypted RF allowed unauthorized dosing. St. Jude pacemaker: Firmware could be modified remotely."},
        
        {"id": "T-302", "stride": "Tampering", "component": "IoT Gateway → Device Data Svc",
         "threat": "Replay Attacks on Sensor Data - old readings replayed",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["UTC timestamps on every message", "Nonce (number used once)", "Message freshness checks (reject >5min old)", "Sequence numbers (monotonic counter)"],
         "incorrect_mitigations": ["No timestamps", "Accept any message age", "No replay detection"],
         "explanation": "Attacker captures MQTT messages containing vital signs. Replays old 'normal' readings while patient's actual vitals are critical. Alert system doesn't trigger.",
         "compliance": "HIPAA 164.312(e)(2)(i), FDA Cybersecurity Guidance",
         "points": 10,
         "why_this_risk": "High/CRITICAL - easy to execute replay attack. Patient doesn't receive life-saving intervention. DEATH possible.",
         "why_these_controls": "Every sensor message includes UTC timestamp. Server rejects messages older than 5 minutes. Combine timestamp + nonce + sequence number.",
         "real_world": "Medical device replay attacks demonstrated in research. ICS/SCADA systems compromised by replay. Sequence numbers standard in safety-critical systems."},
        
        {"id": "T-303", "stride": "Information Disclosure", "component": "Patient DB",
         "threat": "Unencrypted PHI/PII - database backups exposed",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["AES-256 encryption at rest (HIPAA requirement)", "TLS 1.3 for all connections", "AWS KMS for key management", "Encrypted backups"],
         "incorrect_mitigations": ["No encryption", "Unencrypted backups", "Keys stored with data"],
         "explanation": "Database backups stored unencrypted in S3. Misconfiguration makes bucket public. Or attacker compromises AWS credentials and downloads backup. PHI of 10K patients exposed.",
         "compliance": "HIPAA 164.312(a)(2)(iv), HITECH Act",
         "points": 10,
         "why_this_risk": "Medium/critical - HIPAA breach notification required. Massive fines ($3M+ average). Patient privacy violated.",
         "why_these_controls": "AES-256 encryption for RDS, S3, EBS. HIPAA requirement - not optional. AWS KMS manages keys with automatic rotation every 365 days.",
         "real_world": "Healthcare breaches: Anthem (78M records), Premera (11M records) - both unencrypted data. Average HIPAA breach fine: $3M+."},
        
        {"id": "T-304", "stride": "Denial of Service", "component": "Alert Service → Web Portal",
         "threat": "Alert Suppression - critical alerts not delivered",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Redundant alert channels (WebSocket + SMS + Phone)", "Priority queues (P0 critical, P1 urgent, P2 warning)", "Watchdog timers (2-minute timeout)", "Alert rate limiting (except P0)"],
         "incorrect_mitigations": ["Single channel only", "No prioritization", "No watchdog timers"],
         "explanation": "Attacker floods alert system with fake low-priority alerts. Queue fills up. Critical patient alert (cardiac arrest) stuck in queue behind 10K fake alerts. Clinician doesn't see critical alert for 20 minutes.",
         "compliance": "FDA 510(k) safety requirements, IEC 60601-1-8 (medical alarms)",
         "points": 10,
         "why_this_risk": "Medium/CRITICAL - needs system access but PATIENT SUFFERS PREVENTABLE HARM. Deaths from missed alerts.",
         "why_these_controls": "Critical alerts sent via: 1) WebSocket to portal, 2) SMS to on-call, 3) Phone call (after 2 min), 4) Email. P0 alerts bypass rate limiting.",
         "real_world": "Alert fatigue causes 50-90% of alerts ignored. Proper prioritization saves lives. Research shows 1000+ alerts per patient-day, 85-99% false positives."},
        
        {"id": "T-305", "stride": "Tampering", "component": "HL7 Interface → Legacy EHR",
         "threat": "Legacy System Injection - HL7 v2 message manipulation",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["HL7 message validation against specification", "Network isolation (separate VLAN)", "Site-to-site VPN for encryption", "Custom HMAC signatures in ZPD segment"],
         "incorrect_mitigations": ["No HL7 validation", "Open network access", "No encryption"],
         "explanation": "Legacy EHR uses HL7 v2 over MLLP (no encryption, no authentication). Attacker on hospital network injects malicious HL7 messages. Modifies patient prescriptions to lethal dosage.",
         "compliance": "HIPAA, HL7 v2.x specification",
         "points": 10,
         "why_this_risk": "High/high - legacy systems often unpatched. Direct patient harm from prescription modification.",
         "why_these_controls": "Validate every HL7 segment against specification. VPN encrypts all traffic. Message signing provides integrity.",
         "real_world": "Hospital ransomware often exploits legacy systems. HL7 interfaces frequently lack authentication. Network segmentation critical defense."}
    ]
}

# COMPLETE WORKSHOP CONFIGURATIONS
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: Web Application (2-Tier)",
        "architecture_type": "2-Tier Web Application",
        "level": "Foundation",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": None,
        "scenario": {
            "title": "TechMart E-Commerce Store",
            "description": "React frontend + Node.js API + PostgreSQL database",
            "business_context": "Series A startup, 50K monthly users, $2M revenue",
            "assets": ["Customer PII", "Payment data", "User credentials", "Order history"],
            "objectives": ["Confidentiality: Protect customer PII", "Integrity: Order accuracy", "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS Level 4", "GDPR", "CCPA"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA"},
                {"name": "API Backend", "type": "process", "description": "Node.js/Express"},
                {"name": "Database", "type": "datastore", "description": "PostgreSQL"},
                {"name": "Stripe", "type": "external_entity", "description": "Payments"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database", "data": "SQL", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payments", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Internet", "description": "Untrusted → Trusted", "components": ["Customer", "Web Frontend"]},
                {"name": "Application", "description": "Frontend → Backend", "components": ["Web Frontend", "API Backend"]},
                {"name": "Data", "description": "App → Storage", "components": ["API Backend", "Database"]}
            ]
        }
    },
    "2": {
        "name": "Workshop 2: Microservices / API-Based",
        "architecture_type": "Microservices Architecture",
        "level": "Intermediate",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": "1",
        "scenario": {
            "title": "CloudBank Mobile Banking",
            "description": "API Gateway + Multiple Services + Message Queues",
            "business_context": "Regional bank, 500K customers",
            "assets": ["Financial data", "Transactions", "PII", "OAuth tokens"],
            "objectives": ["Confidentiality", "Integrity", "Availability: 99.95%"],
            "compliance": ["PCI-DSS", "SOC 2", "GLBA"],
            "components": [
                {"name": "Mobile App", "type": "external_entity", "description": "iOS/Android"},
                {"name": "API Gateway", "type": "process", "description": "AWS API Gateway"},
                {"name": "User Service", "type": "process", "description": "Auth (ECS)"},
                {"name": "Payment Service", "type": "process", "description": "Transfers (ECS)"},
                {"name": "User DB", "type": "datastore", "description": "DynamoDB"},
                {"name": "Transaction DB", "type": "datastore", "description": "Aurora"}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "User Service", "data": "Auth", "protocol": "HTTP/2"},
                {"source": "API Gateway", "destination": "Payment Service", "data": "Payments", "protocol": "HTTP/2"},
                {"source": "User Service", "destination": "User DB", "data": "Data", "protocol": "DynamoDB"},
                {"source": "Payment Service", "destination": "Transaction DB", "data": "Transactions", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Client", "description": "Mobile → Cloud", "components": ["Mobile App", "API Gateway"]},
                {"name": "Service Mesh", "description": "Microservices", "components": ["User Service", "Payment Service"]},
                {"name": "Data", "description": "Services → DB", "components": ["User DB", "Transaction DB"]}
            ]
        }
    },
    "3": {
        "name": "Workshop 3: Multi-Tenant SaaS",
        "architecture_type": "Multi-Tenant SaaS",
        "level": "Advanced",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": "2",
        "scenario": {
            "title": "DataInsight Analytics Platform",
            "description": "Shared infrastructure with logical tenant isolation",
            "business_context": "B2B SaaS, 500 enterprise customers",
            "assets": ["Business data", "Tenant metadata", "API keys"],
            "objectives": ["Tenant isolation", "Data integrity", "99.99% SLA"],
            "compliance": ["SOC 2 Type II", "ISO 27001", "GDPR"],
            "components": [
                {"name": "Web Dashboard", "type": "external_entity", "description": "React SPA"},
                {"name": "API Gateway", "type": "process", "description": "Kong"},
                {"name": "Ingestion Service", "type": "process", "description": "Data ingestion"},
                {"name": "Kafka", "type": "datastore", "description": "MSK streaming"},
                {"name": "Query Service", "type": "process", "description": "Analytics"},
                {"name": "Data Warehouse", "type": "datastore", "description": "Redshift"}
            ],
            "data_flows": [
                {"source": "Web Dashboard", "destination": "API Gateway", "data": "Requests", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "Ingestion Service", "data": "Data", "protocol": "HTTPS"},
                {"source": "Ingestion Service", "destination": "Kafka", "data": "Events", "protocol": "Kafka"},
                {"source": "Query Service", "destination": "Data Warehouse", "data": "SQL", "protocol": "Redshift"}
            ],
            "trust_boundaries": [
                {"name": "Tenant A", "description": "Tenant A isolation", "components": []},
                {"name": "Tenant B", "description": "Tenant B isolation", "components": []},
                {"name": "Pipeline", "description": "Data pipeline", "components": ["Kafka", "Data Warehouse"]}
            ]
        }
    },
    "4": {
        "name": "Workshop 4: IoT / Healthcare Systems",
        "architecture_type": "IoT / Healthcare",
        "level": "Expert",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": "3",
        "scenario": {
            "title": "HealthMonitor Connected Care",
            "description": "IoT Devices + Edge Gateway + Cloud + Legacy Integration",
            "business_context": "FDA-registered device, 10K patients",
            "assets": ["PHI", "Vital signs (safety-critical)", "Device calibration"],
            "objectives": ["Safety: Data integrity (HIGHEST)", "Privacy: PHI", "Availability: 99.99%"],
            "compliance": ["HIPAA", "FDA 21 CFR Part 11", "HITECH"],
            "components": [
                {"name": "Glucose Monitor", "type": "external_entity", "description": "CGM device"},
                {"name": "IoT Gateway", "type": "process", "description": "Edge device"},
                {"name": "Device Data Svc", "type": "process", "description": "Telemetry"},
                {"name": "Alert Service", "type": "process", "description": "CRITICAL alerts"},
                {"name": "Patient DB", "type": "datastore", "description": "Aurora"},
                {"name": "Web Portal", "type": "external_entity", "description": "Clinician portal"},
                {"name": "Legacy EHR", "type": "external_entity", "description": "HL7 v2"}
            ],
            "data_flows": [
                {"source": "Glucose Monitor", "destination": "IoT Gateway", "data": "Glucose", "protocol": "BLE"},
                {"source": "IoT Gateway", "destination": "Device Data Svc", "data": "Vitals", "protocol": "MQTT/TLS"},
                {"source": "Device Data Svc", "destination": "Alert Service", "data": "Monitoring", "protocol": "HTTP/2"},
                {"source": "Alert Service", "destination": "Web Portal", "data": "Alerts", "protocol": "WebSocket"},
                {"source": "Device Data Svc", "destination": "Patient DB", "data": "PHI", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Patient Home", "description": "Physical access", "components": ["Glucose Monitor", "IoT Gateway"]},
                {"name": "Cloud", "description": "Trusted AWS", "components": ["Device Data Svc", "Alert Service"]},
                {"name": "Safety-Critical", "description": "Alert path", "components": ["Alert Service", "Web Portal"]}
            ]
        }
    }
}

# ATTACK TREE EXAMPLES FOR ALL WORKSHOPS
ATTACK_TREES = {
    "1": {  # Workshop 1: Web Application E-Commerce
        "title": "Attack Tree: Compromise E-Commerce Platform",
        "description": "Complete attack tree showing multiple paths to steal customer payment data from TechMart",
        "tree": {
            "type": "goal",
            "label": "GOAL: Steal Customer\nPayment Data",
            "children": [
                {
                    "type": "or",
                    "label": "Compromise Database",
                    "children": [
                        {
                            "type": "and",
                            "label": "SQL Injection Attack",
                            "children": [
                                {"type": "leaf", "label": "Find injectable\nparameter", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Bypass input\nvalidation", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Extract data via\nUNION query", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Steal Database Backup",
                            "children": [
                                {"type": "leaf", "label": "Find misconfigured\nS3 bucket", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Download backup\nfile", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Decrypt if\nencrypted", "difficulty": "Hard"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Intercept Data in Transit",
                    "children": [
                        {
                            "type": "and",
                            "label": "Man-in-the-Middle",
                            "children": [
                                {"type": "leaf", "label": "Position on\nnetwork path", "difficulty": "Hard"},
                                {"type": "leaf", "label": "Downgrade to HTTP\nor weak TLS", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Capture payment\ndata", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "XSS + Session Hijacking",
                            "children": [
                                {"type": "leaf", "label": "Inject XSS payload\nin search/comments", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Steal session\ncookie", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Access user account\n& payment methods", "difficulty": "Easy"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Compromise API Backend",
                    "children": [
                        {
                            "type": "and",
                            "label": "Exploit Admin Panel",
                            "children": [
                                {"type": "leaf", "label": "Find admin\nendpoint", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Bypass authorization\ncheck", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Export customer\ndata", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "API Key Exposure",
                            "children": [
                                {"type": "leaf", "label": "Find hardcoded keys\nin frontend code", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Use Stripe secret\nkey", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Create fraudulent\ncharges", "difficulty": "Easy"}
                            ]
                        }
                    ]
                }
            ]
        }
    },
    "2": {  # Workshop 2: Microservices Banking
        "title": "Attack Tree: Unauthorized Fund Transfer",
        "description": "Attack tree for stealing money from mobile banking application",
        "tree": {
            "type": "goal",
            "label": "GOAL: Unauthorized\nFund Transfer",
            "children": [
                {
                    "type": "or",
                    "label": "Compromise User Account",
                    "children": [
                        {
                            "type": "and",
                            "label": "BOLA Attack",
                            "children": [
                                {"type": "leaf", "label": "Enumerate account\nIDs", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Access other user's\ntransaction API", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Initiate transfer from\nvictim account", "difficulty": "Medium"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Token Theft from Mobile",
                            "children": [
                                {"type": "leaf", "label": "Install malware on\nuser device", "difficulty": "Hard"},
                                {"type": "leaf", "label": "Extract JWT from\napp storage", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Replay token to\nAPI Gateway", "difficulty": "Easy"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Exploit Service Mesh",
                    "children": [
                        {
                            "type": "and",
                            "label": "Service Impersonation",
                            "children": [
                                {"type": "leaf", "label": "Gain access to\nKubernetes cluster", "difficulty": "Hard"},
                                {"type": "leaf", "label": "Deploy rogue\nPayment Service", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Intercept transfer\nrequests", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Message Queue Poisoning",
                            "children": [
                                {"type": "leaf", "label": "Access SQS queue\nwithout auth", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Inject fraudulent\ntransaction message", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Bypass validation\nchecks", "difficulty": "Medium"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Bypass Rate Limiting",
                    "children": [
                        {
                            "type": "and",
                            "label": "Distributed Attack",
                            "children": [
                                {"type": "leaf", "label": "Rent botnet with\n10K+ IPs", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Bypass per-IP\nrate limits", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Brute force account\ncredentials", "difficulty": "Medium"}
                            ]
                        }
                    ]
                }
            ]
        }
    },
    "3": {  # Workshop 3: Multi-Tenant SaaS
        "title": "Attack Tree: Cross-Tenant Data Breach",
        "description": "Attack tree for accessing competitor's business intelligence data in SaaS platform",
        "tree": {
            "type": "goal",
            "label": "GOAL: Access Competitor's\nBusiness Data",
            "children": [
                {
                    "type": "or",
                    "label": "SQL Injection Bypass",
                    "children": [
                        {
                            "type": "and",
                            "label": "Exploit Query Builder",
                            "children": [
                                {"type": "leaf", "label": "Find custom SQL\nquery endpoint", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Inject SQL to remove\ntenant_id filter", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Extract all tenants'\ndata", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Bypass RLS Policy",
                            "children": [
                                {"type": "leaf", "label": "Find database with\nno RLS", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Direct query without\ntenant context", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Access Redshift\nwithout filters", "difficulty": "Easy"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Tenant Context Manipulation",
                    "children": [
                        {
                            "type": "and",
                            "label": "JWT Token Tampering",
                            "children": [
                                {"type": "leaf", "label": "Capture own JWT\ntoken", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Modify tenant_id\nclaim", "difficulty": "Hard"},
                                {"type": "leaf", "label": "Re-sign with weak\nkey", "difficulty": "Hard"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Request Body Injection",
                            "children": [
                                {"type": "leaf", "label": "Find API accepting\ntenant_id in body", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Change tenant_id to\ntarget tenant", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Write data to victim\ntenant", "difficulty": "Easy"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Shared Resource Access",
                    "children": [
                        {
                            "type": "and",
                            "label": "Kafka Topic Cross-Read",
                            "children": [
                                {"type": "leaf", "label": "Access shared Kafka\ncluster", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Subscribe to all\ntopics", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Read cross-tenant\nmessages", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Shared Encryption Key",
                            "children": [
                                {"type": "leaf", "label": "Compromise DEK\nfor own tenant", "difficulty": "Hard"},
                                {"type": "leaf", "label": "Discover same key\nused for all", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Decrypt competitor\nbackups", "difficulty": "Easy"}
                            ]
                        }
                    ]
                }
            ]
        }
    },
    "4": {  # Workshop 4: IoT Healthcare
        "title": "Attack Tree: Patient Harm via Medical Device",
        "description": "Attack tree showing paths to cause patient harm through device compromise",
        "tree": {
            "type": "goal",
            "label": "GOAL: Cause Patient Harm\nvia Device Compromise",
            "children": [
                {
                    "type": "or",
                    "label": "Suppress Critical Alerts",
                    "children": [
                        {
                            "type": "and",
                            "label": "Alert Flooding DoS",
                            "children": [
                                {"type": "leaf", "label": "Gain network access\nto alert system", "difficulty": "Hard"},
                                {"type": "leaf", "label": "Flood queue with\nfake P2 alerts", "difficulty": "Easy"},
                                {"type": "leaf", "label": "P0 cardiac arrest\nalert delayed", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Replay Normal Readings",
                            "children": [
                                {"type": "leaf", "label": "Capture MQTT messages\nwith vitals", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Replay old 'normal'\nreadings", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Actual critical vitals\nnot reported", "difficulty": "Easy"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Tamper with Device",
                    "children": [
                        {
                            "type": "and",
                            "label": "Physical Firmware Mod",
                            "children": [
                                {"type": "leaf", "label": "Physical access to\nglucose monitor", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Bypass secure boot\nor remove TPM", "difficulty": "Hard"},
                                {"type": "leaf", "label": "Flash malicious\nfirmware", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Device reports false\n'normal' readings", "difficulty": "Easy"}
                            ]
                        },
                        {
                            "type": "and",
                            "label": "Bluetooth MITM",
                            "children": [
                                {"type": "leaf", "label": "Position within BLE\nrange (~10m)", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Exploit weak or no\nBLE encryption", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Inject false glucose\nreadings", "difficulty": "Medium"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Modify HL7 Messages",
                    "children": [
                        {
                            "type": "and",
                            "label": "Hospital Network Attack",
                            "children": [
                                {"type": "leaf", "label": "Gain access to hospital\nnetwork (phishing)", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Locate HL7 interface\non VLAN", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Inject malicious HL7\nmessage", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Modify prescription to\nlethal dose", "difficulty": "Easy"}
                            ]
                        }
                    ]
                },
                {
                    "type": "or",
                    "label": "Compromise PHI for Ransom",
                    "children": [
                        {
                            "type": "and",
                            "label": "Unencrypted Database",
                            "children": [
                                {"type": "leaf", "label": "Find public S3\nbackup bucket", "difficulty": "Medium"},
                                {"type": "leaf", "label": "Download unencrypted\nPHI database", "difficulty": "Easy"},
                                {"type": "leaf", "label": "Threaten to expose\n10K patient records", "difficulty": "Easy"}
                            ]
                        }
                    ]
                }
            ]
        }
    }
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

def generate_attack_tree(tree_structure, title="Attack Tree"):
    """Generate attack tree visualization using Graphviz"""
    try:
        dot = Digraph(comment=title, format="png")
        dot.attr(rankdir="TB", size="14,18", fontname="Arial", bgcolor="white")
        dot.attr("node", fontname="Arial", fontsize="9", shape="box", style="rounded,filled")
        dot.attr("edge", fontname="Arial", fontsize="8")
        
        def add_nodes(node, parent_id=None, node_counter=[0]):
            """Recursively add nodes to the graph"""
            node_counter[0] += 1
            current_id = f"node_{node_counter[0]}"
            
            # Determine node style based on type
            if node.get("type") == "goal":
                color = "#FFCDD2"  # Light red for main goal
                shape = "oval"
            elif node.get("type") == "and":
                color = "#BBDEFB"  # Light blue for AND
                shape = "box"
                label_text = f"{node['label']}\\n[AND]"
            elif node.get("type") == "or":
                color = "#C8E6C9"  # Light green for OR
                shape = "box"
                label_text = f"{node['label']}\\n[OR]"
            elif node.get("type") == "leaf":
                color = "#FFF9C4"  # Light yellow for attack steps
                shape = "box"
            else:
                color = "#E0E0E0"
                shape = "box"
            
            # Add difficulty/cost if present
            label_text = node['label']
            if node.get("difficulty"):
                label_text += f"\\n({node['difficulty']})"
            
            dot.node(current_id, label_text, fillcolor=color, shape=shape)
            
            # Connect to parent
            if parent_id:
                edge_label = node.get("edge_label", "")
                dot.edge(parent_id, current_id, label=edge_label)
            
            # Process children
            for child in node.get("children", []):
                add_nodes(child, current_id, node_counter)
            
            return current_id
        
        # Build tree starting from root
        add_nodes(tree_structure)
        
        path = dot.render("attack_tree", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception as e:
        st.error(f"Attack tree generation error: {e}")
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
    3. **Learn STRIDE** - Understand where each threat category applies
    4. **Build Attack Tree** - Visualize attacker paths and prioritize defenses
    5. **Identify Threats** - Select threats and choose mitigations
    6. **Assess** - Review scored answers with explanations
    7. **Complete** - View results and unlock next workshop
    
    **Start with Workshop 1!** Unlock codes for additional workshops are provided by your instructor.
    """)
    
    st.stop()

# WORKSHOP SELECTED - STEPS 1-5
current_workshop = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

st.title(current_workshop["name"])
st.markdown(f"**{current_workshop['level']}** | {current_workshop['scenario']['title']}")

# Progress
cols = st.columns(7)
steps = ["1️⃣ Scope", "2️⃣ Decompose", "2.5️⃣ STRIDE", "3️⃣ Attack Tree", "4️⃣ Threats", "5️⃣ Assess", "6️⃣ Complete"]
step_values = [1, 2, 2.5, 3, 4, 5, 6]

for idx, (step, step_val) in enumerate(zip(steps, step_values)):
    with cols[idx]:
        if st.session_state.current_step > step_val:
            st.markdown(f"✅ {step}")
        elif st.session_state.current_step == step_val:
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
        if st.button("Next: Learn STRIDE Application ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 2.5
            save_progress()
            st.rerun()

# STEP 2.5: LEARN WHERE TO APPLY STRIDE (NEW LEARNING SECTION)
elif st.session_state.current_step == 2.5:
    st.header("🎓 Step 2.5: Learn Where to Apply STRIDE")
    
    st.markdown("""
    <div class="info-box">
    <h3>📚 Understanding STRIDE Application</h3>
    Before identifying threats, you need to know <strong>WHERE</strong> each STRIDE category applies in your architecture.
    Different components and trust boundaries are vulnerable to different threat types.<br><br>
    <strong>This section teaches you the rules of applying STRIDE systematically.</strong>
    </div>
    """, unsafe_allow_html=True)
    
    # STRIDE CORE RULES
    st.subheader("📜 The STRIDE Application Rules")
    
    st.markdown("""
    <div class="summary-box">
    <h4>The Golden Rule of STRIDE</h4>
    <strong>Every element in your DFD is vulnerable to specific STRIDE categories based on its TYPE.</strong><br><br>
    🎯 External Entities → Spoofing & Data Flows<br>
    ⚙️ Processes → All STRIDE categories<br>
    📊 Data Flows → Tampering, Information Disclosure, DoS<br>
    💾 Data Stores → Tampering, Information Disclosure, DoS, Repudiation
    </div>
    """, unsafe_allow_html=True)
    
    # STRIDE BY CATEGORY
    st.subheader("🔍 STRIDE Categories Explained")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **🎭 SPOOFING (Identity)**
        - **Applies to:** External entities, Processes, Data flows
        - **Question:** Can someone pretend to be someone/something else?
        - **Examples:** Login forms, API auth, Service-to-service calls
        - **Where in architecture:** User login, Service authentication, Network communications
        """)
        
        st.markdown("""
        **✏️ TAMPERING (Integrity)**
        - **Applies to:** Data flows, Data stores, Processes
        - **Question:** Can someone modify data they shouldn't?
        - **Examples:** SQL injection, XSS, MITM attacks
        - **Where in architecture:** API requests, Database queries, Files, Network packets
        """)
        
        st.markdown("""
        **🚫 REPUDIATION (Non-repudiation)**
        - **Applies to:** Processes, Data stores
        - **Question:** Can someone deny they did something?
        - **Examples:** Missing audit logs, No transaction history
        - **Where in architecture:** Transaction logs, User actions, System events
        """)
    
    with col2:
        st.markdown("""
        **🔓 INFORMATION DISCLOSURE (Confidentiality)**
        - **Applies to:** Data stores, Data flows, Processes
        - **Question:** Can someone see data they shouldn't?
        - **Examples:** Unencrypted databases, Verbose errors, Network sniffing
        - **Where in architecture:** Databases, API responses, Log files, Error messages
        """)
        
        st.markdown("""
        **🚫 DENIAL OF SERVICE (Availability)**
        - **Applies to:** Processes, Data flows, Data stores
        - **Question:** Can someone prevent legitimate users from accessing?
        - **Examples:** DDoS, Resource exhaustion, Query floods
        - **Where in architecture:** APIs, Databases, Network bandwidth, CPU/Memory
        """)
        
        st.markdown("""
        **👑 ELEVATION OF PRIVILEGE (Authorization)**
        - **Applies to:** Processes
        - **Question:** Can someone gain unauthorized capabilities?
        - **Examples:** Admin bypass, Broken access control, SQL injection to admin
        - **Where in architecture:** Admin functions, Authorization checks, User roles
        """)
    
    st.markdown("---")
    
    # STRIDE PER ELEMENT TABLE
    st.subheader("📊 STRIDE Per Element Type (Reference Table)")
    
    stride_table_data = pd.DataFrame({
        "DFD Element": ["External Entity", "Process", "Data Flow", "Data Store"],
        "S (Spoofing)": ["✓ YES", "✓ YES", "✓ YES", "— No"],
        "T (Tampering)": ["— No", "✓ YES", "✓ YES", "✓ YES"],
        "R (Repudiation)": ["— No", "✓ YES", "— No", "✓ YES"],
        "I (Info Disc)": ["— No", "✓ YES", "✓ YES", "✓ YES"],
        "D (DoS)": ["— No", "✓ YES", "✓ YES", "✓ YES"],
        "E (Elev Priv)": ["— No", "✓ YES", "— No", "— No"]
    })
    
    st.dataframe(stride_table_data, use_container_width=True, hide_index=True)
    
    st.markdown("""
    <div class="info-box">
    <strong>How to Use This Table:</strong><br>
    1. Look at each element in your DFD (External Entity, Process, Data Flow, Data Store)<br>
    2. Check which STRIDE categories apply (marked ✓ YES)<br>
    3. For each applicable category, ask the relevant threat question<br>
    4. Document threats you identify<br><br>
    <strong>Note:</strong> Processes can have ALL STRIDE threats - they're the most complex elements!
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # ARCHITECTURE-SPECIFIC GUIDANCE
    st.subheader(f"🎯 STRIDE in YOUR Architecture: {current_workshop['architecture_type']}")
    
    # Get architecture-specific guidance based on workshop
    if st.session_state.selected_workshop == "1":  # Web Application
        st.markdown("""
        ### Trust Boundary 1: Internet → Web Frontend
        **🔒 Crossing from UNTRUSTED (Internet) to TRUSTED (Your Application)**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Spoofing** | User authentication happens here | Attacker uses stolen credentials |
        | **Tampering** | User input enters your system | XSS payload in search field |
        | **Info Disclosure** | Sensitive data in responses | API keys visible in JavaScript |
        | **Denial of Service** | Public endpoint can be flooded | DDoS attack on login page |
        
        **Key Questions:**
        - Is authentication strong (MFA)?
        - Is user input sanitized (XSS prevention)?
        - Are there rate limits?
        - Is TLS 1.3 enforced?
        """)
        
        st.markdown("""
        ### Trust Boundary 2: Web Frontend → API Backend
        **🔒 Crossing from CLIENT (Browser) to SERVER (Backend)**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Spoofing** | Session tokens can be stolen | Session hijacking via XSS |
        | **Tampering** | API requests can be modified | Changing price in POST request |
        | **Repudiation** | Actions need to be logged | User denies making purchase |
        | **Info Disclosure** | Responses may expose data | Verbose error with DB schema |
        | **Elev of Privilege** | Authorization bypass | Accessing admin endpoint as user |
        
        **Key Questions:**
        - Are session tokens secure (HttpOnly, Secure)?
        - Is authorization checked on EVERY API call?
        - Are all actions logged with user_id?
        - Do errors expose internals?
        """)
        
        st.markdown("""
        ### Trust Boundary 3: API Backend → Database
        **🔒 Crossing from APPLICATION to DATA STORAGE**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Tampering** | SQL queries can be manipulated | SQL injection attack |
        | **Info Disclosure** | Database contents visible if breached | Unencrypted PII at rest |
        | **Repudiation** | Need audit trail of changes | Can't prove who modified data |
        | **Denial of Service** | Expensive queries lock DB | Unbounded SELECT * query |
        
        **Key Questions:**
        - Are queries parameterized (prevent SQL injection)?
        - Is database encrypted at rest?
        - Are all data modifications logged?
        - Are there query timeouts?
        """)
    
    elif st.session_state.selected_workshop == "2":  # Microservices
        st.markdown("""
        ### Trust Boundary 1: Mobile App → API Gateway
        **🔒 Crossing from MOBILE DEVICE to CLOUD PLATFORM**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Spoofing** | OAuth tokens can be stolen from device | Malware stealing JWT from mobile storage |
        | **Tampering** | Requests can be intercepted/modified | MITM on public WiFi |
        | **Info Disclosure** | API responses expose data | Excessive data in API response |
        | **Denial of Service** | Distributed attacks from botnets | Rate limit bypass with multiple IPs |
        
        **Key Questions:**
        - Are tokens stored securely (Keychain/Keystore)?
        - Is certificate pinning implemented?
        - Are there both global and per-user rate limits?
        - Do API responses filter sensitive fields?
        """)
        
        st.markdown("""
        ### Trust Boundary 2: User Service → Payment Service  
        **🔒 Crossing BETWEEN MICROSERVICES (Service Mesh)**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Spoofing** | Services must authenticate each other | Rogue service impersonating Payment Svc |
        | **Tampering** | Inter-service messages can be modified | Request modification in service mesh |
        | **Repudiation** | Need distributed tracing | Can't trace request path through services |
        | **Info Disclosure** | Unencrypted service-to-service comms | Network sniffing in cluster |
        
        **Key Questions:**
        - Is mutual TLS (mTLS) enforced?
        - Does each service verify caller identity?
        - Are correlation IDs used for tracing?
        - Is all inter-service traffic encrypted?
        """)
        
        st.markdown("""
        ### Trust Boundary 3: Payment Service → Transaction DB
        **🔒 Crossing from SERVICE to CRITICAL DATA**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Info Disclosure** | BOLA - accessing other users' transactions | GET /transactions/123 without ownership check |
        | **Elev of Privilege** | Function-level authorization bypass | Regular user calling admin-only function |
        | **Tampering** | Race conditions on money transfers | Double-spend attack |
        | **Repudiation** | Financial transactions need proof | Disputing a transfer occurred |
        
        **Key Questions:**
        - Is object ownership verified on EVERY query?
        - Are UUIDs used instead of sequential IDs?
        - Are transactions atomic and isolated?
        - Is there cryptographic signing?
        """)
    
    elif st.session_state.selected_workshop == "3":  # Multi-Tenant SaaS
        st.markdown("""
        ### Trust Boundary 1: Tenant Isolation Boundary
        **🔒 CRITICAL: Preventing Tenant A from accessing Tenant B data**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Info Disclosure** | SQL missing tenant_id filter | Query returns data from ALL tenants |
        | **Elev of Privilege** | Tenant context not validated | User modifies tenant_id in JWT |
        | **Tampering** | JWT token manipulation | Changing tenant_id claim to access others |
        
        **Key Questions:**
        - Is tenant_id extracted from JWT ONLY (not request body)?
        - Does EVERY database query include WHERE tenant_id = ?
        - Is Row-Level Security (RLS) enforced in database?
        - Are JWT tokens validated and tenant-scoped?
        """)
        
        st.markdown("""
        ### Trust Boundary 2: Query Service → Data Warehouse
        **🔒 Shared Database - Highest Risk for Cross-Tenant Access**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Info Disclosure** | Shared Redshift without RLS | Tenant A queries Tenant B's data |
        | **Denial of Service** | Expensive query from one tenant | Noisy neighbor exhausting resources |
        | **Elev of Privilege** | Bypassing tenant filter | SQL injection to remove WHERE clause |
        
        **Key Questions:**
        - Does Redshift have Row-Level Security policies?
        - Are there per-tenant resource quotas?
        - Are queries validated before execution?
        - Are query timeouts enforced?
        """)
        
        st.markdown("""
        ### Trust Boundary 3: Data Pipeline (Kafka → Warehouse)
        **🔒 Streaming Data - Ensure Tenant Tagging**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Info Disclosure** | Shared Kafka topics | Consumer reads cross-tenant messages |
        | **Tampering** | Message injection | Malicious tenant injects fake data |
        | **Repudiation** | Missing tenant context in logs | Can't audit which tenant's data was accessed |
        
        **Key Questions:**
        - Is every message tagged with tenant_id?
        - Are Kafka topics per-tenant or with ACLs?
        - Are all pipeline operations tenant-aware?
        - Are logs searchable by tenant?
        """)
    
    elif st.session_state.selected_workshop == "4":  # IoT/Healthcare
        st.markdown("""
        ### Trust Boundary 1: Glucose Monitor → IoT Gateway (Physical)
        **🔒 SAFETY-CRITICAL: Physical Access + Bluetooth Communication**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Tampering** | Physical access to device | Attacker reflashes firmware with malicious code |
        | **Spoofing** | Fake device sending readings | Rogue device impersonating patient's monitor |
        | **Info Disclosure** | Unencrypted Bluetooth | BLE sniffing captures glucose readings (PHI) |
        
        **Key Questions:**
        - Is firmware signed and verified at boot (Secure Boot)?
        - Is BLE encrypted with pairing/bonding?
        - Are there tamper seals and detection?
        - Does device attest to cloud before connecting?
        """)
        
        st.markdown("""
        ### Trust Boundary 2: IoT Gateway → Cloud (MQTT/TLS)
        **🔒 SAFETY-CRITICAL: Patient WiFi (Untrusted) → Cloud (Trusted)**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Tampering** | Replay attacks | Old 'normal' vitals replayed while patient critical |
        | **Info Disclosure** | PHI over patient's WiFi | Network sniffing captures medical data |
        | **Spoofing** | Gateway impersonation | Attacker pretends to be legitimate gateway |
        
        **Key Questions:**
        - Are messages timestamped with freshness checks?
        - Is MQTT over TLS with mutual authentication?
        - Are sequence numbers tracked to prevent replay?
        - Is there a nonce for additional replay protection?
        """)
        
        st.markdown("""
        ### Trust Boundary 3: Alert Service → Emergency 911
        **🔒 LIFE-CRITICAL: Alert Path CANNOT FAIL**
        
        | STRIDE | Why it applies here | Example threat |
        |--------|---------------------|----------------|
        | **Denial of Service** | Alert flooding | Fake alerts suppress critical real alerts |
        | **Spoofing** | Fake emergency calls | Attacker triggers false 911 calls |
        | **Tampering** | Modified alert severity | Critical alert downgraded to warning |
        
        **Key Questions:**
        - Are alerts prioritized (P0 critical, P1 urgent, etc.)?
        - Are there redundant delivery channels (WebSocket + SMS + Phone)?
        - Are critical alerts exempt from rate limiting?
        - Is there device attestation for alerts?
        """)
    
    st.markdown("---")
    
    # PRACTICAL CHECKLIST
    st.subheader("✅ Pre-Threat Identification Checklist")
    
    st.markdown(f"""
    Before moving to threat identification, ensure you understand:
    
    **STRIDE Fundamentals:**
    - [ ] I know what each STRIDE letter stands for
    - [ ] I understand which element types each STRIDE category applies to
    - [ ] I can identify trust boundaries in the architecture
    
    **Architecture-Specific:**
    - [ ] I know the critical trust boundaries in {current_workshop['architecture_type']}
    - [ ] I understand why certain STRIDE categories are high priority here
    - [ ] I can identify the highest-risk components
    
    **Application Rules:**
    - [ ] I know to focus on trust boundary crossings FIRST
    - [ ] I understand that Processes can have ALL STRIDE threats
    - [ ] I know to ask threat questions systematically for each element
    
    **Ready to Proceed:**
    - [ ] I'm confident I can identify WHERE threats occur
    - [ ] I understand WHY certain mitigations work
    - [ ] I'm ready to analyze {current_workshop['target_threats']} threats!
    """)
    
    st.markdown("""
    <div class="success-box">
    <strong>💡 Pro Tip:</strong> Print or screenshot the STRIDE per Element table above. 
    Use it as a reference while identifying threats in the next step!
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Decompose", use_container_width=True):
            st.session_state.current_step = 2
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Build Attack Tree ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()

# STEP 3: ATTACK TREE LEARNING AND BUILDING
elif st.session_state.current_step == 3:
    st.header("🌳 Step 3: Build an Attack Tree")
    
    st.markdown("""
    <div class="info-box">
    <h3>📚 What is an Attack Tree?</h3>
    An <strong>Attack Tree</strong> is a hierarchical diagram that represents the ways an attacker might try to achieve a goal.
    The root node is the attacker's main objective, and branches show different attack paths.<br><br>
    <strong>Why use Attack Trees?</strong>
    <ul>
    <li>Visualize all possible attack paths systematically</li>
    <li>Identify the easiest/cheapest attack vectors</li>
    <li>Prioritize security controls based on likely attack paths</li>
    <li>Communicate threats to non-technical stakeholders</li>
    </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # ATTACK TREE BASICS
    st.subheader("🎯 Attack Tree Fundamentals")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Node Types
        
        **🎯 Goal Node (Root)**
        - Attacker's ultimate objective
        - Example: "Steal customer payment data"
        - Shown in RED/PINK
        
        **AND Gate (All Required)**
        - ALL child nodes must succeed
        - Example: "Exploit admin panel" = Find endpoint AND Bypass auth AND Export data
        - Shown in BLUE
        - More secure (multiple steps required)
        
        **OR Gate (Any Succeeds)**
        - ANY child node succeeding achieves goal
        - Example: "Compromise database" = SQL injection OR Stolen backup OR Direct access
        - Shown in GREEN
        - Less secure (multiple attack paths)
        """)
    
    with col2:
        st.markdown("""
        ### Leaf Nodes (Attack Steps)
        
        **Attack Actions**
        - Specific steps attacker takes
        - Example: "Find injectable parameter"
        - Shown in YELLOW
        
        **Difficulty Ratings**
        - **Easy**: Automated tools, no skill
        - **Medium**: Some technical knowledge
        - **Hard**: Expert skills, expensive
        - **Critical**: Nation-state level
        
        **Why This Matters**
        - Attackers choose EASIEST path
        - One "Easy" path = System compromised
        - Security must block ALL viable paths
        """)
    
    st.markdown("---")
    
    # EXAMPLE ATTACK TREE FOR THIS WORKSHOP
    st.subheader(f"📊 Example Attack Tree: {current_workshop['architecture_type']}")
    
    attack_tree_data = ATTACK_TREES.get(st.session_state.selected_workshop, {})
    
    if attack_tree_data:
        st.markdown(f"""
        <div class="learning-box">
        <strong>{attack_tree_data['title']}</strong><br>
        {attack_tree_data['description']}
        </div>
        """, unsafe_allow_html=True)
        
        # Generate and display the attack tree
        with st.spinner("Generating attack tree visualization..."):
            attack_tree_img = generate_attack_tree(
                attack_tree_data["tree"],
                attack_tree_data["title"]
            )
        
        if attack_tree_img:
            st.image(f"data:image/png;base64,{attack_tree_img}",
                     caption=attack_tree_data["title"],
                     use_container_width=True)
        
        # Explain the tree
        st.markdown("---")
        st.subheader("🔍 Reading This Attack Tree")
        
        # Architecture-specific explanation
        if st.session_state.selected_workshop == "1":
            st.markdown("""
            ### Key Insights from This Tree:
            
            **1. Multiple Attack Paths (OR gates at top level)**
            - Attacker has 3 main strategies to steal payment data
            - System must defend against ALL three paths
            
            **2. Easiest Attack Paths:**
            - **API Key Exposure**: Easy → Easy → Easy (All EASY steps!)
            - **XSS + Session Hijacking**: Medium → Easy → Easy
            - Finding hardcoded secrets in frontend = CRITICAL vulnerability
            
            **3. Hardest Attack Path:**
            - **Man-in-the-Middle**: Hard → Medium → Easy
            - Requires network positioning (hard), but once in place, easy to execute
            
            **4. Defense Priorities (Based on Tree):**
            1. **CRITICAL**: Never hardcode API keys (easiest path)
            2. **HIGH**: XSS prevention (second easiest)
            3. **MEDIUM**: SQL injection protection (requires finding vulnerability first)
            4. **LOWER**: MITM (hardest to position, less likely)
            
            **AND Gates = Security Layers**
            - Each AND gate requires attacker to succeed at ALL steps
            - Breaking any ONE step in an AND chain blocks entire attack
            - Example: SQL Injection AND = Block at input validation OR parameterized queries OR WAF
            """)
        
        elif st.session_state.selected_workshop == "2":
            st.markdown("""
            ### Key Insights from This Tree:
            
            **1. API-Level Vulnerabilities = Easiest Path**
            - **BOLA Attack**: Easy → Easy → Medium (Highest risk!)
            - Enumerating account IDs and accessing others' data trivially easy
            
            **2. Service Mesh Complexity = Attack Surface**
            - Service impersonation requires cluster access (hard to get in)
            - BUT once inside, impersonation might be easy without mTLS
            
            **3. Mobile Security Challenges:**
            - Token theft requires malware installation (hard)
            - But if malware installed, token extraction relatively easy
            
            **4. Defense Priorities:**
            1. **CRITICAL**: Object-level authorization on EVERY API call (blocks BOLA)
            2. **HIGH**: Mutual TLS in service mesh (blocks impersonation)
            3. **MEDIUM**: Distributed rate limiting (harder attack, needs botnet)
            4. **LOWER**: Mobile device security (relies on user behavior)
            
            **Why BOLA is Top Priority:**
            - Three "Easy" or "Easy→Medium" paths
            - Attacker just changes ID in URL
            - No expensive tools or skills needed
            """)
        
        elif st.session_state.selected_workshop == "3":
            st.markdown("""
            ### Key Insights from This Tree:
            
            **1. Tenant Isolation = Make or Break**
            - Multiple paths to cross-tenant access
            - One vulnerability = Business failure
            
            **2. Easiest Attack Paths:**
            - **Request Body Injection**: Medium → Easy → Easy
            - **Kafka Topic Access**: Medium → Easy → Easy
            - SQL injection to remove tenant filters
            
            **3. Shared Resources = Shared Risk**
            - Kafka topics without ACLs
            - Shared encryption keys
            - No Row-Level Security in database
            
            **4. Defense Priorities:**
            1. **CRITICAL**: Row-Level Security (RLS) in ALL databases
            2. **CRITICAL**: Tenant context from JWT ONLY
            3. **HIGH**: Per-tenant Kafka topics with ACLs
            4. **HIGH**: Per-tenant encryption keys
            5. **MEDIUM**: JWT tampering prevention (requires cryptographic attack)
            
            **AND Gate Analysis:**
            - JWT Token Tampering is HARD (requires breaking crypto)
            - But bypassing it via request body injection is EASY
            - Attacker chooses easy path - must block both!
            """)
        
        elif st.session_state.selected_workshop == "4":
            st.markdown("""
            ### Key Insights from This Tree:
            
            **1. LIFE-CRITICAL Stakes = Unique Risk Profile**
            - Patient harm possible through multiple paths
            - Not just data theft - PHYSICAL HARM
            
            **2. Easiest Attack Paths (HIGH PRIORITY):**
            - **Alert Flooding**: Hard → Easy → Easy (Once in, trivial to execute)
            - **Replay Attack**: Medium → Easy → Easy
            - **Unencrypted Database**: Medium → Easy → Easy
            
            **3. Physical Access Attacks:**
            - Require physical proximity (moderate barrier)
            - But patient devices at home = accessible
            - Firmware tampering CRITICAL risk
            
            **4. Defense Priorities:**
            1. **LIFE-CRITICAL**: Alert system resilience (P0 priority queues, redundant channels)
            2. **LIFE-CRITICAL**: Replay attack prevention (timestamps, nonce, sequence numbers)
            3. **HIPAA-CRITICAL**: PHI encryption at rest
            4. **SAFETY-CRITICAL**: Secure boot + firmware signing
            5. **HIGH**: HL7 message validation + network isolation
            
            **Unique Considerations:**
            - Traditional "hard" attacks (physical access) become "medium" in home setting
            - Legacy system integration (HL7) adds attack surface
            - Alert suppression = delayed treatment = death
            - Must defend against ALL paths - no acceptable risk
            """)
        
        st.markdown("---")
        
        # INTERACTIVE LEARNING
        st.subheader("🎓 Apply Your Understanding")
        
        st.markdown("""
        <div class="warning-box">
        <strong>Critical Thinking Exercise:</strong><br>
        Based on this attack tree, answer these questions:
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander("❓ Question 1: Which attack path should be defended FIRST?", expanded=True):
            st.markdown("""
            **Look for:**
            - Paths with the MOST "Easy" difficulty steps
            - OR gates with multiple easy alternatives
            - Leaf nodes that require no special skills/tools
            
            **Answer:** The path with the highest concentration of "Easy" steps that leads directly to the goal.
            This is what attackers will try first (lowest cost, highest success rate).
            """)
        
        with st.expander("❓ Question 2: Where are the AND gates most valuable?"):
            st.markdown("""
            **AND gates = Security layers:**
            - Attacker must succeed at ALL steps
            - Defending ONE step blocks the entire path
            - Example: "SQL Injection Attack" AND gate has 3 steps
              - Block ANY one step → Entire SQL injection path fails
            
            **Defense strategy:**
            - For AND gates: Block at EARLIEST/EASIEST point to defend
            - Example: Input validation (easy to implement) blocks SQL injection
            - Don't need to also encrypt connections, though defense-in-depth helps
            """)
        
        with st.expander("❓ Question 3: How does difficulty rating influence defense?"):
            st.markdown("""
            **High difficulty = Natural barrier:**
            - "Hard" steps might not need additional controls
            - Example: "Gain cluster access" (Hard) already has k8s RBAC
            
            **Low difficulty = Needs immediate attention:**
            - "Easy" steps need STRONG controls
            - Example: "Find hardcoded API keys" (Easy) → Use Secrets Manager
            
            **Risk = Likelihood × Impact:**
            - Easy steps = High likelihood
            - If easy steps lead to critical goal = HIGH RISK
            - Prioritize mitigations for easy steps in high-impact paths
            """)
    
    st.markdown("---")
    
    # BEST PRACTICES
    st.subheader("✅ Attack Tree Best Practices")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Do's ✓
        
        - **Start with specific goal** (not "hack system", but "steal payment data")
        - **Use OR gates for alternatives** (different paths to same goal)
        - **Use AND gates for required steps** (must do ALL to succeed)
        - **Assign difficulty/cost** to leaf nodes
        - **Think like attacker** (easiest path, not most sophisticated)
        - **Include non-technical attacks** (social engineering, phishing)
        - **Update regularly** as system evolves
        """)
    
    with col2:
        st.markdown("""
        ### Don'ts ✗
        
        - **Don't make too shallow** (need enough detail to identify controls)
        - **Don't make too deep** (diminishing returns after 3-4 levels)
        - **Don't forget easiest paths** (attackers are lazy, choose easy route)
        - **Don't assume difficulty** (validate with red team / pentests)
        - **Don't ignore OR gates** (even 10 hard paths + 1 easy = compromised)
        - **Don't forget insider threats** (trusted access = easy attacks)
        """)
    
    st.markdown("---")
    
    # VALIDATION CHECKLIST
    st.subheader("📋 Attack Tree Validation Checklist")
    
    st.markdown(f"""
    Before moving to threat identification, verify your understanding:
    
    **Understanding Attack Trees:**
    - [ ] I understand what OR gates mean (ANY path succeeds)
    - [ ] I understand what AND gates mean (ALL steps required)
    - [ ] I can identify the easiest attack path in the tree
    - [ ] I know why difficulty ratings matter
    
    **Architecture-Specific:**
    - [ ] I can see how attacks map to components in the DFD
    - [ ] I understand which attacks target which trust boundaries
    - [ ] I know the TOP 2-3 highest priority defenses for this architecture
    
    **Next Steps:**
    - [ ] I'm ready to identify threats systematically using STRIDE
    - [ ] I understand how attack trees complement STRIDE analysis
    - [ ] I know that STRIDE identifies WHAT threats exist, attack trees show HOW they're executed
    """)
    
    st.markdown("""
    <div class="success-box">
    <strong>💡 How Attack Trees and STRIDE Work Together:</strong><br>
    • <strong>STRIDE</strong> = Categorizes WHAT threats exist (Spoofing, Tampering, etc.)<br>
    • <strong>Attack Trees</strong> = Shows HOW attackers achieve their goals (step-by-step paths)<br>
    • Use BOTH for complete threat model: STRIDE for coverage, Attack Trees for attacker perspective
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to STRIDE Learning", use_container_width=True):
            st.session_state.current_step = 2.5
            save_progress()
            st.rerun()
    with col2:
        if st.button("Ready: Identify Threats ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 4
            save_progress()
            st.rerun()

# STEP 4: IDENTIFY THREATS WITH VALIDATION AND SCORING (was Step 3)
elif st.session_state.current_step == 4:
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
                
                # Show learning content directly (no nested expander)
                predefined = answer.get("predefined_threat")
                if predefined:
                    st.markdown("---")
                    st.markdown("### 📚 Learn Why")
                    st.markdown(f"**Explanation:**\n\n{predefined.get('explanation', 'N/A')}")
                    st.markdown(f"**Why This Risk Level:**\n\n{predefined.get('why_this_risk', 'N/A')}")
                    st.markdown(f"**Why These Controls Work:**\n\n{predefined.get('why_these_controls', 'N/A')}")
                    st.markdown(f"**Real-World Example:**\n\n{predefined.get('real_world', 'N/A')}")
                    st.markdown(f"**Compliance:** {predefined.get('compliance', 'N/A')}")
    
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
        if st.button("⬅️ Back to Attack Tree", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Assessment ➡️", type="primary", use_container_width=True):
            if st.session_state.user_answers:
                st.session_state.current_step = 5
                save_progress()
                st.rerun()
            else:
                st.error("Complete at least one threat analysis")

# STEP 5: ASSESS WITH THREAT-MAPPED DIAGRAM AND EXPLANATIONS (was Step 4)
elif st.session_state.current_step == 5:
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
            st.session_state.current_step = 4
            save_progress()
            st.rerun()
    with col2:
        if st.button("Complete Workshop ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 6
            save_progress()
            st.rerun()

# STEP 6: COMPLETE (was Step 5)
elif st.session_state.current_step == 6:
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
            st.session_state.current_step = 5
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
