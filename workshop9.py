"""
STRIDE Threat Modeling - COMPLETE FINAL VERSION
AWS Threat Composer Methodology | All 4 Workshop Types | Enhanced Assessment
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
    .info-box{background-color:#E3F2FD;padding:16px;border-radius:4px;border-left:4px solid #1976D2;margin:12px 0}
    .threat-card{background-color:#FFFFFF;padding:16px;border-radius:6px;border:2px solid #E0E0E0;margin:12px 0;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
    .mitigation-card{background-color:#E8F5E9;padding:12px;border-radius:4px;border-left:4px solid #4CAF50;margin:8px 0}
    .stride-badge{display:inline-block;padding:4px 8px;border-radius:4px;font-size:0.8em;font-weight:600;margin:2px;color:white}
    .stride-s{background-color:#E53935}
    .stride-t{background-color:#FB8C00}
    .stride-r{background-color:#FDD835;color:#333}
    .stride-i{background-color:#43A047}
    .stride-d{background-color:#1E88E5}
    .stride-e{background-color:#8E24AA}
    .summary-box{background-color:#F5F5F5;padding:20px;border-radius:8px;border-left:6px solid #028090;margin:16px 0}
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

# COMPLETE THREAT DATABASE BY ARCHITECTURE TYPE
PREDEFINED_THREATS = {
    "1": [  # Web Application (2-Tier)
        {"id": "T-001", "stride": ["Tampering", "Spoofing"], "component": "Web Frontend → API Backend",
         "threat": "XSS (Cross-Site Scripting)", "likelihood": "High", "impact": "High",
         "attack_vector": "Attacker injects malicious JavaScript through user input fields (search, comments, profile). When other users view the page, the script executes in their browser, stealing session cookies or redirecting to phishing sites.",
         "correct_mitigations": ["CSP headers", "DOMPurify sanitization", "Output encoding", "Input validation"],
         "mitigation_details": {
             "CSP headers": "Content-Security-Policy headers define trusted sources for scripts. Example: 'default-src self; script-src cdn.trusted.com' prevents inline scripts and unauthorized external scripts.",
             "DOMPurify sanitization": "DOMPurify library sanitizes HTML/JavaScript before rendering. Converts <script> to safe HTML entities, removing execution capability.",
             "Output encoding": "Context-aware encoding (HTML entity encoding, JavaScript encoding, URL encoding) based on where data is rendered. Converts < to &lt; preventing script execution.",
             "Input validation": "Server-side allowlist validation rejects unexpected characters. Example: names only allow [a-zA-Z ], rejecting <script> attempts."
         },
         "compliance": "OWASP Top 10 A03:2021", "points": 10,
         "real_world": "British Airways breach (2018): XSS injected card skimmer, 380K cards stolen, £20M GDPR fine."},
        
        {"id": "T-002", "stride": ["Tampering"], "component": "API Backend → Database",
         "threat": "SQL Injection", "likelihood": "Medium", "impact": "Critical",
         "attack_vector": "Attacker manipulates SQL queries by injecting malicious SQL through input fields. Example: username field with ' OR '1'='1 bypasses authentication. Can read entire database, modify data, or execute admin commands.",
         "correct_mitigations": ["Parameterized queries", "Input validation", "Least privilege DB user", "WAF rules"],
         "mitigation_details": {
             "Parameterized queries": "Prepared statements separate SQL structure from data. Query: SELECT * FROM users WHERE id=? treats input as data ONLY, never as executable SQL code.",
             "Input validation": "Allowlist validation on server-side. Example: numeric IDs only accept [0-9], rejecting SQL syntax characters like quotes and semicolons.",
             "Least privilege DB user": "Application uses DB account with minimal permissions. Read-only where possible. Can't DROP tables or access system tables even if SQL injection succeeds.",
             "WAF rules": "AWS WAF with OWASP Core Rule Set detects SQL injection patterns (UNION, SELECT, OR 1=1) and blocks requests before they reach application."
         },
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1", "points": 10,
         "real_world": "Target breach (2013): SQL injection led to 40M credit cards stolen, $18M settlement."},
        
        {"id": "T-003", "stride": ["Spoofing"], "component": "Customer → Web Frontend",
         "threat": "Broken Authentication", "likelihood": "High", "impact": "High",
         "attack_vector": "Weak password policy allows brute force. No account lockout means attacker tries millions of passwords. Session tokens not rotated after login, allowing session fixation. Credentials sent over HTTP instead of HTTPS.",
         "correct_mitigations": ["MFA", "Session management", "HttpOnly cookies", "Strong password policy"],
         "mitigation_details": {
             "MFA": "Multi-Factor Authentication requires second factor (TOTP app, SMS, hardware token). Even if password stolen, attacker needs physical device. Blocks 99.9% of credential stuffing attacks.",
             "Session management": "Regenerate session ID after login/privilege change. Set session timeout (30 min). Invalidate on logout. Prevents session fixation and hijacking.",
             "HttpOnly cookies": "HttpOnly flag prevents JavaScript access to session cookies. Secure flag ensures cookies only sent over HTTPS. SameSite prevents CSRF.",
             "Strong password policy": "Minimum 12 characters, complexity requirements, check against breach databases (HaveIBeenPwned API). Account lockout after 5 failed attempts for 15 minutes."
         },
         "compliance": "OWASP Top 10 A07:2021, NIST 800-63B", "points": 10,
         "real_world": "Credential stuffing uses 15B+ leaked passwords. MFA adoption prevented 99.9% of automated attacks (Microsoft 2020)."},
        
        {"id": "T-004", "stride": ["Elevation of Privilege"], "component": "API Backend",
         "threat": "Broken Access Control", "likelihood": "High", "impact": "Critical",
         "attack_vector": "API endpoints don't verify authorization. Attacker changes URL parameter /user/123/orders to /user/456/orders and views other users' data. Or modifies POST body to set isAdmin=true gaining elevated privileges.",
         "correct_mitigations": ["RBAC", "Authorization checks on every request", "Deny by default", "Resource ownership validation"],
         "mitigation_details": {
             "RBAC": "Role-Based Access Control assigns users to roles (customer, staff, admin). Each role has specific permissions. Middleware checks user role on EVERY request.",
             "Authorization checks on every request": "Never assume - verify permissions on every API call. Check: Does this user have permission for this action on this resource? Not just 'are they logged in?'",
             "Deny by default": "Start with no access. Explicitly grant each permission. Better to accidentally block legitimate access than allow unauthorized access.",
             "Resource ownership validation": "For /user/123/orders, verify current user ID == 123 OR user has admin role. Prevent horizontal privilege escalation."
         },
         "compliance": "OWASP Top 10 A01:2021, PCI-DSS 7.1", "points": 10,
         "real_world": "Instagram bug (2020): Any user could call admin endpoints. Uber breach: Admin panel lacked authorization, 57M users exposed."},
        
        {"id": "T-005", "stride": ["Elevation of Privilege", "Information Disclosure"], "component": "API Backend",
         "threat": "Security Misconfiguration", "likelihood": "High", "impact": "High",
         "attack_vector": "Debug mode enabled in production exposes stack traces with database credentials. Default admin passwords unchanged. S3 buckets publicly readable. Unnecessary services running. Outdated libraries with known CVEs.",
         "correct_mitigations": ["TLS 1.3", "Encryption at rest", "Secure defaults", "Regular patching"],
         "mitigation_details": {
             "TLS 1.3": "Latest TLS version for data in transit. Disables weak cipher suites. Forward secrecy protects past sessions if keys compromised. HSTS header forces HTTPS.",
             "Encryption at rest": "AES-256 for databases, S3, EBS volumes. AWS KMS manages keys with automatic rotation. Even if storage media stolen, data unreadable without keys.",
             "Secure defaults": "Disable debug mode in production. Remove default credentials. Principle of least functionality - disable unused features. Security headers (X-Frame-Options, CSP).",
             "Regular patching": "Automated dependency scanning (Dependabot, Snyk). Monthly security patches. Vulnerability management process. Test patches in staging first."
         },
         "compliance": "OWASP Top 10 A05:2021, CIS Benchmarks", "points": 10,
         "real_world": "Equifax breach: Unpatched Apache Struts vulnerability exposed 147M people. MongoDB databases exposed due to no authentication configured."}
    ],
    
    "2": [  # Microservices / API-Based
        {"id": "T-101", "stride": ["Information Disclosure", "Elevation of Privilege"], "component": "API Gateway → Payment Service",
         "threat": "BOLA (Broken Object Level Authorization)", "likelihood": "High", "impact": "Critical",
         "attack_vector": "API returns data based only on object ID without verifying ownership. GET /api/transactions/12345 returns transaction details without checking if current user owns transaction. Attacker iterates IDs to access all users' data.",
         "correct_mitigations": ["Object-level authorization on every API call", "Resource ownership checks", "Indirect object references"],
         "mitigation_details": {
             "Object-level authorization on every API call": "For EVERY API request, verify: 1) User is authenticated, 2) User has permission for this action, 3) User owns this specific resource. Check happens AFTER authentication, BEFORE data access.",
             "Resource ownership checks": "Database query includes ownership: SELECT * FROM transactions WHERE id=? AND user_id=current_user. If no rows returned, user doesn't own resource - return 403 Forbidden.",
             "Indirect object references": "Instead of exposing database IDs (predictable sequence), use UUIDs or encrypted references. Makes enumeration harder but still requires ownership validation."
         },
         "compliance": "OWASP API Security Top 10 - API1:2023", "points": 10,
         "real_world": "Peloton API (2021): Any user could access any other user's data by changing user ID. T-Mobile (2021): BOLA exposed customer data."},
        
        {"id": "T-102", "stride": ["Spoofing"], "component": "User Service → Payment Service",
         "threat": "Service Impersonation", "likelihood": "Medium", "impact": "High",
         "attack_vector": "Attacker deploys rogue service in service mesh pretending to be legitimate service. Without mutual authentication, services accept requests from imposter. Fake Payment Service steals credit card data or approves fraudulent transactions.",
         "correct_mitigations": ["Mutual TLS (mTLS) for service mesh", "Service identity verification", "Certificate-based authentication"],
         "mitigation_details": {
             "Mutual TLS (mTLS) for service mesh": "Both client and server present certificates. Service mesh (Istio, Linkerd) automatically handles mTLS. Each service has unique identity certificate. Connections without valid cert rejected.",
             "Service identity verification": "SPIFFE IDs uniquely identify each service. Format: spiffe://cluster/namespace/service-name. Every request validates caller's SPIFFE ID matches expected service.",
             "Certificate-based authentication": "Short-lived certificates (24 hours) issued by internal CA. Automatic rotation. Private keys never leave container. Certificate revocation for compromised services."
         },
         "compliance": "NIST 800-204, Zero Trust Architecture", "points": 10,
         "real_world": "Service mesh breaches prevented by mTLS. Without it, lateral movement trivial once attacker enters network."},
        
        {"id": "T-103", "stride": ["Repudiation"], "component": "All Services",
         "threat": "Insufficient Logging", "likelihood": "High", "impact": "Medium",
         "attack_vector": "Microservices don't log service-to-service calls. When breach discovered, can't trace attacker's path through system. No correlation IDs across services. Logs don't include user context. Forensics impossible.",
         "correct_mitigations": ["Distributed tracing", "Centralized logging", "Correlation IDs", "Structured logging"],
         "mitigation_details": {
             "Distributed tracing": "OpenTelemetry instruments all service calls. Creates trace showing request path across services. Example: API Gateway → User Service → Database. Each span has timing and status.",
             "Centralized logging": "All services send logs to SIEM (Splunk, ELK, CloudWatch). Aggregates logs from 100+ containers. Searchable, retained 1+ years. Immutable storage prevents tampering.",
             "Correlation IDs": "X-Correlation-ID header propagates through all services. One request = one ID. Allows finding all logs related to specific request across entire system.",
             "Structured logging": "JSON format with standard fields: timestamp, service, user_id, action, resource, result, correlation_id. Machine-parseable for automated analysis."
         },
         "compliance": "PCI-DSS 10, SOC 2 CC7.2", "points": 10,
         "real_world": "Average breach detection: 207 days without centralized logging. With proper logging: detected in hours."},
        
        {"id": "T-104", "stride": ["Denial of Service"], "component": "API Gateway",
         "threat": "Rate Limiting Bypass", "likelihood": "High", "impact": "High",
         "attack_vector": "Attacker uses distributed botnet with different IPs to bypass per-IP rate limits. Or discovers internal service endpoint that bypasses API gateway entirely. Floods system causing resource exhaustion and service outage.",
         "correct_mitigations": ["Global + Per-service rate limits", "Distributed rate limiting", "Circuit breaker pattern"],
         "mitigation_details": {
             "Global + Per-service rate limits": "API Gateway: 10K req/sec global, 100 req/min per IP, 1K req/min per API key. Individual services also enforce limits. Defense in depth - multiple layers.",
             "Distributed rate limiting": "Redis-backed rate limiting shared across all API Gateway instances. Prevents attacker from bypassing by hitting different gateway nodes. Atomic counters ensure accuracy.",
             "Circuit breaker pattern": "When downstream service degraded (response time >1s or error rate >10%), circuit opens. Fail fast instead of retrying. Prevents cascade failures. Auto-recovery after cooldown."
         },
         "compliance": "OWASP API Top 10 API4:2023", "points": 10,
         "real_world": "GitHub API: 5000 req/hour per user. CloudFlare: Global rate limiting prevented Tbps DDoS attacks."},
        
        {"id": "T-105", "stride": ["Information Disclosure", "Tampering"], "component": "User Service → Payment Service",
         "threat": "Insecure Service-to-Service Communication", "likelihood": "Medium", "impact": "Critical",
         "attack_vector": "Services communicate over plain HTTP within cluster. Network sniffer captures credit card data in transit between services. Or attacker performs ARP spoofing to intercept/modify inter-service traffic.",
         "correct_mitigations": ["JWT validation", "Short token expiration", "Service mesh encryption", "TLS for all internal traffic"],
         "mitigation_details": {
             "JWT validation": "Every service validates JWT signature, expiration, issuer, audience. Checks required claims (user_id, roles, permissions). Rejects tokens missing claims or with invalid signature.",
             "Short token expiration": "Access tokens expire in 15 minutes. Refresh tokens in 24 hours. Reduces window if token stolen. Automatic refresh flow keeps users logged in.",
             "Service mesh encryption": "Istio/Linkerd automatically encrypts all pod-to-pod traffic with mTLS. No code changes needed. Network-level encryption layer.",
             "TLS for all internal traffic": "Even 'internal' traffic uses TLS 1.3. Prevents network sniffing, MITM attacks. Defense against insider threats and compromised nodes."
         },
         "compliance": "PCI-DSS 4.1, HIPAA 164.312(e)", "points": 10,
         "real_world": "Enterprises with mTLS prevented 100% of network-based lateral movement in red team exercises."}
    ],
    
    "3": [  # Multi-Tenant SaaS
        {"id": "T-201", "stride": ["Information Disclosure"], "component": "Query Service → Data Warehouse",
         "threat": "Cross-Tenant Data Access", "likelihood": "High", "impact": "Critical",
         "attack_vector": "SQL query doesn't include tenant filter. Attacker from Tenant A crafts API request that returns Tenant B's data. Database doesn't enforce tenant isolation. One query returns data from ALL tenants.",
         "correct_mitigations": ["Row-Level Security (RLS) in databases", "Tenant context validation", "Multi-tenant aware queries"],
         "mitigation_details": {
             "Row-Level Security (RLS) in databases": "PostgreSQL RLS policies enforce tenant_id filter on ALL queries automatically. Policy: CREATE POLICY tenant_isolation ON orders USING (tenant_id = current_setting('app.tenant_id')). Database-level enforcement - can't be bypassed by application bug.",
             "Tenant context validation": "Middleware extracts tenant_id from JWT, validates it exists, sets database session variable. Every query implicitly filtered by tenant. If tenant_id missing from request, reject with 403.",
             "Multi-tenant aware queries": "All SQL includes: WHERE tenant_id = :tenant_id. Use prepared statements. Code review checklist ensures every query has tenant filter. Integration tests verify isolation."
         },
         "compliance": "SOC 2 CC6.1, ISO 27001 A.9.4.1", "points": 10,
         "real_world": "GitHub Gist (2020): Cross-tenant data leak. SaaS platforms average 1-2 tenant isolation bugs per year."},
        
        {"id": "T-202", "stride": ["Information Disclosure", "Elevation of Privilege"], "component": "API Gateway → All Services",
         "threat": "Tenant Isolation Bypass", "likelihood": "Medium", "impact": "Critical",
         "attack_vector": "Attacker discovers admin endpoint /internal/all-tenants that bypasses tenant context. Or exploits race condition in tenant context switching. Gains access to administrative functions affecting all tenants.",
         "correct_mitigations": ["Tenant context in ALL requests", "Middleware validation", "Admin namespace isolation"],
         "mitigation_details": {
             "Tenant context in ALL requests": "Every API request includes X-Tenant-ID header. Backend extracts and validates before processing. No tenant context = automatic 403 rejection. Enforced by API gateway.",
             "Middleware validation": "Express/Koa middleware runs before route handlers. Validates: 1) Tenant exists, 2) User belongs to tenant, 3) Tenant is active. Sets res.locals.tenantId for route access.",
             "Admin namespace isolation": "Admin APIs on separate domain: admin.saas.com vs app.saas.com. Separate authentication. Admin JWT cannot access tenant APIs. Physical separation prevents accidental exposure."
         },
         "compliance": "SOC 2 CC6.1", "points": 10,
         "real_world": "Salesforce: Strict namespace isolation. Multi-tenant architecture review catches 90% of isolation bugs before production."},
        
        {"id": "T-203", "stride": ["Denial of Service"], "component": "Query Service → Data Warehouse",
         "threat": "Noisy Neighbor Resource Exhaustion", "likelihood": "High", "impact": "High",
         "attack_vector": "Tenant A runs expensive analytics query consuming all database CPU. Tenant B's queries time out. Shared resource pool allows one tenant to degrade service for all tenants. Revenue loss for affected customers.",
         "correct_mitigations": ["Per-tenant resource quotas", "Query limits", "Query timeout", "Priority queues"],
         "mitigation_details": {
             "Per-tenant resource quotas": "AWS Service Quotas or custom quota service. Tenant A: max 1000 req/min, 10 concurrent queries, 100GB data scanned/day. Quotas enforced at API gateway and database level.",
             "Query limits": "Max query execution time: 30 seconds. Max rows returned: 10,000. Max JOIN depth: 3 tables. Complexity analysis before execution. Reject queries exceeding limits.",
             "Query timeout": "Statement timeout in PostgreSQL: SET statement_timeout = '30s'. Automatically kills long-running queries. Prevents one tenant monopolizing connections.",
             "Priority queues": "Enterprise tier tenants get dedicated connection pool. Free tier uses shared pool with lower limits. Ensures paying customers not impacted by free tier abuse."
         },
         "compliance": "SLA commitments", "points": 10,
         "real_world": "AWS RDS: Per-instance IOPS limits. Heroku: Per-app dyno limits. Prevents noisy neighbor problems."},
        
        {"id": "T-204", "stride": ["Information Disclosure"], "component": "Encryption Service",
         "threat": "Shared Secret Keys", "likelihood": "Medium", "impact": "Critical",
         "attack_vector": "All tenants' data encrypted with same master key. If key leaked, ALL tenant data decryptable. Insider with access to key can decrypt any tenant's data. Regulatory violation as tenants can't have separate keys.",
         "correct_mitigations": ["Per-tenant encryption keys", "Separate backups", "AWS KMS tenant isolation"],
         "mitigation_details": {
             "Per-tenant encryption keys": "Each tenant has unique data encryption key (DEK). DEKs encrypted with tenant-specific key encryption key (KEK) in AWS KMS. Tenant A's key can't decrypt Tenant B's data.",
             "Separate backups": "Backup files stored in tenant-specific S3 prefixes: s3://backups/tenant-A/, s3://backups/tenant-B/. Separate encryption, separate retention policies, separate restore process.",
             "AWS KMS tenant isolation": "KMS key per tenant with restrictive IAM policy. Only application with tenant context can decrypt. CloudTrail logs all key usage. Automatic key rotation."
         },
         "compliance": "GDPR Article 32, SOC 2 CC6.1", "points": 10,
         "real_world": "GDPR requires data isolation. Multi-tenant SaaS with single key failed audit. Per-tenant keys now standard for enterprise SaaS."},
        
        {"id": "T-205", "stride": ["Elevation of Privilege"], "component": "API Gateway",
         "threat": "Insufficient Tenant Context Validation", "likelihood": "High", "impact": "High",
         "attack_vector": "API accepts tenant_id from request body without validation. Attacker modifies POST body: {tenant_id: 'victim-tenant', data: {...}} to write data to victim's tenant. Creates data integrity and isolation issues.",
         "correct_mitigations": ["Tenant-tagged logs", "Isolation testing", "Tenant context from JWT only"],
         "mitigation_details": {
             "Tenant-tagged logs": "All logs include tenant_id field. Enables per-tenant log analysis. Alert on anomalies: Tenant A suddenly accessing Tenant B's resources. SIEM rules detect cross-tenant access attempts.",
             "Isolation testing": "Automated tests with two test tenants. Test 1: Tenant A tries to read Tenant B data (should fail). Test 2: Create data as Tenant A, verify Tenant B can't see it. Run on every deploy.",
             "Tenant context from JWT only": "NEVER trust tenant_id from request body/query params. Extract from JWT claims only. JWT signed by auth service, can't be forged. Middleware enforces this."
         },
         "compliance": "SOC 2 CC7.2", "points": 10,
         "real_world": "Isolation testing caught 40% of tenant isolation bugs in major SaaS platforms before production deployment."}
    ],
    
    "4": [  # IoT / Healthcare Systems
        {"id": "T-301", "stride": ["Tampering"], "component": "Glucose Monitor → IoT Gateway",
         "threat": "Device Tampering (Physical/Firmware)", "likelihood": "Medium", "impact": "Critical",
         "attack_vector": "Attacker gains physical access to glucose monitor in patient's home. Reflashes firmware to report false readings (always shows 'normal'). Patient doesn't get alerts for dangerously high glucose. Or attacker installs malicious firmware update to compromise device network.",
         "correct_mitigations": ["Secure boot", "Firmware signing", "TPM", "Physical tamper detection"],
         "mitigation_details": {
             "Secure boot": "Device verifies firmware signature before boot. Uses hardware root of trust (burned into chip). Only signed firmware will execute. Prevents malicious firmware installation.",
             "Firmware signing": "Manufacturer signs firmware with private key. Device verifies signature with public key (burned into device). Rolling back to old vulnerable firmware also prevented by monotonic counter.",
             "TPM": "Trusted Platform Module stores cryptographic keys in tamper-resistant hardware. Measures firmware integrity. Attests device health to cloud before establishing connection.",
             "Physical tamper detection": "Tamper-evident seals. Internal sensors detect case opening. Battery disconnect detection. Device reports tampering to cloud. Enters safe mode until service technician verifies."
         },
         "compliance": "FDA 21 CFR Part 11, IEC 62304", "points": 10,
         "real_world": "Medtronic insulin pump recall: Unencrypted RF allowed unauthorized dosing. St. Jude pacemaker: Firmware could be modified remotely."},
        
        {"id": "T-302", "stride": ["Tampering"], "component": "IoT Gateway → Device Data Svc",
         "threat": "Replay Attacks on Sensor Data", "likelihood": "High", "impact": "Critical",
         "attack_vector": "Attacker captures MQTT messages containing vital signs. Replays old 'normal' readings while patient's actual vitals are critical. Alert system doesn't trigger because it sees replayed normal values. Patient doesn't receive life-saving intervention.",
         "correct_mitigations": ["Timestamps", "Nonce", "Message freshness checks", "Sequence numbers"],
         "mitigation_details": {
             "Timestamps": "Every sensor message includes UTC timestamp. Server rejects messages older than 5 minutes. Clock synchronization via NTP. Prevents replay of old captured messages.",
             "Nonce": "Number used once. Each message includes unique nonce. Server tracks recent nonces (last 1000). Duplicate nonce = replay attack detected. Message rejected.",
             "Message freshness checks": "Combine timestamp + nonce + sequence number. All three must be valid. Server maintains sliding window of acceptable messages. Out-of-window = rejected.",
             "Sequence numbers": "Monotonically increasing counter per device. Server expects next sequence = last sequence + 1. Gap or duplicate sequence triggers alert and connection termination."
         },
         "compliance": "HIPAA 164.312(e)(2)(i), FDA Cybersecurity Guidance", "points": 10,
         "real_world": "Medical device replay attacks demonstrated in research. ICS/SCADA systems compromised by replay. Sequence numbers standard in safety-critical systems."},
        
        {"id": "T-303", "stride": ["Information Disclosure"], "component": "Patient DB",
         "threat": "Unencrypted PHI/PII", "likelihood": "Medium", "impact": "Critical",
         "attack_vector": "Database backups stored unencrypted in S3. Misconfiguration makes bucket public. Or attacker compromises AWS credentials and downloads backup. PHI of 10K patients exposed. HIPAA breach notification required. Massive fines.",
         "correct_mitigations": ["Encryption at rest (HIPAA)", "TLS 1.3 in transit", "KMS key management", "Encrypted backups"],
         "mitigation_details": {
             "Encryption at rest (HIPAA)": "AES-256 encryption for RDS, S3, EBS. HIPAA requirement - not optional. Data encrypted before writing to disk. Encryption keys separate from data.",
             "TLS 1.3 in transit": "All client connections use TLS 1.3. No fallback to older versions. Certificate pinning in mobile apps. IoT devices use mutual TLS with device certificates.",
             "KMS key management": "AWS KMS manages encryption keys. Automatic key rotation every 365 days. Audit trail of all key usage via CloudTrail. Key access policies enforce least privilege.",
             "Encrypted backups": "RDS automated backups encrypted with KMS. Manual exports to S3 also encrypted. Backup encryption enforced by AWS Config rule. Non-compliant resources auto-remediated."
         },
         "compliance": "HIPAA 164.312(a)(2)(iv), HITECH", "points": 10,
         "real_world": "Healthcare breaches: Anthem (78M records), Premera (11M records) - both unencrypted data. Average HIPAA breach fine: $3M+."},
        
        {"id": "T-304", "stride": ["Denial of Service"], "component": "Alert Service → Web Portal",
         "threat": "Alert Suppression (Safety-Critical)", "likelihood": "Medium", "impact": "Critical",
         "attack_vector": "Attacker floods alert system with fake low-priority alerts. Queue fills up. Critical patient alert (cardiac arrest) stuck in queue behind 10K fake alerts. Clinician doesn't see critical alert for 20 minutes. Patient suffers preventable harm.",
         "correct_mitigations": ["Redundant alert channels", "Priority queues", "Watchdog timers", "Alert rate limiting"],
         "mitigation_details": {
             "Redundant alert channels": "Critical alerts sent via: 1) WebSocket to portal, 2) SMS to on-call, 3) Phone call (after 2 min), 4) Email. Multi-channel ensures delivery. Each channel independent - failure of one doesn't block others.",
             "Priority queues": "Separate queues: P0 (critical - cardiac arrest, stroke), P1 (urgent), P2 (warning), P3 (info). P0 queue processed first. P0 alerts bypass rate limiting. Dedicated processing capacity.",
             "Watchdog timers": "Every critical alert has 2-minute watchdog. If not acknowledged, escalates. Calls emergency contact. If device loses connectivity >5 min, generate alert for 'device offline'.",
             "Alert rate limiting": "Per-patient limits: Max 10 alerts/minute for P2/P3. No limit on P0. Prevents alert fatigue. Aggregates repeated alerts: '15 high glucose readings' instead of 15 separate alerts."
         },
         "compliance": "FDA 510(k) safety requirements, IEC 60601-1-8", "points": 10,
         "real_world": "Alert fatigue causes 50-90% of alerts ignored. Proper prioritization saves lives. Research shows 1000+ alerts per patient-day, 85-99% false positives."},
        
        {"id": "T-305", "stride": ["Tampering"], "component": "HL7 Interface → Legacy EHR",
         "threat": "Legacy System Injection Attacks", "likelihood": "High", "impact": "High",
         "attack_vector": "Legacy EHR uses HL7 v2 over MLLP (no encryption, no authentication). Attacker on hospital network injects malicious HL7 messages. Modifies patient prescriptions. Increases medication dosage to lethal levels. Or exfiltrates patient data from EHR.",
         "correct_mitigations": ["HL7 message validation", "Network isolation", "VPN", "Message signing"],
         "mitigation_details": {
             "HL7 message validation": "Validate every HL7 segment against specification. Check required fields present. Validate data types (dates, codes). Reject malformed messages. Schema validation prevents injection.",
             "Network isolation": "Legacy EHR on separate VLAN. Firewall rules: Only HL7 Interface can connect to EHR on port 2575. All other traffic blocked. Limits blast radius if cloud platform compromised.",
             "VPN": "Site-to-site VPN between cloud and hospital. IPSec tunnel encrypts all traffic. Even though HL7 v2 doesn't support encryption, VPN provides transport encryption. Prevents eavesdropping.",
             "Message signing": "Custom HL7 extension with HMAC signature in ZPD segment. Both systems share secret key. Signature validates message authenticity and integrity. Detects tampering."
         },
         "compliance": "HIPAA, HL7 v2.x specification", "points": 10,
         "real_world": "Hospital ransomware often exploits legacy systems. HL7 interfaces frequently lack authentication. Network segmentation critical defense."}
    ]
}

# ALL 4 WORKSHOPS COMPLETE
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: Web Application (2-Tier)",
        "architecture_type": "2-Tier Web Application",
        "level": "Foundation", "duration": "2 hours", "target_threats": 5,
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
        "level": "Intermediate", "duration": "2 hours", "target_threats": 5,
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
        "level": "Advanced", "duration": "2 hours", "target_threats": 5,
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
        "level": "Expert", "duration": "2 hours", "target_threats": 5,
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
    """Generate detailed DFD with threat mapping"""
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
            stride_cats = threat.get("stride", threat.get("stride_category", ""))
            
            # Handle multiple STRIDE categories
            if isinstance(stride_cats, list):
                stride_initials = "".join([s[0] for s in stride_cats])
            else:
                stride_initials = stride_cats[0] if stride_cats else "?"
            
            threat_info = f"{threat_id}({stride_initials})"
            
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
                style["fillcolor"] = "#FFE082"
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
    
    # Handle multiple STRIDE categories
    expected_stride = predefined_threat["stride"]
    user_stride = user_threat["stride"]
    
    if isinstance(expected_stride, list):
        if user_stride in expected_stride:
            score += 2
            feedback.append(f"✓ Correct STRIDE (valid category from {', '.join(expected_stride)})")
        else:
            feedback.append(f"✗ Expected one of: {', '.join(expected_stride)}")
    else:
        if user_stride == expected_stride:
            score += 2
            feedback.append("✓ Correct STRIDE")
        else:
            feedback.append(f"✗ Expected STRIDE: {expected_stride}")
    
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
        
        st.caption(f"{ws['architecture_type']}")
        st.caption(f"{ws['level']} | {ws['target_threats']} threats")
        st.markdown("---")
    
    st.markdown("### 📚 Resources")
    st.markdown("[AWS Threat Composer](https://awslabs.github.io/threat-composer/)")

# MAIN
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling")
    st.markdown("Select a workshop from the sidebar to begin.")
    st.info("**Note:** Workshop unlock codes will be provided by your instructor.")
    
    st.markdown("""
    ### Architecture Types Covered
    
    1. **Web Application (2-Tier)** - Frontend + Backend API + Database
    2. **Microservices / API-Based** - API Gateway + Multiple Services + Message Queues
    3. **Multi-Tenant SaaS** - Shared infrastructure with logical tenant isolation
    4. **IoT / Healthcare Systems** - IoT Devices + Edge Gateway + Cloud + Legacy Integration
    
    Each workshop teaches architecture-specific threats and mitigations following AWS Threat Composer methodology.
    """)
    st.stop()

current = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

st.title(current["name"])
st.caption(f"{current['architecture_type']} | {current['scenario']['title']}")

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
        st.markdown(f"**Architecture:** {current['architecture_type']}")
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
    st.info(f"Goal: {current['target_threats']} threats for {current['architecture_type']}")
    
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
            
            # Handle multiple STRIDE categories
            stride_options = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"]
            user_stride = st.selectbox("STRIDE:", stride_options)
            
            user_likelihood = st.select_slider("Likelihood:", ["Low", "Medium", "High", "Critical"])
            user_impact = st.select_slider("Impact:", ["Low", "Medium", "High", "Critical"])
        
        with col2:
            all_mits = selected_predefined["correct_mitigations"]
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
    
    # Display answers
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

# STEP 4 - ENHANCED ASSESSMENT FOLLOWING AWS THREAT COMPOSER
elif st.session_state.current_step == 4:
    st.header("Step 4: Threat Model Assessment")
    
    if not st.session_state.user_answers:
        st.warning("No answers")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
        st.stop()
    
    # SUMMARY
    st.markdown(f"""
    <div class="summary-box">
    <h3>📋 Threat Model Summary</h3>
    <strong>Architecture:</strong> {current['architecture_type']}<br>
    <strong>System:</strong> {current['scenario']['title']}<br>
    <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}<br>
    <strong>Threats Identified:</strong> {len(st.session_state.user_answers)}/{current['target_threats']}<br>
    <strong>Your Score:</strong> {st.session_state.total_score}/{st.session_state.max_score} ({(st.session_state.total_score/st.session_state.max_score*100):.1f}%)
    </div>
    """, unsafe_allow_html=True)
    
    # THREAT-MAPPED DIAGRAM
    st.subheader("🗺️ Architecture with Threat Mapping")
    st.markdown("""
    <div class="info-box">
    <strong>Reading the Diagram:</strong><br>
    • <strong>Orange highlights</strong> = Components/flows with identified threats<br>
    • <strong>Threat labels</strong> show ID and STRIDE category (e.g., T-001(T,S) = Tampering & Spoofing)<br>
    • <strong>Purple dashed boxes</strong> = Trust boundaries (critical security zones)
    </div>
    """, unsafe_allow_html=True)
    
    with st.spinner("Generating threat-mapped diagram..."):
        threat_diagram = generate_detailed_dfd(current, st.session_state.threats)
    
    if threat_diagram:
        st.image(f"data:image/png;base64,{threat_diagram}",
                 caption=f"{current['architecture_type']} - Threats Highlighted",
                 use_column_width=True)
    
    # DETAILED THREAT CARDS
    st.subheader(f"🎯 Top {current['target_threats']} Threats for {current['architecture_type']}")
    
    for idx, answer in enumerate(st.session_state.user_answers):
        predefined = answer.get("predefined", {})
        
        # Handle multiple STRIDE categories
        stride_cats = predefined.get("stride", [])
        if isinstance(stride_cats, list):
            stride_display = " + ".join(stride_cats)
            stride_badges = "".join([f'<span class="stride-badge stride-{s[0].lower()}">{s[0]}</span>' for s in stride_cats])
        else:
            stride_display = stride_cats
            stride_badges = f'<span class="stride-badge stride-{stride_cats[0].lower()}">{stride_cats[0]}</span>'
        
        st.markdown(f"""
        <div class="threat-card">
        <h4>{predefined.get('id', 'Unknown')}: {predefined.get('threat', 'Unknown')}</h4>
        <p><strong>STRIDE Categories:</strong> {stride_badges}</p>
        <p><strong>Affected Component:</strong> {predefined.get('component', 'Unknown')}</p>
        <p><strong>Risk:</strong> {predefined.get('likelihood', 'Unknown')} likelihood × {predefined.get('impact', 'Unknown')} impact</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"**🎭 Attack Vector:**")
        st.markdown(f"> {predefined.get('attack_vector', 'No description available')}")
        
        st.markdown(f"**✅ Essential Mitigations:**")
        mitigation_details = predefined.get('mitigation_details', {})
        for mit in predefined.get('correct_mitigations', []):
            st.markdown(f"""
            <div class="mitigation-card">
            <strong>• {mit}</strong><br>
            <small>{mitigation_details.get(mit, 'No detailed explanation available')}</small>
            </div>
            """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**📜 Compliance:** {predefined.get('compliance', 'N/A')}")
        with col2:
            st.markdown(f"**🌍 Real-World:** {predefined.get('real_world', 'N/A')}")
        
        st.markdown("---")
    
    # STATISTICS
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percent", f"{final_score_pct:.1f}%")
    col3.metric("Grade", "A" if final_score_pct >= 90 else "B" if final_score_pct >= 80 else "C")
    
    # LEARNING OUTCOMES
    st.subheader("📚 Key Learnings")
    
    st.markdown(f"""
    <div class="info-box">
    <strong>What You've Learned:</strong><br>
    • How {current['architecture_type']} systems are vulnerable to specific threat patterns<br>
    • Why certain mitigations are essential for this architecture type<br>
    • How to map threats to architectural components<br>
    • Real-world examples of attacks and their prevention<br><br>
    <strong>AWS Threat Composer Methodology:</strong><br>
    This assessment follows AWS best practices for threat modeling. Learn more at:<br>
    <a href="https://awslabs.github.io/threat-composer/" target="_blank">AWS Threat Composer</a>
    </div>
    """, unsafe_allow_html=True)
    
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
        st.success(f"Excellent! {final_score_pct:.1f}% - You've mastered {current['architecture_type']} threat modeling!")
    else:
        st.info(f"Completed! {final_score_pct:.1f}%")
    
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()
    
    next_ws = str(int(st.session_state.selected_workshop) + 1)
    
    if next_ws in WORKSHOPS:
        st.info(f"Ready for Workshop {next_ws}: {WORKSHOPS[next_ws]['architecture_type']}?\n\nAsk your instructor for the unlock code.")
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

st.caption("STRIDE Threat Modeling | AWS Threat Composer Methodology")
