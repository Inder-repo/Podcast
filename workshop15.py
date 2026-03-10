"""
STRIDE Threat Modeling - COMPLETE PRODUCTION VERSION (ENHANCED)
All 4 Workshops | Hidden Unlock Codes | Full Decompose | Threat Mapping | Enhanced Assessment
Aligned with Infosec Institute 4-Step Methodology:
  1. Design the threat model (DFD with interactors/modules/connections)
  2. Apply Zones of Trust (criticality labels + numerical 0-9 scale)
  3. Discover threats with STRIDE (rules-based by element type & zone direction)
  4. Explore mitigations and controls (OWASP Top 10 + compliance mapping)
"""

import streamlit as st
import base64
import json
import os
import pandas as pd
from graphviz import Digraph
from datetime import datetime
import random
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 PageBreak, Table, TableStyle)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from io import BytesIO

st.set_page_config(
    page_title="STRIDE Threat Modeling Learning Lab",
    page_icon="🔒",
    layout="wide"
)

# ─────────────────────────────────────────────────────────────────────────────
# UNLOCK CODES  (never shown in UI)
# Workshop 2: MICRO2025   Workshop 3: TENANT2025   Workshop 4: HEALTH2025
# ─────────────────────────────────────────────────────────────────────────────
WORKSHOP_CODES = {"1": None, "2": "MICRO2025", "3": "TENANT2025", "4": "HEALTH2025"}

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""<style>
.stButton>button{width:100%;border-radius:4px;font-weight:500}
.threat-critical{background:#B71C1C;color:white;padding:12px;border-radius:4px;border-left:5px solid #D32F2F;margin:8px 0}
.threat-high{background:#FFE5E5;padding:12px;border-radius:4px;border-left:5px solid #F96167;margin:8px 0}
.threat-medium{background:#FFF9E5;padding:12px;border-radius:4px;border-left:5px solid #FFC107;margin:8px 0}
.threat-low{background:#E8F5E9;padding:12px;border-radius:4px;border-left:5px solid #2C5F2D;margin:8px 0}
.correct-answer{background:#C8E6C9;padding:12px;border-radius:4px;border-left:5px solid #4CAF50;margin:8px 0}
.incorrect-answer{background:#FFCDD2;padding:12px;border-radius:4px;border-left:5px solid #F44336;margin:8px 0}
.partial-answer{background:#FFF9C4;padding:12px;border-radius:4px;border-left:5px solid #FFC107;margin:8px 0}
.score-excellent{background:#4CAF50;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
.score-good{background:#8BC34A;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
.score-fair{background:#FFC107;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
.score-poor{background:#FF5722;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
.badge-completed{background:#2C5F2D;color:white;padding:4px 12px;border-radius:12px;font-size:.85em;font-weight:600}
.badge-locked{background:#757575;color:white;padding:4px 12px;border-radius:12px;font-size:.85em;font-weight:600}
.info-box{background:#E3F2FD;padding:16px;border-radius:4px;border-left:4px solid #1976D2;margin:12px 0}
.success-box{background:#E8F5E9;padding:16px;border-radius:4px;border-left:4px solid #388E3C;margin:12px 0}
.warning-box{background:#FFF3E0;padding:16px;border-radius:4px;border-left:4px solid #F57C00;margin:12px 0}
.learning-box{background:#E8EAF6;padding:16px;border-radius:4px;border-left:4px solid #3F51B5;margin:12px 0}
.component-card{background:#F5F5F5;padding:12px;border-radius:4px;border-left:3px solid #028090;margin:8px 0}
.mitigation-card{background:#FFFDE7;padding:12px;border-radius:4px;border-left:4px solid #F9A825;margin:8px 0}
.zone-critical{background:#FFCDD2;padding:8px;border-radius:4px;border:2px solid #D32F2F;margin:4px 0}
.zone-high{background:#FFE0B2;padding:8px;border-radius:4px;border:2px solid #E65100;margin:4px 0}
.zone-medium{background:#FFF9C4;padding:8px;border-radius:4px;border:2px solid #F9A825;margin:4px 0}
.zone-low{background:#E8F5E9;padding:8px;border-radius:4px;border:2px solid #388E3C;margin:4px 0}
.zone-external{background:#F5F5F5;padding:8px;border-radius:4px;border:2px solid #757575;margin:4px 0}
.stride-rule-box{background:#E8EAF6;padding:14px;border-radius:6px;border-left:5px solid #3F51B5;margin:10px 0}
.owasp-box{background:#E0F2F1;padding:14px;border-radius:6px;border-left:5px solid #00695C;margin:10px 0}
.methodology-step{background:white;padding:16px;border-radius:8px;border:2px solid #028090;margin:12px 0;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.practical-task{background:#FFF8E1;padding:16px;border-radius:6px;border:2px dashed #F9A825;margin:12px 0}
.flow-arrow{background:#E3F2FD;padding:8px 16px;border-radius:20px;display:inline-block;margin:4px}
</style>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
def init_session_state():
    defaults = {
        'selected_workshop': None,
        'completed_workshops': set(),
        'unlocked_workshops': {'1'},
        'current_step': 1,
        'threats': [],
        'user_answers': [],
        'total_score': 0,
        'max_score': 0,
        'diagram_generated': None,
        'detailed_diagram_generated': None,
        'show_unlock_form': {},
        # NEW: Zone of Trust labelling state per workshop
        'zone_labels': {},          # {component: criticality_label}
        'zone_scores': {},          # {component: 0-9 score}
        'zone_labelling_done': False,
        # NEW: STRIDE rules exercise state
        'stride_rules_answers': {},
        'stride_rules_submitted': False,
        # NEW: OWASP mapping exercise state
        'owasp_mapping_answers': {},
        'owasp_mapping_submitted': False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


# ─────────────────────────────────────────────────────────────────────────────
# OWASP ↔ STRIDE MAPPING  (from Infosec walkthrough)
# ─────────────────────────────────────────────────────────────────────────────
OWASP_STRIDE_MAP = {
    "Spoofing": {
        "owasp": ["A07:2021 – Identification and Authentication Failures",
                  "A02:2021 – Cryptographic Failures"],
        "controls": [
            "Implement multi-factor authentication (MFA) to prevent credential stuffing and brute force",
            "Use server-side, secure session manager generating random session IDs with high entropy",
            "Invalidate sessions after logout, idle and absolute timeouts",
            "Enforce strong password policies aligned with NIST 800-63B"
        ],
        "owasp_detail": "Broken Authentication maps directly to Spoofing – an attacker impersonates a legitimate user by exploiting weak authentication.",
    },
    "Tampering": {
        "owasp": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"],
        "controls": [
            "Use parameterized queries / prepared statements (never concatenate user input into SQL)",
            "Use positive (allowlist) server-side input validation",
            "Implement digital signatures / HMAC on serialized objects to prevent hostile data modification",
            "Use ORM frameworks that abstract safe SQL generation"
        ],
        "owasp_detail": "Injection (SQL, command, LDAP) and Insecure Deserialization both enable attackers to modify data or behaviour – the hallmark of Tampering.",
    },
    "Repudiation": {
        "owasp": ["A09:2021 – Security Logging and Monitoring Failures"],
        "controls": [
            "Ensure logs are generated in a format consumable by centralized log management (SIEM)",
            "Ensure high-value transactions have an audit trail with integrity controls (append-only DB tables)",
            "Log authentication events, data modifications, and access control failures",
            "Use write-once / immutable log storage to prevent attacker log tampering"
        ],
        "owasp_detail": "Insufficient logging means an attacker can act without a trace – enabling repudiation of their actions. OWASP ranks this #9 because most breaches exploit the absence of monitoring.",
    },
    "Information Disclosure": {
        "owasp": ["A02:2021 – Cryptographic Failures",
                  "A05:2021 – Security Misconfiguration"],
        "controls": [
            "Encrypt all data in transit with TLS 1.3 + HSTS (HTTP Strict Transport Security)",
            "Store passwords using strong adaptive hashing (Argon2, bcrypt, PBKDF2)",
            "Disable verbose error messages in production (use generic user-facing messages)",
            "Apply least-privilege access to secrets; use a secrets manager (AWS Secrets Manager, Vault)"
        ],
        "owasp_detail": "Cryptographic Failures (formerly Sensitive Data Exposure) occurs when data is transmitted or stored without adequate encryption. Security Misconfiguration (verbose errors, open S3 buckets) leaks information to attackers.",
    },
    "Denial of Service": {
        "owasp": ["A05:2021 – Security Misconfiguration",
                  "A04:2021 – Insecure Design"],
        "controls": [
            "Implement segmented application architecture with effective separation between components",
            "Apply rate limiting per user/IP at the API gateway layer",
            "Use circuit breaker pattern to prevent cascade failures",
            "Enable auto-scaling and deploy WAF with rate-based rules (AWS WAF / Cloudflare)"
        ],
        "owasp_detail": "Security Misconfiguration (no rate limits, open network) and Insecure Design (unbounded queries, no timeouts) create conditions for DoS. The attacker exploits a lack of resource controls.",
    },
    "Elevation of Privilege": {
        "owasp": ["A01:2021 – Broken Access Control",
                  "A04:2021 – Insecure Design"],
        "controls": [
            "Deny access by default – explicitly grant each permission",
            "Implement access control mechanisms once and re-use throughout the application",
            "Minimize CORS usage; validate ownership on every API object access",
            "Use Role-Based Access Control (RBAC) and validate on every request server-side"
        ],
        "owasp_detail": "Broken Access Control is OWASP #1 – it covers privilege escalation (user→admin), BOLA (horizontal escalation), and function-level authorization bypass. All are Elevation of Privilege.",
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# CRITICALITY ZONE DEFINITIONS  (from Infosec walkthrough)
# ─────────────────────────────────────────────────────────────────────────────
CRITICALITY_ZONES = {
    "Not in Control of System": {
        "range": "0",
        "score": 0,
        "color": "#F5F5F5",
        "border": "#757575",
        "description": "External actors (users, third-party services) – no trust assumed",
        "examples": "End users, external APIs, third-party payment providers",
        "stride_applicability": "Source of Spoofing, DoS, and Repudiation threats"
    },
    "Minimal Trust": {
        "range": "1–2",
        "score": 1,
        "color": "#E8F5E9",
        "border": "#388E3C",
        "description": "Entry points with basic authentication – low criticality",
        "examples": "Web frontend, mobile app, CDN edge",
        "stride_applicability": "Tampering and Information Disclosure via unvalidated input/output"
    },
    "Standard Application": {
        "range": "3–4",
        "score": 3,
        "color": "#FFF9C4",
        "border": "#F9A825",
        "description": "Application-layer services with authentication enforced",
        "examples": "API backend, microservices, application servers",
        "stride_applicability": "All STRIDE categories – most complex threat surface"
    },
    "Elevated Trust": {
        "range": "5–6",
        "score": 5,
        "color": "#FFE0B2",
        "border": "#E65100",
        "description": "Services with privileged access or sensitive business logic",
        "examples": "Payment services, auth services, admin APIs",
        "stride_applicability": "Elevation of Privilege, Tampering, and Information Disclosure are highest risk"
    },
    "Critical": {
        "range": "7–8",
        "score": 7,
        "color": "#FFCDD2",
        "border": "#D32F2F",
        "description": "Data stores and systems containing sensitive/regulated data",
        "examples": "Databases, data warehouses, encryption key stores",
        "stride_applicability": "Information Disclosure and Tampering are existential risks"
    },
    "Maximum Security": {
        "range": "9",
        "score": 9,
        "color": "#B71C1C",
        "border": "#7B0000",
        "description": "Safety-critical or life-critical systems",
        "examples": "Medical device data, safety alert systems, nuclear control",
        "stride_applicability": "All STRIDE threats carry life-safety or business-ending consequences"
    }
}

# STRIDE RULES based on zone relationships (from Infosec walkthrough methodology)
STRIDE_ZONE_RULES = {
    "flows": {
        "Tampering": {
            "rule": "Data flow from a LESS critical zone to a MORE critical zone",
            "rationale": "An attacker at lower trust can inject malicious data into a higher-trust system (e.g., SQL injection from web input to database)",
            "direction": "less → more",
            "example": "Web Frontend (zone 1) → API Backend (zone 3): Attacker injects XSS payload"
        },
        "Information Disclosure": {
            "rule": "Data flow from a MORE critical zone to a LESS critical zone",
            "rationale": "Sensitive data flowing outward may be captured by a less-trusted component (e.g., database results returned to browser)",
            "direction": "more → less",
            "example": "Database (zone 7) → API Backend (zone 3): Attacker reads sensitive data in verbose API response"
        },
        "Denial of Service": {
            "rule": "Any flow from a 'Not in Control' (zone 0) node to any other node",
            "rationale": "External actors with no trust can flood any entry point they can reach",
            "direction": "zone 0 → any",
            "example": "User/Internet (zone 0) → API Backend (zone 3): Botnet floods login endpoint"
        }
    },
    "nodes": {
        "Spoofing": {
            "rule": "Any node that a 'Not in Control' (zone 0) entity can connect to",
            "rationale": "If an external actor can reach a node, they may impersonate a legitimate user or system",
            "applies_to": "Nodes connected to zone-0 entities",
            "example": "Login endpoint reached by Users: Attacker uses stolen credentials or brute force"
        },
        "Repudiation": {
            "rule": "Any node where BOTH Spoofing AND Tampering are applicable",
            "rationale": "If identity can be spoofed and data can be tampered, an attacker can perform actions that cannot be traced back to them",
            "applies_to": "Nodes at spoofing + tampering intersection",
            "example": "API Backend: Actions can be performed as a fake identity with modified data, then denied"
        },
        "Denial of Service": {
            "rule": "Any node that a 'Not in Control' (zone 0) entity connects to",
            "rationale": "External entities can exhaust resources of any reachable node",
            "applies_to": "All nodes reachable from zone-0",
            "example": "API Backend: External user floods requests until service crashes"
        },
        "Elevation of Privilege": {
            "rule": "Any node connected to a less-critical (lower zone number) node",
            "rationale": "If a less-trusted component can reach this node, an attacker who compromises the lower zone may gain the privileges of the higher zone",
            "applies_to": "Higher-zone nodes reachable from lower-zone nodes",
            "example": "Admin API (zone 5) reachable from API Backend (zone 3): Attacker escalates from regular user to admin"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# COMPLETE THREAT DATABASE
# ─────────────────────────────────────────────────────────────────────────────
PREDEFINED_THREATS = {
    "1": [
        {"id": "T-001", "stride": "Spoofing", "component": "Web Frontend → API Backend",
         "threat": "Session hijacking via XSS allowing attacker to impersonate legitimate user",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["HttpOnly and Secure flags on cookies",
                                  "Content Security Policy (CSP) headers",
                                  "Input sanitization with DOMPurify",
                                  "XSS prevention through output encoding"],
         "incorrect_mitigations": ["Increase password complexity", "Add rate limiting", "Enable 2FA"],
         "explanation": "XSS attacks allow stealing session cookies. HttpOnly prevents JavaScript from accessing cookies, CSP restricts allowed script sources, and input sanitization prevents malicious script injection.",
         "compliance": "OWASP Top 10 A03:2021 (Injection), OWASP ASVS V5.3.3, PCI-DSS 6.5.7",
         "points": 10,
         "why_this_risk": "Medium likelihood because XSS is common (found in 40% of apps). High impact because session hijacking gives full account access.",
         "why_these_controls": "HttpOnly blocks cookie theft via JavaScript. CSP prevents unauthorized scripts from running. DOMPurify sanitizes user input before rendering.",
         "real_world": "British Airways fined £20M for breach involving XSS (2019). Magecart attacks use XSS to steal payment data.",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering/Spoofing: Less-critical zone (1) to more-critical zone (3) + external entity (zone 0) connection",
         "owasp_categories": ["A03:2021 – Injection", "A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-002", "stride": "Tampering", "component": "API Backend → Database",
         "threat": "SQL injection allowing modification of product prices or customer data",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Parameterized queries/Prepared statements",
                                  "Use ORM (Sequelize, TypeORM)",
                                  "Input validation with allowlisting",
                                  "Least privilege database user"],
         "incorrect_mitigations": ["Encrypt database connections", "Add logging", "Use strong passwords"],
         "explanation": "SQL injection exploits unsanitized user input in SQL queries. Parameterized queries separate SQL code from data, preventing injection.",
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1, CWE-89",
         "points": 10,
         "why_this_risk": "Medium likelihood - still found in 25% of applications. Critical impact - can modify/delete ALL data including prices and customer records.",
         "why_these_controls": "Parameterized queries treat user input as data only, never as executable SQL. ORMs abstract SQL generation safely.",
         "real_world": "Target breach (2013) started with SQL injection. 40M credit cards stolen, $18M settlement.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Tampering: Data flow from less-critical (zone 3 API) to more-critical (zone 7 DB) – attacker injects SQL via lower zone",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]},

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
         "real_world": "Equifax breach exposed 147M people. Encryption would have limited damage. €50M GDPR fine.",
         "zone_from": "Critical", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Data in critical zone (7) – direct node risk when zone boundary collapses through misconfig",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A05:2021 – Security Misconfiguration"]},

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
         "real_world": "GitHub survived 1.35 Tbps DDoS (2018) using auto-scaling and traffic filtering. Dyn DNS attack took down Twitter, Netflix (2016).",
         "zone_from": "Not in Control of System", "zone_to": "Standard Application",
         "stride_rule_applied": "Denial of Service: Zone-0 (Users) connects to API Backend – external entity can exhaust any reachable node",
         "owasp_categories": ["A05:2021 – Security Misconfiguration", "A04:2021 – Insecure Design"]},

        {"id": "T-005", "stride": "Elevation of Privilege", "component": "API Backend",
         "threat": "Broken access control allowing regular user to access admin endpoints",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Role-Based Access Control (RBAC)",
                                  "Validate permissions on every request",
                                  "Principle of least privilege",
                                  "Deny by default access policy"],
         "incorrect_mitigations": ["Encrypt API traffic", "Add logging", "Use strong authentication"],
         "explanation": "Authentication confirms identity, but authorization determines access rights. RBAC ensures users only access resources appropriate for their role.",
         "compliance": "OWASP Top 10 A01:2021 (Broken Access Control), PCI-DSS 7.1, NIST 800-53 AC-2",
         "points": 10,
         "why_this_risk": "Medium likelihood - common developer oversight. High impact - admin access = full system control, data modification.",
         "why_these_controls": "Check authorization on EVERY request, not just authentication. Deny by default means explicitly grant each permission.",
         "real_world": "Instagram API bug (2020) let users access admin endpoints. Peloton API allowed accessing any user's data (2021).",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Elevation of Privilege: API Backend (zone 3) connected to lower-trust frontend (zone 1) – lower zone can attempt to gain higher-zone capabilities",
         "owasp_categories": ["A01:2021 – Broken Access Control"]},

        {"id": "T-006", "stride": "Repudiation", "component": "API Backend",
         "threat": "Insufficient logging allows attackers to cover tracks or users to deny actions",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Comprehensive audit logging",
                                  "Log authentication events",
                                  "Log all data modifications",
                                  "Centralized logging (CloudWatch)",
                                  "Write-once log storage"],
         "incorrect_mitigations": ["Add encryption", "Enable 2FA", "Use firewalls"],
         "explanation": "Non-repudiation requires proof of actions. Comprehensive audit logs create immutable record of who did what and when.",
         "compliance": "PCI-DSS 10 (all requirements), SOC 2 CC7.2, HIPAA 164.312(b)",
         "points": 10,
         "why_this_risk": "Medium/medium - can't investigate incidents without logs. Average time to detect breach: 207 days without proper logging.",
         "why_these_controls": "Audit logs record WHO (user), WHAT (action), WHEN (timestamp), WHERE (location). Write-once storage prevents log tampering.",
         "real_world": "Many breaches undetected for months due to no logging. GDPR requires logging for breach notification.",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Repudiation: API Backend has BOTH Spoofing (zone-0 entities connect) AND Tampering (less→more zone flows) – repudiation applies where both are present",
         "owasp_categories": ["A09:2021 – Security Logging and Monitoring Failures"]},

        {"id": "T-007", "stride": "Tampering", "component": "Customer → Web Frontend",
         "threat": "Man-in-the-middle attack intercepting and modifying data in transit",
         "likelihood": "Low", "impact": "High",
         "correct_mitigations": ["TLS 1.3 for all connections", "HSTS headers",
                                  "Certificate pinning in mobile apps",
                                  "Enforce HTTPS with redirects"],
         "incorrect_mitigations": ["Add database encryption", "Enable logging", "Use strong passwords"],
         "explanation": "MITM attacks intercept unencrypted communications. TLS encrypts data in transit, HSTS prevents protocol downgrade attacks.",
         "compliance": "PCI-DSS 4.1, OWASP ASVS V9.1.1",
         "points": 10,
         "why_this_risk": "Low likelihood - HTTPS now default. High impact - can steal credentials, payment data, session tokens.",
         "why_these_controls": "TLS 1.3 encrypts all traffic. HSTS forces browsers to always use HTTPS, preventing downgrade to HTTP.",
         "real_world": "Public WiFi MITM attacks common. Firesheep tool (2010) showed how easy cookie theft is on unencrypted WiFi.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Tampering: Flow from zone-0 (Customer) to zone-1 (Frontend) – the least-trusted boundary where MITM attacks intercept data",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A08:2021 – Software and Data Integrity Failures"]},

        {"id": "T-008", "stride": "Information Disclosure", "component": "API Backend",
         "threat": "Verbose error messages exposing stack traces and internal system paths to attackers",
         "likelihood": "High", "impact": "Low",
         "correct_mitigations": ["Generic error messages for users",
                                  "Log detailed errors server-side only",
                                  "Disable debug mode in production",
                                  "Custom error pages"],
         "incorrect_mitigations": ["Encrypt error messages", "Add authentication", "Use rate limiting"],
         "explanation": "Detailed errors reveal system internals to attackers. Production systems show generic errors to users while logging details server-side.",
         "compliance": "OWASP Top 10 A05:2021, CWE-209 (Information Exposure Through Error Message)",
         "points": 10,
         "why_this_risk": "High likelihood - very common mistake, often left in production. Low impact - aids reconnaissance but doesn't directly breach data.",
         "why_these_controls": "Generic user-facing errors hide internals. Detailed server-side logs help debugging without exposing information.",
         "real_world": "Stack traces fingerprint frameworks and versions, helping attackers find known exploits.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Data flows from higher-trust API (zone 3) back to zone-0 User – verbose errors leak internal architecture",
         "owasp_categories": ["A05:2021 – Security Misconfiguration", "A02:2021 – Cryptographic Failures"]},

        {"id": "T-009", "stride": "Spoofing", "component": "Customer",
         "threat": "Weak password policy allowing brute force attacks to compromise user accounts",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Strong password requirements (12+ chars, complexity)",
                                  "Multi-Factor Authentication (MFA)",
                                  "Account lockout after failed attempts",
                                  "CAPTCHA on login",
                                  "Password breach detection"],
         "incorrect_mitigations": ["Encrypt passwords in database", "Add logging", "Use HTTPS"],
         "explanation": "Weak passwords easily guessed. Strong password policies combined with MFA and account lockout make brute force impractical.",
         "compliance": "OWASP ASVS V2.1.1, PCI-DSS 8.2.3, NIST 800-63B",
         "points": 10,
         "why_this_risk": "High likelihood - 80% of breaches involve weak/stolen passwords. Medium impact - one account compromised, not entire database.",
         "why_these_controls": "Long passwords resist brute force (12 chars = 10^21 combinations). MFA requires second factor even if password stolen.",
         "real_world": "Credential stuffing tries leaked passwords across sites. 15B credentials available on dark web. MFA blocks 99.9% of attacks.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Spoofing: Zone-0 (Customer) connects to login system – external entity impersonates legitimate user through credential attack",
         "owasp_categories": ["A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-010", "stride": "Elevation of Privilege", "component": "API Backend → S3 Storage",
         "threat": "Misconfigured S3 bucket with public access allowing unauthorized uploads or data exposure",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["S3 Block Public Access enabled",
                                  "Bucket policies with least privilege",
                                  "IAM roles for API access (not keys)",
                                  "S3 access logging enabled",
                                  "Regular access audits"],
         "incorrect_mitigations": ["Encrypt S3 objects", "Add CloudWatch monitoring", "Use strong passwords"],
         "explanation": "Misconfigured S3 buckets common vulnerability. Block Public Access prevents accidental exposure, IAM roles provide granular control.",
         "compliance": "AWS Well-Architected Security Pillar, CIS AWS Foundations Benchmark 2.1.5",
         "points": 10,
         "why_this_risk": "Medium likelihood - easy to misconfigure. High impact - public data breach, regulatory fines.",
         "why_these_controls": "Block Public Access is global override preventing public access. IAM roles rotate credentials automatically.",
         "real_world": "Capital One breach (2019) exposed 100M customers via S3 misconfiguration. $80M fine.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Elevation of Privilege: S3 (critical zone) reachable from lower-trust API – misconfiguration lets attacker gain storage-level access beyond their role",
         "owasp_categories": ["A01:2021 – Broken Access Control", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-011", "stride": "Tampering", "component": "Web Frontend",
         "threat": "DOM-based XSS through client-side JavaScript manipulation of user input",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Use React's built-in XSS protection",
                                  "Avoid dangerouslySetInnerHTML",
                                  "DOMPurify for sanitization when needed",
                                  "Content Security Policy",
                                  "Validate all user inputs"],
         "incorrect_mitigations": ["Add server-side validation only", "Use HTTPS", "Enable database encryption"],
         "explanation": "DOM-based XSS occurs in browser. React escapes output by default, but developers must avoid unsafe patterns.",
         "compliance": "OWASP Top 10 A03:2021, CWE-79 (XSS)",
         "points": 10,
         "why_this_risk": "Medium likelihood - requires unsafe React patterns. Medium impact - session theft, defacement.",
         "why_these_controls": "React auto-escapes JSX expressions. dangerouslySetInnerHTML bypasses protection. CSP blocks unauthorized scripts.",
         "real_world": "DOM XSS harder to detect than reflected XSS. Modern frameworks help but developers can still create vulnerabilities.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Tampering: Zone-0 user input enters zone-1 frontend – malicious script modifies DOM behavior",
         "owasp_categories": ["A03:2021 – Injection"]},

        {"id": "T-012", "stride": "Information Disclosure", "component": "API Backend → Stripe",
         "threat": "API keys hardcoded in frontend code exposing Stripe credentials in source",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Use Stripe publishable keys in frontend",
                                  "Store secret keys in AWS Secrets Manager",
                                  "Never commit keys to version control",
                                  "Rotate keys regularly",
                                  "Use environment variables"],
         "incorrect_mitigations": ["Encrypt keys in code", "Obfuscate JavaScript", "Add rate limiting"],
         "explanation": "Frontend code is visible to users. Use publishable keys for client-side, keep secret keys server-side in secure stores.",
         "compliance": "PCI-DSS 6.5.3 (Protect cryptographic keys), OWASP Top 10 A05:2021",
         "points": 10,
         "why_this_risk": "High likelihood - frontend code is PUBLIC. Critical impact - direct financial fraud, unauthorized charges.",
         "why_these_controls": "Publishable keys safe for frontend (restricted capabilities). Secret keys server-side only. Secrets Manager encrypts and rotates.",
         "real_world": "GitHub finds thousands of exposed API keys daily. Automated bots scan commits for secrets. $1M+ stolen via exposed Stripe keys.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Secret credentials (high trust) leak into zone-0 visible frontend – any user can extract the key",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-013", "stride": "Denial of Service", "component": "Database",
         "threat": "Expensive database queries without pagination causing resource exhaustion",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Implement pagination (limit/offset)", "Query timeouts",
                                  "Database connection pooling",
                                  "Index frequently queried fields",
                                  "Query complexity analysis"],
         "incorrect_mitigations": ["Add more database storage", "Enable encryption", "Add logging"],
         "explanation": "Unbounded queries exhaust memory and CPU. Pagination limits result sets, timeouts prevent long-running queries.",
         "compliance": "OWASP API Security Top 10 API4:2023 (Unrestricted Resource Consumption)",
         "points": 10,
         "why_this_risk": "Medium/medium - legitimate users can trigger expensive queries. Impacts all users when DB slows.",
         "why_these_controls": "Pagination limits data returned per request. Timeouts kill runaway queries. Indexes speed up lookups.",
         "real_world": "Unoptimized queries crash databases during traffic spikes. Black Friday sales bring down e-commerce sites.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Denial of Service: API (zone 3) sends requests to DB (zone 7) – unbounded queries exhaust critical data store resources",
         "owasp_categories": ["A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-014", "stride": "Spoofing", "component": "API Backend → SendGrid",
         "threat": "Email spoofing allowing attackers to send phishing emails appearing from legitimate domain",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["SPF records configured", "DKIM signing enabled",
                                  "DMARC policy enforced (p=reject)",
                                  "Verify SendGrid API key security",
                                  "Monitor email sending patterns"],
         "incorrect_mitigations": ["Encrypt email content", "Add rate limiting", "Use strong passwords"],
         "explanation": "Email authentication (SPF, DKIM, DMARC) proves emails originate from authorized servers, preventing domain spoofing.",
         "compliance": "DMARC RFC 7489, Anti-Phishing Best Practices",
         "points": 10,
         "why_this_risk": "Medium/medium - easy to spoof emails. Brand damage from phishing, customer trust loss.",
         "why_these_controls": "SPF lists authorized mail servers. DKIM cryptographically signs emails. DMARC tells receivers what to do with failures.",
         "real_world": "Business Email Compromise (BEC) scams cost $2.4B in 2021 (FBI). Email spoofing enables phishing attacks.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Spoofing: Email flows out to zone-0 recipients – attacker impersonates your domain to attack your users",
         "owasp_categories": ["A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-015", "stride": "Tampering", "component": "API Backend",
         "threat": "Mass assignment vulnerability allowing users to modify unintended database fields",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Explicitly define allowed fields (allowlist)",
                                  "Use DTO (Data Transfer Objects)",
                                  "Validate input against schema",
                                  "Blacklist sensitive fields like isAdmin",
                                  "Use ORM's field protection"],
         "incorrect_mitigations": ["Encrypt the request", "Add authentication", "Enable logging"],
         "explanation": "Mass assignment occurs when APIs blindly accept all input fields. Explicitly defining allowed fields prevents modifying protected attributes.",
         "compliance": "OWASP API Security Top 10 API6:2023 (Mass Assignment), CWE-915",
         "points": 10,
         "why_this_risk": "Medium/high - can set isAdmin=true via POST. Trivial to exploit once discovered.",
         "why_these_controls": "Allow-lists define exactly which fields are updateable. Anything not on list is rejected.",
         "real_world": "GitHub mass assignment vulnerability (2012) let anyone gain admin access. Rails applications particularly vulnerable without strong_parameters.",
         "zone_from": "Not in Control of System", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering: Zone-0 user submits POST body to zone-3 API – unvalidated fields tamper with business-critical data",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]}
    ],

    "2": [
        {"id": "T-101", "stride": "Information Disclosure", "component": "API Gateway → Payment Service",
         "threat": "BOLA (Broken Object Level Authorization) - accessing other users' data",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Object-level authorization on every API call",
                                  "Resource ownership checks",
                                  "Use UUIDs not sequential IDs",
                                  "Validate user owns resource"],
         "incorrect_mitigations": ["Add authentication", "Encrypt account ID", "Add rate limiting"],
         "explanation": "BOLA = broken object authorization. API returns data based only on object ID without verifying ownership.",
         "compliance": "OWASP API Security Top 10 - API1:2023",
         "points": 10,
         "why_this_risk": "High likelihood - trivial to exploit in banking apps. Critical impact - access to all customer financial data.",
         "why_these_controls": "Validate ownership on EVERY API call. Database query must include: WHERE id=? AND user_id=current_user",
         "real_world": "Peloton API (2021): Any user could access any other user's data by changing user ID. First American leaked 885M docs via BOLA (2019).",
         "zone_from": "Minimal Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Information Disclosure: API Gateway (zone 1) to Payment Service (zone 5) – data flows outward if ownership check missing",
         "owasp_categories": ["A01:2021 – Broken Access Control", "A02:2021 – Cryptographic Failures"]},

        {"id": "T-102", "stride": "Spoofing", "component": "User Service → Payment Service",
         "threat": "Service Impersonation - rogue service in service mesh",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Mutual TLS (mTLS) for service mesh",
                                  "Service identity verification",
                                  "Certificate-based authentication",
                                  "SPIFFE IDs for services"],
         "incorrect_mitigations": ["Use API keys only", "Add logging", "Network firewall"],
         "explanation": "Without mutual authentication, services accept requests from imposter. Attacker deploys rogue service pretending to be legitimate Payment Service.",
         "compliance": "NIST 800-204, Zero Trust Architecture",
         "points": 10,
         "why_this_risk": "Medium/high - needs cluster access but enables lateral movement and data theft.",
         "why_these_controls": "mTLS means both client and server present certificates. Service mesh (Istio, Linkerd) automatically handles mTLS.",
         "real_world": "Service mesh breaches prevented by mTLS. Without it, lateral movement trivial once attacker enters network.",
         "zone_from": "Elevated Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Spoofing: Both services are zone-5 (Elevated Trust) but service-to-service calls can be intercepted if mTLS not enforced",
         "owasp_categories": ["A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-103", "stride": "Repudiation", "component": "Payment Service",
         "threat": "Insufficient Logging - can't trace distributed requests",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Distributed tracing (OpenTelemetry)",
                                  "Centralized logging (ELK/Splunk)",
                                  "Correlation IDs across services",
                                  "Structured JSON logging"],
         "incorrect_mitigations": ["Local file logging only", "No correlation IDs", "Minimal logging"],
         "explanation": "Microservices don't log service-to-service calls. When breach discovered, can't trace attacker's path through system.",
         "compliance": "PCI-DSS 10, SOC 2 CC7.2",
         "points": 10,
         "why_this_risk": "High/medium - very common oversight. Can't investigate incidents or prove compliance without proper logging.",
         "why_these_controls": "Distributed tracing creates trace showing request path across ALL services. Correlation ID propagates through every service call.",
         "real_world": "Average breach detection: 207 days without centralized logging. With proper logging: detected in hours.",
         "zone_from": "Elevated Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Repudiation: Payment Service has both Spoofing AND Tampering applicability – actions can be denied without distributed tracing",
         "owasp_categories": ["A09:2021 – Security Logging and Monitoring Failures"]},

        {"id": "T-104", "stride": "Denial of Service", "component": "API Gateway",
         "threat": "Rate Limiting Bypass - distributed botnet attack",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Global + Per-service rate limits",
                                  "Distributed rate limiting (Redis)",
                                  "Circuit breaker pattern",
                                  "WAF with geo-blocking"],
         "incorrect_mitigations": ["Per-IP limits only", "No distributed tracking", "Increase server capacity only"],
         "explanation": "Attacker uses distributed botnet with different IPs to bypass per-IP rate limits.",
         "compliance": "OWASP API Top 10 API4:2023 (Unrestricted Resource Consumption)",
         "points": 10,
         "why_this_risk": "High/high - DDoS attacks cheap and easy. Service outage = revenue loss for banking app.",
         "why_these_controls": "Redis-backed rate limiting shared across ALL gateway instances. Circuit breaker prevents cascade failures.",
         "real_world": "GitHub API: 5000 req/hour per user. CloudFlare: Global rate limiting prevented Tbps DDoS attacks.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Denial of Service: Zone-0 Mobile App connects to API Gateway (zone 1) – external entities flood the entry point",
         "owasp_categories": ["A05:2021 – Security Misconfiguration", "A04:2021 – Insecure Design"]},

        {"id": "T-105", "stride": "Tampering", "component": "User Service → Payment Service",
         "threat": "Insecure Service-to-Service Communication - unencrypted inter-service traffic",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["JWT validation on every service call",
                                  "Short token expiration (15min)",
                                  "Service mesh encryption (mTLS)",
                                  "TLS for all internal traffic"],
         "incorrect_mitigations": ["HTTP only for internal", "No token validation", "Long-lived tokens"],
         "explanation": "Services communicate over plain HTTP within cluster. Network sniffer captures credit card data in transit between services.",
         "compliance": "PCI-DSS 4.1, HIPAA 164.312(e)",
         "points": 10,
         "why_this_risk": "Medium/critical - needs network access but financial data exposed.",
         "why_these_controls": "Service mesh automatically encrypts all pod-to-pod traffic with mTLS. Network-level encryption layer prevents MITM.",
         "real_world": "Enterprises with mTLS prevented 100% of network-based lateral movement in red team exercises.",
         "zone_from": "Elevated Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Tampering: Inter-service flow within same zone – but without mTLS, a compromised node can modify messages in transit",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]}
    ],

    "3": [
        {"id": "T-201", "stride": "Information Disclosure", "component": "Query Service → Data Warehouse",
         "threat": "Cross-Tenant Data Access - SQL missing tenant filter",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Row-Level Security (RLS) in PostgreSQL/Redshift",
                                  "Tenant context validation on every request",
                                  "WHERE tenant_id = :tenant_id in ALL queries",
                                  "Database-level enforcement"],
         "incorrect_mitigations": ["Application-level filtering only", "Trust tenant_id from request", "No RLS policies"],
         "explanation": "SQL query doesn't include tenant filter. Attacker from Tenant A crafts API request that returns Tenant B's data.",
         "compliance": "SOC 2 CC6.1 (Logical Access), ISO 27001 A.9.4.1",
         "points": 10,
         "why_this_risk": "High/critical - THE multi-tenant SaaS vulnerability. One query returns data from ALL tenants.",
         "why_these_controls": "PostgreSQL RLS policies enforce tenant_id filter on ALL queries automatically at database level.",
         "real_world": "GitHub Gist (2020): Cross-tenant data leak. SaaS platforms average 1-2 tenant isolation bugs per year.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Information Disclosure: Query Service (zone 3) accesses Data Warehouse (zone 7) – missing tenant filter exposes all tenants' data from the critical zone",
         "owasp_categories": ["A01:2021 – Broken Access Control", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-202", "stride": "Elevation of Privilege", "component": "API Gateway",
         "threat": "Tenant Isolation Bypass - modifying tenant context",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Tenant context from JWT ONLY (never request body)",
                                  "Middleware validation before all routes",
                                  "Admin namespace isolation (separate domain)",
                                  "Tenant existence and active status checks"],
         "incorrect_mitigations": ["Accept tenant_id from request body", "No middleware validation", "Same domain for admin and tenant APIs"],
         "explanation": "Attacker discovers admin endpoint /internal/all-tenants that bypasses tenant context.",
         "compliance": "SOC 2 CC6.1",
         "points": 10,
         "why_this_risk": "Medium/critical - needs to find vulnerability but impact is catastrophic cross-tenant access.",
         "why_these_controls": "EVERY API request includes X-Tenant-ID header extracted from JWT. Backend validates before processing.",
         "real_world": "Salesforce: Strict namespace isolation. Multi-tenant architecture review catches 90% of isolation bugs before production.",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Elevation of Privilege: API Gateway (zone 1-3) connected to shared services – user elevates from single-tenant to cross-tenant access",
         "owasp_categories": ["A01:2021 – Broken Access Control"]},

        {"id": "T-203", "stride": "Denial of Service", "component": "Query Service → Data Warehouse",
         "threat": "Noisy Neighbor Resource Exhaustion - one tenant impacts all",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Per-tenant resource quotas (CPU/memory/queries)",
                                  "Query timeout enforcement (30 seconds)",
                                  "Query complexity limits",
                                  "Priority queues for enterprise vs free tier"],
         "incorrect_mitigations": ["Unlimited resources per tenant", "No query timeouts", "Shared pool without limits"],
         "explanation": "Tenant A runs expensive analytics query consuming all database CPU. Tenant B's queries time out.",
         "compliance": "SLA commitments, Fair usage policies",
         "points": 10,
         "why_this_risk": "High/high - very common in shared infrastructure. Revenue loss when paying customers impacted.",
         "why_these_controls": "AWS Service Quotas or custom quota service. Tenant A: max 1000 req/min, 10 concurrent queries, 100GB data scanned/day.",
         "real_world": "AWS RDS: Per-instance IOPS limits. Heroku: Per-app dyno limits. Prevents noisy neighbor problems.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Denial of Service: Flow from zone-3 (Query Service) to zone-7 (Data Warehouse) – any tenant can exhaust the shared critical resource",
         "owasp_categories": ["A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-204", "stride": "Information Disclosure", "component": "Data Lake → Data Warehouse",
         "threat": "Shared Secret Keys - all tenant data with same encryption key",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Per-tenant encryption keys (DEK per tenant)",
                                  "Separate backup files per tenant",
                                  "AWS KMS with tenant isolation",
                                  "Automatic key rotation"],
         "incorrect_mitigations": ["Single master key for all tenants", "Shared backups", "No key separation"],
         "explanation": "All tenants' data encrypted with same master key. If key leaked, ALL tenant data decryptable.",
         "compliance": "GDPR Article 32 (Security of processing), SOC 2 CC6.1",
         "points": 10,
         "why_this_risk": "Medium/critical - needs key compromise but exposes EVERYTHING.",
         "why_these_controls": "Each tenant has unique DEK. DEKs encrypted with tenant-specific KEK in AWS KMS.",
         "real_world": "GDPR requires data isolation. Multi-tenant SaaS with single key failed audit. Per-tenant keys now standard for enterprise SaaS.",
         "zone_from": "Critical", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Critical zone (7) data store – a single compromised key exposes all tenants when keys are shared",
         "owasp_categories": ["A02:2021 – Cryptographic Failures"]},

        {"id": "T-205", "stride": "Tampering", "component": "API Gateway",
         "threat": "Insufficient Tenant Context Validation - accepting tenant_id from request",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Tenant-tagged logs with tenant_id in every log",
                                  "Isolation testing (automated tests with 2 tenants)",
                                  "Tenant context from JWT claims only",
                                  "Middleware enforcement"],
         "incorrect_mitigations": ["Trust request body tenant_id", "No isolation tests", "Optional tenant validation"],
         "explanation": "API accepts tenant_id from request body without validation. Attacker modifies POST body: {tenant_id: 'victim-tenant', data: {...}}",
         "compliance": "SOC 2 CC7.2 (System Monitoring)",
         "points": 10,
         "why_this_risk": "High/high - extremely common mistake. Direct data integrity and isolation issues.",
         "why_these_controls": "NEVER trust tenant_id from request body/query params. Extract from JWT claims only.",
         "real_world": "Isolation testing caught 40% of tenant isolation bugs in major SaaS platforms before production deployment.",
         "zone_from": "Not in Control of System", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering: Zone-0 tenant user sends POST request to zone-3 API Gateway – forged tenant_id in body tampers with tenant isolation boundary",
         "owasp_categories": ["A03:2021 – Injection", "A01:2021 – Broken Access Control"]}
    ],

    "4": [
        {"id": "T-301", "stride": "Tampering", "component": "Glucose Monitor → IoT Gateway",
         "threat": "Device Tampering - firmware modification or physical access",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Secure boot with signature verification",
                                  "Firmware signing with manufacturer key",
                                  "TPM (Trusted Platform Module)",
                                  "Physical tamper detection sensors"],
         "incorrect_mitigations": ["No firmware verification", "Unsigned firmware allowed", "No tamper seals"],
         "explanation": "Attacker gains physical access to glucose monitor. Reflashes firmware to report false readings.",
         "compliance": "FDA 21 CFR Part 11, IEC 62304 (medical device software)",
         "points": 10,
         "why_this_risk": "Medium/CRITICAL - needs physical access but LIFE-THREATENING. Patient could die from missed alerts.",
         "why_these_controls": "Secure boot verifies firmware signature before boot using hardware root of trust. Only signed firmware will execute.",
         "real_world": "Medtronic insulin pump recall: Unencrypted RF allowed unauthorized dosing. St. Jude pacemaker: Firmware could be modified remotely.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Tampering: Physical device (zone 0 - patient home) to IoT Gateway (zone 1) – attacker with physical access tampers at the lowest trust boundary",
         "owasp_categories": ["A08:2021 – Software and Data Integrity Failures"]},

        {"id": "T-302", "stride": "Tampering", "component": "IoT Gateway → Device Data Svc",
         "threat": "Replay Attacks on Sensor Data - old readings replayed",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["UTC timestamps on every message",
                                  "Nonce (number used once)",
                                  "Message freshness checks (reject >5min old)",
                                  "Sequence numbers (monotonic counter)"],
         "incorrect_mitigations": ["No timestamps", "Accept any message age", "No replay detection"],
         "explanation": "Attacker captures MQTT messages containing vital signs. Replays old 'normal' readings while patient's actual vitals are critical.",
         "compliance": "HIPAA 164.312(e)(2)(i), FDA Cybersecurity Guidance",
         "points": 10,
         "why_this_risk": "High/CRITICAL - easy to execute replay attack. Patient doesn't receive life-saving intervention. DEATH possible.",
         "why_these_controls": "Every sensor message includes UTC timestamp. Server rejects messages older than 5 minutes.",
         "real_world": "Medical device replay attacks demonstrated in research. ICS/SCADA systems compromised by replay.",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering: IoT Gateway (zone 1) to Cloud Service (zone 3) – replayed messages tamper with the integrity of real-time patient data",
         "owasp_categories": ["A08:2021 – Software and Data Integrity Failures", "A02:2021 – Cryptographic Failures"]},

        {"id": "T-303", "stride": "Information Disclosure", "component": "Patient DB",
         "threat": "Unencrypted PHI/PII - database backups exposed",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["AES-256 encryption at rest (HIPAA requirement)",
                                  "TLS 1.3 for all connections",
                                  "AWS KMS for key management",
                                  "Encrypted backups"],
         "incorrect_mitigations": ["No encryption", "Unencrypted backups", "Keys stored with data"],
         "explanation": "Database backups stored unencrypted in S3. Misconfiguration makes bucket public.",
         "compliance": "HIPAA 164.312(a)(2)(iv), HITECH Act",
         "points": 10,
         "why_this_risk": "Medium/critical - HIPAA breach notification required. Massive fines ($3M+ average). Patient privacy violated.",
         "why_these_controls": "AES-256 encryption for RDS, S3, EBS. HIPAA requirement - not optional.",
         "real_world": "Healthcare breaches: Anthem (78M records), Premera (11M records) - both unencrypted data. Average HIPAA breach fine: $3M+.",
         "zone_from": "Critical", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Patient DB (zone 9 - Maximum Security) – PHI flows outward if backup misconfiguration collapses the zone boundary",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-304", "stride": "Denial of Service", "component": "Alert Service → Web Portal",
         "threat": "Alert Suppression - critical alerts not delivered",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Redundant alert channels (WebSocket + SMS + Phone)",
                                  "Priority queues (P0 critical, P1 urgent, P2 warning)",
                                  "Watchdog timers (2-minute timeout)",
                                  "Alert rate limiting (except P0)"],
         "incorrect_mitigations": ["Single channel only", "No prioritization", "No watchdog timers"],
         "explanation": "Attacker floods alert system with fake low-priority alerts. Queue fills up. Critical patient alert stuck in queue.",
         "compliance": "FDA 510(k) safety requirements, IEC 60601-1-8 (medical alarms)",
         "points": 10,
         "why_this_risk": "Medium/CRITICAL - needs system access but PATIENT SUFFERS PREVENTABLE HARM.",
         "why_these_controls": "Critical alerts sent via: 1) WebSocket to portal, 2) SMS to on-call, 3) Phone call (after 2 min), 4) Email. P0 alerts bypass rate limiting.",
         "real_world": "Alert fatigue causes 50-90% of alerts ignored. Proper prioritization saves lives.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Denial of Service: Alert Service (zone 3) to Web Portal/Clinician (zone 0) – flooding the queue is a DoS on the safety-critical alert path",
         "owasp_categories": ["A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-305", "stride": "Tampering", "component": "HL7 Interface → Legacy EHR",
         "threat": "Legacy System Injection - HL7 v2 message manipulation",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["HL7 message validation against specification",
                                  "Network isolation (separate VLAN)",
                                  "Site-to-site VPN for encryption",
                                  "Custom HMAC signatures in ZPD segment"],
         "incorrect_mitigations": ["No HL7 validation", "Open network access", "No encryption"],
         "explanation": "Legacy EHR uses HL7 v2 over MLLP (no encryption, no authentication). Attacker on hospital network injects malicious HL7 messages.",
         "compliance": "HIPAA, HL7 v2.x specification",
         "points": 10,
         "why_this_risk": "High/high - legacy systems often unpatched. Direct patient harm from prescription modification.",
         "why_these_controls": "Validate every HL7 segment against specification. VPN encrypts all traffic. Message signing provides integrity.",
         "real_world": "Hospital ransomware often exploits legacy systems. HL7 interfaces frequently lack authentication.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Tampering: Hospital application (zone 3) to Legacy EHR (zone 0 - external/uncontrolled) – injecting HL7 messages tampers with prescription data in an unprotected legacy system",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]}
    ]
}


# ─────────────────────────────────────────────────────────────────────────────
# WORKSHOPS CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: Web Application (2-Tier)",
        "architecture_type": "2-Tier Web Application",
        "level": "Foundation",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": None,
        "learning_objectives": [
            "Apply the 4-step Infosec threat modeling methodology end-to-end",
            "Label system components with Criticality Zones (0–9 scale)",
            "Apply STRIDE rules based on zone relationships and element types",
            "Map identified threats to OWASP Top 10 controls",
            "Understand why each STRIDE category applies to specific DFD elements"
        ],
        "scenario": {
            "title": "TechMart E-Commerce Store",
            "description": "React frontend + Node.js API + PostgreSQL database",
            "business_context": "Series A startup, 50K monthly users, $2M revenue",
            "assets": ["Customer PII", "Payment data", "User credentials", "Order history"],
            "objectives": ["Confidentiality: Protect customer PII",
                           "Integrity: Order accuracy",
                           "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS Level 4", "GDPR", "CCPA"],
            "components": [
                {"name": "Customer", "type": "external_entity",
                 "description": "End users (untrusted)", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "Web Frontend", "type": "process",
                 "description": "React SPA in browser", "zone": "Minimal Trust", "zone_score": 1},
                {"name": "API Backend", "type": "process",
                 "description": "Node.js/Express", "zone": "Standard Application", "zone_score": 3},
                {"name": "Database", "type": "datastore",
                 "description": "PostgreSQL – stores PII & orders", "zone": "Critical", "zone_score": 7},
                {"name": "Stripe", "type": "external_entity",
                 "description": "3rd-party payment processor", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "SendGrid", "type": "external_entity",
                 "description": "3rd-party email service", "zone": "Not in Control of System", "zone_score": 0}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend",
                 "data": "Requests/input", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend",
                 "data": "API calls", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database",
                 "data": "SQL queries", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe",
                 "data": "Payment data", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "SendGrid",
                 "data": "Email content", "protocol": "HTTPS"},
                {"source": "Database", "destination": "API Backend",
                 "data": "Query results", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Internet Boundary",
                 "description": "Zone 0 (Untrusted Internet) → Zone 1 (Frontend)",
                 "components": ["Customer", "Web Frontend"]},
                {"name": "Application Boundary",
                 "description": "Zone 1 (Frontend) → Zone 3 (API Backend)",
                 "components": ["Web Frontend", "API Backend"]},
                {"name": "Data Boundary",
                 "description": "Zone 3 (Application) → Zone 7 (Database)",
                 "components": ["API Backend", "Database"]}
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
        "learning_objectives": [
            "Apply zone-based STRIDE rules to service mesh architectures",
            "Identify BOLA and service impersonation threats using zone analysis",
            "Understand how mTLS enforces zone trust boundaries in microservices",
            "Map distributed tracing requirements to Repudiation prevention",
            "Apply OWASP API Security Top 10 alongside OWASP Top 10"
        ],
        "scenario": {
            "title": "CloudBank Mobile Banking",
            "description": "API Gateway + Multiple Services + Message Queues",
            "business_context": "Regional bank, 500K customers",
            "assets": ["Financial data", "Transactions", "PII", "OAuth tokens"],
            "objectives": ["Confidentiality", "Integrity", "Availability: 99.95%"],
            "compliance": ["PCI-DSS", "SOC 2", "GLBA"],
            "components": [
                {"name": "Mobile App", "type": "external_entity",
                 "description": "iOS/Android client", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "API Gateway", "type": "process",
                 "description": "AWS API Gateway – entry point", "zone": "Minimal Trust", "zone_score": 1},
                {"name": "User Service", "type": "process",
                 "description": "Auth & identity (ECS)", "zone": "Elevated Trust", "zone_score": 5},
                {"name": "Payment Service", "type": "process",
                 "description": "Financial transfers (ECS)", "zone": "Elevated Trust", "zone_score": 5},
                {"name": "User DB", "type": "datastore",
                 "description": "DynamoDB – user profiles", "zone": "Critical", "zone_score": 7},
                {"name": "Transaction DB", "type": "datastore",
                 "description": "Aurora – financial records", "zone": "Critical", "zone_score": 8}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway",
                 "data": "HTTPS requests", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "User Service",
                 "data": "Auth requests", "protocol": "HTTP/2 + mTLS"},
                {"source": "API Gateway", "destination": "Payment Service",
                 "data": "Payment requests", "protocol": "HTTP/2 + mTLS"},
                {"source": "User Service", "destination": "User DB",
                 "data": "User data", "protocol": "DynamoDB SDK"},
                {"source": "Payment Service", "destination": "Transaction DB",
                 "data": "Transactions", "protocol": "PostgreSQL"},
                {"source": "User Service", "destination": "Payment Service",
                 "data": "Auth tokens", "protocol": "HTTP/2"}
            ],
            "trust_boundaries": [
                {"name": "Client Boundary",
                 "description": "Zone 0 (Mobile App) → Zone 1 (API Gateway)",
                 "components": ["Mobile App", "API Gateway"]},
                {"name": "Service Mesh Boundary",
                 "description": "Zone 1 → Zone 5 (Microservices)",
                 "components": ["API Gateway", "User Service", "Payment Service"]},
                {"name": "Data Boundary",
                 "description": "Zone 5 (Services) → Zone 7–8 (Databases)",
                 "components": ["User DB", "Transaction DB"]}
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
        "learning_objectives": [
            "Identify unique threats when multiple tenants share infrastructure",
            "Apply zone rules to detect cross-tenant data leakage paths",
            "Design tenant isolation using database-level Row-Level Security",
            "Understand how STRIDE Elevation of Privilege maps to tenant context bypass",
            "Master the SOC 2 and ISO 27001 compliance implications of multi-tenancy"
        ],
        "scenario": {
            "title": "DataInsight Analytics Platform",
            "description": "Shared infrastructure with logical tenant isolation",
            "business_context": "B2B SaaS, 500 enterprise customers",
            "assets": ["Business intelligence data", "Tenant metadata", "API keys", "Proprietary analytics"],
            "objectives": ["Tenant isolation", "Data integrity", "99.99% SLA"],
            "compliance": ["SOC 2 Type II", "ISO 27001", "GDPR"],
            "components": [
                {"name": "Web Dashboard", "type": "external_entity",
                 "description": "React SPA (tenant user)", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "API Gateway", "type": "process",
                 "description": "Kong – tenant routing", "zone": "Minimal Trust", "zone_score": 2},
                {"name": "Ingestion Service", "type": "process",
                 "description": "Data ingestion (shared)", "zone": "Standard Application", "zone_score": 3},
                {"name": "Query Service", "type": "process",
                 "description": "Analytics query engine", "zone": "Standard Application", "zone_score": 3},
                {"name": "Kafka", "type": "datastore",
                 "description": "MSK streaming – shared topics", "zone": "Elevated Trust", "zone_score": 5},
                {"name": "Data Warehouse", "type": "datastore",
                 "description": "Redshift – ALL tenant data", "zone": "Critical", "zone_score": 8}
            ],
            "data_flows": [
                {"source": "Web Dashboard", "destination": "API Gateway",
                 "data": "Tenant requests", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "Ingestion Service",
                 "data": "Data upload", "protocol": "HTTPS"},
                {"source": "Ingestion Service", "destination": "Kafka",
                 "data": "Events", "protocol": "Kafka protocol"},
                {"source": "Kafka", "destination": "Query Service",
                 "data": "Streaming data", "protocol": "Kafka Consumer"},
                {"source": "Query Service", "destination": "Data Warehouse",
                 "data": "SQL queries", "protocol": "Redshift JDBC"},
                {"source": "Data Warehouse", "destination": "Query Service",
                 "data": "Query results", "protocol": "Redshift JDBC"}
            ],
            "trust_boundaries": [
                {"name": "Tenant Boundary",
                 "description": "Zone 0 (Tenant User) → Zone 2 (API Gateway)",
                 "components": ["Web Dashboard", "API Gateway"]},
                {"name": "Isolation Boundary",
                 "description": "Zone 2-3 (Services) ← MUST enforce tenant_id →",
                 "components": ["Ingestion Service", "Query Service", "Kafka"]},
                {"name": "Shared Data Boundary",
                 "description": "Zone 3-5 → Zone 8 (Data Warehouse – ALL tenant data)",
                 "components": ["Kafka", "Data Warehouse"]}
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
        "learning_objectives": [
            "Apply Maximum Security (zone 9) designations to life-critical components",
            "Understand physical trust boundaries in IoT device environments",
            "Map STRIDE threats to FDA medical device cybersecurity requirements",
            "Identify how replay attacks bypass zone boundaries in safety-critical systems",
            "Design redundant safety-critical alert delivery against DoS threats"
        ],
        "scenario": {
            "title": "HealthMonitor Connected Care",
            "description": "IoT Devices + Edge Gateway + Cloud + Legacy Integration",
            "business_context": "FDA-registered device, 10K patients",
            "assets": ["PHI (HIPAA-regulated)", "Vital signs (safety-critical)",
                       "Device calibration data", "Clinical alert state"],
            "objectives": ["Safety: Data integrity (HIGHEST PRIORITY)",
                           "Privacy: PHI protection",
                           "Availability: 99.99% (life-critical)"],
            "compliance": ["HIPAA", "FDA 21 CFR Part 11", "HITECH", "IEC 62304"],
            "components": [
                {"name": "Glucose Monitor", "type": "external_entity",
                 "description": "CGM device (patient home – physical access)", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "IoT Gateway", "type": "process",
                 "description": "Edge device (patient home)", "zone": "Minimal Trust", "zone_score": 1},
                {"name": "Device Data Svc", "type": "process",
                 "description": "Cloud telemetry processor", "zone": "Standard Application", "zone_score": 4},
                {"name": "Alert Service", "type": "process",
                 "description": "SAFETY-CRITICAL alert dispatch", "zone": "Maximum Security", "zone_score": 9},
                {"name": "Patient DB", "type": "datastore",
                 "description": "Aurora – PHI (HIPAA)", "zone": "Maximum Security", "zone_score": 9},
                {"name": "Web Portal", "type": "external_entity",
                 "description": "Clinician portal", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "Legacy EHR", "type": "external_entity",
                 "description": "Hospital EHR via HL7 v2", "zone": "Not in Control of System", "zone_score": 0}
            ],
            "data_flows": [
                {"source": "Glucose Monitor", "destination": "IoT Gateway",
                 "data": "Glucose readings", "protocol": "BLE"},
                {"source": "IoT Gateway", "destination": "Device Data Svc",
                 "data": "Vital signs telemetry", "protocol": "MQTT/TLS"},
                {"source": "Device Data Svc", "destination": "Alert Service",
                 "data": "Alert events", "protocol": "HTTP/2"},
                {"source": "Alert Service", "destination": "Web Portal",
                 "data": "Clinical alerts", "protocol": "WebSocket"},
                {"source": "Device Data Svc", "destination": "Patient DB",
                 "data": "PHI records", "protocol": "PostgreSQL"},
                {"source": "Device Data Svc", "destination": "Legacy EHR",
                 "data": "HL7 messages", "protocol": "MLLP/HL7v2"}
            ],
            "trust_boundaries": [
                {"name": "Physical Device Boundary",
                 "description": "Zone 0 (Physical device at patient home) → Zone 1 (IoT Gateway)",
                 "components": ["Glucose Monitor", "IoT Gateway"]},
                {"name": "Edge-to-Cloud Boundary",
                 "description": "Zone 1 (Edge) → Zone 4 (Cloud processing)",
                 "components": ["IoT Gateway", "Device Data Svc"]},
                {"name": "Safety-Critical Boundary",
                 "description": "Zone 4 → Zone 9 (Life-critical systems – Maximum Security)",
                 "components": ["Alert Service", "Patient DB"]}
            ]
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK TREES
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_TREES = {
    "1": {
        "title": "Attack Tree: Compromise E-Commerce Platform",
        "description": "Complete attack tree showing multiple paths to steal customer payment data from TechMart",
        "tree": {
            "type": "goal", "label": "GOAL: Steal Customer\nPayment Data",
            "children": [
                {"type": "or", "label": "Compromise Database",
                 "children": [
                     {"type": "and", "label": "SQL Injection Attack",
                      "children": [
                          {"type": "leaf", "label": "Find injectable\nparameter", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Bypass input\nvalidation", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Extract data via\nUNION query", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Steal Database Backup",
                      "children": [
                          {"type": "leaf", "label": "Find misconfigured\nS3 bucket", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Download backup\nfile", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Decrypt if\nencrypted", "difficulty": "Hard"}
                      ]}
                 ]},
                {"type": "or", "label": "Intercept Data in Transit",
                 "children": [
                     {"type": "and", "label": "Man-in-the-Middle",
                      "children": [
                          {"type": "leaf", "label": "Position on\nnetwork path", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Downgrade to HTTP\nor weak TLS", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Capture payment\ndata", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "XSS + Session Hijacking",
                      "children": [
                          {"type": "leaf", "label": "Inject XSS payload\nin search/comments", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Steal session\ncookie", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Access user account\n& payment methods", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Compromise API Backend",
                 "children": [
                     {"type": "and", "label": "Exploit Admin Panel",
                      "children": [
                          {"type": "leaf", "label": "Find admin\nendpoint", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Bypass authorization\ncheck", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Export customer\ndata", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "API Key Exposure",
                      "children": [
                          {"type": "leaf", "label": "Find hardcoded keys\nin frontend code", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Use Stripe secret\nkey", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Create fraudulent\ncharges", "difficulty": "Easy"}
                      ]}
                 ]}
            ]
        }
    },
    "2": {
        "title": "Attack Tree: Unauthorized Fund Transfer",
        "description": "Attack tree for stealing money from mobile banking application",
        "tree": {
            "type": "goal", "label": "GOAL: Unauthorized\nFund Transfer",
            "children": [
                {"type": "or", "label": "Exploit API Authorization",
                 "children": [
                     {"type": "and", "label": "BOLA Attack",
                      "children": [
                          {"type": "leaf", "label": "Enumerate account\nIDs", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Access other user's\ntransaction API", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Initiate transfer from\nvictim account", "difficulty": "Medium"}
                      ]},
                     {"type": "and", "label": "Token Theft from Mobile",
                      "children": [
                          {"type": "leaf", "label": "Install malware on\nuser device", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Extract JWT from\napp storage", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Replay token to\nAPI Gateway", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Exploit Service Mesh",
                 "children": [
                     {"type": "and", "label": "Service Impersonation",
                      "children": [
                          {"type": "leaf", "label": "Gain access to\nKubernetes cluster", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Deploy rogue\nPayment Service", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Intercept transfer\nrequests", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Replay Transaction",
                      "children": [
                          {"type": "leaf", "label": "Capture valid\ntransaction token", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Replay to Payment\nService", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Double-process\ntransfer", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Bypass Rate Limiting",
                 "children": [
                     {"type": "and", "label": "Distributed Attack",
                      "children": [
                          {"type": "leaf", "label": "Rent botnet with\n10K+ IPs", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Bypass per-IP\nrate limits", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Brute force account\ncredentials", "difficulty": "Medium"}
                      ]}
                 ]}
            ]
        }
    },
    "3": {
        "title": "Attack Tree: Cross-Tenant Data Breach",
        "description": "Attack tree for accessing competitor's business intelligence data in SaaS platform",
        "tree": {
            "type": "goal", "label": "GOAL: Access Competitor's\nBusiness Data",
            "children": [
                {"type": "or", "label": "SQL Injection Bypass",
                 "children": [
                     {"type": "and", "label": "Remove Tenant Filter",
                      "children": [
                          {"type": "leaf", "label": "Find custom SQL\nquery endpoint", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Inject SQL to remove\ntenant_id filter", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Extract all tenants'\ndata", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Bypass RLS Policy",
                      "children": [
                          {"type": "leaf", "label": "Find DB without\nRLS configured", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Direct query without\ntenant context", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Access Redshift\nwithout filters", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Tenant Context Manipulation",
                 "children": [
                     {"type": "and", "label": "JWT Token Tampering",
                      "children": [
                          {"type": "leaf", "label": "Capture own JWT\ntoken", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Modify tenant_id\nclaim", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Re-sign with weak\nkey", "difficulty": "Hard"}
                      ]},
                     {"type": "and", "label": "Request Body Injection",
                      "children": [
                          {"type": "leaf", "label": "Find API accepting\ntenant_id in body", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Change tenant_id to\ntarget tenant", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Write/read data in\nvictim tenant", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Shared Resource Access",
                 "children": [
                     {"type": "and", "label": "Kafka Topic Cross-Read",
                      "children": [
                          {"type": "leaf", "label": "Access shared Kafka\ncluster", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Subscribe to all\ntopics (no ACL)", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Read cross-tenant\nmessages", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Shared Encryption Key",
                      "children": [
                          {"type": "leaf", "label": "Compromise own\ntenant DEK", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Discover same key\nused for all", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Decrypt competitor\nbackups", "difficulty": "Easy"}
                      ]}
                 ]}
            ]
        }
    },
    "4": {
        "title": "Attack Tree: Patient Harm via Medical Device",
        "description": "Attack tree showing paths to cause patient harm through device compromise",
        "tree": {
            "type": "goal", "label": "GOAL: Cause Patient Harm\nvia Device Compromise",
            "children": [
                {"type": "or", "label": "Suppress Critical Alerts",
                 "children": [
                     {"type": "and", "label": "Alert Flooding DoS",
                      "children": [
                          {"type": "leaf", "label": "Gain network access\nto alert system", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Flood queue with\nfake P2 alerts", "difficulty": "Easy"},
                          {"type": "leaf", "label": "P0 cardiac arrest\nalert delayed", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Replay Normal Readings",
                      "children": [
                          {"type": "leaf", "label": "Capture MQTT vitals\nmessages", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Replay old 'normal'\nreadings", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Critical vitals\nnot reported", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Tamper with Device",
                 "children": [
                     {"type": "and", "label": "Physical Firmware Mod",
                      "children": [
                          {"type": "leaf", "label": "Physical access to\nglucose monitor", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Bypass secure boot\nor remove TPM", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Flash malicious\nfirmware", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Device reports false\n'normal' readings", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "BLE MITM Attack",
                      "children": [
                          {"type": "leaf", "label": "Position within BLE\nrange (~10m)", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Exploit unencrypted\nBLE pairing", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Inject false glucose\nreadings", "difficulty": "Medium"}
                      ]}
                 ]},
                {"type": "or", "label": "Inject HL7 Messages",
                 "children": [
                     {"type": "and", "label": "Hospital Network Attack",
                      "children": [
                          {"type": "leaf", "label": "Access hospital\nnetwork (phishing)", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Locate HL7 interface\non VLAN", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Inject malicious HL7\nmessage", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Modify prescription\nto lethal dose", "difficulty": "Easy"}
                      ]}
                 ]}
            ]
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# DIAGRAM GENERATORS
# ─────────────────────────────────────────────────────────────────────────────
ZONE_COLORS = {
    "Not in Control of System": "#F5F5F5",
    "Minimal Trust": "#C8E6C9",
    "Standard Application": "#FFF9C4",
    "Elevated Trust": "#FFE0B2",
    "Critical": "#FFCDD2",
    "Maximum Security": "#D32F2F"
}

ZONE_FONT_COLORS = {
    "Not in Control of System": "black",
    "Minimal Trust": "black",
    "Standard Application": "black",
    "Elevated Trust": "black",
    "Critical": "black",
    "Maximum Security": "white"
}


def generate_zone_labeled_dfd(workshop_config, show_stride_rules=False, threats=None):
    """Generate DFD with criticality zone labels (Infosec methodology Step 2)."""
    try:
        dot = Digraph(comment="Zone-Labeled DFD", format="png")
        dot.attr(rankdir="LR", size="16,12", fontname="Arial", bgcolor="white",
                 splines="polyline", nodesep="0.8", ranksep="1.2")
        dot.attr("node", fontname="Arial", fontsize="10")
        dot.attr("edge", fontname="Arial", fontsize="9")

        node_zones = {c["name"]: c.get("zone", "Standard Application")
                      for c in workshop_config["scenario"]["components"]}
        node_scores = {c["name"]: c.get("zone_score", 3)
                       for c in workshop_config["scenario"]["components"]}

        type_shapes = {
            "external_entity": "oval",
            "process": "box",
            "datastore": "cylinder"
        }

        threat_nodes = set()
        threat_flows = set()
        if threats:
            for t in threats:
                comp = t.get("component", "")
                if "→" in comp:
                    threat_flows.add(comp)
                else:
                    threat_nodes.add(comp)

        # Group components by zone for subgraphs
        zone_comps = {}
        for comp in workshop_config["scenario"]["components"]:
            z = comp.get("zone", "Standard Application")
            zone_comps.setdefault(z, []).append(comp)

        zone_order = ["Not in Control of System", "Minimal Trust", "Standard Application",
                      "Elevated Trust", "Critical", "Maximum Security"]

        for z_idx, zone_name in enumerate(zone_order):
            if zone_name not in zone_comps:
                continue
            fill = ZONE_COLORS.get(zone_name, "#E0E0E0")
            fc = ZONE_FONT_COLORS.get(zone_name, "black")
            score = CRITICALITY_ZONES[zone_name]["score"]

            with dot.subgraph(name=f"cluster_{z_idx}") as sg:
                sg.attr(
                    label=f"Zone: {zone_name} (Score: {score})",
                    style="dashed,filled",
                    fillcolor=fill,
                    color="purple",
                    fontsize="11",
                    fontcolor="purple",
                    penwidth="2"
                )
                for comp in zone_comps[zone_name]:
                    name = comp["name"]
                    shape = type_shapes.get(comp["type"], "box")
                    node_fill = "#90EE90" if name in threat_nodes else fill
                    border = "red" if name in threat_nodes else "black"
                    pw = "3" if name in threat_nodes else "1.5"
                    score_val = comp.get("zone_score", score)
                    label = f"{name}\\n[{comp['description'][:25]}]\\nCriticality: {score_val}"
                    sg.node(name, label,
                            shape=shape,
                            style="filled",
                            fillcolor=node_fill,
                            color=border,
                            penwidth=pw,
                            fontcolor=fc if name not in threat_nodes else "black")

        # Edges (data flows)
        for flow in workshop_config["scenario"]["data_flows"]:
            src, dst = flow["source"], flow["destination"]
            key = f"{src} → {dst}"
            src_score = node_scores.get(src, 3)
            dst_score = node_scores.get(dst, 3)

            # Determine STRIDE edge annotation
            stride_ann = ""
            if show_stride_rules:
                if src_score < dst_score:
                    stride_ann = "⚠ T"
                elif src_score > dst_score:
                    stride_ann = "⚠ I"
                if src_score == 0:
                    stride_ann += "/D"

            color = "red" if key in threat_flows else ("blue" if show_stride_rules and stride_ann else "black")
            pw = "3" if key in threat_flows else "1.5"
            lbl = f"{flow['data']}\\n{flow['protocol']}"
            if stride_ann:
                lbl += f"\\n[{stride_ann}]"

            dot.edge(src, dst, label=lbl, color=color, penwidth=pw,
                     fontsize="8")

        path = dot.render("zone_dfd", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        st.error(f"Diagram error: {e}")
        return None


def generate_stride_annotated_dfd(workshop_config, threats=None):
    """DFD with STRIDE annotations on edges and nodes (Step 3 output)."""
    return generate_zone_labeled_dfd(workshop_config, show_stride_rules=True, threats=threats)


def generate_attack_tree(tree_structure, title="Attack Tree"):
    """Generate attack tree visualization."""
    try:
        dot = Digraph(comment=title, format="png")
        dot.attr(rankdir="TB", size="16,20", fontname="Arial", bgcolor="white")
        dot.attr("node", fontname="Arial", fontsize="9", shape="box", style="rounded,filled")
        dot.attr("edge", fontname="Arial", fontsize="8")
        counter = [0]

        def add_node(node, parent_id=None):
            counter[0] += 1
            nid = f"n{counter[0]}"
            ntype = node.get("type", "leaf")
            if ntype == "goal":
                fill, shape = "#FFCDD2", "oval"
                lbl = node["label"]
            elif ntype == "and":
                fill, shape = "#BBDEFB", "box"
                lbl = f"{node['label']}\\n[AND – all steps required]"
            elif ntype == "or":
                fill, shape = "#C8E6C9", "box"
                lbl = f"{node['label']}\\n[OR – any path succeeds]"
            else:
                fill, shape = "#FFF9C4", "box"
                diff = node.get("difficulty", "")
                diff_colors = {"Easy": "🔴", "Medium": "🟡", "Hard": "🟢", "Critical": "⚫"}
                lbl = node["label"]
                if diff:
                    lbl += f"\\n{diff_colors.get(diff, '')} {diff}"
            dot.node(nid, lbl, fillcolor=fill, shape=shape)
            if parent_id:
                dot.edge(parent_id, nid)
            for child in node.get("children", []):
                add_node(child, nid)
            return nid

        add_node(tree_structure)
        path = dot.render("attack_tree", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        st.error(f"Attack tree error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────────────────────────────────────
def calculate_threat_score(user_threat, predefined_threat):
    score, max_score, feedback = 0, predefined_threat["points"], []

    if user_threat["component"] == predefined_threat["component"]:
        score += 2; feedback.append("✓ Correct component identified")
    else:
        feedback.append(f"✗ Wrong component. Expected: {predefined_threat['component']}")

    if user_threat["stride"] == predefined_threat["stride"]:
        score += 2; feedback.append("✓ Correct STRIDE category")
    else:
        feedback.append(f"✗ Wrong STRIDE. Expected: {predefined_threat['stride']}")

    if user_threat["likelihood"] == predefined_threat["likelihood"]:
        score += 1; feedback.append("✓ Correct likelihood")
    else:
        feedback.append(f"✗ Likelihood should be: {predefined_threat['likelihood']}")

    if user_threat["impact"] == predefined_threat["impact"]:
        score += 1; feedback.append("✓ Correct impact")
    else:
        feedback.append(f"✗ Impact should be: {predefined_threat['impact']}")

    correct_mits = set(predefined_threat["correct_mitigations"])
    user_mits = set(user_threat.get("selected_mitigations", []))
    incorrect_mits = set(predefined_threat.get("incorrect_mitigations", []))
    correct_selected = user_mits & correct_mits
    incorrect_selected = user_mits & incorrect_mits

    if len(correct_selected) >= 3:
        score += 4; feedback.append(f"✓ Excellent mitigation selection ({len(correct_selected)} correct)")
    elif len(correct_selected) >= 2:
        score += 3; feedback.append(f"✓ Good mitigation selection ({len(correct_selected)} correct)")
    elif len(correct_selected) >= 1:
        score += 2; feedback.append(f"⚠ Partial mitigation selection ({len(correct_selected)} correct)")
    else:
        feedback.append("✗ No correct mitigations selected")

    if incorrect_selected:
        score -= len(incorrect_selected)
        feedback.append(f"✗ Incorrect mitigations penalty: {', '.join(incorrect_selected)}")

    return max(0, score), max_score, feedback


# ─────────────────────────────────────────────────────────────────────────────
# PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────
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
    except Exception:
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
    except Exception:
        pass


load_progress()


def is_workshop_unlocked(ws_id):
    return ws_id in st.session_state.unlocked_workshops


# ─────────────────────────────────────────────────────────────────────────────
# PDF GENERATORS
# ─────────────────────────────────────────────────────────────────────────────
def generate_user_threat_model_pdf(workshop_config, user_answers, total_score, max_score):
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=22,
                                     textColor=colors.HexColor('#1976D2'),
                                     spaceAfter=20, alignment=TA_CENTER)
        h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                            textColor=colors.HexColor('#028090'), spaceAfter=10, spaceBefore=10)

        story.append(Paragraph("STRIDE Threat Model Report", title_style))
        story.append(Paragraph(workshop_config['name'], styles['Heading2']))
        story.append(Spacer(1, 0.2 * inch))

        final_pct = (total_score / max_score * 100) if max_score else 0
        meta = [
            ['Report Type:', 'User Submission'],
            ['Workshop Level:', workshop_config['level']],
            ['Architecture:', workshop_config.get('architecture_type', 'N/A')],
            ['Methodology:', '4-Step Infosec Threat Modeling'],
            ['Date:', datetime.now().strftime('%Y-%m-%d %H:%M')],
            ['Score:', f"{total_score}/{max_score} ({final_pct:.1f}%)"]
        ]
        t = Table(meta, colWidths=[2 * inch, 4 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E3F2FD')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(PageBreak())

        story.append(Paragraph("4-Step Methodology Applied", h2))
        steps = [
            "Step 1: Design – DFD with interactors, modules, and connections",
            "Step 2: Apply Zones of Trust – Criticality labelling (0–9 scale)",
            "Step 3: Discover Threats – STRIDE rules based on zone relationships",
            "Step 4: Explore Mitigations – OWASP Top 10 control mapping"
        ]
        for s in steps:
            story.append(Paragraph(f"• {s}", styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Identified Threats", h2))
        for idx, answer in enumerate(user_answers, 1):
            pct = answer['score'] / answer['max_score'] * 100
            pred = answer.get('predefined_threat', {})
            story.append(Paragraph(f"Threat {idx}: {answer.get('matched_threat_id', 'N/A')}", styles['Heading3']))

            row = [
                ['Component:', answer['component']],
                ['STRIDE:', answer['stride']],
                ['Zone Rule:', pred.get('stride_rule_applied', 'N/A')],
                ['OWASP:', ', '.join(pred.get('owasp_categories', []))],
                ['Risk:', f"{answer['likelihood']} likelihood × {answer['impact']} impact"],
                ['Score:', f"{answer['score']}/{answer['max_score']} ({pct:.0f}%)"]
            ]
            rt = Table(row, colWidths=[1.8 * inch, 4.5 * inch])
            rt.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FFF9C4')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(rt)
            story.append(Spacer(1, 0.1 * inch))

            if answer.get('selected_mitigations'):
                story.append(Paragraph("<b>Selected Mitigations:</b>", styles['Normal']))
                for m in answer['selected_mitigations']:
                    story.append(Paragraph(f"• {m}", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        st.error(f"PDF error: {e}")
        return None


def generate_complete_threat_model_pdf(workshop_config, workshop_id):
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        story = []

        all_threats = PREDEFINED_THREATS.get(workshop_id, [])

        title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=22,
                                     textColor=colors.HexColor('#1976D2'),
                                     spaceAfter=20, alignment=TA_CENTER)
        h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                            textColor=colors.HexColor('#028090'), spaceAfter=10, spaceBefore=10)
        h3 = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12,
                            textColor=colors.HexColor('#2C5F2D'), spaceAfter=8, spaceBefore=8)

        # Cover
        story.append(Paragraph("COMPREHENSIVE THREAT MODEL", title_style))
        story.append(Paragraph(workshop_config['name'], styles['Heading2']))
        story.append(Paragraph(workshop_config['scenario']['title'], styles['Heading3']))
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("<b>Methodology:</b> 4-Step Infosec Threat Modeling (Design → Zones → STRIDE → OWASP Mitigations)", styles['Normal']))
        story.append(PageBreak())

        # Step 2: Zone Labels
        story.append(Paragraph("Step 2: Criticality Zone Labels", h2))
        zone_data = [['Component', 'Type', 'Zone', 'Score (0-9)', 'STRIDE Focus']]
        for comp in workshop_config['scenario']['components']:
            zone = comp.get('zone', 'Standard Application')
            zinfo = CRITICALITY_ZONES.get(zone, {})
            zone_data.append([
                comp['name'], comp['type'].replace('_', ' ').title(),
                zone, str(comp.get('zone_score', '?')),
                zinfo.get('stride_applicability', '')[:60]
            ])
        zt = Table(zone_data, colWidths=[1.2 * inch, 1.2 * inch, 1.5 * inch, 0.8 * inch, 2.5 * inch])
        zt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#028090')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
        ]))
        story.append(zt)
        story.append(PageBreak())

        # Step 3: STRIDE Rules Applied
        story.append(Paragraph("Step 3: STRIDE Threat Discovery (Zone-Based Rules)", h2))
        stride_rule_text = """
        Threats are identified by applying STRIDE rules based on zone relationships:<br/>
        • <b>Tampering</b>: Data flow from LESS critical → MORE critical zone<br/>
        • <b>Information Disclosure</b>: Data flow from MORE critical → LESS critical zone<br/>
        • <b>Denial of Service</b>: Any flow from Zone 0 (Not in Control) → any other zone<br/>
        • <b>Spoofing</b>: Any node reachable by Zone 0 entities<br/>
        • <b>Repudiation</b>: Any node where both Spoofing AND Tampering apply<br/>
        • <b>Elevation of Privilege</b>: Any node connected to a lower-trust zone node
        """
        story.append(Paragraph(stride_rule_text, styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        # Threat catalog
        story.append(Paragraph("Step 3 + 4: Full Threat Catalog with OWASP Controls", h2))
        for idx, threat in enumerate(all_threats, 1):
            story.append(Paragraph(f"{threat['id']}: {threat.get('threat', '')}", h3))
            row = [
                ['STRIDE:', threat['stride']],
                ['Component:', threat['component']],
                ['Zone Rule:', threat.get('stride_rule_applied', 'N/A')],
                ['Risk:', f"{threat['likelihood']} likelihood × {threat['impact']} impact"],
                ['OWASP:', ', '.join(threat.get('owasp_categories', []))],
                ['Compliance:', threat.get('compliance', 'N/A')]
            ]
            rt = Table(row, colWidths=[1.5 * inch, 5 * inch])
            rt.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FFF9C4')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(rt)
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph(f"<b>Explanation:</b> {threat.get('explanation', '')}", styles['Normal']))
            story.append(Paragraph("<b>Mitigations (OWASP-aligned):</b>", styles['Normal']))
            for m in threat.get('correct_mitigations', []):
                story.append(Paragraph(f"• {m}", styles['Normal']))
            story.append(Paragraph(f"<b>Real-world example:</b> {threat.get('real_world', '')}", styles['Normal']))
            story.append(Spacer(1, 0.15 * inch))
            if idx % 2 == 0 and idx < len(all_threats):
                story.append(PageBreak())

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        st.error(f"Complete PDF error: {e}")
        import traceback; st.error(traceback.format_exc())
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.title("🔒 STRIDE Learning Lab")
    st.markdown("### 4-Step Methodology")
    st.markdown("""
    1. 🎨 **Design** – DFD
    2. 🏷️ **Zones of Trust** – 0–9 scale
    3. 🔍 **STRIDE** – rule-based discovery
    4. 🛡️ **Mitigations** – OWASP mapping
    """)
    st.markdown("---")

    if st.session_state.selected_workshop and st.session_state.max_score > 0:
        pct = st.session_state.total_score / st.session_state.max_score * 100
        st.markdown("### 📊 Current Score")
        st.progress(pct / 100)
        st.markdown(f"**{st.session_state.total_score}/{st.session_state.max_score}** ({pct:.1f}%)")
        if pct >= 90: st.success("🏆 Excellent!")
        elif pct >= 75: st.info("👍 Good!")
        elif pct >= 60: st.warning("📚 Keep learning!")
        else: st.error("💪 Review materials!")
        st.markdown("---")

    st.markdown("### Select Workshop")
    for ws_id, ws_config in WORKSHOPS.items():
        unlocked = is_workshop_unlocked(ws_id)
        completed = ws_id in st.session_state.completed_workshops
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"Workshop {ws_id}", key=f"ws_{ws_id}",
                         disabled=not unlocked, use_container_width=True):
                st.session_state.selected_workshop = ws_id
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                st.session_state.zone_labels = {}
                st.session_state.zone_scores = {}
                st.session_state.zone_labelling_done = False
                st.session_state.stride_rules_answers = {}
                st.session_state.stride_rules_submitted = False
                st.session_state.owasp_mapping_answers = {}
                st.session_state.owasp_mapping_submitted = False
                save_progress()
                st.rerun()
        with col2:
            if completed:
                st.markdown('<span class="badge-completed">✓</span>', unsafe_allow_html=True)
            elif not unlocked:
                st.markdown('<span class="badge-locked">🔒</span>', unsafe_allow_html=True)

        if not unlocked and ws_id != "1":
            uk = f"unlock_{ws_id}"
            if uk not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[uk] = False
            if st.button(f"🔓 Unlock", key=f"unlock_btn_{ws_id}", use_container_width=True):
                st.session_state.show_unlock_form[uk] = not st.session_state.show_unlock_form[uk]
                st.rerun()
            if st.session_state.show_unlock_form[uk]:
                with st.form(f"unlock_form_{ws_id}"):
                    st.caption("Enter the unlock code provided by your instructor")
                    code = st.text_input("Unlock Code", type="password", key=f"code_{ws_id}")
                    if st.form_submit_button("Submit"):
                        if code == WORKSHOP_CODES.get(ws_id):
                            st.session_state.unlocked_workshops.add(ws_id)
                            st.session_state.show_unlock_form[uk] = False
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
    with st.expander("📚 STRIDE Quick Reference"):
        st.markdown("""
        **S** – Spoofing: Identity impersonation  
        **T** – Tampering: Data modification  
        **R** – Repudiation: Denying actions  
        **I** – Info Disclosure: Data exposure  
        **D** – Denial of Service: Availability  
        **E** – Elevation of Privilege: Unauthorized access
        """)
    with st.expander("🏷️ Zone Scale Reference"):
        for z, info in CRITICALITY_ZONES.items():
            st.caption(f"**{z}** ({info['range']}): {info['description'][:50]}")


# ═══════════════════════════════════════════════════════════════════════════════
#  HOME PAGE
# ═══════════════════════════════════════════════════════════════════════════════
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling Learning Lab")
    st.markdown("### Master the 4-Step Infosec Threat Modeling Methodology")

    st.markdown("""
    <div class="info-box">
    <strong>Based on the Infosec Institute 4-Step Methodology:</strong><br>
    This lab teaches threat modeling the way security professionals actually do it — starting from 
    architecture design, applying criticality zones, discovering threats through systematic rules, 
    and mapping to OWASP controls. Not just theory — you'll <em>practice</em> every step.
    </div>
    """, unsafe_allow_html=True)

    # 4-step methodology overview
    st.markdown("### 📋 The 4-Step Threat Modeling Process")
    cols = st.columns(4)
    step_info = [
        ("1️⃣", "Design", "#E3F2FD", "Create DFD with interactors, modules (processes), data stores, and connections. Visualize the complete system."),
        ("2️⃣", "Zones of Trust", "#FFF9C4", "Label every component with a criticality zone (0=untrusted → 9=life-critical). Use numerical scores for granularity."),
        ("3️⃣", "STRIDE Discovery", "#FFE0B2", "Apply zone-based rules: Tampering flows upward (less→more critical), Info Disclosure flows downward, DoS from zone-0."),
        ("4️⃣", "OWASP Controls", "#E8F5E9", "Map each STRIDE threat to OWASP Top 10 vulnerabilities and apply specific security controls from OWASP guidance.")
    ]
    for col, (icon, title, color, desc) in zip(cols, step_info):
        with col:
            st.markdown(f"""
            <div class="methodology-step" style="background:{color}">
                <h3>{icon} {title}</h3>
                <p style="font-size:0.85em">{desc}</p>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # Workshop progression
    st.markdown("### 📊 Progressive Workshop Architecture")
    cols2 = st.columns(4)
    for idx, (ws_id, ws) in enumerate(WORKSHOPS.items()):
        with cols2[idx]:
            unlocked = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            badge = "✅ Completed" if completed else "🔓 Available" if unlocked else "🔒 Locked"
            color = "#2C5F2D" if completed else "#028090" if unlocked else "#757575"
            st.markdown(f"""
            <div style="padding:15px;border:2px solid {color};border-radius:8px">
                <h4>Workshop {ws_id}</h4>
                <p style="font-size:0.9em"><strong>{ws['scenario']['title']}</strong></p>
                <p style="font-size:0.8em;color:#666">{ws['level']} · {ws['target_threats']} threats</p>
                <p style="font-size:0.8em;color:#555">{ws.get('architecture_type','')}</p>
                <span style="background:{color};color:white;padding:3px 8px;border-radius:10px;font-size:0.8em">{badge}</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    ### 🎯 What Makes This Different

    Traditional STRIDE training teaches the categories in isolation. This lab teaches you to
    **apply STRIDE systematically using zone-based rules** — the same way Microsoft's threat
    modeling tool and professional security architects do it:

    - **Zones of Trust** make threat discovery *mechanical*, not guesswork
    - **Zone direction rules** tell you *exactly* which STRIDE categories apply to each flow
    - **OWASP mapping** gives you *concrete controls* for every identified threat
    - **Progressive workshops** build mastery from simple web apps to life-critical IoT systems

    Start with **Workshop 1** and work through all four to achieve mastery.
    """)
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
#  WORKSHOP SELECTED – STEP NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════════
current_workshop = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

st.title(current_workshop["name"])
st.markdown(f"**{current_workshop['level']}** | **{current_workshop['scenario']['title']}** | "
            f"4-Step Infosec Methodology")

# Progress bar across steps
step_labels = ["1️⃣ Design", "2️⃣ Zones", "2.5 STRIDE Rules", "3️⃣ Attack Tree",
               "4️⃣ Identify", "5️⃣ Assess", "6️⃣ Complete"]
step_values = [1, 2, 2.5, 3, 4, 5, 6]
cols_steps = st.columns(len(step_labels))
for col, label, val in zip(cols_steps, step_labels, step_values):
    with col:
        if st.session_state.current_step > val:
            st.markdown(f"✅ {label}")
        elif st.session_state.current_step == val:
            st.markdown(f"**▶️ {label}**")
        else:
            st.markdown(f"⭕ {label}")
st.markdown("---")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: DESIGN – SYSTEM OVERVIEW + HIGH-LEVEL DFD
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.current_step == 1:
    st.header("Step 1: Design the Threat Model")

    st.markdown("""
    <div class="methodology-step">
    <strong>🎨 Infosec Step 1: Design</strong><br>
    The first step is to create a Data Flow Diagram (DFD) that identifies all 
    <strong>Interactors</strong> (external entities), <strong>Modules</strong> (processes and data stores), 
    and <strong>Connections</strong> (data flows between them).<br><br>
    This visual representation is the foundation on which all subsequent threat analysis is built.
    </div>
    """, unsafe_allow_html=True)

    scenario = current_workshop["scenario"]

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("📋 System Overview")
        st.markdown(f"**System:** {scenario['description']}")
        st.markdown(f"**Business Context:** {scenario['business_context']}")

        st.markdown("### 🎯 Security Objectives (CIA)")
        for obj in scenario["objectives"]:
            st.markdown(f"- {obj}")

        st.markdown("### 💎 Critical Assets to Protect")
        for asset in scenario["assets"]:
            st.markdown(f"- {asset}")

        st.markdown("### 📜 Regulatory Compliance")
        for comp in scenario["compliance"]:
            st.markdown(f"- {comp}")

    with col2:
        st.markdown(f"""
        <div class="success-box">
        <strong>Workshop Objectives</strong><br><br>
        📊 Identify {current_workshop['target_threats']} threats<br>
        ⏱️ {current_workshop['duration']}<br>
        📈 {current_workshop['level']} level<br>
        🎯 Score 90%+ for mastery!<br><br>
        <strong>Learning Objectives:</strong>
        </div>
        """, unsafe_allow_html=True)
        for lo in current_workshop.get("learning_objectives", [])[:3]:
            st.markdown(f"• {lo}")

    st.markdown("---")

    # DFD ELEMENT TYPES – educational content
    st.subheader("📘 The 3 Types of DFD Elements")

    st.markdown("""
    <div class="info-box">
    Every threat model diagram uses exactly these three types of elements 
    (per the Infosec methodology). Learning to classify them correctly is essential — 
    because <strong>different element types are vulnerable to different STRIDE categories</strong>.
    </div>
    """, unsafe_allow_html=True)

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown("""
        <div class="methodology-step" style="background:#FFE5E5">
        <h4>👤 Interactors (External Entities)</h4>
        <p>People or systems <em>outside</em> your control that interact with your system.</p>
        <strong>Examples:</strong> End users, 3rd party APIs, payment processors<br><br>
        <strong>STRIDE exposure:</strong> Primary sources of Spoofing and Denial of Service threats.
        They are in <em>Zone 0 – Not in Control of System</em>.
        </div>
        """, unsafe_allow_html=True)
    with col_b:
        st.markdown("""
        <div class="methodology-step" style="background:#E3F2FD">
        <h4>⚙️ Modules (Processes & Data Stores)</h4>
        <p>Components <em>within</em> your system that process or store data.</p>
        <strong>Examples:</strong> API servers, databases, message queues<br><br>
        <strong>STRIDE exposure:</strong> All 6 STRIDE categories can apply — 
        processes are the most complex threat surface.
        </div>
        """, unsafe_allow_html=True)
    with col_c:
        st.markdown("""
        <div class="methodology-step" style="background:#E8F5E9">
        <h4>🔗 Connections (Data Flows)</h4>
        <p>The links between interactors and modules, carrying data.</p>
        <strong>Examples:</strong> HTTPS requests, SQL queries, MQTT messages<br><br>
        <strong>STRIDE exposure:</strong> Tampering, Information Disclosure, and Denial of Service 
        based on zone direction of the flow.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Component breakdown for this workshop
    st.subheader(f"📦 {scenario['title']} – DFD Elements")

    comp_types = {"external_entity": [], "process": [], "datastore": []}
    for comp in scenario["components"]:
        comp_types[comp["type"]].append(comp)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**👤 Interactors (External Entities)**")
        for comp in comp_types["external_entity"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br>
            <small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("**⚙️ Modules (Processes)**")
        for comp in comp_types["process"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br>
            <small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("**💾 Modules (Data Stores)**")
        for comp in comp_types["datastore"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br>
            <small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("🔗 Connections (Data Flows)")

    flows_df = pd.DataFrame([{
        "Source": f["source"], "→": "→", "Destination": f["destination"],
        "Data Type": f["data"], "Protocol": f["protocol"]
    } for f in scenario["data_flows"]])
    st.dataframe(flows_df, use_container_width=True, hide_index=True)

    st.markdown("""
    <div class="practical-task">
    <strong>🎯 Step 1 Complete</strong> – You now have a complete picture of the system design:<br>
    • All <strong>Interactors</strong> (external entities) identified<br>
    • All <strong>Modules</strong> (processes + data stores) listed<br>
    • All <strong>Connections</strong> (data flows) documented with protocols<br><br>
    Next: Apply <strong>Zones of Trust</strong> to every component using the 0–9 criticality scale.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    if st.button("Next: Apply Zones of Trust ➡️", type="primary", use_container_width=True):
        st.session_state.current_step = 2
        save_progress()
        st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: ZONES OF TRUST (INFOSEC STEP 2)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 2:
    st.header("Step 2: Apply Zones of Trust")

    st.markdown("""
    <div class="methodology-step">
    <strong>🏷️ Infosec Step 2: Apply Zones of Trust</strong><br>
    Every component in your DFD must be labeled with a <strong>criticality zone</strong>.
    Zones indicate how sensitive/trusted a component is, using both a <em>label</em> 
    (e.g., "Critical") and a <em>numerical score</em> (0–9).<br><br>
    <strong>Why this matters:</strong> The <em>direction</em> of data flows between zones 
    determines which STRIDE categories apply — this is the mechanical heart of the methodology.
    </div>
    """, unsafe_allow_html=True)

    # ZONE SCALE EXPLANATION
    st.subheader("🏷️ The Criticality Zone Scale")
    st.markdown("*(From the Infosec Institute threat modeling methodology)*")

    zone_cols = st.columns(3)
    zone_list = list(CRITICALITY_ZONES.items())
    for i, (zone_name, zinfo) in enumerate(zone_list):
        col = zone_cols[i % 3]
        with col:
            st.markdown(f"""
            <div style="background:{zinfo['color']};padding:12px;border-radius:6px;
                        border:2px solid {zinfo['border']};margin:6px 0">
                <strong>{zone_name}</strong><br>
                <span style="font-size:1.3em;font-weight:bold">Score: {zinfo['range']}</span><br>
                <small>{zinfo['description']}</small><br>
                <small><em>Examples: {zinfo['examples']}</em></small><br>
                <small style="color:#555">STRIDE: {zinfo['stride_applicability']}</small>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # PRACTICAL LABELLING EXERCISE
    st.subheader("🎯 Practical Exercise: Label Your System Components")

    st.markdown("""
    <div class="practical-task">
    <strong>Your Task:</strong> Assign a criticality zone to each component in the system.
    Think carefully about: How sensitive is the data? Who controls this component? 
    What is the impact if it's compromised?<br><br>
    After you submit, you'll see the <strong>correct answer</strong> and <strong>why</strong> 
    each zone was chosen — this teaches the reasoning, not just the answer.
    </div>
    """, unsafe_allow_html=True)

    scenario = current_workshop["scenario"]
    zone_options = list(CRITICALITY_ZONES.keys())

    with st.form("zone_labelling_form"):
        user_zone_labels = {}
        user_zone_scores_input = {}
        cols_zone = st.columns(2)

        for i, comp in enumerate(scenario["components"]):
            col = cols_zone[i % 2]
            with col:
                st.markdown(f"**{comp['name']}** — *{comp['description']}*")
                label_key = f"zone_label_{comp['name']}"
                score_key = f"zone_score_{comp['name']}"
                user_zone_labels[comp['name']] = st.selectbox(
                    f"Zone for {comp['name']}:",
                    zone_options,
                    key=label_key,
                    help="What criticality zone does this component belong to?"
                )
                user_zone_scores_input[comp['name']] = st.slider(
                    f"Numerical score (0–9) for {comp['name']}:",
                    0, 9, 3, key=score_key
                )
                st.markdown("---")

        submitted_zones = st.form_submit_button(
            "✅ Submit Zone Labels & See Results", type="primary", use_container_width=True
        )

    if submitted_zones or st.session_state.get('zone_labelling_done'):
        if submitted_zones:
            st.session_state.zone_labels = user_zone_labels
            st.session_state.zone_scores = user_zone_scores_input
            st.session_state.zone_labelling_done = True
            save_progress()

        st.markdown("---")
        st.subheader("📊 Zone Label Results & Explanation")

        correct_count = 0
        total_comps = len(scenario["components"])

        for comp in scenario["components"]:
            name = comp["name"]
            correct_zone = comp.get("zone", "Standard Application")
            correct_score = comp.get("zone_score", 3)
            user_zone_val = st.session_state.zone_labels.get(name, "")
            user_score_val = st.session_state.zone_scores.get(name, 0)
            zone_match = user_zone_val == correct_zone
            score_close = abs(user_score_val - correct_score) <= 1

            if zone_match:
                correct_count += 1
                status = "✅"
                css_class = "correct-answer"
            elif score_close:
                status = "⚠️"
                css_class = "partial-answer"
            else:
                status = "❌"
                css_class = "incorrect-answer"

            zinfo = CRITICALITY_ZONES.get(correct_zone, {})
            st.markdown(f"""
            <div class="{css_class}">
            {status} <strong>{name}</strong><br>
            Your label: <em>{user_zone_val}</em> (score: {user_score_val}) →
            Correct: <strong>{correct_zone}</strong> (score: {correct_score})<br>
            <strong>Why:</strong> {comp['description']}. 
            {zinfo.get('stride_applicability', '')}
            </div>
            """, unsafe_allow_html=True)

        score_pct = correct_count / total_comps * 100
        st.markdown(f"""
        <div class="{'score-excellent' if score_pct>=80 else 'score-good' if score_pct>=60 else 'score-fair'}">
        Zone Labelling Score: {correct_count}/{total_comps} ({score_pct:.0f}%)
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")
        st.subheader("📊 Zone-Labeled DFD")

        st.markdown("""
        <div class="info-box">
        The diagram below shows the correct zone assignments for all components.
        The zone boundaries (shown as dashed boxes) are where data crosses trust levels —
        these are the highest-risk areas for your threat analysis in Step 3.
        </div>
        """, unsafe_allow_html=True)

        with st.spinner("Generating zone-labeled DFD..."):
            zone_dfd = generate_zone_labeled_dfd(current_workshop)

        if zone_dfd:
            st.image(f"data:image/png;base64,{zone_dfd}",
                     caption=f"Zone-Labeled DFD – {scenario['title']}",
                     use_column_width=True)

        # Trust boundaries explanation
        st.markdown("---")
        st.subheader("🔒 Trust Boundaries – Where Threats Are Born")

        st.markdown("""
        A **trust boundary** is a line in your DFD that separates components of different 
        criticality zones. When data crosses a trust boundary:
        - The **direction** (up or down in zone score) determines which STRIDE threats apply
        - **Zone 0 → any zone**: Always check Spoofing and DoS
        - **Lower zone → Higher zone**: Always check Tampering
        - **Higher zone → Lower zone**: Always check Information Disclosure
        """)

        for boundary in scenario["trust_boundaries"]:
            with st.expander(f"🔐 {boundary['name']}", expanded=True):
                st.markdown(f"**Crossing:** {boundary['description']}")
                if boundary.get("components"):
                    st.markdown(f"**Components at boundary:** {', '.join(boundary['components'])}")
                # Find relevant flows for this boundary
                boundary_comps = set(boundary.get("components", []))
                relevant_flows = [
                    f for f in scenario["data_flows"]
                    if f["source"] in boundary_comps or f["destination"] in boundary_comps
                ]
                if relevant_flows:
                    st.markdown("**Flows crossing this boundary:**")
                    for rf in relevant_flows:
                        src_score = next((c["zone_score"] for c in scenario["components"] if c["name"] == rf["source"]), 0)
                        dst_score = next((c["zone_score"] for c in scenario["components"] if c["name"] == rf["destination"]), 0)
                        direction = "📈 less→more critical (⚠ Tampering risk)" if dst_score > src_score else "📉 more→less critical (⚠ Info Disclosure risk)"
                        st.markdown(f"  → **{rf['source']}** → **{rf['destination']}**: {rf['data']} ({rf['protocol']}) — {direction}")

        st.markdown("""
        <div class="practical-task">
        <strong>✅ Step 2 Complete</strong><br>
        You have applied criticality zones to all components. Now you can use zone direction 
        to <strong>mechanically derive</strong> which STRIDE threats apply to each flow and node.
        This is the key insight from the Infosec methodology: 
        STRIDE is not guesswork — it follows rules.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Design", use_container_width=True):
            st.session_state.current_step = 1
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: STRIDE Rules ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 2.5
            save_progress()
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2.5: STRIDE RULES + OWASP MAPPING (INFOSEC STEPS 3 & 4 THEORY)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 2.5:
    st.header("Step 2.5: STRIDE Rules + OWASP Mapping")

    st.markdown("""
    <div class="methodology-step">
    <strong>🔍 Infosec Step 3 (Theory): STRIDE Discovery Rules</strong><br>
    STRIDE threats are not discovered by intuition — they are <em>derived mechanically</em> 
    from your zone-labeled DFD using a specific set of rules. Once you know the zones, 
    you know exactly which STRIDE categories apply to each element.
    </div>
    """, unsafe_allow_html=True)

    # STRIDE RULES REFERENCE TABLE
    st.subheader("📜 The STRIDE Zone-Direction Rules")

    st.markdown("""
    <div class="stride-rule-box">
    <strong>How to read the rules:</strong> Look at each connection (flow) and node in your DFD.
    Check its zone relationship. The rules below tell you which STRIDE categories are applicable.
    </div>
    """, unsafe_allow_html=True)

    # Flows rules
    st.markdown("#### 🔗 Rules for Connections (Data Flows)")

    flow_rules_data = [
        ["Tampering (T)", "Less critical → More critical zone",
         "Attacker at lower trust injects malicious data flowing into higher-trust system",
         "Zone 1 (Frontend) → Zone 7 (Database): SQL injection risk"],
        ["Information Disclosure (I)", "More critical → Less critical zone",
         "Sensitive data flowing outward may be captured or leaked",
         "Zone 7 (Database) → Zone 0 (User): PII exposed in API response"],
        ["Denial of Service (D)", "Zone 0 (External) → Any other zone",
         "External actors with no trust can flood any entry point they reach",
         "Zone 0 (User) → Zone 3 (API): Request flooding exhausts resources"]
    ]
    for rule_row in flow_rules_data:
        stride_cat, trigger, rationale, example = rule_row
        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>⚡ {stride_cat}</strong><br>
        <strong>Applies when:</strong> {trigger}<br>
        <strong>Why:</strong> {rationale}<br>
        <strong>Example:</strong> <em>{example}</em>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("#### 🔵 Rules for Nodes (Interactors, Processes, Data Stores)")

    node_rules_data = [
        ["Spoofing (S)", "Any node reachable by a Zone 0 (Not in Control) entity",
         "External actors can impersonate legitimate users/systems at any reachable node",
         "Login page reachable from Internet: Attacker impersonates valid user"],
        ["Repudiation (R)", "Any node where BOTH Spoofing AND Tampering apply",
         "If identity can be faked AND data modified, actions can be performed untraceably",
         "API server with user input: Orders placed, then denied as fake"],
        ["Denial of Service (D)", "Any node reachable by a Zone 0 entity",
         "External actors can exhaust resources of any node they can reach",
         "Public API endpoint: Botnet flood crashes the service"],
        ["Elevation of Privilege (E)", "Any node connected to a lower-criticality-zone node",
         "Attacker who compromises lower zone may gain higher-zone capabilities",
         "Admin API (zone 5) reachable from regular API (zone 3): Privilege escalation"]
    ]
    for rule_row in node_rules_data:
        stride_cat, trigger, rationale, example = rule_row
        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>⚡ {stride_cat}</strong><br>
        <strong>Applies when:</strong> {trigger}<br>
        <strong>Why:</strong> {rationale}<br>
        <strong>Example:</strong> <em>{example}</em>
        </div>
        """, unsafe_allow_html=True)

    # STRIDE PER ELEMENT TYPE
    st.markdown("---")
    st.subheader("📊 STRIDE per DFD Element Type (Quick Reference)")

    stride_matrix = pd.DataFrame({
        "Element Type": ["External Entity (Interactor)", "Process (Module)",
                         "Data Flow (Connection)", "Data Store (Module)"],
        "S – Spoofing": ["✓ YES (zone 0)", "✓ YES", "✓ YES", "— Rare"],
        "T – Tampering": ["— No", "✓ YES", "✓ YES (less→more)", "✓ YES"],
        "R – Repudiation": ["✓ YES", "✓ YES", "— No", "✓ YES"],
        "I – Info Disclosure": ["— No", "✓ YES", "✓ YES (more→less)", "✓ YES"],
        "D – Denial of Svc": ["— No", "✓ YES", "✓ YES (zone 0)", "✓ YES"],
        "E – Elev Privilege": ["— No", "✓ YES", "— No", "— No"]
    })
    st.dataframe(stride_matrix, use_container_width=True, hide_index=True)

    # INTERACTIVE STRIDE RULES EXERCISE
    st.markdown("---")
    st.subheader("🎯 Practical Exercise: Apply STRIDE Rules to Your Architecture")

    scenario = current_workshop["scenario"]
    st.markdown(f"""
    <div class="practical-task">
    <strong>Your Task:</strong> For each data flow below, identify which STRIDE categories apply 
    based on the zone direction rules you just learned. Select all that apply.
    </div>
    """, unsafe_allow_html=True)

    # Build correct answers per flow
    stride_flow_answers = {}
    for flow in scenario["data_flows"][:4]:  # First 4 flows for exercise
        src_comp = next((c for c in scenario["components"] if c["name"] == flow["source"]), None)
        dst_comp = next((c for c in scenario["components"] if c["name"] == flow["destination"]), None)
        if not src_comp or not dst_comp:
            continue
        src_score = src_comp.get("zone_score", 3)
        dst_score = dst_comp.get("zone_score", 3)
        correct = []
        if dst_score > src_score:
            correct.append("Tampering")
        if src_score > dst_score:
            correct.append("Information Disclosure")
        if src_score == 0:
            correct.append("Denial of Service")
            correct.append("Spoofing")
        stride_flow_answers[f"{flow['source']} → {flow['destination']}"] = {
            "correct": correct,
            "src_zone": src_comp.get("zone"), "src_score": src_score,
            "dst_zone": dst_comp.get("zone"), "dst_score": dst_score,
            "flow": flow
        }

    with st.form("stride_rules_form"):
        user_stride_selections = {}
        for flow_key, flow_info in stride_flow_answers.items():
            fl = flow_info["flow"]
            st.markdown(f"**Flow: {flow_key}** — {fl['data']} ({fl['protocol']})")
            st.caption(f"From: **{flow_info['src_zone']}** (score {flow_info['src_score']}) → "
                       f"To: **{flow_info['dst_zone']}** (score {flow_info['dst_score']})")
            user_stride_selections[flow_key] = st.multiselect(
                f"Which STRIDE categories apply to this flow?",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"],
                key=f"stride_ex_{flow_key}"
            )
            st.markdown("---")

        submitted_stride = st.form_submit_button(
            "✅ Check My STRIDE Rules Analysis", type="primary", use_container_width=True
        )

    if submitted_stride or st.session_state.get('stride_rules_submitted'):
        if submitted_stride:
            st.session_state.stride_rules_answers = user_stride_selections
            st.session_state.stride_rules_submitted = True
            save_progress()

        st.markdown("---")
        st.subheader("📋 STRIDE Rules Exercise Results")

        total_correct = 0
        total_questions = len(stride_flow_answers)

        for flow_key, flow_info in stride_flow_answers.items():
            correct_set = set(flow_info["correct"])
            user_set = set(st.session_state.stride_rules_answers.get(flow_key, []))
            fl = flow_info["flow"]

            matches = correct_set == user_set
            if matches:
                total_correct += 1
                status_class = "correct-answer"
                status_icon = "✅"
            else:
                status_class = "partial-answer" if correct_set & user_set else "incorrect-answer"
                status_icon = "⚠️" if correct_set & user_set else "❌"

            # Build the rule explanation
            rule_explanation = []
            if "Tampering" in correct_set:
                rule_explanation.append(f"**Tampering**: {flow_info['src_zone']} (zone {flow_info['src_score']}) → {flow_info['dst_zone']} (zone {flow_info['dst_score']}) — less→more critical")
            if "Information Disclosure" in correct_set:
                rule_explanation.append(f"**Information Disclosure**: {flow_info['src_zone']} (zone {flow_info['src_score']}) → {flow_info['dst_zone']} (zone {flow_info['dst_score']}) — more→less critical")
            if "Denial of Service" in correct_set:
                rule_explanation.append(f"**Denial of Service**: Source is Zone 0 (Not in Control) — can flood any target")
            if "Spoofing" in correct_set:
                rule_explanation.append(f"**Spoofing**: Zone 0 (external entity) can impersonate legitimate users at this entry point")

            st.markdown(f"""
            <div class="{status_class}">
            {status_icon} <strong>{flow_key}</strong> — {fl['data']}<br>
            Your answer: {', '.join(user_set) if user_set else 'None'}<br>
            Correct: <strong>{', '.join(correct_set) if correct_set else 'None'}</strong><br><br>
            <strong>Why these categories apply:</strong><br>
            {"<br>".join(["• " + r for r in rule_explanation]) if rule_explanation else "• No STRIDE categories apply to this flow based on zone rules"}
            </div>
            """, unsafe_allow_html=True)

        score_pct = total_correct / total_questions * 100 if total_questions else 0
        st.markdown(f"""
        <div class="{'score-excellent' if score_pct>=80 else 'score-good' if score_pct>=60 else 'score-fair'}">
        STRIDE Rules Score: {total_correct}/{total_questions} ({score_pct:.0f}%)
        </div>
        """, unsafe_allow_html=True)

    # OWASP MAPPING SECTION
    st.markdown("---")
    st.subheader("🛡️ Step 4: STRIDE → OWASP Top 10 Mapping")

    st.markdown("""
    <div class="methodology-step">
    <strong>🛡️ Infosec Step 4: Explore Mitigations (OWASP)</strong><br>
    Once threats are identified via STRIDE, you select mitigations from the 
    <strong>OWASP Top 10</strong> list. The table below shows which OWASP vulnerability 
    categories map to each STRIDE threat category — this is how professionals translate 
    threat categories into concrete security controls.
    </div>
    """, unsafe_allow_html=True)

    for stride_cat, owasp_info in OWASP_STRIDE_MAP.items():
        with st.expander(f"🔗 {stride_cat} → {' + '.join(owasp_info['owasp'])}", expanded=False):
            st.markdown(f"""
            <div class="owasp-box">
            <strong>OWASP Mapping:</strong> {', '.join(owasp_info['owasp'])}<br><br>
            <strong>Why these OWASP categories map to {stride_cat}:</strong><br>
            {owasp_info['owasp_detail']}
            </div>
            """, unsafe_allow_html=True)

            st.markdown("**OWASP-recommended controls:**")
            for ctrl in owasp_info["controls"]:
                st.markdown(f"• {ctrl}")

    # PRACTICAL OWASP MAPPING EXERCISE
    st.markdown("---")
    st.subheader("🎯 Practical Exercise: Map STRIDE to OWASP Controls")

    st.markdown("""
    <div class="practical-task">
    <strong>Your Task:</strong> For each STRIDE category below, select the correct OWASP Top 10 vulnerability 
    that maps to it. This tests whether you understand the <em>relationship</em> between threat categories 
    and vulnerability classifications.
    </div>
    """, unsafe_allow_html=True)

    owasp_exercise = {
        "Spoofing": {
            "question": "Which OWASP category directly enables Spoofing attacks?",
            "options": ["A01:2021 – Broken Access Control",
                        "A07:2021 – Identification and Authentication Failures",
                        "A03:2021 – Injection",
                        "A09:2021 – Security Logging and Monitoring Failures"],
            "correct": "A07:2021 – Identification and Authentication Failures",
            "explanation": "Broken Authentication (A07) means an attacker can bypass identity verification — directly enabling impersonation (Spoofing)."
        },
        "Tampering": {
            "question": "A SQL injection modifies database records. Which OWASP + STRIDE pairing is this?",
            "options": ["Information Disclosure + A02:2021 – Cryptographic Failures",
                        "Tampering + A03:2021 – Injection",
                        "Elevation of Privilege + A01:2021 – Broken Access Control",
                        "Denial of Service + A04:2021 – Insecure Design"],
            "correct": "Tampering + A03:2021 – Injection",
            "explanation": "SQL injection modifies data (Tampering) and maps to A03 – Injection, the most classic pairing in STRIDE/OWASP analysis."
        },
        "Information Disclosure": {
            "question": "Unencrypted data in a database backup is exposed. Which OWASP category applies?",
            "options": ["A01:2021 – Broken Access Control",
                        "A09:2021 – Security Logging and Monitoring Failures",
                        "A02:2021 – Cryptographic Failures",
                        "A08:2021 – Software and Data Integrity Failures"],
            "correct": "A02:2021 – Cryptographic Failures",
            "explanation": "Unencrypted data at rest or in transit is A02 – Cryptographic Failures (formerly 'Sensitive Data Exposure'). This directly causes Information Disclosure."
        },
        "Repudiation": {
            "question": "An attacker performs a fraudulent transaction and you cannot prove who did it. Which OWASP category?",
            "options": ["A05:2021 – Security Misconfiguration",
                        "A07:2021 – Identification and Authentication Failures",
                        "A09:2021 – Security Logging and Monitoring Failures",
                        "A04:2021 – Insecure Design"],
            "correct": "A09:2021 – Security Logging and Monitoring Failures",
            "explanation": "Without audit logs (A09 – Insufficient Logging), there is no evidence trail — enabling Repudiation."
        }
    }

    with st.form("owasp_mapping_form"):
        user_owasp_answers = {}
        for stride_q, q_data in owasp_exercise.items():
            st.markdown(f"**{stride_q} Scenario:** {q_data['question']}")
            user_owasp_answers[stride_q] = st.radio(
                f"Select the correct answer:",
                q_data["options"],
                key=f"owasp_q_{stride_q}",
                index=None
            )
            st.markdown("---")

        submitted_owasp = st.form_submit_button(
            "✅ Submit OWASP Mapping Answers", type="primary", use_container_width=True
        )

    if submitted_owasp or st.session_state.get('owasp_mapping_submitted'):
        if submitted_owasp:
            st.session_state.owasp_mapping_answers = user_owasp_answers
            st.session_state.owasp_mapping_submitted = True
            save_progress()

        st.markdown("---")
        st.subheader("📋 OWASP Mapping Results")
        owasp_correct = 0
        for stride_q, q_data in owasp_exercise.items():
            user_ans = st.session_state.owasp_mapping_answers.get(stride_q, "")
            is_correct = user_ans == q_data["correct"]
            if is_correct:
                owasp_correct += 1
            css = "correct-answer" if is_correct else "incorrect-answer"
            icon = "✅" if is_correct else "❌"
            st.markdown(f"""
            <div class="{css}">
            {icon} <strong>{stride_q}</strong><br>
            Your answer: {user_ans or 'Not answered'}<br>
            Correct: <strong>{q_data['correct']}</strong><br>
            <em>{q_data['explanation']}</em>
            </div>
            """, unsafe_allow_html=True)

        owasp_pct = owasp_correct / len(owasp_exercise) * 100
        st.markdown(f"""
        <div class="{'score-excellent' if owasp_pct>=80 else 'score-good' if owasp_pct>=60 else 'score-fair'}">
        OWASP Mapping Score: {owasp_correct}/{len(owasp_exercise)} ({owasp_pct:.0f}%)
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="practical-task">
    <strong>✅ Steps 3 & 4 Theory Complete</strong><br>
    You now know both the <strong>STRIDE rules</strong> (derived from zone relationships) 
    and the <strong>OWASP controls</strong> that address each STRIDE category.<br>
    Next: Build an <strong>Attack Tree</strong> to understand <em>how</em> attackers exploit these threats.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Zones", use_container_width=True):
            st.session_state.current_step = 2
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Build Attack Tree ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: ATTACK TREE
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 3:
    st.header("🌳 Step 3: Build an Attack Tree")

    st.markdown("""
    <div class="info-box">
    <h3>📚 What is an Attack Tree and How Does it Complement STRIDE?</h3>
    An <strong>Attack Tree</strong> shows HOW an attacker would exploit the STRIDE threats 
    you identified using zone rules. While STRIDE tells you WHAT threats exist, 
    attack trees show the step-by-step path an attacker takes.<br><br>
    <strong>The connection to your zones:</strong> Each leaf node in the attack tree 
    corresponds to a zone boundary crossing in your DFD.
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        ### Node Types
        **🎯 Goal Node (Root)** – Attacker's ultimate objective (PINK)  
        **AND Gate** – ALL child steps must succeed (BLUE)  
        **OR Gate** – ANY child path succeeds (GREEN)  
        **🟡 Leaf Nodes** – Specific attack steps with difficulty ratings
        
        ### Difficulty Ratings
        🔴 **Easy** – Automated tools, no skill needed  
        🟡 **Medium** – Some technical knowledge required  
        🟢 **Hard** – Expert skills or expensive resources  
        """)
    with col2:
        st.markdown("""
        ### How to Use Attack Trees with Zone Analysis
        
        1. **Start at Zone 0** – Attacker always begins outside your system
        2. **Trace zone crossings** – Each attack step crosses a trust boundary
        3. **AND gates = defense in depth** – Breaking one step blocks the path
        4. **OR gates = multiple attack surfaces** – Each must be defended
        5. **Easy leaf nodes = highest priority** – Attackers choose the path of least resistance
        """)

    st.markdown("---")
    st.subheader(f"📊 Attack Tree: {current_workshop['architecture_type']}")

    attack_tree_data = ATTACK_TREES.get(st.session_state.selected_workshop, {})
    if attack_tree_data:
        st.markdown(f"""
        <div class="learning-box">
        <strong>{attack_tree_data['title']}</strong><br>
        {attack_tree_data['description']}
        </div>
        """, unsafe_allow_html=True)

        with st.spinner("Generating attack tree..."):
            tree_img = generate_attack_tree(attack_tree_data["tree"], attack_tree_data["title"])

        if tree_img:
            st.image(f"data:image/png;base64,{tree_img}",
                     caption=attack_tree_data["title"], use_column_width=True)

        st.markdown("---")
        st.subheader("🔍 Connecting Attack Tree to Zone Analysis")

        ws_id = st.session_state.selected_workshop
        scenario = current_workshop["scenario"]

        if ws_id == "1":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for TechMart

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | API Key Exposure | Zone 3 (API) → Zone 0 (Public) | Information Disclosure (more→less) | 🔴 **CRITICAL** – 3 Easy steps |
            | XSS + Session Hijack | Zone 0 → Zone 1 then Zone 1 → Zone 3 | Tampering (less→more) + Spoofing | 🟡 **HIGH** – Medium+Easy+Easy |
            | SQL Injection | Zone 1 → Zone 3 → Zone 7 | Tampering (less→more × 2 zone jumps) | 🟡 **HIGH** – stops at validation |
            | Admin Panel Exploit | Zone 1 → Zone 3 (admin) | Elevation of Privilege | 🟡 **HIGH** – auth bypass needed |
            | MITM Attack | Zone 0 → Zone 1 | Tampering on entry flow | 🟢 **LOWER** – Hard positioning step |

            **Key insight**: The API Key Exposure path has 3 consecutive "Easy" steps and crosses from 
            Zone 3 to Zone 0 (high→low, Information Disclosure). This is your **#1 priority**.
            """)
        elif ws_id == "2":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for CloudBank

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | BOLA Attack | Zone 1 (Gateway) → Zone 5 (Payment) | Information Disclosure (ownership bypass) | 🔴 **CRITICAL** – Easy+Easy+Medium |
            | Service Impersonation | Zone 5 → Zone 5 (no mTLS) | Spoofing (same zone, no mutual auth) | 🟡 **HIGH** – needs cluster access |
            | Replay Transaction | Zone 5 internal | Tampering (replayed message) | 🟡 **HIGH** – Medium+Easy+Easy |
            | Rate Limit Bypass | Zone 0 → Zone 1 | DoS (Zone 0 to any) | 🟡 **HIGH** – distributed attack |

            **Key insight**: BOLA (Broken Object Level Authorization) is the #1 OWASP API risk 
            because the zone boundary exists but ownership checks are missing from the flow.
            """)
        elif ws_id == "3":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for DataInsight

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | Request Body Injection | Zone 0 → Zone 2 (missing JWT check) | Tampering + EoP (tenant boundary bypass) | 🔴 **CRITICAL** – Medium+Easy+Easy |
            | SQL Injection (remove filter) | Zone 3 (Query Svc) → Zone 8 (DW) | Tampering (zone 3→8, less→more) | 🔴 **CRITICAL** – Easy+Medium+Easy |
            | Kafka Cross-Read | Zone 5 (Kafka, no ACL) → Zone 3 | Information Disclosure (zone 5→3) | 🟡 **HIGH** – Medium+Easy+Easy |
            | JWT Token Tampering | Zone 0 → Zone 2 | Spoofing + Tampering | 🟢 **LOWER** – Hard+Hard (crypto) |

            **Key insight**: Both "Critical" paths have Easy leaf nodes that cross the tenant isolation boundary.
            Database-level Row-Level Security (RLS) blocks BOTH SQL paths at the zone boundary.
            """)
        elif ws_id == "4":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for HealthMonitor

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | Replay Normal Readings | Zone 1 (Gateway) → Zone 4 (Cloud) | Tampering (less→more, replayed data) | 🔴 **LIFE-CRITICAL** – Medium+Easy+Easy |
            | Alert Flooding DoS | Zone 4 → Zone 9 (Alert Svc) | DoS on life-critical zone | 🔴 **LIFE-CRITICAL** – Hard+Easy+Easy |
            | BLE MITM Attack | Zone 0 → Zone 1 | Tampering (entry boundary) | 🔴 **CRITICAL** – Easy+Medium+Medium |
            | Physical Firmware Mod | Zone 0 → Zone 1 | Tampering (physical boundary, zone 0) | 🟡 **HIGH** – Medium+Hard+Medium+Easy |
            | HL7 Injection | Zone 3 → Zone 0 (Legacy EHR) | Tampering (unprotected external) | 🟡 **HIGH** – Medium+Medium+Easy+Easy |

            **Key insight**: When zone 9 (Maximum Security) is involved, even a "Hard" first step 
            becomes unacceptable risk — life-safety requires blocking ALL paths.
            """)

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to STRIDE Rules", use_container_width=True):
            st.session_state.current_step = 2.5
            save_progress()
            st.rerun()
    with col2:
        if st.button("Ready: Identify Threats ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 4
            save_progress()
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: IDENTIFY THREATS (PRACTICAL STRIDE APPLICATION)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 4:
    st.header("Step 4: Identify Threats (Practical STRIDE Application)")

    st.markdown(f"""
    <div class="info-box">
    <strong>Applying Steps 3 & 4 of the Infosec Methodology:</strong><br>
    Now you apply the STRIDE zone-rules to systematically identify threats and then 
    map them to <strong>OWASP Top 10</strong> controls.<br><br>
    For each threat: (1) identify the component, (2) apply the zone rule to confirm the STRIDE category,
    (3) assess likelihood × impact, (4) select OWASP-aligned mitigations.<br><br>
    <strong>Goal:</strong> Analyze {current_workshop['target_threats']} threats to demonstrate mastery
    </div>
    """, unsafe_allow_html=True)

    # Show quick STRIDE rules reference
    with st.expander("📋 Quick Reference: STRIDE Zone Rules", expanded=False):
        st.markdown("""
        **Flow rules (check zone direction):**
        - **Tampering**: Less-critical → More-critical (score goes UP)
        - **Info Disclosure**: More-critical → Less-critical (score goes DOWN)
        - **DoS**: Zone 0 → Any zone

        **Node rules:**
        - **Spoofing**: Node reachable by Zone 0 entity
        - **Repudiation**: Node where Spoofing + Tampering both apply
        - **DoS**: Node reachable by Zone 0
        - **Elevation of Privilege**: Node connected to lower-zone node
        """)

    with st.form("threat_selection_form"):
        st.subheader("➕ Analyze a Threat Scenario")

        threat_options = {f"{t['id']}: {t['threat'][:70]}...": t for t in workshop_threats}
        if not threat_options:
            st.error("No threats available for this workshop")
            st.stop()

        selected_threat_key = st.selectbox(
            "Choose a threat scenario:",
            list(threat_options.keys()),
            help="Select the threat to analyze using STRIDE zone rules"
        )
        selected_predefined = threat_options[selected_threat_key]

        # Show zone context for the selected threat
        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>Zone Context for this threat:</strong><br>
        From zone: <strong>{selected_predefined.get('zone_from', 'N/A')}</strong> → 
        To zone: <strong>{selected_predefined.get('zone_to', 'N/A')}</strong><br>
        STRIDE rule applied: <em>{selected_predefined.get('stride_rule_applied', 'N/A')}</em>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🎯 Your Analysis")
            all_components = [comp["name"] for comp in current_workshop["scenario"]["components"]]
            all_flows = [f"{f['source']} → {f['destination']}"
                         for f in current_workshop["scenario"]["data_flows"]]

            user_component = st.selectbox(
                "Which component/flow is affected?",
                all_components + all_flows
            )
            user_stride = st.selectbox(
                "STRIDE Category (apply zone rules!):",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"]
            )
            user_likelihood = st.select_slider(
                "Likelihood", options=["Low", "Medium", "High", "Critical"], value="Medium"
            )
            user_impact = st.select_slider(
                "Impact", options=["Low", "Medium", "High", "Critical"], value="Medium"
            )

        with col2:
            st.markdown("### 🛡️ OWASP-Aligned Mitigations")
            st.caption("Select controls that address this threat (OWASP Top 10 aligned):")

            owasp_hint = OWASP_STRIDE_MAP.get(selected_predefined["stride"], {})
            if owasp_hint:
                st.info(f"💡 Hint: For **{selected_predefined['stride']}** threats, "
                        f"look at OWASP {', '.join(owasp_hint['owasp'])}")

            all_possible = (selected_predefined["correct_mitigations"] +
                            selected_predefined.get("incorrect_mitigations", []))
            random.shuffle(all_possible)

            user_mitigations = st.multiselect(
                "Security Controls:", all_possible,
                help="Select all appropriate mitigations"
            )

        st.markdown("---")
        submitted = st.form_submit_button(
            "✅ Submit & Get STRIDE Rule Feedback", type="primary", use_container_width=True
        )

        if submitted:
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
                "score": score, "max_score": max_score,
                "feedback": feedback,
                "predefined_threat": selected_predefined
            })
            st.session_state.threats.append(user_answer)
            save_progress()
            st.rerun()

    # Show previous answers
    if st.session_state.user_answers:
        st.markdown("---")
        st.subheader(f"📊 Your Answers ({len(st.session_state.user_answers)}/{current_workshop['target_threats']})")

        for idx, answer in enumerate(st.session_state.user_answers):
            score_pct = answer["score"] / answer["max_score"] * 100
            if score_pct >= 80:
                css, emoji, grade = "correct-answer", "✅", "Excellent"
            elif score_pct >= 50:
                css, emoji, grade = "partial-answer", "⚠️", "Partial"
            else:
                css, emoji, grade = "incorrect-answer", "❌", "Needs Review"

            pred = answer.get("predefined_threat", {})
            with st.expander(f"{emoji} Threat {idx+1}: {answer['matched_threat_id']} – {grade} ({score_pct:.0f}%)"):
                st.markdown(f"""
                <div class="{css}">
                    <strong>Your Analysis:</strong><br>
                    Component: {answer['component']} | STRIDE: {answer['stride']}<br>
                    Risk: {answer['likelihood']} likelihood × {answer['impact']} impact
                </div>
                """, unsafe_allow_html=True)

                # Zone rule explanation
                st.markdown(f"""
                <div class="stride-rule-box">
                <strong>Zone Rule Applied:</strong> {pred.get('stride_rule_applied', 'N/A')}<br>
                <strong>From zone:</strong> {pred.get('zone_from', 'N/A')} → 
                <strong>To zone:</strong> {pred.get('zone_to', 'N/A')}
                </div>
                """, unsafe_allow_html=True)

                # Score feedback
                for fb in answer["feedback"]:
                    if "✓" in fb: st.success(fb)
                    elif "✗" in fb: st.error(fb)
                    else: st.warning(fb)

                # OWASP mapping for this threat
                st.markdown("---")
                owasp_info = OWASP_STRIDE_MAP.get(pred.get("stride", ""), {})
                if owasp_info:
                    st.markdown(f"""
                    <div class="owasp-box">
                    <strong>OWASP Mapping for {pred.get('stride', '')}:</strong><br>
                    {', '.join(owasp_info['owasp'])}<br><br>
                    {owasp_info['owasp_detail']}
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown("**OWASP Controls that apply:**")
                    for ctrl in owasp_info["controls"][:3]:
                        st.markdown(f"• {ctrl}")

                # Learning content
                st.markdown("---")
                st.markdown(f"**Explanation:** {pred.get('explanation', 'N/A')}")
                st.markdown(f"**Why this risk level:** {pred.get('why_this_risk', 'N/A')}")
                st.markdown(f"**Why these controls work:** {pred.get('why_these_controls', 'N/A')}")
                st.markdown(f"**Real-world example:** {pred.get('real_world', 'N/A')}")
                st.markdown(f"**Compliance:** {pred.get('compliance', 'N/A')}")

    # Progress
    progress = len(st.session_state.user_answers) / current_workshop['target_threats']
    st.progress(min(progress, 1.0))

    if len(st.session_state.user_answers) >= current_workshop['target_threats']:
        final_pct = st.session_state.total_score / st.session_state.max_score * 100
        grade_css = ("score-excellent" if final_pct >= 90 else "score-good" if final_pct >= 75
                     else "score-fair" if final_pct >= 60 else "score-poor")
        grade_msg = ("🏆 Excellent! STRIDE mastery demonstrated!" if final_pct >= 90
                     else "👍 Good!" if final_pct >= 75 else "📚 Fair – review feedback."
                     if final_pct >= 60 else "💪 Keep learning!")
        st.markdown(f"""
        <div class="{grade_css}">
        {grade_msg} Score: {st.session_state.total_score}/{st.session_state.max_score} ({final_pct:.1f}%)
        </div>
        """, unsafe_allow_html=True)
    else:
        remaining = current_workshop['target_threats'] - len(st.session_state.user_answers)
        st.info(f"⚠️ {remaining} more threats needed to complete this workshop.")

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
                st.error("Complete at least one threat analysis first")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: ASSESS – THREAT-MAPPED DFD + FULL REVIEW
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 5:
    st.header("Step 5: Assessment & Threat-Mapped Architecture Review")

    if not st.session_state.user_answers:
        st.warning("No answers to assess")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 4; save_progress(); st.rerun()
        st.stop()

    final_pct = st.session_state.total_score / st.session_state.max_score * 100

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percentage", f"{final_pct:.1f}%")
    col3.metric("Threats Analyzed", len(st.session_state.user_answers))
    col4.metric("Grade", "A" if final_pct >= 90 else "B" if final_pct >= 80
                else "C" if final_pct >= 70 else "D" if final_pct >= 60 else "F")

    st.markdown("---")
    st.subheader("🗺️ STRIDE-Annotated Architecture Diagram")

    st.markdown("""
    <div class="learning-box">
    This diagram shows your threat-mapped DFD with zone labels and STRIDE annotations.
    Green-highlighted components/flows are where threats were identified.
    Zone direction labels (T=Tampering, I=Info Disclosure, D=DoS) appear on flows.
    </div>
    """, unsafe_allow_html=True)

    with st.spinner("Generating STRIDE-annotated zone DFD..."):
        mapped_dfd = generate_stride_annotated_dfd(current_workshop, st.session_state.threats)

    if mapped_dfd:
        st.image(f"data:image/png;base64,{mapped_dfd}",
                 caption="STRIDE-Annotated Zone DFD", use_column_width=True)

    # Full methodology review
    st.markdown("---")
    st.subheader("📋 4-Step Methodology Review")

    step_tabs = st.tabs(["Step 1: Design", "Step 2: Zones", "Step 3: STRIDE", "Step 4: OWASP"])

    with step_tabs[0]:
        st.markdown("### ✅ Step 1: Design Review")
        scenario = current_workshop["scenario"]
        st.markdown(f"**System:** {scenario['title']} – {scenario['description']}")
        comps_df = pd.DataFrame([{
            "Component": c["name"], "Type": c["type"].replace("_", " ").title(),
            "Description": c["description"]
        } for c in scenario["components"]])
        st.dataframe(comps_df, use_container_width=True, hide_index=True)

    with step_tabs[1]:
        st.markdown("### ✅ Step 2: Zone Labels Applied")
        zone_df = pd.DataFrame([{
            "Component": c["name"],
            "Zone": c.get("zone", "N/A"),
            "Score (0-9)": c.get("zone_score", "?"),
            "STRIDE Focus": CRITICALITY_ZONES.get(c.get("zone", ""), {}).get("stride_applicability", "")[:60]
        } for c in scenario["components"]])
        st.dataframe(zone_df, use_container_width=True, hide_index=True)

    with step_tabs[2]:
        st.markdown("### ✅ Step 3: STRIDE Threats Identified")
        for answer in st.session_state.user_answers:
            pred = answer.get("predefined_threat", {})
            pct = answer["score"] / answer["max_score"] * 100
            css = "correct-answer" if pct >= 80 else "partial-answer" if pct >= 50 else "incorrect-answer"
            st.markdown(f"""
            <div class="{css}">
            <strong>{answer['matched_threat_id']}</strong>: {pred.get('threat', '')}<br>
            STRIDE: {answer['stride']} | Zone rule: {pred.get('stride_rule_applied', 'N/A')}<br>
            Score: {answer['score']}/{answer['max_score']} ({pct:.0f}%)
            </div>
            """, unsafe_allow_html=True)

    with step_tabs[3]:
        st.markdown("### ✅ Step 4: OWASP Control Mapping")
        for stride_cat, owasp_info in OWASP_STRIDE_MAP.items():
            # Check if any of user's answers used this STRIDE category
            user_used = any(a["stride"] == stride_cat for a in st.session_state.user_answers)
            icon = "✅" if user_used else "⭕"
            st.markdown(f"""
            <div class="owasp-box">
            {icon} <strong>{stride_cat}</strong> → {', '.join(owasp_info['owasp'])}<br>
            Key controls: {'; '.join(owasp_info['controls'][:2])}
            </div>
            """, unsafe_allow_html=True)

    # PERFORMANCE
    st.markdown("---")
    st.subheader("📊 Performance Analysis")

    correct_count = sum(1 for a in st.session_state.user_answers if a["score"]/a["max_score"] >= 0.8)
    partial_count = sum(1 for a in st.session_state.user_answers if 0.5 <= a["score"]/a["max_score"] < 0.8)
    incorrect_count = sum(1 for a in st.session_state.user_answers if a["score"]/a["max_score"] < 0.5)

    col1, col2, col3 = st.columns(3)
    col1.metric("Excellent (80%+)", correct_count)
    col2.metric("Partial (50-79%)", partial_count)
    col3.metric("Needs Review (<50%)", incorrect_count)

    # RECOMMENDATIONS
    st.subheader("📚 Learning Recommendations")
    if final_pct < 70:
        st.warning("""
        **Areas to Review:**
        - Go back and redo the Zone Labelling exercise
        - Study the STRIDE zone direction rules carefully
        - Review OWASP → STRIDE mapping table
        - For each wrong answer, trace the zone boundary direction
        """)
    elif final_pct < 90:
        st.info("""
        **To Reach Mastery:**
        - Fine-tune zone direction analysis (less→more vs more→less)
        - Study the OWASP control specifics for your weaker STRIDE categories
        - Review feedback on partial answers
        """)
    else:
        st.success("""
        **🏆 Excellent – Methodology Mastered!**
        - Strong zone-based threat identification
        - Correct STRIDE category selection using rules
        - Good OWASP control mapping
        - Ready for next workshop!
        """)

    # EXPORT
    st.markdown("---")
    st.subheader("📥 Export Your Threat Model")
    st.markdown("""
    <div class="info-box">
    <strong>Two exports available:</strong><br>
    • <strong>Your Submission PDF</strong>: Your analysis with zone labels, STRIDE rules, OWASP mappings, and scores<br>
    • <strong>Complete Reference PDF</strong>: All threats with full 4-step methodology documentation
    </div>
    """, unsafe_allow_html=True)

    results_df = pd.DataFrame([{
        "Threat_ID": a["matched_threat_id"],
        "Component": a["component"],
        "STRIDE": a["stride"],
        "Zone_Rule": a.get("predefined_threat", {}).get("stride_rule_applied", ""),
        "OWASP": ", ".join(a.get("predefined_threat", {}).get("owasp_categories", [])),
        "Likelihood": a["likelihood"],
        "Impact": a["impact"],
        "Score": f"{a['score']}/{a['max_score']} ({a['score']/a['max_score']*100:.0f}%)",
        "Mitigations": ", ".join(a.get('selected_mitigations', []))
    } for a in st.session_state.user_answers])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.download_button(
            "📥 CSV Results (with OWASP)",
            results_df.to_csv(index=False),
            f"stride_results_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.csv",
            "text/csv", use_container_width=True
        )
    with col2:
        with st.spinner("Building your PDF..."):
            user_pdf = generate_user_threat_model_pdf(
                current_workshop, st.session_state.user_answers,
                st.session_state.total_score, st.session_state.max_score
            )
        if user_pdf:
            st.download_button(
                "📄 My Threat Model PDF",
                user_pdf,
                f"my_threat_model_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.pdf",
                "application/pdf", use_container_width=True
            )
    with col3:
        with st.spinner("Building reference PDF..."):
            complete_pdf = generate_complete_threat_model_pdf(
                current_workshop, st.session_state.selected_workshop
            )
        if complete_pdf:
            st.download_button(
                "📚 Complete Reference PDF",
                complete_pdf,
                f"complete_model_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.pdf",
                "application/pdf", use_container_width=True
            )

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Threats", use_container_width=True):
            st.session_state.current_step = 4; save_progress(); st.rerun()
    with col2:
        if st.button("Complete Workshop ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 6; save_progress(); st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: COMPLETE
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 6:
    st.header("🎉 Workshop Complete!")

    final_pct = st.session_state.total_score / st.session_state.max_score * 100

    if final_pct >= 90:
        st.balloons()
        st.success(f"""
        🏆 **Outstanding! 4-Step Methodology Mastered!**

        Completed **{current_workshop['name']}** with **{final_pct:.1f}%**

        You have demonstrated mastery of:
        - ✅ Step 1: Designing DFDs with interactors, modules, and connections
        - ✅ Step 2: Applying Zone of Trust labels (0–9 scale)
        - ✅ Step 3: Using zone-direction rules to derive STRIDE threats
        - ✅ Step 4: Mapping STRIDE to OWASP Top 10 controls
        """)
    elif final_pct >= 70:
        st.info(f"👍 **Good job!** Score: **{final_pct:.1f}%** – Review the zone rules for any missed areas.")
    else:
        st.warning(f"📚 **Completed.** Score: **{final_pct:.1f}%** – Revisit Steps 2–3 for improvement.")

    # Mark completed
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Threats Analyzed", len(st.session_state.threats))
    col2.metric("Final Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col3.metric("Percentage", f"{final_pct:.1f}%")
    col4.metric("Grade", "A" if final_pct >= 90 else "B" if final_pct >= 80
                else "C" if final_pct >= 70 else "D" if final_pct >= 60 else "F")

    # Methodology mastery summary
    st.markdown("---")
    st.subheader("📋 4-Step Methodology Mastery Summary")

    methodology_scores = {
        "Step 1 – Design (DFD)": "✅ Completed",
        "Step 2 – Zones of Trust": "✅ Completed" if st.session_state.get('zone_labelling_done') else "⭕ Skipped",
        "Step 3 – STRIDE Rules": "✅ Completed" if st.session_state.get('stride_rules_submitted') else "⭕ Skipped",
        "Step 4 – OWASP Mapping": "✅ Completed" if st.session_state.get('owasp_mapping_submitted') else "⭕ Skipped",
        "Practical Threat ID": f"✅ {len(st.session_state.user_answers)} threats analyzed"
    }
    for step, status in methodology_scores.items():
        st.markdown(f"- **{step}**: {status}")

    # Next workshop
    st.markdown("---")
    next_ws = str(int(st.session_state.selected_workshop) + 1)
    if next_ws in WORKSHOPS:
        next_config = WORKSHOPS[next_ws]
        st.info(f"""
        **Ready for Workshop {next_ws}?**

        **{next_config['name']}** – {next_config['level']}

        New concepts introduced:
        {"".join(f"• {lo}" + chr(10) for lo in next_config.get('learning_objectives', [])[:3])}

        *(Ask your instructor for the unlock code)*
        """)
        if is_workshop_unlocked(next_ws):
            if st.button(f"Start Workshop {next_ws} ➡️", type="primary", use_container_width=True):
                st.session_state.selected_workshop = next_ws
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                st.session_state.zone_labels = {}
                st.session_state.zone_scores = {}
                st.session_state.zone_labelling_done = False
                st.session_state.stride_rules_answered = {}
                st.session_state.stride_rules_submitted = False
                st.session_state.owasp_mapping_answers = {}
                st.session_state.owasp_mapping_submitted = False
                save_progress()
                st.rerun()
    else:
        st.success("🏆 **All Workshops Completed! Full 4-Step Methodology Mastered!**")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review Assessment", use_container_width=True):
            st.session_state.current_step = 5; save_progress(); st.rerun()
    with col2:
        if st.button("🏠 Return to Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            save_progress()
            st.rerun()

st.markdown("---")
st.caption("STRIDE Threat Modeling Learning Lab | 4-Step Infosec Methodology: Design → Zones → STRIDE → OWASP Controls")
