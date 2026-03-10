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
from io import BytesIO

def _get_reportlab():
    """Lazy-load reportlab only when a PDF is actually requested."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     PageBreak, Table, TableStyle)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    return (letter, getSampleStyleSheet, ParagraphStyle, inch, colors,
            SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table,
            TableStyle, TA_CENTER, TA_LEFT)

st.set_page_config(
    page_title="STRIDE Threat Modeling Learning Lab",
    page_icon="🔒",
    layout="wide"
)

# ─────────────────────────────────────────────────────────────────────────────
# DATA CACHE HELPERS - loaded once per server session, not per rerun
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_resource
def get_predefined_threats():
    """Return threat DB - cached at resource level (parsed only once)."""
    return PREDEFINED_THREATS

@st.cache_resource
def get_workshops():
    """Return workshop configs - cached at resource level."""
    return WORKSHOPS

@st.cache_resource
def get_attack_trees():
    """Return attack trees - cached at resource level."""
    return ATTACK_TREES

# ─────────────────────────────────────────────────────────────────────────────
# UNLOCK CODES  (never shown in UI)
# Workshop 2: MICRO2025   Workshop 3: TENANT2025   Workshop 4: HEALTH2025
# ─────────────────────────────────────────────────────────────────────────────
WORKSHOP_CODES = {"1": None, "2": "MICRO2025", "3": "TENANT2025", "4": "HEALTH2025"}

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""<style>
/* ── Design System ─────────────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,wght@0,300;0,400;0,500;0,700;1,400&family=DM+Mono:wght@400;500&family=Sora:wght@600;700;800&display=swap');

html, body, [class*="css"] { font-family: 'DM Sans', system-ui, sans-serif; }
h1,h2,h3,h4,h5,h6 { font-family: 'Sora', sans-serif !important; letter-spacing:-0.5px; }
code,pre,.mono,kbd { font-family: 'DM Mono', monospace !important; }

/* Global button */
.stButton>button {
  width:100%; border-radius:8px; font-weight:600; font-size:0.93em;
  padding:10px 16px; transition:all 0.2s ease;
  border: 1.5px solid transparent;
}
.stButton>button:hover { transform:translateY(-1px); box-shadow:0 4px 12px rgba(0,0,0,0.15); }

/* Primary buttons */
.stButton>button[kind="primary"] {
  background: linear-gradient(135deg,#0F4C75,#1B6CA8) !important;
  color:white !important; border:none !important;
}

/* ── Cards ────────────────────────────────────────────────────────────── */
.premium-card {
  background:white; border-radius:12px; padding:20px;
  box-shadow:0 2px 12px rgba(0,0,0,0.08); margin:10px 0;
  border:1px solid #E8EDF2; transition:box-shadow 0.2s;
}
.premium-card:hover { box-shadow:0 4px 20px rgba(0,0,0,0.12); }

.concept-card {
  border-radius:10px; padding:18px; margin:8px 0;
  border-left:5px solid; box-shadow:0 1px 6px rgba(0,0,0,0.06);
}

/* ── Threat severity ─────────────────────────────────────────────────── */
.threat-critical{background:linear-gradient(135deg,#B71C1C,#C62828);color:white;padding:14px 16px;border-radius:8px;margin:8px 0;box-shadow:0 2px 8px rgba(183,28,28,0.3)}
.threat-high{background:#FFF5F5;padding:14px 16px;border-radius:8px;border-left:5px solid #EF5350;margin:8px 0}
.threat-medium{background:#FFFBF0;padding:14px 16px;border-radius:8px;border-left:5px solid #FF9800;margin:8px 0}
.threat-low{background:#F1F8E9;padding:14px 16px;border-radius:8px;border-left:5px solid #66BB6A;margin:8px 0}

/* ── Answer feedback ─────────────────────────────────────────────────── */
.correct-answer{background:linear-gradient(135deg,#E8F5E9,#F1F8E9);padding:14px;border-radius:8px;border-left:5px solid #43A047;margin:8px 0;box-shadow:0 1px 4px rgba(67,160,71,0.15)}
.incorrect-answer{background:linear-gradient(135deg,#FFEBEE,#FFF5F5);padding:14px;border-radius:8px;border-left:5px solid #E53935;margin:8px 0;box-shadow:0 1px 4px rgba(229,57,53,0.15)}
.partial-answer{background:linear-gradient(135deg,#FFFDE7,#FFFBF0);padding:14px;border-radius:8px;border-left:5px solid #FB8C00;margin:8px 0}

/* ── Scores ─────────────────────────────────────────────────────────── */
.score-excellent{background:linear-gradient(135deg,#1B5E20,#2E7D32);color:white;padding:20px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:700;box-shadow:0 4px 16px rgba(27,94,32,0.4)}
.score-good{background:linear-gradient(135deg,#33691E,#558B2F);color:white;padding:20px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:700}
.score-fair{background:linear-gradient(135deg,#E65100,#F57C00);color:white;padding:20px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:700}
.score-poor{background:linear-gradient(135deg,#BF360C,#D84315);color:white;padding:20px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:700}

/* ── Badges ─────────────────────────────────────────────────────────── */
.badge-completed{background:linear-gradient(135deg,#1B5E20,#2E7D32);color:white;padding:4px 14px;border-radius:20px;font-size:.82em;font-weight:600;letter-spacing:0.3px}
.badge-locked{background:#ECEFF1;color:#607D8B;padding:4px 14px;border-radius:20px;font-size:.82em;font-weight:500}
.badge-available{background:linear-gradient(135deg,#01579B,#0288D1);color:white;padding:4px 14px;border-radius:20px;font-size:.82em;font-weight:600}

/* ── Info boxes ─────────────────────────────────────────────────────── */
.info-box{background:linear-gradient(135deg,#E3F2FD,#EFF8FF);padding:16px 20px;border-radius:10px;border-left:5px solid #1976D2;margin:12px 0;box-shadow:0 1px 6px rgba(25,118,210,0.1)}
.success-box{background:linear-gradient(135deg,#E8F5E9,#F1F8E9);padding:16px 20px;border-radius:10px;border-left:5px solid #388E3C;margin:12px 0}
.warning-box{background:linear-gradient(135deg,#FFF3E0,#FFF8F0);padding:16px 20px;border-radius:10px;border-left:5px solid #F57C00;margin:12px 0}
.learning-box{background:linear-gradient(135deg,#EDE7F6,#F3E5F5);padding:16px 20px;border-radius:10px;border-left:5px solid #7B1FA2;margin:12px 0}
.expert-box{background:linear-gradient(135deg,#0D1B2A,#1B2B3A);color:#E8F4FD;padding:18px 22px;border-radius:10px;border-left:5px solid #00BCD4;margin:12px 0}
.callout-box{background:linear-gradient(135deg,#FFF8E1,#FFFBF0);padding:16px 20px;border-radius:10px;border:2px solid #FFD54F;margin:12px 0}

/* ── Component cards ─────────────────────────────────────────────────── */
.component-card{background:white;padding:14px 16px;border-radius:8px;border-left:4px solid #0288D1;margin:6px 0;box-shadow:0 1px 4px rgba(0,0,0,0.06)}
.mitigation-card{background:#FFFDE7;padding:14px;border-radius:8px;border-left:5px solid #F9A825;margin:8px 0}
.zone-card{border-radius:10px;padding:14px 16px;margin:6px 0;border:2px solid;box-shadow:0 2px 6px rgba(0,0,0,0.08)}

/* ── STRIDE / OWASP boxes ───────────────────────────────────────────── */
.stride-rule-box{background:linear-gradient(135deg,#E8EAF6,#EDE7F6);padding:16px 20px;border-radius:10px;border-left:5px solid #3F51B5;margin:10px 0;box-shadow:0 1px 4px rgba(63,81,181,0.12)}
.owasp-box{background:linear-gradient(135deg,#E0F2F1,#E8F8F5);padding:16px 20px;border-radius:10px;border-left:5px solid #00897B;margin:10px 0;box-shadow:0 1px 4px rgba(0,137,123,0.12)}
.methodology-step{background:white;padding:18px 20px;border-radius:10px;border:2px solid #E0E7EF;margin:12px 0;box-shadow:0 2px 8px rgba(0,0,0,0.07);transition:box-shadow 0.2s}
.methodology-step:hover{box-shadow:0 4px 16px rgba(0,0,0,0.12)}
.practical-task{background:linear-gradient(135deg,#FFF8E1,#FFFBF0);padding:18px 20px;border-radius:10px;border:2px dashed #FFB300;margin:12px 0}
.flow-arrow{background:#E3F2FD;padding:8px 18px;border-radius:20px;display:inline-block;margin:4px;font-weight:500;font-size:0.9em}

/* ── Step progress bar ───────────────────────────────────────────────── */
.step-active{background:linear-gradient(135deg,#0F4C75,#1B6CA8);color:white;padding:8px 12px;border-radius:8px;font-weight:700;font-size:0.82em;text-align:center;box-shadow:0 2px 8px rgba(15,76,117,0.35)}
.step-done{background:#E8F5E9;color:#2E7D32;padding:8px 12px;border-radius:8px;font-weight:600;font-size:0.82em;text-align:center;border:1.5px solid #A5D6A7}
.step-todo{background:#F5F5F5;color:#9E9E9E;padding:8px 12px;border-radius:8px;font-size:0.82em;text-align:center;border:1.5px solid #E0E0E0}

/* ── Concept callout ─────────────────────────────────────────────────── */
.key-concept{background:linear-gradient(135deg,#0F4C75,#1B6CA8);color:white;padding:16px 20px;border-radius:10px;margin:10px 0;box-shadow:0 3px 12px rgba(15,76,117,0.3)}
.key-concept h4{color:#90CAF9;margin:0 0 6px 0;font-size:0.85em;text-transform:uppercase;letter-spacing:1px}

/* ── Real-world callout ─────────────────────────────────────────────── */
.real-world-box{background:linear-gradient(135deg,#1A237E,#283593);color:white;padding:16px 20px;border-radius:10px;border-left:5px solid #5C6BC0;margin:10px 0}
.real-world-box strong{color:#90CAF9}

/* ── Metric cards ────────────────────────────────────────────────────── */
.metric-card{background:white;border-radius:10px;padding:16px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.08);border:1px solid #E8EDF2}
.metric-card .value{font-size:2em;font-weight:700;color:#0F4C75}
.metric-card .label{font-size:0.82em;color:#607D8B;margin-top:4px}

/* ── Sidebar ─────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {background:linear-gradient(180deg,#0D1B2A 0%,#1B2B3A 100%)}
[data-testid="stSidebar"] * {color:#E8F4FD !important}
[data-testid="stSidebar"] .stButton>button {
  background:#1B6CA8 !important; color:white !important;
  border:1px solid #2980B9 !important; margin:2px 0;
}
[data-testid="stSidebar"] .stButton>button:hover {background:#2980B9 !important}
[data-testid="stSidebar"] hr {border-color:#2C3E50 !important}

/* ── Section headers ─────────────────────────────────────────────────── */
h1{color:#0F4C75 !important;font-weight:700 !important}
h2{color:#1B4F72 !important;font-weight:600 !important;border-bottom:2px solid #E8EDF2;padding-bottom:6px}
h3{color:#1A5276 !important;font-weight:600 !important}

/* ── Tab styling ────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab"] {font-weight:500;font-size:0.9em;padding:10px 16px}
.stTabs [aria-selected="true"] {color:#0F4C75 !important;font-weight:700 !important}

/* ── Dataframe ───────────────────────────────────────────────────────── */
.dataframe{border-radius:8px;overflow:hidden}

/* ── Progress bar ────────────────────────────────────────────────────── */
.stProgress > div > div {background:linear-gradient(90deg,#0F4C75,#1B6CA8) !important;border-radius:4px}

/* ── Expander ────────────────────────────────────────────────────────── */
details{border-radius:8px !important;border:1px solid #E8EDF2 !important}

/* ── Divider ─────────────────────────────────────────────────────────── */
hr{border:none;border-top:1px solid #E8EDF2;margin:20px 0}

/* ── Knowledge check box ─────────────────────────────────────────────── */
.knowledge-check{background:linear-gradient(135deg,#E8EAF6,#EDE7F6);padding:18px 20px;border-radius:10px;border:2px solid #7986CB;margin:14px 0}
.knowledge-check h4{color:#3949AB;margin-top:0}

/* ── Mastery badge ────────────────────────────────────────────────────── */
.mastery-badge{background:linear-gradient(135deg,#B8860B,#DAA520);color:white;padding:12px 20px;border-radius:10px;text-align:center;font-weight:700;font-size:1.1em;box-shadow:0 3px 12px rgba(184,134,11,0.4);margin:10px 0}

/* ── Scrollable diagram container ────────────────────────────────────── */
.diagram-container{overflow-x:auto;border:1px solid #E8EDF2;border-radius:10px;padding:12px;background:white;box-shadow:0 2px 8px rgba(0,0,0,0.06)}
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
         "stride_rule_applied": "Elevation of Privilege (Node rule): API Backend (zone 3) is connected to a lower-zone node (Web Frontend zone 1). An attacker who compromises the lower zone (or forges requests appearing to come from it) can attempt to gain the privileges of the higher zone – e.g. calling admin endpoints that only the API backend should control.",
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
         "zone_from": "Standard Application", "zone_to": "Standard Application",
         "stride_rule_applied": "Repudiation (Node rule): API Backend (zone 3) is reachable from Zone-0 (Spoofing applies) AND receives data from less-critical zones (Tampering applies). When BOTH Spoofing AND Tampering apply to the same node, Repudiation applies – an attacker can act as a fake identity with modified data, leaving no trace.",
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
         "stride_rule_applied": "Tampering: HL7 Interface (zone 3) injects malicious messages INTO Legacy EHR (zone 0 - uncontrolled, no auth). Although data flows zone 3 → zone 0 (normally Info Disclosure direction), this threat is Tampering because the ATTACKER is modifying the HL7 message contents en-route (network interception). The attacker sits between zones on the hospital network, making this a data-in-transit tampering attack.",
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




# ─────────────────────────────────────────────────────────────────────────────
# DRAW.IO-STYLE ARCHITECTURE DIAGRAM (SVG, fully dynamic from workshop config)
# ─────────────────────────────────────────────────────────────────────────────

def get_component_icon(comp_type):
    """Return SVG path / shape info based on component type."""
    return {
        "external_entity": "ellipse",
        "process":         "rect",
        "datastore":       "cylinder",
    }.get(comp_type, "rect")


def _zone_hex(zone_name):
    return {
        "Not in Control of System": "#EEEEEE",
        "Minimal Trust":            "#C8E6C9",
        "Standard Application":     "#FFF9C4",
        "Elevated Trust":           "#FFE0B2",
        "Critical":                 "#FFCDD2",
        "Maximum Security":         "#FFAB91",
    }.get(zone_name, "#E3F2FD")


def _zone_stroke(zone_name):
    return {
        "Not in Control of System": "#9E9E9E",
        "Minimal Trust":            "#388E3C",
        "Standard Application":     "#F9A825",
        "Elevated Trust":           "#E65100",
        "Critical":                 "#C62828",
        "Maximum Security":         "#BF360C",
    }.get(zone_name, "#1565C0")


def _xml(s):
    """Escape string for SVG text content."""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

# ── Zone visual config ─────────────────────────────────────────────────────
_ZONE_STYLE = {
    "Not in Control of System": {"fill":"#ECEFF1","stroke":"#78909C","dark":"#37474F","band":"#CFD8DC"},
    "Minimal Trust":            {"fill":"#E8F5E9","stroke":"#388E3C","dark":"#1B5E20","band":"#C8E6C9"},
    "Standard Application":     {"fill":"#FFFDE7","stroke":"#F9A825","dark":"#E65100","band":"#FFF9C4"},
    "Elevated Trust":           {"fill":"#FFF3E0","stroke":"#E64A19","dark":"#BF360C","band":"#FFCCBC"},
    "Critical":                 {"fill":"#FFEBEE","stroke":"#C62828","dark":"#B71C1C","band":"#FFCDD2"},
    "Maximum Security":         {"fill":"#F9E8EA","stroke":"#880E4F","dark":"#4A0E2A","band":"#F8BBD9"},
}
_ZONE_ORDER = [
    "Not in Control of System",
    "Minimal Trust",
    "Standard Application",
    "Elevated Trust",
    "Critical",
    "Maximum Security",
]
_STRIDE_TAG_COLOR = {"T":"#E65100","I":"#1565C0","D":"#6A1B9A"}


def render_architecture_svg(workshop_config, highlighted_threats=None, mode="architecture"):
    """
    Professional horizontal swimlane DFD.
    Lanes = zones. Trust increases top→bottom.
    Shapes: oval=external entity, rounded-rect=process, open-rect=data store.
    Edges use cubic bezier with staggered offsets for parallel flows.
    STRIDE tags shown as colored circles on edges (no text overlap).
    """
    highlighted_threats = highlighted_threats or []
    scenario   = workshop_config["scenario"]
    components = scenario["components"]
    flows      = scenario["data_flows"]

    threat_nodes = set()
    threat_flows = set()
    for t in highlighted_threats:
        c = t.get("component", "")
        (threat_flows if "→" in c else threat_nodes).add(c)

    from collections import OrderedDict
    zone_comps = OrderedDict()
    for z in _ZONE_ORDER:
        bucket = [c for c in components if c.get("zone") == z]
        if bucket:
            zone_comps[z] = bucket

    present_zones = list(zone_comps.keys())
    n_lanes = len(present_zones)

    LABEL_W  = 138
    NODE_W   = 132
    NODE_H   = 52
    LANE_H   = 108
    TOP_BAR  = 46
    BOT_H    = 56
    EDGE_STEP = 12

    max_n = max(len(v) for v in zone_comps.values())
    CANVAS_W = LABEL_W + max(max_n * (NODE_W + 28) + 28, 640)
    CANVAS_H = TOP_BAR + n_lanes * LANE_H + BOT_H

    node_pos  = {}
    lane_y    = {}
    zsc_map   = {c["name"]: c.get("zone_score", 3) for c in components}

    for li, z in enumerate(present_zones):
        top = TOP_BAR + li * LANE_H
        lane_y[z] = top
        nodes = zone_comps[z]
        n     = len(nodes)
        avail = CANVAS_W - LABEL_W
        sp    = avail / (n + 1)
        for i, comp in enumerate(nodes):
            cx = int(LABEL_W + sp * (i + 1))
            cy = int(top + LANE_H // 2)
            node_pos[comp["name"]] = (cx, cy)

    W, H = CANVAS_W, CANVAS_H
    svg  = []

    # SVG header — no embedded quotes in style attr
    svg.append(
        '<svg xmlns="http://www.w3.org/2000/svg"'
        f' width="{W}" height="{H}" viewBox="0 0 {W} {H}"'
        ' style="background:white;border-radius:10px;box-shadow:0 2px 18px rgba(0,0,0,0.12)">'
    )
    svg.append("""<defs>
  <style>
    .sv-title { font-family:'Sora','DM Sans',Arial; font-weight:700; font-size:13px; fill:white; }
    .sv-sub   { font-family:'DM Sans',Arial; font-size:10px; fill:#90CAF9; }
    .sv-zone  { font-family:'Sora','DM Sans',Arial; font-weight:700; font-size:9.5px; }
    .sv-zscore{ font-family:'DM Mono',monospace; font-size:9px; font-weight:500; fill:white; }
    .sv-name  { font-family:'Sora','DM Sans',Arial; font-weight:700; font-size:11px; fill:#1A2B3C; }
    .sv-desc  { font-family:'DM Sans',Arial; font-size:8.5px; fill:#607D8B; }
    .sv-edge  { font-family:'DM Sans',Arial; font-size:8.5px; }
    .sv-leg   { font-family:'DM Sans',Arial; font-size:8.5px; fill:#546E7A; }
    .sv-legt  { font-family:'Sora','DM Sans',Arial; font-weight:700; font-size:9px; fill:#455A64; }
  </style>
  <marker id="ma"  markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
    <path d="M1,1 L7,4 L1,7 Z" fill="#78909C"/></marker>
  <marker id="ma-r" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
    <path d="M1,1 L7,4 L1,7 Z" fill="#C62828"/></marker>
  <marker id="ma-b" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
    <path d="M1,1 L7,4 L1,7 Z" fill="#5C6BC0"/></marker>
  <filter id="nd">
    <feDropShadow dx="0" dy="2" stdDeviation="2.5" flood-color="#00000020"/></filter>
  <filter id="nd-r">
    <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#C6282850"/></filter>
</defs>""")

    # Top bar
    title_txt = _xml(scenario.get("title","System Architecture"))
    mode_lbl  = {"architecture":"Architecture Overview","stride":"STRIDE Analysis","threat":"Threat Impact Map"}.get(mode,"")
    svg.append(f'<rect width="{W}" height="{TOP_BAR}" fill="#0D1B2A"/>')
    svg.append(f'<text x="{LABEL_W+12}" y="19" class="sv-title">{title_txt}</text>')
    svg.append(f'<text x="{LABEL_W+12}" y="36" class="sv-sub">{_xml(mode_lbl)} · Zone trust increases left to right</text>')

    # Swimlanes
    for li, z in enumerate(present_zones):
        zs  = _ZONE_STYLE.get(z, _ZONE_STYLE["Standard Application"])
        top = lane_y[z]
        zsc = next((c.get("zone_score",0) for c in zone_comps[z]), 0)
        alpha = "0.5" if li % 2 == 0 else "0.32"
        svg.append(f'<rect x="0" y="{top}" width="{W}" height="{LANE_H}" fill="{zs["band"]}" opacity="{alpha}"/>')
        svg.append(f'<rect x="0" y="{top}" width="{LABEL_W}" height="{LANE_H}" fill="{zs["stroke"]}" opacity="0.14"/>')
        svg.append(f'<text x="8" y="{top+20}" class="sv-zone" fill="{zs["dark"]}">{_xml(z)}</text>')
        svg.append(f'<rect x="8" y="{top+27}" width="38" height="15" rx="7" fill="{zs["stroke"]}"/>')
        svg.append(f'<text x="27" y="{top+38}" class="sv-zscore" text-anchor="middle">Z-{zsc}</text>')
        if li > 0:
            svg.append(f'<line x1="0" y1="{top}" x2="{W}" y2="{top}" stroke="{zs["stroke"]}" stroke-width="1.2" opacity="0.45"/>')
            svg.append(f'<rect x="{LABEL_W-4}" y="{top-7}" width="8" height="14" rx="3" fill="#7B1FA2" opacity="0.85"/>')

    svg.append(f'<line x1="{LABEL_W}" y1="{TOP_BAR}" x2="{LABEL_W}" y2="{H-BOT_H}" stroke="#B0BEC5" stroke-width="1" stroke-dasharray="4,3"/>')

    # Edges — count parallel pairs for offset
    pair_count = {}
    for f in flows:
        k = tuple(sorted([f["source"], f["destination"]]))
        pair_count[k] = pair_count.get(k, 0) + 1
    pair_seen = {}

    for flow in flows:
        src, dst = flow["source"], flow["destination"]
        if src not in node_pos or dst not in node_pos:
            continue
        x1, y1 = node_pos[src]
        x2, y2 = node_pos[dst]
        pk  = tuple(sorted([src, dst]))
        oi  = pair_seen.get(pk, 0)
        pair_seen[pk] = oi + 1
        off = (oi - (pair_count.get(pk, 1) - 1) / 2) * EDGE_STEP

        is_thr = (f"{src} → {dst}") in threat_flows
        sz, dz = zsc_map.get(src, 3), zsc_map.get(dst, 3)

        tags = []
        if mode == "stride":
            if sz < dz: tags.append("T")
            if sz > dz: tags.append("I")
            if sz == 0: tags.append("D")

        col    = "#C62828" if is_thr else ("#5C6BC0" if tags else "#90A4AE")
        marker = "ma-r"    if is_thr else ("ma-b"    if tags else "ma")
        sw     = "2.5"     if is_thr else "1.8"
        dash   = 'stroke-dasharray="5,3"' if (tags and not is_thr) else ""

        same = abs(y1 - y2) < 8
        if same:
            arc_y = int(min(y1, y2) - 40 - abs(x2 - x1) * 0.05 + off)
            mx    = (x1 + x2) // 2
            ey1   = y1 - NODE_H // 2
            ey2   = y2 - NODE_H // 2
            svg.append(f'<path d="M{x1},{ey1} Q{mx},{arc_y} {x2},{ey2}" fill="none" stroke="{col}" stroke-width="{sw}" {dash} marker-end="url(#{marker})"/>')
            lx, ly_e = mx, arc_y - 8
        else:
            ex1 = x1 + NODE_W//2 if x2 > x1 else x1 - NODE_W//2
            ex2 = x2 - NODE_W//2 if x2 > x1 else x2 + NODE_W//2
            yo1 = int(y1 + off)
            yo2 = int(y2 + off)
            cp1x = int(ex1 + (ex2 - ex1) * 0.55)
            cp2x = int(ex1 + (ex2 - ex1) * 0.45)
            svg.append(f'<path d="M{ex1},{yo1} C{cp1x},{yo1} {cp2x},{yo2} {ex2},{yo2}" fill="none" stroke="{col}" stroke-width="{sw}" {dash} marker-end="url(#{marker})"/>')
            lx    = (ex1 + ex2) // 2
            ly_e  = int((yo1 + yo2) // 2 - 8)

        # Data label pill
        dlbl = _xml((flow.get("data","") or "")[:22])
        lw   = int(len(dlbl) * 5.4 + 12)
        svg.append(f'<rect x="{lx-lw//2}" y="{ly_e-11}" width="{lw}" height="14" rx="3" fill="white" opacity="0.93"/>')
        svg.append(f'<text x="{lx}" y="{ly_e}" text-anchor="middle" class="sv-edge" fill="{col}">{dlbl}</text>')

        # STRIDE tag circles
        for ti, tag in enumerate(tags):
            tc  = _STRIDE_TAG_COLOR.get(tag, "#555")
            tx  = lx + lw//2 + 8 + ti * 17
            svg.append(f'<circle cx="{tx}" cy="{ly_e-5}" r="8" fill="{tc}" opacity="0.92"/>')
            svg.append(f'<text x="{tx}" y="{ly_e-1}" text-anchor="middle" font-family="DM Mono,monospace" font-size="8" font-weight="600" fill="white">{tag}</text>')

    # Nodes
    for comp in components:
        name = comp["name"]
        if name not in node_pos:
            continue
        cx, cy = node_pos[name]
        ctype  = comp.get("type","process")
        zone   = comp.get("zone","Standard Application")
        score  = comp.get("zone_score",3)
        zs     = _ZONE_STYLE.get(zone, _ZONE_STYLE["Standard Application"])
        is_thr = name in threat_nodes
        fill   = "#FFCDD2" if is_thr else "white"
        stroke = "#C62828" if is_thr else zs["stroke"]
        sw_n   = "3"       if is_thr else "1.8"
        flt    = 'filter="url(#nd-r)"' if is_thr else 'filter="url(#nd)"'
        x0, y0 = cx - NODE_W//2, cy - NODE_H//2

        if ctype == "external_entity":
            svg.append(f'<ellipse cx="{cx}" cy="{cy}" rx="{NODE_W//2}" ry="{NODE_H//2}" fill="{fill}" stroke="{stroke}" stroke-width="{sw_n}" {flt}/>')
        elif ctype == "datastore":
            cap = 9
            svg.append(f'<rect x="{x0}" y="{y0+cap}" width="{NODE_W}" height="{NODE_H-cap*2}" fill="{fill}" stroke="none" {flt}/>')
            svg.append(f'<line x1="{x0}" y1="{y0+cap}" x2="{x0+NODE_W}" y2="{y0+cap}" stroke="{stroke}" stroke-width="{sw_n}"/>')
            svg.append(f'<line x1="{x0}" y1="{y0+NODE_H-cap}" x2="{x0+NODE_W}" y2="{y0+NODE_H-cap}" stroke="{stroke}" stroke-width="{sw_n}"/>')
            # Side outline only (no fill for open-ended appearance)
            svg.append(f'<rect x="{x0}" y="{y0+cap}" width="{NODE_W}" height="{NODE_H-cap*2}" fill="none" stroke="{stroke}" stroke-width="{sw_n}"/>')
        else:
            svg.append(f'<rect x="{x0}" y="{y0}" width="{NODE_W}" height="{NODE_H}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="{sw_n}" {flt}/>')

        if is_thr:
            svg.append(f'<ellipse cx="{cx}" cy="{cy}" rx="{NODE_W//2+10}" ry="{NODE_H//2+10}" fill="none" stroke="#C62828" stroke-width="1.5" stroke-dasharray="4,3" opacity="0.65"/>')
            svg.append(f'<circle cx="{x0+NODE_W+2}" cy="{y0-2}" r="9" fill="#C62828"/>')
            svg.append(f'<text x="{x0+NODE_W+2}" y="{y0+3}" text-anchor="middle" font-family="Sora,Arial" font-size="11" font-weight="700" fill="white">!</text>')

        svg.append(f'<text x="{cx}" y="{cy-3}" text-anchor="middle" class="sv-name">{_xml(name[:20])}</text>')
        svg.append(f'<text x="{cx}" y="{cy+12}" text-anchor="middle" class="sv-desc">{_xml((comp.get("description","") or "")[:26])}</text>')
        svg.append(f'<rect x="{x0+NODE_W-30}" y="{y0+NODE_H-15}" width="28" height="13" rx="6" fill="{zs["stroke"]}" opacity="0.85"/>')
        svg.append(f'<text x="{x0+NODE_W-16}" y="{y0+NODE_H-4}" text-anchor="middle" font-family="DM Mono,monospace" font-size="8.5" font-weight="500" fill="white">z{score}</text>')
        type_mark = {"external_entity":"⬭","process":"⚙","datastore":"⊣⊢"}.get(ctype,"●")
        svg.append(f'<text x="{x0+6}" y="{y0+13}" font-size="9" fill="{zs["dark"]}" opacity="0.65">{type_mark}</text>')

    # Legend
    ly_leg = H - BOT_H
    svg.append(f'<rect x="0" y="{ly_leg}" width="{W}" height="{BOT_H}" fill="#F7F9FC"/>')
    svg.append(f'<line x1="0" y1="{ly_leg}" x2="{W}" y2="{ly_leg}" stroke="#E0E7EF" stroke-width="1"/>')
    svg.append(f'<text x="12" y="{ly_leg+14}" class="sv-legt">LEGEND</text>')

    leg_items = [
        ("white","#78909C","⬭ External Entity"),
        ("white","#F9A825","⚙ Process"),
        ("white","#E53935","⊣⊢ Data Store"),
        ("#FFCDD2","#C62828","! Threat Node"),
    ]
    if mode == "stride":
        leg_items += [("#E65100","#E65100","T Tampering"),("#1565C0","#1565C0","I Info Disc"),("#6A1B9A","#6A1B9A","D DoS")]
    lxp = 14
    for fl_l, st_l, lb_l in leg_items:
        svg.append(f'<rect x="{lxp}" y="{ly_leg+22}" width="11" height="11" rx="2" fill="{fl_l}" stroke="{st_l}" stroke-width="1.5"/>')
        svg.append(f'<text x="{lxp+15}" y="{ly_leg+32}" class="sv-leg">{_xml(lb_l)}</text>')
        lxp += int(len(lb_l) * 5.5 + 26)

    svg.append("</svg>")
    return "\n".join(svg)


def show_architecture_diagram(workshop_config, threats=None, mode="architecture", key_suffix=""):
    captions = {
        "architecture": "Architecture overview — lanes = trust zones, shapes: ⬭ external entity · ⚙ process · ⊣⊢ data store · z-score = criticality",
        "stride":       "STRIDE analysis — dots on edges: 🟠 T=Tampering (↑ zone)  🔵 I=Info Disclosure (↓ zone)  🟣 D=DoS (Zone-0 source)",
        "threat":       "Threat map — components with identified threats shown in red with ! badge",
    }
    svg = render_architecture_svg(workshop_config, highlighted_threats=threats or [], mode=mode)
    if mode in captions:
        st.markdown(f'<p style="font-size:0.78em;color:#78909C;margin:0 0 5px 6px">📐 {captions[mode]}</p>', unsafe_allow_html=True)
    st.markdown(f'<div style="overflow-x:auto">{svg}</div>', unsafe_allow_html=True)



@st.cache_data(show_spinner=False)
def generate_zone_labeled_dfd(workshop_config_json, show_stride_rules=False, threats_json=None):
    """Generate DFD with criticality zone labels (Infosec methodology Step 2)."""
    workshop_config = json.loads(workshop_config_json)
    threats = json.loads(threats_json) if threats_json else None
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


# generate_stride_annotated_dfd merged into generate_zone_labeled_dfd


@st.cache_data(show_spinner=False)
def generate_attack_tree(tree_json, title="Attack Tree"):
    tree_structure = json.loads(tree_json)
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
    """Only load from disk if session state hasn't been initialised yet."""
    if st.session_state.get('_progress_loaded'):
        return
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
    st.session_state['_progress_loaded'] = True


load_progress()


def is_workshop_unlocked(ws_id):
    return ws_id in st.session_state.unlocked_workshops


# ─────────────────────────────────────────────────────────────────────────────
# PDF GENERATORS
# ─────────────────────────────────────────────────────────────────────────────
def generate_user_threat_model_pdf(workshop_config, user_answers, total_score, max_score):
    try:
        (letter, getSampleStyleSheet, ParagraphStyle, inch, colors,
         SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table,
         TableStyle, TA_CENTER, TA_LEFT) = _get_reportlab()
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
        (letter, getSampleStyleSheet, ParagraphStyle, inch, colors,
         SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table,
         TableStyle, TA_CENTER, TA_LEFT) = _get_reportlab()
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        story = []

        all_threats = get_predefined_threats().get(workshop_id, [])

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
    st.markdown("""
    <div style="text-align:center;padding:10px 0 8px 0">
      <div style="font-size:2em">🔒</div>
      <div style="font-weight:700;font-size:1.05em;margin:4px 0">Threat Modeling Lab</div>
      <div style="font-size:0.78em;opacity:0.7">4-Step Infosec Methodology</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("**🗺️ Methodology Steps**")
    st.markdown("""
    1. 🎨 **Design** – DFD
    2. 🏷️ **Zones of Trust** – 0–9 scale
    3. 🔍 **STRIDE** – rule-based discovery
    4. 🛡️ **Mitigations** – OWASP mapping
    """)
    st.markdown("---")

    if st.session_state.selected_workshop:
        ws_name = get_workshops().get(st.session_state.selected_workshop,{}).get("name","")
        step_names = {1:"Design",2:"Zones",2.5:"STRIDE Rules",3:"Attack Tree",4:"Identify",5:"Assess",6:"Complete"}
        cur_step_name = step_names.get(st.session_state.current_step,"")
        ws_level = get_workshops().get(st.session_state.selected_workshop,{}).get("level","")
        st.markdown(f"""
        <div style="background:rgba(79,195,247,0.12);border:1px solid rgba(79,195,247,0.3);
                    border-radius:8px;padding:10px 12px;margin:6px 0">
          <div style="font-size:0.7em;text-transform:uppercase;letter-spacing:1.5px;color:#4FC3F7;margin-bottom:4px">NOW STUDYING</div>
          <div style="font-weight:700;font-size:0.92em;color:#E8F4FD">{ws_name}</div>
          <div style="font-size:0.78em;color:#90CAF9;margin-top:2px">{ws_level} · Step: {cur_step_name}</div>
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.max_score > 0:
            pct = st.session_state.total_score / st.session_state.max_score * 100
            bar_color = "#43A047" if pct >= 80 else "#F9A825" if pct >= 60 else "#E53935"
            st.markdown(f"""
            <div style="margin:6px 0 2px 0;font-size:0.8em;color:#90CAF9">
            Score: <strong style="color:#E8F4FD">{st.session_state.total_score}/{st.session_state.max_score}</strong>
            &nbsp;({pct:.0f}%)
            </div>""", unsafe_allow_html=True)
            st.progress(pct / 100)
        st.markdown("---")

    st.markdown("### Select Workshop")
    for ws_id, ws_config in get_workshops().items():
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

        # Only show detail expander for selected workshop to avoid rendering all
        if st.session_state.selected_workshop == ws_id:
            with st.expander("ℹ️ Details", expanded=False):
                st.caption(f"**Level:** {ws_config['level']}")
                st.caption(f"**Duration:** {ws_config['duration']}")
                st.caption(f"**Threats:** {ws_config['target_threats']}")

    st.markdown("---")
    with st.expander("⚡ STRIDE Quick Reference"):
        stride_items = [
            ("S","Spoofing","#FFCDD2","Identity impersonation — pretending to be someone else","Zone-0 reachable nodes"),
            ("T","Tampering","#FFE0B2","Data modification — altering data or code","Less→more critical flows"),
            ("R","Repudiation","#FFF9C4","Denying actions — no proof of who did what","Nodes with Spoofing+Tampering"),
            ("I","Info Disclosure","#E0F7FA","Data exposure — secrets reaching wrong party","More→less critical flows"),
            ("D","DoS","#F3E5F5","Availability — crashing or degrading services","Zone-0→any node flows"),
            ("E","EoP","#E8F5E9","Privilege escalation — gaining unauthorized access","Higher nodes adj to lower"),
        ]
        for letter, name, bg, desc, rule in stride_items:
            st.markdown(f"""
            <div style="background:{bg};border-radius:6px;padding:8px 10px;margin:3px 0;font-size:0.82em">
              <strong style="font-size:1em">{letter} — {name}</strong><br>
              <span style="color:#444">{desc}</span><br>
              <span style="color:#777;font-size:0.85em">Rule: {rule}</span>
            </div>
            """, unsafe_allow_html=True)

    with st.expander("🏷️ Zone Scale (0–9)"):
        zone_mini = [
            (0,"Not in Control","#EEEEEE","#757575"),
            (1,"Minimal Trust","#C8E6C9","#388E3C"),
            (3,"Standard App","#FFF9C4","#F9A825"),
            (5,"Elevated Trust","#FFE0B2","#E65100"),
            (7,"Critical","#FFCDD2","#C62828"),
            (9,"Maximum Security","#FFAB91","#BF360C"),
        ]
        for score, label, bg, border in zone_mini:
            st.markdown(f"""
            <div style="background:{bg};border-left:3px solid {border};border-radius:4px;
                        padding:5px 8px;margin:2px 0;font-size:0.8em">
              <strong>z{score}</strong> — {label}
            </div>
            """, unsafe_allow_html=True)

    with st.expander("📐 Zone-Direction Rules"):
        rules = [
            ("↑ Tampering","Less → More critical zone flow"),
            ("↓ Info Disclosure","More → Less critical zone flow"),
            ("💥 DoS","Zone-0 → any node"),
            ("🎭 Spoofing","Node reachable from Zone-0"),
            ("🔄 Repudiation","Node where Spoofing + Tampering both apply"),
            ("⬆ EoP","Higher-zone node adjacent to lower-zone node"),
        ]
        for rule, desc in rules:
            st.markdown(f"**{rule}**: {desc}")


# ═══════════════════════════════════════════════════════════════════════════════
#  HOME PAGE
# ═══════════════════════════════════════════════════════════════════════════════
if not st.session_state.selected_workshop:
    # ── Hero banner ─────────────────────────────────────────────────────────
    st.markdown("""
    <div style="background:linear-gradient(135deg,#0D1B2A 0%,#1B4F72 60%,#0F4C75 100%);
                padding:40px 36px;border-radius:14px;margin-bottom:28px;
                box-shadow:0 6px 24px rgba(0,0,0,0.25)">
      <h1 style="color:white;margin:0 0 8px 0;font-size:2.2em;font-weight:700">
        🔒 STRIDE Threat Modeling Mastery Lab
      </h1>
      <p style="color:#90CAF9;font-size:1.1em;margin:0 0 16px 0">
        From security novice → professional threat modeler in 4 progressive workshops
      </p>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <span style="background:rgba(255,255,255,0.15);color:white;padding:6px 14px;border-radius:20px;font-size:0.85em">📚 4 Hands-On Workshops</span>
        <span style="background:rgba(255,255,255,0.15);color:white;padding:6px 14px;border-radius:20px;font-size:0.85em">🎯 30 Real-World Threats</span>
        <span style="background:rgba(255,255,255,0.15);color:white;padding:6px 14px;border-radius:20px;font-size:0.85em">⚡ Live Architecture Diagrams</span>
        <span style="background:rgba(255,255,255,0.15);color:white;padding:6px 14px;border-radius:20px;font-size:0.85em">🏆 Mastery Certification</span>
        <span style="background:rgba(255,255,255,0.15);color:white;padding:6px 14px;border-radius:20px;font-size:0.85em">🛡️ OWASP Top 10 Aligned</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Overall progress (if returning student) ──────────────────────────────
    completed_count = len(st.session_state.completed_workshops)
    if completed_count > 0:
        total_ws = 4
        prog_pct = completed_count / total_ws
        st.markdown(f"""
        <div class="success-box">
        <strong>🎓 Your Progress: {completed_count}/{total_ws} workshops completed</strong>
        </div>
        """, unsafe_allow_html=True)
        st.progress(prog_pct)
        st.markdown("---")

    # ── Learning journey tabs ──────────────────────────────────────────────
    home_tabs = st.tabs(["🗺️ Learning Path", "🧠 What You'll Master", "📋 The 4-Step Method", "🏆 Skill Tree"])

    with home_tabs[0]:
        st.markdown("### Your Journey from Novice to Expert")
        st.markdown("""
        <div class="info-box">
        This lab uses the <strong>Infosec Institute 4-Step Methodology</strong> — the same framework used
        by Microsoft, OWASP, and enterprise security teams. Each workshop adds a new layer of complexity,
        building on what you've learned before.
        </div>
        """, unsafe_allow_html=True)

        ws_data = list(get_workshops().items())
        level_colors = {"Foundation":"#1B6CA8","Intermediate":"#2E7D32","Advanced":"#E65100","Expert":"#7B1FA2"}
        level_icons  = {"Foundation":"🌱","Intermediate":"🌿","Advanced":"🌳","Expert":"🔥"}
        for idx, (ws_id, ws) in enumerate(ws_data):
            unlocked  = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            lc = level_colors.get(ws["level"], "#0F4C75")
            li = level_icons.get(ws["level"], "📚")
            status_html = (
                '<span class="badge-completed">✅ Completed</span>' if completed else
                '<span class="badge-available">🔓 Available</span>' if unlocked else
                '<span class="badge-locked">🔒 Locked</span>'
            )
            connector = f'<div style="text-align:center;color:{lc};font-size:1.5em;margin:-4px 0">↓</div>' if idx < len(ws_data)-1 else ""
            st.markdown(f"""
            <div class="premium-card" style="border-left:5px solid {lc}">
              <div style="display:flex;justify-content:space-between;align-items:flex-start">
                <div style="flex:1">
                  <h4 style="margin:0 0 4px 0;color:{lc}">{li} Workshop {ws_id}: {ws['scenario']['title']}</h4>
                  <p style="margin:0 0 8px 0;color:#555;font-size:0.9em">{ws['scenario']['description']} · {ws['scenario']['business_context']}</p>
                  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
                    <span style="background:#F0F4F8;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">📊 {ws['level']}</span>
                    <span style="background:#F0F4F8;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">⏱️ {ws['duration']}</span>
                    <span style="background:#F0F4F8;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">🎯 {ws['target_threats']} threats</span>
                    <span style="background:#F0F4F8;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">🏗️ {ws.get('architecture_type','')}</span>
                  </div>
                  <div><strong style="font-size:0.85em;color:#555">You will learn:</strong><br>
                  {''.join(f"<span style='font-size:0.82em;color:#444'>• {lo}</span><br>" for lo in ws.get('learning_objectives',[]))}
                  </div>
                </div>
                <div style="text-align:right;padding-left:16px">{status_html}</div>
              </div>
            </div>
            {connector}
            """, unsafe_allow_html=True)

            if unlocked and not completed:
                if st.button(f"▶ Start Workshop {ws_id}: {ws['scenario']['title']}", key=f"start_home_{ws_id}", type="primary"):
                    st.session_state.selected_workshop = ws_id
                    st.session_state.current_step = 1
                    save_progress()
                    st.rerun()
            elif completed:
                if st.button(f"↩ Revisit Workshop {ws_id}", key=f"revisit_home_{ws_id}"):
                    st.session_state.selected_workshop = ws_id
                    st.session_state.current_step = 1
                    save_progress()
                    st.rerun()

    with home_tabs[1]:
        st.markdown("### What You Will Master by Completing All 4 Workshops")
        skills = [
            ("🏗️", "System Architecture Analysis",
             "Read any system diagram and immediately identify Interactors (external entities), Modules (processes + data stores), and Connections (data flows). Classify every component using DFD notation.",
             ["Web apps","Microservices","SaaS platforms","IoT systems"]),
            ("🏷️", "Criticality Zone Assignment",
             "Assign a numerical Zone of Trust score (0–9) to every component in a system. Understand why Zone 0 = untrusted external, Zone 9 = life-critical internal, and everything in between.",
             ["Zone labelling","Score calibration","Trust boundary identification","Zone rationale"]),
            ("⚡", "Zone-Based Threat Discovery",
             "Apply the 5 zone-direction rules to mechanically discover which STRIDE categories apply to each data flow and node. No guesswork — pure systematic derivation.",
             ["Tampering: less→more critical","Info Disclosure: more→less critical","DoS: Zone-0→any","Spoofing: Zone-0 reachable","EoP: higher zone adjacent to lower"]),
            ("🛡️", "OWASP Control Mapping",
             "Map every STRIDE threat to the OWASP Top 10 (2021) and identify the specific controls that mitigate it. Understand which controls address which STRIDE categories and why.",
             ["OWASP A01–A10 mapping","Control selection","Defence-in-depth","Compliance alignment"]),
            ("📊", "Attack Tree Construction",
             "Build and read attack trees showing all paths to a threat goal. Understand AND/OR node logic — how attackers chain simple steps into sophisticated attacks.",
             ["Goal decomposition","AND-node chaining","OR-node enumeration","Attack path prioritisation"]),
            ("🏥", "Domain-Specific Threat Modeling",
             "Apply STRIDE to four distinct architecture types: traditional web apps, microservices, multi-tenant SaaS, and IoT/healthcare systems — each with domain-specific threats and compliance frameworks.",
             ["PCI-DSS for e-commerce","SOC 2 for SaaS","HIPAA for healthcare","FDA requirements for IoT"]),
        ]
        for icon, title, desc, topics in skills:
            with st.expander(f"{icon} {title}", expanded=False):
                st.markdown(f"""
                <div class="learning-box">{desc}</div>
                """, unsafe_allow_html=True)
                st.markdown("**Topics covered:**")
                cols_sk = st.columns(2)
                for i, t in enumerate(topics):
                    cols_sk[i%2].markdown(f"✓ {t}")

    with home_tabs[2]:
        st.markdown("### The 4-Step Infosec Threat Modeling Methodology")
        steps_detail = [
            ("1", "Design the Threat Model", "#E3F2FD", "#1565C0",
             "Create a Data Flow Diagram (DFD) that captures the complete system architecture.",
             ["Identify all <strong>Interactors</strong> — external people and systems you don't control",
              "Map all <strong>Modules</strong> — processes that transform data + data stores that persist it",
              "Draw all <strong>Connections</strong> — every data flow, its protocol, and what data it carries",
              "Document <strong>Trust Boundaries</strong> — the lines where control or ownership changes"],
             "Before you can find threats you must know exactly what you're protecting. A missing component in the diagram means a missed threat.",
             "Microsoft Threat Modeling Tool, STRIDE-per-Element, DFD Level 0/1/2"),
            ("2", "Apply Zones of Trust", "#FFF9C4", "#F57F17",
             "Assign every component a criticality level from 0 (untrusted) to 9 (life-critical).",
             ["Zone 0: Not in system control (external users, 3rd party services)",
              "Zone 1–2: Entry points — minimal authentication enforced",
              "Zone 3–4: Application layer — standard security controls",
              "Zone 5–6: Elevated trust — privileged services, payment processing",
              "Zone 7–8: Critical — databases, regulated data stores",
              "Zone 9: Maximum security — safety-critical, life-critical systems"],
             "Zones turn threat discovery from art into science. The zone difference between source and destination tells you which STRIDE categories mechanically apply.",
             "Microsoft SDL Zone of Trust, NIST 800-207 Zero Trust"),
            ("3", "Discover Threats with STRIDE", "#FFE0B2", "#E65100",
             "Apply zone-direction rules to systematically derive applicable STRIDE threats.",
             ["<strong>Flows:</strong> Tampering on less→more critical flows; Info Disclosure on more→less",
              "<strong>Flows from Zone 0:</strong> Always check Denial of Service",
              "<strong>Nodes reachable from Zone 0:</strong> Spoofing applies",
              "<strong>Nodes where Spoofing + Tampering both apply:</strong> Repudiation applies",
              "<strong>Higher-zone nodes adjacent to lower-zone nodes:</strong> Elevation of Privilege"],
             "These rules come from Microsoft's original STRIDE paper. They make threat discovery repeatable — two analysts working independently produce the same threat list.",
             "STRIDE-per-Element, SAFECode Threat Modeling, OWASP Threat Dragon"),
            ("4", "Explore Mitigations and Controls", "#E8F5E9", "#2E7D32",
             "Map each identified STRIDE threat to OWASP Top 10 and select specific controls.",
             ["Spoofing → OWASP A07 (Authentication Failures) → MFA, secure sessions",
              "Tampering → OWASP A03 (Injection) + A08 (Integrity) → parameterised queries, HMAC",
              "Repudiation → OWASP A09 (Logging Failures) → immutable audit logs, SIEM",
              "Info Disclosure → OWASP A02 (Crypto Failures) → TLS 1.3, AES-256 at rest",
              "DoS → OWASP A04 (Insecure Design) → rate limiting, circuit breakers, WAF",
              "EoP → OWASP A01 (Broken Access Control) → RBAC, deny-by-default"],
             "Controls must be specific, implementable, and auditable. Vague controls like 'add security' are useless — each must map to a concrete engineering action.",
             "OWASP Top 10 (2021), OWASP ASVS v4, NIST 800-53, CIS Controls v8"),
        ]
        for num, title, bg, border, summary, bullets, insight, refs in steps_detail:
            st.markdown(f"""
            <div class="premium-card" style="border-left:5px solid {border};background:{bg}20">
              <h3 style="color:{border};margin:0 0 8px 0">Step {num}: {title}</h3>
              <p style="margin:0 0 10px 0;color:#333">{summary}</p>
              <div style="margin-bottom:10px">
                {''.join(f"<div style='font-size:0.88em;color:#444;padding:3px 0'>▸ {b}</div>" for b in bullets)}
              </div>
              <div class="callout-box" style="margin:8px 0">
                <strong>💡 Why this step matters:</strong> {insight}
              </div>
              <div style="font-size:0.8em;color:#777;margin-top:6px">📖 Industry references: {refs}</div>
            </div>
            """, unsafe_allow_html=True)

    with home_tabs[3]:
        st.markdown("### 🏆 Skill Progression Tree")
        st.markdown("""
        <div class="info-box">
        Each workshop unlocks new skills. Skills build on each other — you cannot skip ahead
        without the foundational knowledge. Track your progress through the tree below.
        </div>
        """, unsafe_allow_html=True)

        completed_ws = st.session_state.completed_workshops
        skill_tree = [
            ("WS1", "Foundation",
             ["DFD element classification","Zone 0–7 assignment","Basic STRIDE rules","OWASP A01–A10 mapping","XSS / SQLi / IDOR recognition"],
             "1" in completed_ws),
            ("WS2", "Intermediate",
             ["Service mesh threat modeling","mTLS & BOLA identification","Distributed tracing for Repudiation","OWASP API Security Top 10","Microservices zone rules"],
             "2" in completed_ws),
            ("WS3", "Advanced",
             ["Multi-tenant isolation threats","Row-Level Security design","Cross-tenant EoP patterns","SOC 2 compliance mapping","Kafka/streaming threat surfaces"],
             "3" in completed_ws),
            ("WS4", "Expert",
             ["IoT/edge trust boundary analysis","Replay attack detection design","HIPAA/FDA control mapping","Life-critical zone 9 threats","HL7/legacy protocol security"],
             "4" in completed_ws),
        ]
        level_grad = {
            "Foundation":  "linear-gradient(135deg,#1B6CA8,#2980B9)",
            "Intermediate":"linear-gradient(135deg,#1B5E20,#2E7D32)",
            "Advanced":    "linear-gradient(135deg,#E65100,#F57C00)",
            "Expert":      "linear-gradient(135deg,#4A148C,#7B1FA2)",
        }
        cols_tree = st.columns(4)
        for col, (ws_label, level, skills_list, done) in zip(cols_tree, skill_tree):
            with col:
                grad = level_grad.get(level,"linear-gradient(135deg,#0F4C75,#1B6CA8)")
                alpha = "1" if done else "0.45"
                skill_rows = "".join(
                    f'<div style="font-size:0.8em;padding:3px 0;color:#{"E8F4FD" if done else "777"}">{"✅" if done else "⭕"} {s}</div>'
                    for s in skills_list
                )
                st.markdown(f"""
                <div style="background:{grad};border-radius:10px;padding:16px;opacity:{alpha};
                            box-shadow:0 3px 10px rgba(0,0,0,0.2);min-height:200px">
                  <div style="color:white;font-weight:700;font-size:1em;margin-bottom:4px">{ws_label}</div>
                  <div style="color:rgba(255,255,255,0.7);font-size:0.8em;margin-bottom:10px">{level}</div>
                  {skill_rows}
                  {'<div style="margin-top:10px;background:rgba(255,255,255,0.2);border-radius:6px;padding:4px 8px;text-align:center;color:white;font-size:0.8em;font-weight:600">✅ MASTERED</div>' if done else ''}
                </div>
                """, unsafe_allow_html=True)

    st.markdown("---")
    # Quick-start CTA
    st.markdown("""
    <div class="key-concept">
      <h4>Ready to Begin?</h4>
      <p style="margin:0;font-size:1em">Start with Workshop 1 — no prior security knowledge needed. Each step teaches
      you the <em>why</em> behind every decision, not just the what. By Workshop 4 you will be
      threat modeling systems that protect human lives.</p>
    </div>
    """, unsafe_allow_html=True)

    ws1_config = get_workshops()["1"]
    if st.button("▶ Start Workshop 1: TechMart E-Commerce →", type="primary", use_container_width=True):
        st.session_state.selected_workshop = "1"
        st.session_state.current_step = 1
        save_progress()
        st.rerun()
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
#  WORKSHOP SELECTED – STEP NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════════
current_workshop = get_workshops()[st.session_state.selected_workshop]
workshop_threats = get_predefined_threats().get(st.session_state.selected_workshop, [])

# Premium workshop header
ws_level_color = {"Foundation":"#1B6CA8","Intermediate":"#2E7D32","Advanced":"#E65100","Expert":"#7B1FA2"}.get(current_workshop["level"],"#0F4C75")
st.markdown(f"""
<div style="display:flex;align-items:center;gap:16px;margin-bottom:4px">
  <div>
    <h1 style="margin:0;color:#0F4C75">{current_workshop['name']}</h1>
    <div style="display:flex;gap:8px;margin-top:6px;flex-wrap:wrap">
      <span style="background:{ws_level_color};color:white;padding:3px 12px;border-radius:12px;font-size:0.82em;font-weight:600">{current_workshop['level']}</span>
      <span style="background:#F0F4F8;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">⏱️ {current_workshop['duration']}</span>
      <span style="background:#F0F4F8;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">🎯 {current_workshop['target_threats']} threats</span>
      <span style="background:#F0F4F8;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">🏗️ {current_workshop.get('architecture_type','')}</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Step progress bar — compact horizontal stepper ────────────────────────
_step_defs = [
    (1,   "1","Design",      "🏗"),
    (2,   "2","Zones",       "🏷"),
    (2.5, "3","STRIDE Rules","⚡"),
    (3,   "4","Attack Tree", "🌳"),
    (4,   "5","Identify",    "🎯"),
    (5,   "6","Assess",      "📊"),
    (6,   "7","Complete",    "🏆"),
]
step_html_parts = []
for val, num, label, icon in _step_defs:
    if st.session_state.current_step > val:
        bg, fg, ring = "#1B5E20","white","#43A047"
        content = f"✓"
    elif st.session_state.current_step == val:
        bg, fg, ring = "#0D1B2A","white","#4FC3F7"
        content = num
    else:
        bg, fg, ring = "#ECEFF1","#78909C","#B0BEC5"
        content = num
    step_html_parts.append(
        f'<div style="display:flex;flex-direction:column;align-items:center;gap:3px;min-width:56px">' +
        f'<div style="width:28px;height:28px;border-radius:50%;background:{bg};color:{fg};' +
        f'border:2px solid {ring};display:flex;align-items:center;justify-content:center;' +
        f'font-family:Sora,Arial;font-weight:700;font-size:11px">{content}</div>' +
        f'<div style="font-family:DM Sans,Arial;font-size:9.5px;color:{"#1B5E20" if st.session_state.current_step>val else ("#0D1B2A" if st.session_state.current_step==val else "#90A4AE")};font-weight:{"700" if st.session_state.current_step==val else "400"};text-align:center">{label}</div>' +
        '</div>'
    )

connector = '<div style="flex:1;height:2px;background:#E0E7EF;margin-top:14px;min-width:8px"></div>'
step_html = connector.join(step_html_parts)

st.markdown(
    f'<div style="display:flex;align-items:flex-start;gap:0;padding:10px 0 6px 0;overflow-x:auto">{step_html}</div>',
    unsafe_allow_html=True
)
_step_num_map = {1:1, 2:2, 2.5:3, 3:4, 4:5, 5:6, 6:7}
st.progress(_step_num_map.get(st.session_state.current_step, 1) / 7)
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
        <div style="background:white;border-radius:10px;padding:18px;border:2px solid #FFCDD2;
                    box-shadow:0 2px 8px rgba(0,0,0,0.07);height:100%">
        <div style="font-size:1.3em;margin-bottom:6px">👤</div>
        <h4 style="margin:0 0 8px 0;color:#C62828;font-family:Sora,Arial">Interactors</h4>
        <div style="font-size:0.82em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#EF5350;margin-bottom:8px">External Entities</div>
        <p style="font-size:0.88em;color:#444;margin:0 0 10px 0">People and systems <strong>outside your control</strong> that send data to or receive data from your system.</p>
        <div style="background:#FFEBEE;border-radius:6px;padding:8px 10px;margin:6px 0;font-size:0.82em">
          <strong>Always Zone 0</strong> — Not in Control of System<br>
          <span style="color:#666">Examples: End users, payment gateways, IoT sensors, partner APIs</span>
        </div>
        <div style="font-size:0.82em;color:#555;margin-top:8px">
          <strong>STRIDE exposure:</strong><br>
          ⚫ Spoofing (they can impersonate others)<br>
          ⚫ DoS (they can flood your entry points)<br>
          <em style="color:#888">Cannot be Tampering or EoP — they have no internal access</em>
        </div>
        </div>
        """, unsafe_allow_html=True)
    with col_b:
        st.markdown("""
        <div style="background:white;border-radius:10px;padding:18px;border:2px solid #BBDEFB;
                    box-shadow:0 2px 8px rgba(0,0,0,0.07);height:100%">
        <div style="font-size:1.3em;margin-bottom:6px">⚙️</div>
        <h4 style="margin:0 0 8px 0;color:#1565C0;font-family:Sora,Arial">Modules</h4>
        <div style="font-size:0.82em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#1976D2;margin-bottom:8px">Processes & Data Stores</div>
        <p style="font-size:0.88em;color:#444;margin:0 0 10px 0">Components <strong>inside your system</strong> — processes transform data, data stores persist it.</p>
        <div style="background:#E3F2FD;border-radius:6px;padding:8px 10px;margin:6px 0;font-size:0.82em">
          <strong>Zones 1–9</strong> — assigned based on criticality<br>
          <span style="color:#666">Examples: APIs, databases, auth services, message queues</span>
        </div>
        <div style="font-size:0.82em;color:#555;margin-top:8px">
          <strong>STRIDE exposure:</strong><br>
          ⚫ All 6 STRIDE categories can apply<br>
          <em style="color:#888">Highest-complexity threat surface — the zone determines which rules apply</em>
        </div>
        </div>
        """, unsafe_allow_html=True)
    with col_c:
        st.markdown("""
        <div style="background:white;border-radius:10px;padding:18px;border:2px solid #C8E6C9;
                    box-shadow:0 2px 8px rgba(0,0,0,0.07);height:100%">
        <div style="font-size:1.3em;margin-bottom:6px">🔗</div>
        <h4 style="margin:0 0 8px 0;color:#2E7D32;font-family:Sora,Arial">Connections</h4>
        <div style="font-size:0.82em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#388E3C;margin-bottom:8px">Data Flows</div>
        <p style="font-size:0.88em;color:#444;margin:0 0 10px 0">Every path <strong>data travels</strong> between components — the network of information exchange.</p>
        <div style="background:#E8F5E9;border-radius:6px;padding:8px 10px;margin:6px 0;font-size:0.82em">
          <strong>Zone direction = STRIDE rule</strong><br>
          <span style="color:#666">Examples: HTTPS requests, SQL queries, Kafka messages, BLE</span>
        </div>
        <div style="font-size:0.82em;color:#555;margin-top:8px">
          <strong>STRIDE exposure by direction:</strong><br>
          ↑ Less→More critical: Tampering<br>
          ↓ More→Less critical: Information Disclosure<br>
          Zone-0 source: + DoS
        </div>
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

    # ── Key concept callout ───────────────────────────────────────────────
    st.markdown("""
    <div class="key-concept">
      <h4>Key Concept: Why Data Flows Are the Heart of Threat Modeling</h4>
      <p style="margin:0;font-size:0.95em">Every security failure ultimately involves data moving somewhere it shouldn't,
      or being modified somewhere it shouldn't. Data flows are where <strong>Tampering</strong>,
      <strong>Information Disclosure</strong>, and <strong>Denial of Service</strong> threats
      are discovered. The protocol matters too — HTTPS is encrypted,
      plain HTTP is not. MQTT/BLE in IoT may have no authentication at all.</p>
    </div>
    """, unsafe_allow_html=True)

    flows_df = pd.DataFrame([{
        "Source": f["source"], "→": "→", "Destination": f["destination"],
        "Data Type": f["data"], "Protocol": f["protocol"]
    } for f in scenario["data_flows"]])
    st.dataframe(flows_df, use_container_width=True, hide_index=True)

    # Trust boundaries callout
    if scenario.get("trust_boundaries"):
        st.markdown("---")
        st.subheader("🚧 Trust Boundaries")
        st.markdown("""
        <div class="info-box">
        <strong>What is a Trust Boundary?</strong><br>
        A trust boundary is any line in your diagram where data crosses from one level of trust
        to another — from the internet to your frontend, from your API to your database.
        <strong>Every trust boundary crossing is a potential attack surface.</strong>
        The more critical the zone on the receiving side, the higher the threat potential.
        </div>
        """, unsafe_allow_html=True)
        for tb in scenario["trust_boundaries"]:
            st.markdown(f"""
            <div class="component-card">
            <strong>🚧 {tb['name']}</strong><br>
            <span style="color:#555;font-size:0.9em">{tb['description']}</span><br>
            <span style="font-size:0.82em;color:#777">Components: {', '.join(tb['components'])}</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("""
    <div class="practical-task">
    <strong>🎯 Step 1 Complete</strong> – You now have a complete picture of the system design:<br>
    • All <strong>Interactors</strong> (external entities) identified<br>
    • All <strong>Modules</strong> (processes + data stores) listed<br>
    • All <strong>Connections</strong> (data flows) documented with protocols<br><br>
    Next: Apply <strong>Zones of Trust</strong> to every component using the 0–9 criticality scale.
    </div>
    """, unsafe_allow_html=True)

    # ── Dynamic architecture diagram ──────────────────────────────────────
    st.markdown("---")
    st.subheader("🏗️ Architecture Diagram (Auto-generated)")
    st.markdown("""
    <div class="info-box">
    This diagram is dynamically generated from the workshop architecture — like a Draw.io diagram.
    <b>Columns</b> = Zone boundaries &nbsp;|&nbsp; <b>Purple dashed lines</b> = Trust boundaries &nbsp;|&nbsp;
    <b>Oval</b> = External Entity &nbsp;|&nbsp; <b>Rounded rect</b> = Process &nbsp;|&nbsp;
    <b>Cylinder</b> = Data Store &nbsp;|&nbsp; <b>z0–z9 badge</b> = Criticality zone score
    </div>
    """, unsafe_allow_html=True)

    diag_tabs = st.tabs(["🏗️ Architecture Overview", "🔵 STRIDE Flow Annotations", "📊 Component Table"])
    with diag_tabs[0]:
        show_architecture_diagram(current_workshop, mode="architecture", key_suffix="s1_arch")
    with diag_tabs[1]:
        st.caption("**T** = Tampering risk (data flows from less → more critical zone) | **I** = Information Disclosure (more → less) | **D** = Denial of Service (Zone 0 → any)")
        show_architecture_diagram(current_workshop, mode="stride", key_suffix="s1_stride")
    with diag_tabs[2]:
        comp_df_rows = []
        for c in current_workshop["scenario"]["components"]:
            comp_df_rows.append({
                "Component": c["name"],
                "Type": c["type"].replace("_"," ").title(),
                "Zone": c.get("zone","N/A"),
                "Score (0-9)": c.get("zone_score","?"),
                "Description": c["description"]
            })
        st.dataframe(pd.DataFrame(comp_df_rows), use_container_width=True, hide_index=True)

        # Flow table
        st.markdown("**Data Flows:**")
        flow_df_rows = []
        for f in current_workshop["scenario"]["data_flows"]:
            src_z = next((c.get("zone_score",0) for c in current_workshop["scenario"]["components"] if c["name"]==f["source"]), 0)
            dst_z = next((c.get("zone_score",0) for c in current_workshop["scenario"]["components"] if c["name"]==f["destination"]), 0)
            stride_risk = "Tampering" if src_z < dst_z else ("Information Disclosure" if src_z > dst_z else "Same Zone")
            if src_z == 0: stride_risk += " + DoS"
            flow_df_rows.append({
                "Flow": f"{f['source']} → {f['destination']}",
                "Data": f["data"], "Protocol": f["protocol"],
                "STRIDE Risk": stride_risk
            })
        st.dataframe(pd.DataFrame(flow_df_rows), use_container_width=True, hide_index=True)

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
    <div style="background:linear-gradient(135deg,#FFF8E1,#FFFBF0);border-radius:10px;
                padding:18px 22px;border:2px dashed #FFB300;margin:12px 0">
    <div style="font-size:0.75em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                color:#E65100;margin-bottom:8px">🎯 PRACTICAL EXERCISE — ZONE LABELLING</div>
    <p style="margin:0 0 10px 0;color:#333;font-size:0.95em">
    For each component, ask yourself three questions before selecting a zone:
    </p>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;font-size:0.85em">
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #E65100">
        <strong style="color:#E65100">1. Who controls it?</strong><br>
        <span style="color:#555">Your org = higher zone. External party = Zone 0.</span>
      </div>
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #E65100">
        <strong style="color:#E65100">2. What data passes through?</strong><br>
        <span style="color:#555">PII/financial/health = higher zone. Public content = lower.</span>
      </div>
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #E65100">
        <strong style="color:#E65100">3. What's the breach impact?</strong><br>
        <span style="color:#555">Life-safety/regulatory = Zone 7–9. Minor = Zone 1–3.</span>
      </div>
    </div>
    <p style="margin:10px 0 0 0;color:#666;font-size:0.85em">
    After submitting, you'll see the correct zones and — more importantly — <strong>why</strong> each 
    component belongs there. The reasoning matters more than memorizing the answer.
    </p>
    </div>
    """, unsafe_allow_html=True)

    scenario = current_workshop["scenario"]
    zone_options = list(CRITICALITY_ZONES.keys())

    with st.form("zone_labelling_form"):
        user_zone_labels = {}
        user_zone_scores_input = {}

        # Group by type so students see external entities together, then processes, then stores
        type_groups = {
            "external_entity": ("👤 External Entities — Zone 0 (Not in Control)", []),
            "process":         ("⚙️ Processes — Your Application Components", []),
            "datastore":       ("💾 Data Stores — Persistence Layer", []),
        }
        for comp in scenario["components"]:
            t = comp.get("type","process")
            if t in type_groups:
                type_groups[t][1].append(comp)

        for ttype, (group_label, group_comps) in type_groups.items():
            if not group_comps:
                continue
            st.markdown(f"#### {group_label}")
            st.markdown(f"""
            <div class="info-box" style="margin:4px 0 10px 0;padding:8px 14px">
            <small>{"External entities are always Zone 0 — they are outside your system control. Assign scores 0–1." if ttype=="external_entity" else
                    "Processes receive and transform data. Consider: what data flows through here? What is the impact if compromised?" if ttype=="process" else
                    "Data stores persist sensitive information. Consider: what data is stored? What regulations apply?"}</small>
            </div>
            """, unsafe_allow_html=True)
            cols_zone = st.columns(min(len(group_comps), 3))
            for i, comp in enumerate(group_comps):
                with cols_zone[i % min(len(group_comps), 3)]:
                    st.markdown(f"""
                    <div style="background:#F7F9FC;border:1px solid #E0E7EF;border-radius:8px;
                                padding:10px 12px;margin:0 0 8px 0">
                    <strong>{comp['name']}</strong><br>
                    <small style="color:#607D8B">{comp['description']}</small>
                    </div>
                    """, unsafe_allow_html=True)
                    user_zone_labels[comp['name']] = st.selectbox(
                        f"Zone:",
                        zone_options,
                        key=f"zone_label_{comp['name']}",
                        help="What criticality zone does this component belong to?"
                    )
                    user_zone_scores_input[comp['name']] = st.slider(
                        f"Score (0–9):",
                        0, 9, 0 if ttype=="external_entity" else 3,
                        key=f"zone_score_{comp['name']}"
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
            zone_color = zinfo.get('color','#F5F5F5')
            zone_border = zinfo.get('border','#9E9E9E')
            st.markdown(f"""
            <div class="{css_class}" style="margin:6px 0">
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
              <div>
                {status} <strong>{name}</strong>
                &nbsp;·&nbsp; <span style="font-size:0.85em">
                  Your: <em>{user_zone_val}</em> (z{user_score_val})
                  &nbsp;→&nbsp;
                  Correct: <strong style="color:{"#2E7D32" if zone_match else "#C62828"}">{correct_zone}</strong> (z{correct_score})
                </span>
              </div>
            </div>
            <div style="margin-top:8px;font-size:0.88em;color:#444">
              <strong>Why {correct_zone}:</strong> {comp.get("zone_rationale", comp["description"])}
            </div>
            <div style="margin-top:6px;font-size:0.82em;color:#666">
              <strong>STRIDE exposure:</strong> {zinfo.get("stride_applicability","Check zone-direction rules")}
            </div>
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
            zone_dfd = generate_zone_labeled_dfd(json.dumps(current_workshop, default=str))

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

    # WORKED EXAMPLE first — teach before quizzing
    st.subheader("🎓 Worked Example: How a Professional Derives Threats")

    st.markdown("""
    <div style="background:linear-gradient(135deg,#0D1B2A,#1B2B3A);color:#E8F4FD;padding:20px 24px;
                border-radius:10px;border-left:5px solid #4FC3F7;margin:12px 0">
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                color:#4FC3F7;margin-bottom:10px">📚 WORKED EXAMPLE — READ THIS BEFORE THE QUIZ</div>
    <p style="margin:0 0 12px 0;font-size:0.95em;color:#C8DCF0">
    A professional does NOT look at a system and guess threats. They follow a mechanical process.
    Here is exactly how to think through every flow and node.</p>
    <hr style="border-color:rgba(255,255,255,0.15);margin:10px 0">

    <strong style="color:#90CAF9">Scenario:</strong>
    <span style="color:#C8DCF0"> Customer Browser (Zone 0) → Web Frontend (Zone 1) → Database (Zone 7)</span><br><br>

    <strong style="color:#90CAF9">Step 1 — Identify the flow direction:</strong><br>
    <span style="color:#C8DCF0">
    Flow A: Browser → Frontend = Zone 0 → Zone 1 = score 0 → score 1 = <strong style="color:#FFB74D">GOING UP</strong><br>
    Flow B: Frontend → Database = Zone 1 → Zone 7 = score 1 → score 7 = <strong style="color:#FFB74D">GOING UP</strong>
    </span><br><br>

    <strong style="color:#90CAF9">Step 2 — Apply the zone-direction rules:</strong><br>
    <span style="color:#C8DCF0">
    Going UP (less→more critical) = <strong style="color:#FFB74D">TAMPERING</strong> applies<br>
    Flow A source = Zone 0 (external) = <strong style="color:#FFB74D">DoS + SPOOFING</strong> also apply
    </span><br><br>

    <strong style="color:#90CAF9">Step 3 — Check node rules for the destination (Web Frontend):</strong><br>
    <span style="color:#C8DCF0">
    Reachable from Zone 0? Yes → <strong style="color:#FFB74D">SPOOFING</strong> applies<br>
    Connected to lower-zone node (Browser zone 0)? Yes → <strong style="color:#FFB74D">EoP</strong> applies<br>
    SPOOFING + TAMPERING both apply? Yes → <strong style="color:#FFB74D">REPUDIATION</strong> also applies
    </span><br><br>

    <strong style="color:#4FC3F7">Result for Flow A (Browser→Frontend):</strong>
    <span style="color:#C8DCF0"> Tampering, DoS, Spoofing</span><br>
    <strong style="color:#4FC3F7">Result for Web Frontend node:</strong>
    <span style="color:#C8DCF0"> Spoofing, Tampering, Repudiation, DoS, EoP</span><br>
    <strong style="color:#4FC3F7">Result for Flow B (Frontend→Database):</strong>
    <span style="color:#C8DCF0"> Tampering (1→7 = going up, no Zone 0 source)</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    # STRIDE RULES REFERENCE TABLE
    st.subheader("📜 The STRIDE Zone-Direction Rules (Reference)")

    st.markdown("""
    <div class="stride-rule-box">
    <strong>Now you know the pattern.</strong> Apply the same logic below:
    check zone scores, check direction, check Zone-0 status, check node adjacency.
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

    col_retry_s, _ = st.columns([1,4])
    with col_retry_s:
        if st.session_state.get('stride_rules_submitted'):
            if st.button("🔄 Retry STRIDE Rules Quiz", key="retry_stride"):
                st.session_state.stride_rules_submitted = False
                st.session_state.stride_rules_answers = {}
                st.rerun()

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
            "question": """An e-commerce site lets users log in with just a username — no password required. 
            An attacker logs in as any customer by guessing their username. 
            Which OWASP 2021 category does this vulnerability fall under?""",
            "options": [
                "A01 — Broken Access Control (users can access other users' orders)",
                "A07 — Identification and Authentication Failures (broken login = impersonation possible)",
                "A03 — Injection (attacker injects a fake identity into the session)",
                "A05 — Security Misconfiguration (the login form is misconfigured)",
            ],
            "correct": "A07 — Identification and Authentication Failures (broken login = impersonation possible)",
            "explanation": "When authentication is weak or absent, attackers can impersonate legitimate users. This is STRIDE Spoofing, enabled by OWASP A07 – Identification and Authentication Failures. The fix is strong MFA + session management."
        },
        "Tampering": {
            "question": """A shopping cart API accepts this URL: /cart?item_id=5&price=1.00
            A customer changes price=1.00 to price=0.01 and buys a £500 laptop for 1p.
            Which OWASP category and STRIDE threat does this represent?""",
            "options": [
                "Information Disclosure + A02 — they exposed the price field in the URL",
                "Elevation of Privilege + A01 — the user bypassed pricing access controls",
                "Tampering + A04 — the system was insecurely designed to trust client-supplied price data",
                "Spoofing + A07 — the user spoofed a lower price to the server",
            ],
            "correct": "Tampering + A04 — the system was insecurely designed to trust client-supplied price data",
            "explanation": "Never trust client-supplied data for security decisions like pricing. This is Tampering (modifying data in transit/at input). OWASP A04 – Insecure Design covers systems that have no security controls at the design level. The fix: compute price server-side from a trusted catalog, never from user input."
        },
        "Information Disclosure": {
            "question": """A hospital database backup is stored in an S3 bucket. The bucket is private but
            the backup files are not encrypted. An AWS misconfiguration briefly makes the bucket public.
            All patient records are readable. Which OWASP category is the ROOT CAUSE?""",
            "options": [
                "A05 — Security Misconfiguration (the bucket was briefly public)",
                "A02 — Cryptographic Failures (data was unencrypted, so exposure = full disclosure)",
                "A01 — Broken Access Control (the bucket access control was broken)",
                "A09 — Security Logging and Monitoring Failures (nobody noticed the exposure)",
            ],
            "correct": "A02 — Cryptographic Failures (data was unencrypted, so exposure = full disclosure)",
            "explanation": "A05 (misconfiguration) was the trigger, but the ROOT CAUSE of Information Disclosure is A02 – Cryptographic Failures. If data at rest were encrypted (AES-256), a brief public exposure would expose ciphertext not plaintext. Defense-in-depth means you fix BOTH, but the Information Disclosure STRIDE threat maps to A02 as the primary control."
        },
        "Repudiation": {
            "question": """A bank employee transfers £2M to a fraudulent account. When investigated, 
            the bank discovers the transaction logs were stored in the same database as transactions — 
            and had been deleted. The employee denies all knowledge.
            Which OWASP category enables this Repudiation attack?""",
            "options": [
                "A04 — Insecure Design (the system should have been designed with separate audit logs)",
                "A07 — Authentication Failures (the employee was authenticated, so authentication failed)",
                "A09 — Security Logging and Monitoring Failures (logs deleted = no audit trail = Repudiation)",
                "A01 — Broken Access Control (the employee accessed records they shouldn't have)",
            ],
            "correct": "A09 — Security Logging and Monitoring Failures (logs deleted = no audit trail = Repudiation)",
            "explanation": "Repudiation requires both the act AND the absence of proof. A09 – Security Logging and Monitoring Failures is the direct enabler: without immutable, out-of-band audit logs (e.g., append-only SIEM, WORM storage), there is no non-repudiation. A04 is a contributing issue but A09 is the specific OWASP category that maps to STRIDE Repudiation."
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

    col_retry_o, _ = st.columns([1,4])
    with col_retry_o:
        if st.session_state.get('owasp_mapping_submitted'):
            if st.button("🔄 Retry OWASP Quiz", key="retry_owasp"):
                st.session_state.owasp_mapping_submitted = False
                st.session_state.owasp_mapping_answers = {}
                st.rerun()

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

    attack_tree_data = get_attack_trees().get(st.session_state.selected_workshop, {})
    if attack_tree_data:
        st.markdown(f"""
        <div class="learning-box">
        <strong>{attack_tree_data['title']}</strong><br>
        {attack_tree_data['description']}
        </div>
        """, unsafe_allow_html=True)

        # HOW TO READ AN ATTACK TREE — before showing it
        st.markdown("""
        <div style="background:linear-gradient(135deg,#1A237E,#283593);color:white;
                    padding:18px 22px;border-radius:10px;margin:10px 0;border-left:5px solid #7986CB">
        <div style="font-size:0.7em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                    color:#9FA8DA;margin-bottom:10px">HOW TO READ THIS ATTACK TREE</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div>
          <strong style="color:#90CAF9">🎯 GOAL node (root, pink)</strong><br>
          <span style="font-size:0.88em;color:#C5CAE9">The attacker's final objective. Everything below is a path toward this goal.</span>
        </div>
        <div>
          <strong style="color:#90CAF9">🔵 OR gates (green)</strong><br>
          <span style="font-size:0.88em;color:#C5CAE9">ANY child path succeeds = goal reached. Each OR branch is a separate attack surface you must defend.</span>
        </div>
        <div>
          <strong style="color:#90CAF9">🔗 AND gates (blue)</strong><br>
          <span style="font-size:0.88em;color:#C5CAE9">ALL children must succeed. Block ANY single step → entire path blocked. This is defense-in-depth.</span>
        </div>
        <div>
          <strong style="color:#90CAF9">🟡 Leaf nodes</strong><br>
          <span style="font-size:0.88em;color:#C5CAE9">Atomic attack steps. <strong style="color:#EF9A9A">Easy</strong>=automated tools, no skill. <strong style="color:#FFF176">Medium</strong>=technical knowledge. <strong style="color:#A5D6A7">Hard</strong>=expert + resources.</span>
        </div>
        </div>
        <hr style="border-color:rgba(255,255,255,0.2);margin:12px 0">
        <strong style="color:#90CAF9">Prioritization rule:</strong>
        <span style="color:#C5CAE9"> Find the path with the most "Easy" leaf nodes and the fewest AND gates.
        That is your highest-priority fix — it's the cheapest attack and provides the most options to the attacker.</span>
        </div>
        """, unsafe_allow_html=True)

        with st.spinner("Generating attack tree..."):
            tree_img = generate_attack_tree(json.dumps(attack_tree_data["tree"]), attack_tree_data["title"])

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

    # ── Live architecture diagram showing currently affected components ─────
    st.subheader("🗺️ Live Architecture Map")
    st.markdown("""
    <div class="info-box">
    This diagram updates as you analyze threats. Affected components are highlighted in red with a ⚠ badge.
    Use this to understand <em>where</em> each threat sits in the architecture.
    </div>
    """, unsafe_allow_html=True)
    live_tabs = st.tabs(["🏗️ Current Threat Map", "🔵 STRIDE Annotations", "🏗️ Clean Architecture"])
    with live_tabs[0]:
        show_architecture_diagram(current_workshop, threats=st.session_state.threats, mode="threat", key_suffix="step4_live")
    with live_tabs[1]:
        show_architecture_diagram(current_workshop, threats=st.session_state.threats, mode="stride", key_suffix="step4_stride")
    with live_tabs[2]:
        show_architecture_diagram(current_workshop, mode="architecture", key_suffix="step4_arch")

    st.markdown("---")
    # Already-analyzed threat IDs — prevents duplicate inflation
    analyzed_ids = {a["matched_threat_id"] for a in st.session_state.user_answers}
    remaining_threats = [t for t in workshop_threats if t["id"] not in analyzed_ids]

    if not remaining_threats:
        st.success("✅ All threats for this workshop have been analyzed!")
    else:
        st.markdown(f"""
        <div style="background:#E3F2FD;padding:10px 16px;border-radius:8px;border-left:4px solid #1976D2;margin:8px 0">
        <strong>Progress: {len(analyzed_ids)}/{current_workshop['target_threats']} threats analyzed</strong>
        &nbsp;·&nbsp; {len(remaining_threats)} remaining
        </div>
        """, unsafe_allow_html=True)

    with st.form("threat_selection_form"):
        st.subheader("➕ Analyze a Threat Scenario")

        available_threats = remaining_threats if remaining_threats else workshop_threats
        threat_options = {f"{t['id']}: {t['threat'][:65]}...": t for t in available_threats}
        if not threat_options:
            st.error("No threats available for this workshop")
            st.stop()

        selected_threat_key = st.selectbox(
            "Choose a threat scenario to analyze:",
            list(threat_options.keys()),
            help="Each threat can only be analyzed once. Select from remaining threats."
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

        # ── Contextual guidance based on the selected threat ─────────────
        threat_zone_from  = selected_predefined.get("zone_from", "")
        threat_zone_to    = selected_predefined.get("zone_to", "")
        threat_stride_cat = selected_predefined["stride"]
        threat_owasp      = OWASP_STRIDE_MAP.get(threat_stride_cat, {})

        # Build a minimal valid STRIDE options list:
        # - The correct answer is always present
        # - Add 2 plausible distractors based on zone direction
        distractor_map = {
            "Tampering":             ["Injection", "Repudiation"],
            "Spoofing":              ["Elevation of Privilege", "Repudiation"],
            "Repudiation":           ["Spoofing", "Tampering"],
            "Information Disclosure":["Tampering", "Denial of Service"],
            "Denial of Service":     ["Tampering", "Elevation of Privilege"],
            "Elevation of Privilege":["Spoofing", "Denial of Service"],
        }
        # Always show all 6 but highlight guidance for the zone direction
        all_stride = ["Spoofing", "Tampering", "Repudiation",
                      "Information Disclosure", "Denial of Service", "Elevation of Privilege"]

        # Zone-direction guidance text
        if threat_zone_from and threat_zone_to:
            zone_from_score = next((c.get("zone_score", 3) for c in current_workshop["scenario"]["components"]
                                    if c["name"] == threat_zone_from.replace(" Zone", "")),
                                   CRITICALITY_ZONES.get(threat_zone_from, {}).get("score", 3))
            zone_to_score   = next((c.get("zone_score", 3) for c in current_workshop["scenario"]["components"]
                                    if c["name"] == threat_zone_to.replace(" Zone", "")),
                                   CRITICALITY_ZONES.get(threat_zone_to, {}).get("score", 3))
            if zone_from_score < zone_to_score:
                direction_hint = "⬆ Flow goes **less → more** critical zone → primary risk: **Tampering**"
            elif zone_from_score > zone_to_score:
                direction_hint = "⬇ Flow goes **more → less** critical zone → primary risk: **Information Disclosure**"
            else:
                direction_hint = "↔ Flow within the **same zone** → check node-level rules (Spoofing, EoP)"
            if zone_from_score == 0:
                direction_hint += " | Zone-0 source → also watch for **Denial of Service** and **Spoofing**"
        else:
            direction_hint = "Review the zone labels above to determine the applicable STRIDE rule."

        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>🧭 Zone-Direction Guidance:</strong> {direction_hint}<br>
        <em>Use this rule to select the most appropriate STRIDE category below.</em>
        </div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🎯 Your Analysis")

            # Component options: match real components + flows from this workshop
            all_components = [comp["name"] for comp in current_workshop["scenario"]["components"]]
            all_flows = [f"{f['source']} → {f['destination']}"
                         for f in current_workshop["scenario"]["data_flows"]]

            # Try to pre-select the correct component
            correct_comp = selected_predefined.get("component", "")
            all_options  = all_components + all_flows
            default_idx  = all_options.index(correct_comp) if correct_comp in all_options else 0

            user_component = st.selectbox(
                "Which component/flow is affected?",
                ["— select —"] + all_options,
                index=0,
                help="Identify the component or flow from the threat description above"
            )

            # STRIDE — always starts blank, no pre-selection
            user_stride = st.selectbox(
                "STRIDE Category — apply the zone-direction rule:",
                ["— select —", "Spoofing", "Tampering", "Repudiation",
                 "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
                index=0,
                help="Use the zone-direction guidance above to derive the correct category"
            )

            # Likelihood & impact — NOT pre-set; student must assess independently
            user_likelihood = st.select_slider(
                "Likelihood — how probable is this attack?",
                options=["Low", "Medium", "High", "Critical"],
                value="Low",
            )
            user_impact = st.select_slider(
                "Impact — if exploited, how severe?",
                options=["Low", "Medium", "High", "Critical"],
                value="Low",
            )

        with col2:
            st.markdown("### 🛡️ OWASP-Aligned Mitigations")
            st.caption("Select ALL controls that correctly address this threat:")

            if threat_owasp:
                st.markdown(f"""
                <div class="owasp-box">
                <strong>💡 OWASP Mapping for {threat_stride_cat}:</strong><br>
                {', '.join(threat_owasp['owasp'])}<br>
                <small>{threat_owasp.get('owasp_detail','')}</small>
                </div>
                """, unsafe_allow_html=True)

            # Correct + incorrect options — shuffled but with clear instructions
            correct_opts   = selected_predefined["correct_mitigations"]
            incorrect_opts = selected_predefined.get("incorrect_mitigations", [])
            all_possible   = correct_opts + incorrect_opts
            # Deterministic shuffle based on threat id (not random each rerun)
            import hashlib
            seed_val = int(hashlib.md5(selected_predefined["id"].encode()).hexdigest(), 16) % 10000
            rng = __import__("random").Random(seed_val)
            rng.shuffle(all_possible)

            st.markdown(f"*{len(correct_opts)} correct controls, {len(incorrect_opts)} distractors — choose wisely*")
            user_mitigations = st.multiselect(
                "Security Controls (select all that apply):",
                all_possible,
                help="Only select controls that directly address the STRIDE threat above"
            )

            # Show component mini-diagram highlighting the affected node
            st.markdown("---")
            st.markdown("**📍 Component Location in Architecture:**")
            affected_comp_name = selected_predefined.get("component", "")
            # Find which zone this component sits in
            for c in current_workshop["scenario"]["components"]:
                if c["name"] == affected_comp_name or c["name"] in affected_comp_name:
                    zone_n = c.get("zone","N/A")
                    zone_s = c.get("zone_score","?")
                    zone_col_hex = _zone_hex(zone_n)
                    zone_str_hex = _zone_stroke(zone_n)
                    st.markdown(f"""
                    <div style="background:{zone_col_hex};padding:10px;border-radius:6px;
                                border:2px solid {zone_str_hex};margin:4px 0">
                    <strong>{c['name']}</strong> — {c['description']}<br>
                    Zone: <strong>{zone_n}</strong> (Score: {zone_s})<br>
                    Type: {c['type'].replace('_',' ').title()}
                    </div>
                    """, unsafe_allow_html=True)
                    break

        st.markdown("---")
        submitted = st.form_submit_button(
            "✅ Submit & Get STRIDE Rule Feedback", type="primary", use_container_width=True
        )

        if submitted:
            # Validate selections — reject placeholder values
            errors = []
            if user_component == "— select —":
                errors.append("Select a component or data flow")
            if user_stride == "— select —":
                errors.append("Select a STRIDE category")
            if errors:
                st.error("⚠️ Please complete all selections: " + " · ".join(errors))
            else:
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

                # Learning content — rich format
                st.markdown("---")
                exp  = pred.get('explanation','')
                risk = pred.get('why_this_risk','')
                ctrl = pred.get('why_these_controls','')
                rw   = pred.get('real_world','')
                comp_str = pred.get('compliance','')
                stride_cat2 = pred.get('stride','')
                owasp2 = OWASP_STRIDE_MAP.get(stride_cat2,{}).get("owasp",[""])
                if exp:
                    st.markdown(f"""
                    <div style="background:#F0F4F8;border-radius:8px;padding:12px 16px;margin:6px 0">
                    <strong style="color:#1A3A5C">📖 Explanation</strong><br>
                    <span style="font-size:0.91em;color:#2C3E50">{exp}</span>
                    </div>""", unsafe_allow_html=True)
                if risk or ctrl:
                    c1, c2 = st.columns(2)
                    with c1:
                        if risk:
                            st.markdown(f"""
                            <div style="background:#FFF8E1;border-left:4px solid #F9A825;border-radius:6px;padding:10px 14px;margin:4px 0">
                            <strong style="color:#E65100;font-size:0.85em">⚖️ WHY THIS RISK LEVEL</strong><br>
                            <span style="font-size:0.88em;color:#444">{risk}</span>
                            </div>""", unsafe_allow_html=True)
                    with c2:
                        if ctrl:
                            st.markdown(f"""
                            <div style="background:#E8F5E9;border-left:4px solid #43A047;border-radius:6px;padding:10px 14px;margin:4px 0">
                            <strong style="color:#1B5E20;font-size:0.85em">🛡️ WHY THESE CONTROLS</strong><br>
                            <span style="font-size:0.88em;color:#444">{ctrl}</span>
                            </div>""", unsafe_allow_html=True)
                if rw:
                    st.markdown(f"""
                    <div style="background:linear-gradient(135deg,#0D1B2A,#102040);color:#C8DCF0;
                                border-radius:8px;padding:14px 18px;margin:8px 0;border-left:5px solid #5C6BC0">
                      <div style="font-size:0.7em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                                  color:#7986CB;margin-bottom:6px">🌐 REAL-WORLD BREACH</div>
                      <p style="margin:0 0 8px 0;font-size:0.9em;line-height:1.6">{rw}</p>
                      <div style="font-size:0.78em;color:#90A4AE">
                        STRIDE: <strong style="color:#90CAF9">{stride_cat2}</strong>
                        &nbsp;·&nbsp; OWASP: <strong style="color:#90CAF9">{", ".join(owasp2[:2])}</strong>
                        &nbsp;·&nbsp; {comp_str}
                      </div>
                    </div>""", unsafe_allow_html=True)

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
    st.subheader("🗺️ Architecture & Threat Assessment Diagrams")

    st.markdown("""
    <div class="learning-box">
    These diagrams show your complete threat-mapped architecture.
    <b>Red nodes/edges</b> = you identified threats there.
    <b>Blue annotations [T/I/D]</b> = STRIDE rules from zone direction analysis.
    </div>
    """, unsafe_allow_html=True)

    assess_diag_tabs = st.tabs([
        "🔴 Threat-Highlighted Map",
        "🔵 STRIDE-Annotated Map",
        "🏗️ Clean Architecture",
        "📊 Graphviz DFD"
    ])
    with assess_diag_tabs[0]:
        show_architecture_diagram(current_workshop,
                                  threats=st.session_state.threats,
                                  mode="threat", key_suffix="s5_threat")
    with assess_diag_tabs[1]:
        show_architecture_diagram(current_workshop,
                                  threats=st.session_state.threats,
                                  mode="stride", key_suffix="s5_stride")
    with assess_diag_tabs[2]:
        show_architecture_diagram(current_workshop,
                                  mode="architecture", key_suffix="s5_arch")
    with assess_diag_tabs[3]:
        st.caption("Graphviz-rendered DFD (zone subgraphs + edge annotations)")
        with st.spinner("Generating Graphviz DFD..."):
            mapped_dfd = generate_zone_labeled_dfd(
                json.dumps(current_workshop, default=str),
                show_stride_rules=True,
                threats_json=json.dumps(st.session_state.threats, default=str)
            )
        if mapped_dfd:
            st.image(f"data:image/png;base64,{mapped_dfd}",
                     caption="STRIDE-Annotated Zone DFD (Graphviz)", use_column_width=True)

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
        if st.button("📄 Generate My Threat Model PDF", use_container_width=True):
            with st.spinner("Building PDF..."):
                user_pdf = generate_user_threat_model_pdf(
                    current_workshop, st.session_state.user_answers,
                    st.session_state.total_score, st.session_state.max_score
                )
            if user_pdf:
                st.download_button(
                    "⬇️ Download My PDF",
                    user_pdf,
                    f"my_threat_model_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.pdf",
                    "application/pdf", use_container_width=True,
                    key="dl_user_pdf"
                )
            else:
                st.error("PDF generation failed")
    with col3:
        if st.button("📚 Generate Complete Reference PDF", use_container_width=True):
            with st.spinner("Building reference PDF (may take ~10s)..."):
                complete_pdf = generate_complete_threat_model_pdf(
                    current_workshop, st.session_state.selected_workshop
                )
            if complete_pdf:
                st.download_button(
                    "⬇️ Download Reference PDF",
                    complete_pdf,
                    f"complete_model_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.pdf",
                    "application/pdf", use_container_width=True,
                    key="dl_complete_pdf"
                )
            else:
                st.error("PDF generation failed")

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
    # Mark completed
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()

    final_pct  = st.session_state.total_score / st.session_state.max_score * 100 if st.session_state.max_score > 0 else 0
    grade      = "A+" if final_pct >= 95 else "A" if final_pct >= 90 else "B" if final_pct >= 80 else "C" if final_pct >= 70 else "D" if final_pct >= 60 else "F"
    grade_grad = ("linear-gradient(135deg,#B8860B,#DAA520)" if final_pct >= 90 else
                  "linear-gradient(135deg,#1B5E20,#2E7D32)" if final_pct >= 80 else
                  "linear-gradient(135deg,#E65100,#F57C00)" if final_pct >= 70 else
                  "linear-gradient(135deg,#BF360C,#D84315)")

    if final_pct >= 90:
        st.balloons()

    # ── Certificate-style completion banner ─────────────────────────────────
    from datetime import date
    today = date.today().strftime("%B %d, %Y")
    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#0D1B2A,#1B4F72);border-radius:14px;
                padding:32px 36px;text-align:center;box-shadow:0 6px 24px rgba(0,0,0,0.3);
                border:2px solid rgba(255,255,255,0.1)">
      <div style="color:#90CAF9;font-size:0.85em;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px">
        Certificate of Completion
      </div>
      <h1 style="color:white;margin:0 0 8px 0;font-size:2em">🏆 {current_workshop['name']}</h1>
      <div style="color:#B3D9F7;font-size:1em;margin-bottom:16px">
        {current_workshop['scenario']['title']} · {current_workshop['level']}
      </div>
      <div style="display:inline-block;background:{grade_grad};color:white;
                  padding:12px 32px;border-radius:30px;font-size:1.8em;font-weight:700;
                  box-shadow:0 3px 12px rgba(0,0,0,0.4);margin-bottom:16px">
        Grade: {grade} &nbsp;|&nbsp; {final_pct:.1f}%
      </div>
      <div style="color:#90CAF9;font-size:0.85em">{today}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # ── Score metrics ───────────────────────────────────────────────────────
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    c2.metric("Percentage", f"{final_pct:.1f}%")
    c3.metric("Grade", grade)
    c4.metric("Threats", len(st.session_state.user_answers))
    correct_ct = sum(1 for a in st.session_state.user_answers if a["score"]/a["max_score"] >= 0.8)
    c5.metric("Correct", f"{correct_ct}/{len(st.session_state.user_answers)}")

    # ── 4-step mastery review ───────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📋 4-Step Methodology Mastery Summary")

    steps_done = [
        ("🏗️", "Step 1 — Design (DFD)", True, "Identified all interactors, modules, connections and trust boundaries"),
        ("🏷️", "Step 2 — Zones of Trust", st.session_state.get('zone_labelling_done', False), "Labelled every component with a criticality zone (0–9 scale)"),
        ("⚡", "Step 3 — STRIDE Rules", st.session_state.get('stride_rules_submitted', False), "Applied zone-direction rules to derive STRIDE threat categories"),
        ("🛡️", "Step 4 — OWASP Controls", st.session_state.get('owasp_mapping_submitted', False), "Mapped STRIDE threats to OWASP Top 10 mitigations"),
        ("🎯", "Practical Threat Analysis", len(st.session_state.user_answers) > 0,
         f"Analysed {len(st.session_state.user_answers)} threat scenarios with scoring feedback"),
    ]
    for icon, label, done, detail in steps_done:
        bg   = "linear-gradient(135deg,#E8F5E9,#F1F8E9)" if done else "#F5F5F5"
        clr  = "#2E7D32" if done else "#9E9E9E"
        mark = "✅" if done else "⭕"
        st.markdown(f"""
        <div style="background:{bg};border-left:4px solid {clr};border-radius:8px;
                    padding:12px 16px;margin:6px 0;display:flex;align-items:center;gap:12px">
          <span style="font-size:1.3em">{mark}</span>
          <div>
            <strong style="color:{clr}">{icon} {label}</strong><br>
            <span style="font-size:0.85em;color:#555">{detail}</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Skills unlocked ─────────────────────────────────────────────────────
    ws_skill_map = {
        "1": ["DFD element classification","Zone assignment (0–7)","Basic STRIDE zone rules","OWASP A01–A10 mapping","XSS/SQLi/IDOR identification"],
        "2": ["Service mesh threat modeling","mTLS & service spoofing","BOLA (API1:2023)","Distributed tracing for Repudiation","OWASP API Security Top 10"],
        "3": ["Multi-tenant isolation design","Cross-tenant EoP","Row-Level Security","SOC 2 / ISO 27001 mapping","Shared infrastructure threats"],
        "4": ["IoT/edge trust boundaries","Replay attack design","HIPAA / FDA 21 CFR compliance","Life-critical (Zone 9) threat modeling","HL7 v2 injection"],
    }
    new_skills = ws_skill_map.get(st.session_state.selected_workshop, [])
    if new_skills:
        st.markdown("---")
        st.subheader("🔓 Skills Unlocked This Workshop")
        cols_sk = st.columns(3)
        for i, sk in enumerate(new_skills):
            cols_sk[i%3].markdown(f"""
            <div style="background:linear-gradient(135deg,#E3F2FD,#EFF8FF);padding:10px 14px;
                        border-radius:8px;border-left:4px solid #1976D2;margin:4px 0;font-size:0.88em">
              🔓 <strong>{sk}</strong>
            </div>
            """, unsafe_allow_html=True)

    # ── Personalised improvement areas ──────────────────────────────────────
    st.markdown("---")
    st.subheader("📈 Personalised Feedback")

    wrong_answers = [a for a in st.session_state.user_answers if a["score"]/a["max_score"] < 0.8]
    if wrong_answers:
        st.markdown("""<div class="warning-box"><strong>Areas to review before moving on:</strong></div>""", unsafe_allow_html=True)
        for wa in wrong_answers:
            pred = wa.get("predefined_threat", {})
            pct_w = wa["score"]/wa["max_score"]*100
            st.markdown(f"""
            <div style="background:#FFF5F5;border-left:4px solid #EF5350;border-radius:8px;
                        padding:12px 16px;margin:6px 0">
              <strong>{wa['matched_threat_id']}</strong> — {pred.get('stride','')} on {pred.get('component','')}
              &nbsp;({pct_w:.0f}%)<br>
              <small style="color:#555">Review: {pred.get('stride_rule_applied','')}</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""<div class="success-box"><strong>🎯 Perfect execution — no areas flagged for review!</strong></div>""", unsafe_allow_html=True)

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
