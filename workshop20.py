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
import streamlit.components.v1 as components_html
import base64
import hashlib
import hmac
import json
import math
import os
import re
import tempfile
import uuid
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
# UNLOCK CODES - stored only as salted SHA-256 digests (no plaintext in source).
# To rotate a code:  hashlib.sha256(("stride-lab:" + NEW_CODE).encode()).hexdigest()
# ─────────────────────────────────────────────────────────────────────────────
_CODE_SALT = "stride-lab:"
WORKSHOP_CODE_HASHES = {
    "1": None,
    "2": "95b6136894dfc65f89a7ffb93daeb0c8b22590bf0199178a4b7cac03c68b2918",
    "3": "6c0e199c86eebe61ce83988daffc2137d9c846977aebadf8297ee77c73963a4c",
    "4": "dd8982302a0c0908185ffb8c2036d6e4deaf15314deb3618c1f8be1862ca4f2f",
}


def verify_unlock_code(ws_id, code):
    expected = WORKSHOP_CODE_HASHES.get(ws_id)
    if not expected:
        return False
    digest = hashlib.sha256((_CODE_SALT + (code or "").strip()).encode()).hexdigest()
    return hmac.compare_digest(digest, expected)

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
        'annotations': {},          # {workshop_id: [label dicts]}
        'annot_nonce': 0,
        'scope_models': {},         # {workshop_id: scope / assumptions / exclusions}
        'open_questions': {},       # {workshop_id: {questions, accepted}}
        'review_plans': {},         # {workshop_id: review cadence + triggers}
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


def start_workshop(ws_id):
    """Single place that resets all per-workshop state (was duplicated, with a key typo)."""
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
    st.session_state.annotations[ws_id] = []
    st.session_state.scope_models[ws_id] = {}
    st.session_state.open_questions[ws_id] = {}
    st.session_state.review_plans[ws_id] = {}
    for k in [k for k in st.session_state.keys() if str(k).startswith(("w_", "_seed_", "ed_"))]:
        del st.session_state[k]


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
_STRIDE_TAG_COLOR = {"T": "#E65100", "I": "#1565C0", "D": "#6A1B9A"}
_STRIDE_TAG_TIP = {
    "T": "Tampering risk: data flows from a less-critical to a more-critical zone",
    "I": "Information disclosure risk: data flows from a more-critical to a less-critical zone",
    "D": "Denial of service risk: source is an untrusted Zone-0 entity",
}

# ── Swimlane columns (left → right), as in the reference architecture style ──
LANE_ORDER = ["External", "DMZ", "Internal Services", "Third-Party"]
LANE_SUBTITLE = {
    "External":          "outside our control",
    "DMZ":               "edge / entry points",
    "Internal Services": "our systems & data",
    "Third-Party":       "vendors & partners",
}
# Lane for each component by name. A component dict may also carry its own "lane" key.
# Anything not listed: external_entity → Third-Party, everything else → Internal Services.
COMPONENT_LANES = {
    "Customer": "External", "Mobile App": "External", "Web Dashboard": "External",
    "Glucose Monitor": "External", "Web Portal": "External",
    "Web Frontend": "DMZ", "API Gateway": "DMZ", "IoT Gateway": "DMZ",
    "Stripe": "Third-Party", "SendGrid": "Third-Party", "Legacy EHR": "Third-Party",
}

# ── Label kinds the learner can place on any diagram ────────────────────────
ANNOTATION_KINDS = {
    "actor":   {"prefix": "TA", "title": "Threat Actor",          "icon": "🎭", "fill": "#C62828", "stroke": "#8E0000", "text": "white"},
    "asset":   {"prefix": "AS", "title": "Asset",                 "icon": "💎", "fill": "#1565C0", "stroke": "#0D47A1", "text": "white"},
    "threat":  {"prefix": "T",  "title": "Threat Scenario",       "icon": "⚡", "fill": "white",   "stroke": "#212121", "text": "#212121"},
    "control": {"prefix": "C",  "title": "Control / Mitigation",  "icon": "🛡️", "fill": "#2E7D32", "stroke": "#1B5E20", "text": "white"},
}
_KIND_ORDER = ["actor", "asset", "threat", "control"]
_NODE_W, _NODE_H, _DS_H = 140, 56, 62
_ROW_H, _TOP, _LEG_H = 112, 72, 84
_FONT = "'DM Sans','Segoe UI',Helvetica,Arial,sans-serif"
_MONO = "'DM Mono',Consolas,'Courier New',monospace"


def _lane_of(comp):
    lane = comp.get("lane")
    if lane in LANE_ORDER:
        return lane
    if comp["name"] in COMPONENT_LANES:
        return COMPONENT_LANES[comp["name"]]
    return "Third-Party" if comp.get("type") == "external_entity" else "Internal Services"


def _trunc(s, n):
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _flow_key(flow):
    return f"{flow['source']} → {flow['destination']}"


def _ann_sort(item):
    try:
        num = int(re.sub(r"\D", "", item["id"]) or 0)
    except ValueError:
        num = 0
    return (_KIND_ORDER.index(item["kind"]) if item["kind"] in _KIND_ORDER else 9, num)


def _node_h(ctype):
    return _DS_H if ctype == "datastore" else _NODE_H


def _layout_swimlanes(components, flows):
    """Place nodes in lane columns; order rows by the average position of their neighbours."""
    lane_of = {c["name"]: _lane_of(c) for c in components}
    order = {l: [c["name"] for c in components if lane_of[c["name"]] == l] for l in LANE_ORDER}
    present = [l for l in LANE_ORDER if order[l]]
    lane_w = max(260, 960 // max(1, len(present)))
    content_h = max(len(order[l]) for l in present) * _ROW_H

    ypos = {}

    def assign():
        for l in present:
            n = len(order[l])
            slot = content_h / n
            for i, nm in enumerate(order[l]):
                ypos[nm] = _TOP + slot * (i + 0.5)

    assign()
    nbrs = {}
    for f in flows:
        nbrs.setdefault(f["source"], set()).add(f["destination"])
        nbrs.setdefault(f["destination"], set()).add(f["source"])
    for _ in range(2):
        for l in present:
            def bary(nm, _l=l):
                ys = [ypos[x] for x in nbrs.get(nm, ()) if x in ypos and lane_of.get(x) != _l]
                return sum(ys) / len(ys) if ys else ypos[nm]
            order[l] = sorted(order[l], key=bary)
        assign()

    pos = {}
    for li, l in enumerate(present):
        cx = lane_w * li + lane_w / 2
        for nm in order[l]:
            pos[nm] = (cx, ypos[nm])
    return {
        "present": present, "lane_w": lane_w, "order": order, "lane_of": lane_of, "pos": pos,
        "W": lane_w * len(present), "H": _TOP + content_h + _LEG_H, "content_h": content_h,
    }


def _badge_w(code, kind):
    return 22 if kind == "threat" else max(26, 7 * len(code) + 10)


def _badge_svg(x, y, code, kind, tip=""):
    """Badge whose left edge is x and vertical centre is y."""
    k = ANNOTATION_KINDS[kind]
    w = _badge_w(code, kind)
    title = f"<title>{_xml(tip)}</title>" if tip else ""
    if kind == "threat":   # numbered circle, as in the reference diagram
        cx = x + w / 2
        return (f'<g>{title}<circle cx="{cx}" cy="{y}" r="11" fill="white" stroke="{k["stroke"]}" stroke-width="1.7"/>'
                f'<text x="{cx}" y="{y + 3.3}" text-anchor="middle" class="t-badge" fill="{k["text"]}">{_xml(code)}</text></g>')
    return (f'<g>{title}<rect x="{x}" y="{y - 10}" width="{w}" height="20" rx="6" fill="{k["fill"]}" '
            f'stroke="{k["stroke"]}" stroke-width="1.2"/>'
            f'<text x="{x + w / 2}" y="{y + 3.3}" text-anchor="middle" class="t-badge" fill="{k["text"]}">{_xml(code)}</text></g>')


def _edge_x(cx, dy, ctype, right):
    """x coordinate where a horizontal edge at vertical offset dy meets the node outline."""
    hw = _NODE_W / 2
    if ctype == "external_entity":
        ry = _NODE_H / 2
        hw = hw * math.sqrt(max(0.0, 1 - (dy / ry) ** 2))
    return cx + (hw if right else -hw)


def _item_tip(it):
    k = ANNOTATION_KINDS[it["kind"]]
    tip = f"{it['id']} · {k['title']}: {it['label']}"
    if it.get("notes"):
        tip += f" — {it['notes']}"
    if it.get("links"):
        tip += f" (linked: {', '.join(it['links'])})"
    return tip


def render_architecture_svg(workshop_config, highlighted_threats=None, mode="architecture", annotations=None,
                            out_of_scope=(), risk_map=None, ctrl_map=None):
    """
    Swimlane architecture / DFD diagram.
      columns  = External | DMZ | Internal Services | Third-Party (dotted dividers)
      shapes   = oval external entity · rounded rect process · cylinder data store
      z-chip   = criticality zone score (0–9) of each component
      badges   = learner labels: TA threat actor · AS asset · T threat scenario · C control
    mode: architecture | stride | threat | zones
    """
    highlighted_threats = highlighted_threats or []
    annotations = annotations or []
    oos = set(out_of_scope or ())
    risk_map = risk_map or {}
    ctrl_map = ctrl_map or {}
    heat = mode in ("scoring", "controls", "residual")
    scenario = workshop_config["scenario"]
    components, flows = scenario["components"], scenario["data_flows"]
    comp_by_name = {c["name"]: c for c in components}

    threat_nodes, threat_flows = set(), set()
    for t in highlighted_threats:
        c = t.get("component", "")
        (threat_flows if "→" in c else threat_nodes).add(c)

    lay = _layout_swimlanes(components, flows)
    W, H, lane_w, pos = lay["W"], lay["H"], lay["lane_w"], lay["pos"]
    order, lane_of, present = lay["order"], lay["lane_of"], lay["present"]
    zsc = {c["name"]: c.get("zone_score", 3) for c in components}
    HW = _NODE_W / 2

    by_target = {}
    for it in annotations:
        by_target.setdefault(it.get("target"), []).append(it)

    s = []
    s.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
             f'style="width:100%;height:auto;max-width:{W}px;background:white" role="img">')
    s.append(f"""<defs><style>
.t-title{{font:700 13px {_FONT};fill:#0D1B2A}}
.t-mode{{font:500 10px {_FONT};fill:#78909C}}
.t-lane{{font:800 11px {_FONT};letter-spacing:1.6px;fill:#263238}}
.t-lsub{{font:400 9px {_FONT};fill:#90A4AE}}
.t-name{{font:700 11.5px {_FONT};fill:#1A2B3C}}
.t-desc{{font:400 8.5px {_FONT};fill:#607D8B}}
.t-edge{{font:500 9px {_FONT}}}
.t-badge{{font:700 9px {_MONO}}}
.t-zone{{font:600 8.5px {_MONO};fill:white}}
.t-leg{{font:400 9px {_FONT};fill:#455A64}}
.t-legt{{font:700 9px {_FONT};fill:#455A64;letter-spacing:1px}}
</style>
<marker id="mk-n" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M1,1 L8,4.5 L1,8 Z" fill="#546E7A"/></marker>
<marker id="mk-r" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M1,1 L8,4.5 L1,8 Z" fill="#C62828"/></marker>
<marker id="mk-b" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M1,1 L8,4.5 L1,8 Z" fill="#5C6BC0"/></marker>
<marker id="mk-a" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M1,1 L8,4.5 L1,8 Z" fill="#E69500"/></marker>
<marker id="mk-g" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M1,1 L8,4.5 L1,8 Z" fill="#2E7D32"/></marker>
<marker id="mk-o" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M1,1 L8,4.5 L1,8 Z" fill="#B0BEC5"/></marker>
<filter id="sh" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="1.5" stdDeviation="2" flood-color="#000" flood-opacity="0.16"/></filter>
</defs>""")

    mode_lbl = {"architecture": "Architecture overview", "stride": "STRIDE flow annotations",
                "threat": "Threat impact map", "zones": "Zones of trust", "scope": "Scope view: in scope vs out of scope",
                "scoring": "Inherent risk heat map (impact × likelihood)", "controls": "Controls applied to risks",
                "residual": "Residual risk heat map (after controls)"}.get(mode, "")
    s.append(f'<text x="14" y="21" class="t-title">{_xml(scenario.get("title", "System architecture"))}</text>')
    s.append(f'<text x="{W - 14}" y="21" text-anchor="end" class="t-mode">{_xml(mode_lbl)}</text>')

    # lanes: faint tint, header, dotted dividers
    for li, l in enumerate(present):
        x0 = li * lane_w
        if li % 2 == 1:
            s.append(f'<rect x="{x0}" y="32" width="{lane_w}" height="{H - 32 - _LEG_H}" fill="#F7F9FB"/>')
        s.append(f'<text x="{x0 + lane_w / 2}" y="49" text-anchor="middle" class="t-lane">{_xml(l.upper())}</text>')
        s.append(f'<text x="{x0 + lane_w / 2}" y="61" text-anchor="middle" class="t-lsub">{_xml(LANE_SUBTITLE[l])}</text>')
        if li > 0:
            s.append(f'<line x1="{x0}" y1="32" x2="{x0}" y2="{H - _LEG_H}" stroke="#78909C" stroke-width="1.6" '
                     f'stroke-dasharray="1.5,6" stroke-linecap="round"/>')

    # edges
    pair_n, pair_seen = {}, {}
    for f in flows:
        k = tuple(sorted([f["source"], f["destination"]]))
        pair_n[k] = pair_n.get(k, 0) + 1

    labels = []   # drawn after nodes so they stay readable
    done_keys = set()
    anchors = {}
    for f in flows:
        src, dst = f["source"], f["destination"]
        if src not in pos or dst not in pos:
            continue
        (x1, y1), (x2, y2) = pos[src], pos[dst]
        pk = tuple(sorted([src, dst]))
        oi = pair_seen.get(pk, 0)
        pair_seen[pk] = oi + 1
        off = (oi - (pair_n[pk] - 1) / 2) * 14
        key = _flow_key(f)
        is_thr = key in threat_flows
        sz, dz = zsc.get(src, 3), zsc.get(dst, 3)
        tags = []
        if mode == "stride":
            if sz < dz: tags.append("T")
            if sz > dz: tags.append("I")
            if sz == 0: tags.append("D")
        col = "#C62828" if is_thr else ("#5C6BC0" if tags else "#546E7A")
        mk = "mk-r" if is_thr else ("mk-b" if tags else "mk-n")
        sw = 2.6 if is_thr else 1.7
        dash = ' stroke-dasharray="6,3"' if (tags and not is_thr) else ""
        xb = []
        if heat and key in risk_map:
            band = risk_band(risk_map[key])
            col, mk, sw = BAND_COLORS[band][1], {"High": "mk-r", "Medium": "mk-a", "Low": "mk-g"}[band], 3
            xb.append(("risk", (f"R{risk_map[key]}", band), 30))
            if mode == "controls" and ctrl_map.get(key):
                xb.append(("ctl", ctrl_map[key], 30))
        if src in oos or dst in oos:
            col, mk, sw, dash = "#B0BEC5", "mk-o", 1.3, ' stroke-dasharray="3,4"'
        t1, t2 = comp_by_name[src].get("type"), comp_by_name[dst].get("type")
        vert, side = False, 0

        if lane_of[src] != lane_of[dst]:
            right = x2 > x1
            sx, ex = _edge_x(x1, off, t1, right), _edge_x(x2, off, t2, not right)
            sy, ey = y1 + off, y2 + off
            mid = (sx + ex) / 2
            d = f"M{sx:.1f},{sy:.1f} C{mid:.1f},{sy:.1f} {mid:.1f},{ey:.1f} {ex:.1f},{ey:.1f}"
            lx, ly = mid, (sy + ey) / 2
        else:
            ids = order[lane_of[src]]
            if abs(ids.index(src) - ids.index(dst)) == 1:
                down = y2 > y1
                sy = y1 + (_node_h(t1) / 2 if down else -_node_h(t1) / 2)
                ey = y2 - (_node_h(t2) / 2 if down else -_node_h(t2) / 2)
                xo = x1 + off
                d = f"M{xo:.1f},{sy:.1f} L{xo:.1f},{ey:.1f}"
                lx, ly = xo, (sy + ey) / 2 + 3
                vert = True
                side = 0 if pair_n[pk] == 1 else (-1 if off < 0 else 1)
            else:   # non-adjacent in the same lane: bow out to the right
                sx, ex = x1 + HW, x2 + HW
                bow = 46 + abs(off)
                d = f"M{sx:.1f},{y1 + off:.1f} C{sx + bow:.1f},{y1 + off:.1f} {ex + bow:.1f},{y2 + off:.1f} {ex:.1f},{y2 + off:.1f}"
                lx, ly = max(sx, ex) + bow * 0.75 + 4, (y1 + y2) / 2 + off
        s.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="{sw}"{dash} marker-end="url(#{mk})"/>')
        data = (f.get("data", "") or "")
        proto = f.get("protocol", "")
        tip = f"{key} · {data}" + (f" · {proto}" if proto else "")
        labels.append((key, lx, ly, data, tip, col, tags, vert, side, xb))
        anchors.setdefault(key, (lx, ly, data))

    # nodes
    for comp in components:
        name = comp["name"]
        if name not in pos:
            continue
        cx, cy = pos[name]
        ctype = comp.get("type", "process")
        zone = comp.get("zone", "Standard Application")
        zs = _ZONE_STYLE.get(zone, _ZONE_STYLE["Standard Application"])
        is_thr = name in threat_nodes
        h = _node_h(ctype)
        x0, y0 = cx - HW, cy - h / 2
        fill = "#FFCDD2" if is_thr else (zs["band"] if mode == "zones" else "white")
        stroke = "#C62828" if is_thr else (zs["stroke"] if mode == "zones" else "#263238")
        swn = 3 if is_thr else 1.8
        in_oos = name in oos
        r_here = risk_map.get(name) if heat else None
        if r_here:
            fill, stroke, swn = BAND_COLORS[risk_band(r_here)][0], BAND_COLORS[risk_band(r_here)][1], 3
        if in_oos:
            fill, stroke, swn = "#ECEFF1", "#90A4AE", 1.5
        sd = ' stroke-dasharray="5,3"' if in_oos else ""
        tstyle = ' style="fill:#90A4AE"' if in_oos else ""
        tip = f"<title>{_xml(name)} — {_xml(comp.get('description', ''))} · {_xml(zone)} (Z{comp.get('zone_score', 0)})</title>"
        if ctype == "external_entity":
            s.append(f'<g filter="url(#sh)">{tip}<ellipse cx="{cx}" cy="{cy}" rx="{HW}" ry="{h / 2}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        elif ctype == "datastore":
            cap = 9
            body = (f'M{x0},{y0 + cap} L{x0},{y0 + h - cap} A{HW},{cap} 0 0 0 {x0 + _NODE_W},{y0 + h - cap} '
                    f'L{x0 + _NODE_W},{y0 + cap} Z')
            s.append(f'<g filter="url(#sh)">{tip}<path d="{body}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/>'
                     f'<ellipse cx="{cx}" cy="{y0 + cap}" rx="{HW}" ry="{cap}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        else:
            s.append(f'<g filter="url(#sh)">{tip}<rect x="{x0}" y="{y0}" width="{_NODE_W}" height="{h}" rx="9" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        desc = zone if mode == "zones" else comp.get("description", "")
        yb = cy + (6 if ctype == "datastore" else 0)
        s.append(f'<text x="{cx}" y="{yb - 2}" text-anchor="middle" class="t-name"{tstyle}>{_xml(_trunc(name, 22))}</text>')
        s.append(f'<text x="{cx}" y="{yb + 11}" text-anchor="middle" class="t-desc"{tstyle}>{_xml(_trunc(desc, 30))}</text>')
        s.append(f'<rect x="{cx - 16}" y="{cy + h / 2 - 7}" width="32" height="14" rx="7" fill="{zs["stroke"]}"/>'
                 f'<text x="{cx}" y="{cy + h / 2 + 3}" text-anchor="middle" class="t-zone">Z{_xml(comp.get("zone_score", 0))}</text>')
        if in_oos:
            s.append(f'<rect x="{x0 + _NODE_W - 78}" y="{y0 - 8}" width="78" height="15" rx="7" fill="#78909C"/>'
                     f'<text x="{x0 + _NODE_W - 39}" y="{y0 + 2.5}" text-anchor="middle" class="t-zone">OUT OF SCOPE</text>')
        if r_here:
            rf, rs = BAND_COLORS[risk_band(r_here)]
            s.append(f'<g><title>Risk score {r_here} ({risk_band(r_here)})</title><rect x="{x0 + _NODE_W - 30}" y="{y0 - 9}" width="34" height="18" rx="7" fill="{rs}"/>'
                     f'<text x="{x0 + _NODE_W - 13}" y="{y0 + 3.5}" text-anchor="middle" class="t-zone">R{r_here}</text></g>')
            if mode == "controls" and ctrl_map.get(name):
                s.append(f'<g><title>{ctrl_map[name]} control(s) selected</title><rect x="{x0 + _NODE_W - 66}" y="{y0 - 9}" width="32" height="18" rx="7" fill="#2E7D32"/>'
                         f'<text x="{x0 + _NODE_W - 50}" y="{y0 + 3.5}" text-anchor="middle" class="t-zone">C×{ctrl_map[name]}</text></g>')
        if is_thr:
            s.append(f'<circle cx="{x0 + _NODE_W}" cy="{y0}" r="9" fill="#C62828"/>'
                     f'<text x="{x0 + _NODE_W}" y="{y0 + 4}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="700" fill="white">!</text>')

    # learner labels on components (row above the node, wrapping upward)
    for name, (cx, cy) in pos.items():
        items = sorted(by_target.get(name, []), key=_ann_sort)
        if not items:
            continue
        ytop = cy - _node_h(comp_by_name[name].get("type")) / 2
        bx, row, x_start = cx - HW, 0, cx - HW
        for it in items:
            w = _badge_w(it["id"], it["kind"])
            if bx > x_start and bx + w > x_start + _NODE_W + 30:
                bx, row = x_start, row + 1
            s.append(_badge_svg(bx, ytop - 14 - row * 24, it["id"], it["kind"], _item_tip(it)))
            bx += w + 4

    # edge labels, STRIDE chips and learner labels on flows
    placed = []   # bounding boxes of labels already drawn (simple collision avoidance)

    def _free(box):
        return not any(box[0] < q[2] + 3 and box[2] > q[0] - 3 and box[1] < q[3] + 3 and box[3] > q[1] - 3 for q in placed)

    for key, lx, ly, data, tip, col, tags, vert, side, xb in sorted(labels, key=lambda x: not x[7]):   # vertical flows first
        txt = _trunc(data, 22)
        lw = len(txt) * 5.2 + 12 if txt else 0
        if vert and side:
            lx = lx + side * (lw / 2 + 7)      # parallel vertical flows: label sits beside its own line
        extras = [("chip", tg, 16) for tg in tags] + list(xb)
        if key not in done_keys:               # learner labels go on the first flow with this key
            done_keys.add(key)
            for it in sorted(by_target.get(key, []), key=_ann_sort):
                extras.append(("ann", it, _badge_w(it["id"], it["kind"])))
        total = sum(e[2] for e in extras) + 4 * max(0, len(extras) - 1)
        if vert:   # extras beside the label, on the outer side
            ex0 = (lx - lw / 2 - 6 - total) if side < 0 else (lx + lw / 2 + 6)
            ey = -2
        else:      # extras centred under the label
            ex0, ey = lx - total / 2, 21
        dy = 0
        for cand in ([0] if vert else [0, -18, 18, -36, 36, -54, 54]):
            box = [min(lx - lw / 2, ex0 if extras else 1e9), ly + cand - 10,
                   max(lx + lw / 2, ex0 + total if extras else -1e9), ly + cand + (ey + 11 if extras else 6)]
            dy = cand
            if _free(box):
                break
        placed.append(box)
        ly += dy
        if txt:
            s.append(f'<g><title>{_xml(tip)}</title><rect x="{lx - lw / 2:.1f}" y="{ly - 9:.1f}" width="{lw:.1f}" height="14" rx="4" fill="white" stroke="#CFD8DC" stroke-width="0.8"/>'
                     f'<text x="{lx:.1f}" y="{ly + 1:.1f}" text-anchor="middle" class="t-edge" fill="{col}">{_xml(txt)}</text></g>')
        bx, by = ex0, ly + ey
        for typ, obj, w in extras:
            if typ == "risk":
                rf, rs = BAND_COLORS[risk_band(int(obj[0][1:]))]
                s.append(f'<g><title>Risk score {obj[0][1:]} ({obj[1]})</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="30" height="16" rx="6" fill="{rs}"/>'
                         f'<text x="{bx + 15:.1f}" y="{by + 3.5:.1f}" text-anchor="middle" class="t-zone">{obj[0]}</text></g>')
            elif typ == "ctl":
                s.append(f'<g><title>{obj} control(s) selected</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="30" height="16" rx="6" fill="#2E7D32"/>'
                         f'<text x="{bx + 15:.1f}" y="{by + 3.5:.1f}" text-anchor="middle" class="t-zone">C×{obj}</text></g>')
            elif typ == "chip":
                tc = _STRIDE_TAG_COLOR.get(obj, "#555")
                s.append(f'<g><title>{_xml(_STRIDE_TAG_TIP.get(obj, ""))}</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="16" height="16" rx="4" fill="{tc}"/>'
                         f'<text x="{bx + 8:.1f}" y="{by + 3.5:.1f}" text-anchor="middle" class="t-badge" fill="white">{obj}</text></g>')
            else:
                s.append(_badge_svg(round(bx, 1), round(by, 1), obj["id"], obj["kind"], _item_tip(obj)))
            bx += w + 4

    # legend
    ly0 = H - _LEG_H
    s.append(f'<rect x="0" y="{ly0}" width="{W}" height="{_LEG_H}" fill="#F7F9FC"/>'
             f'<line x1="0" y1="{ly0}" x2="{W}" y2="{ly0}" stroke="#E0E7EF"/>')
    s.append(f'<text x="14" y="{ly0 + 15}" class="t-legt">LEGEND</text>')

    def ic_ellipse(x, y): return f'<ellipse cx="{x + 9}" cy="{y}" rx="9" ry="6" fill="white" stroke="#263238" stroke-width="1.3"/>', 18
    def ic_rect(x, y):    return f'<rect x="{x}" y="{y - 6}" width="18" height="12" rx="3" fill="white" stroke="#263238" stroke-width="1.3"/>', 18
    def ic_cyl(x, y):
        return (f'<path d="M{x},{y - 3} L{x},{y + 3} A9,3 0 0 0 {x + 18},{y + 3} L{x + 18},{y - 3} Z" fill="white" stroke="#263238" stroke-width="1.2"/>'
                f'<ellipse cx="{x + 9}" cy="{y - 3}" rx="9" ry="3" fill="white" stroke="#263238" stroke-width="1.2"/>'), 18
    def ic_zone(x, y):    return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="6" fill="#F9A825"/><text x="{x + 11}" y="{y + 3}" text-anchor="middle" class="t-zone">Z3</text>', 22
    def ic_bang(x, y):    return f'<circle cx="{x + 8}" cy="{y}" r="8" fill="#C62828"/><text x="{x + 8}" y="{y + 4}" text-anchor="middle" font-family="Arial" font-size="11" font-weight="700" fill="white">!</text>', 16
    def ic_badge(kind, code):
        return lambda x, y: (_badge_svg(x, y, code, kind), _badge_w(code, kind))
    def ic_chip(tg):
        return lambda x, y: (f'<rect x="{x}" y="{y - 8}" width="16" height="16" rx="4" fill="{_STRIDE_TAG_COLOR[tg]}"/><text x="{x + 8}" y="{y + 3.5}" text-anchor="middle" class="t-badge" fill="white">{tg}</text>', 16)

    def ic_oos(x, y):
        return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="5" fill="#ECEFF1" stroke="#90A4AE" stroke-dasharray="3,2"/>', 22

    def ic_risk(band):
        return lambda x, y: (f'<rect x="{x}" y="{y - 7}" width="22" height="14" rx="6" fill="{BAND_COLORS[band][1]}"/>', 22)

    def ic_ctl(x, y):
        return f'<rect x="{x}" y="{y - 7}" width="26" height="14" rx="6" fill="#2E7D32"/><text x="{x + 13}" y="{y + 3}" text-anchor="middle" class="t-zone">C×n</text>', 26

    items = [(ic_ellipse, "External entity"), (ic_rect, "Process"), (ic_cyl, "Data store"),
             (ic_zone, "Criticality zone (0–9)"),
             (ic_badge("actor", "TA1"), "Threat actor"), (ic_badge("asset", "AS1"), "Asset"),
             (ic_badge("threat", "T1"), "Threat scenario"), (ic_badge("control", "C1"), "Control / mitigation")]
    if mode == "stride":
        items += [(ic_chip("T"), "Tampering"), (ic_chip("I"), "Info disclosure"), (ic_chip("D"), "DoS")]
    if threat_nodes or threat_flows:
        items.append((ic_bang, "Threat identified"))
    if oos:
        items.append((ic_oos, "Out of scope"))
    if heat:
        items += [(ic_risk("Low"), "Low risk (1–2)"), (ic_risk("Medium"), "Medium (3–4)"), (ic_risk("High"), "High (6–9)")]
    if mode == "controls":
        items.append((ic_ctl, "Controls selected"))
    lx_, ly_ = 14, ly0 + 34
    for fn, text in items:
        w_item = 30 + len(text) * 5.1
        if lx_ + w_item > W - 10:
            lx_, ly_ = 14, ly_ + 20
        svg_i, iw = fn(lx_, ly_)
        s.append(svg_i)
        s.append(f'<text x="{lx_ + iw + 6}" y="{ly_ + 3}" class="t-leg">{_xml(text)}</text>')
        lx_ += iw + 6 + len(text) * 5.1 + 18
    s.append("</svg>")
    return "\n".join(s)


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC LABELS: threat actors · assets · threat scenarios · controls
# ─────────────────────────────────────────────────────────────────────────────
def get_annotations(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    return st.session_state.annotations.setdefault(ws_id, [])


def _next_annotation_id(items, kind):
    pre = ANNOTATION_KINDS[kind]["prefix"]
    nums = [int(re.sub(r"\D", "", i["id"]) or 0) for i in items if i["kind"] == kind]
    return f"{pre}{max(nums, default=0) + 1}"


def annotation_register_df(items, include_scenario_links=True):
    rows = []
    for it in sorted(items, key=_ann_sort):
        rows.append({
            "ID": it["id"], "Type": ANNOTATION_KINDS[it["kind"]]["title"], "Label": it["label"],
            "Attached to": it["target"], "Linked to": ", ".join(it.get("links", [])), "Notes": it.get("notes", ""),
        })
    return pd.DataFrame(rows, columns=["ID", "Type", "Label", "Attached to", "Linked to", "Notes"])


def diagram_label_editor(workshop_config, key, default_kind=None):
    """Expander that lets the learner add / remove labels on the diagram of the current workshop."""
    ws_id = st.session_state.selected_workshop
    items = get_annotations(ws_id)
    sc = workshop_config["scenario"]
    targets = [c["name"] for c in sc["components"]] + list(dict.fromkeys(_flow_key(f) for f in sc["data_flows"]))
    nonce = st.session_state.annot_nonce

    with st.expander(f"✏️ Label this diagram — actors · assets · threat scenarios · controls  ({len(items)} labels)",
                     expanded=False):
        st.caption("Labels appear on every diagram of this workshop. Attach a label to a component or to a data flow, "
                   "link threat scenarios to actors/assets, and link controls to the scenarios they mitigate.")
        c1, c2 = st.columns([1, 2])
        kind = c1.selectbox("Label type", _KIND_ORDER, key=f"{key}_kind",
                            index=_KIND_ORDER.index(default_kind) if default_kind in _KIND_ORDER else 0,
                            format_func=lambda k: f"{ANNOTATION_KINDS[k]['icon']} {ANNOTATION_KINDS[k]['title']}")
        target = c2.selectbox("Attach to (component or data flow)", targets, key=f"{key}_target_{nonce}")

        suggestion = None
        if kind == "asset" and sc.get("assets"):
            pick = st.selectbox("Suggestions from this scenario", ["(type your own)"] + list(sc["assets"]),
                                key=f"{key}_sugg_{nonce}")
            suggestion = None if pick == "(type your own)" else pick
        label = st.text_input("Label", max_chars=80, key=f"{key}_label_{nonce}",
                              placeholder={"actor": "e.g. Financially motivated external attacker",
                                           "asset": "e.g. Customer PII",
                                           "threat": "e.g. SQL injection alters order totals",
                                           "control": "e.g. Parameterised queries"}[kind])
        link_kinds = {"threat": ["actor", "asset"], "control": ["threat"]}.get(kind, [])
        link_opts = [i for i in sorted(items, key=_ann_sort) if i["kind"] in link_kinds]
        links = []
        if link_opts:
            verb = "Threat actors / assets involved" if kind == "threat" else "Threat scenarios this control mitigates"
            links = st.multiselect(verb, [i["id"] for i in link_opts], key=f"{key}_links_{nonce}",
                                   format_func=lambda cid: f"{cid} — " + next(i["label"] for i in link_opts if i["id"] == cid))
        notes = st.text_input("Notes (optional)", max_chars=160, key=f"{key}_notes_{nonce}")

        if st.button("➕ Add label", key=f"{key}_add", type="primary"):
            final = (label or "").strip() or (suggestion or "")
            if not final:
                st.warning("Enter a label first.")
            else:
                items.append({"id": _next_annotation_id(items, kind), "kind": kind, "label": final,
                              "target": target, "links": links, "notes": (notes or "").strip()})
                st.session_state.annot_nonce += 1
                save_progress()
                st.rerun()

        if items:
            st.markdown("**Current labels**")
            for it in sorted(items, key=_ann_sort):
                a, b, c, d = st.columns([1, 5, 4, 1])
                a.markdown(f"**{it['id']}**")
                b.text(f"{ANNOTATION_KINDS[it['kind']]['title']}: {it['label']}")
                c.text(f"on {it['target']}" + (f"  ↔ {', '.join(it['links'])}" if it.get("links") else ""))
                if d.button("🗑", key=f"{key}_del_{it['id']}", help=f"Remove {it['id']}"):
                    items[:] = [x for x in items if x["id"] != it["id"]]
                    for x in items:
                        x["links"] = [l for l in x.get("links", []) if l != it["id"]]
                    save_progress()
                    st.rerun()
            b1, b2 = st.columns(2)
            b1.download_button("⬇️ Export label register (CSV)", annotation_register_df(items).to_csv(index=False),
                               file_name=f"workshop{ws_id}_labels.csv", mime="text/csv", key=f"{key}_csv",
                               use_container_width=True)
            if b2.button("🧹 Clear all labels", key=f"{key}_clear", use_container_width=True):
                st.session_state.annotations[ws_id] = []
                save_progress()
                st.rerun()


def _risk_maps(mode):
    risk, ctrl = {}, {}
    for r in st.session_state.user_answers:
        v = rec_residual(r) if mode == "residual" else rec_risk(r)
        if not v:
            continue
        risk[r["component"]] = max(risk.get(r["component"], 0), v)
        if mode == "controls" and r.get("controlled"):
            ctrl[r["component"]] = ctrl.get(r["component"], 0) + len(r.get("selected_mitigations", []))
    return risk, ctrl


def show_architecture_diagram(workshop_config, threats=None, mode="architecture", key_suffix="", editable=False, default_kind=None):
    captions = {
        "architecture": "Architecture overview — columns = where the component lives · Z-chip = criticality zone · hover any shape or badge for details",
        "stride":       "STRIDE flow annotations — chips on flows: T = Tampering (low→high zone) · I = Info disclosure (high→low) · D = DoS (Zone-0 source)",
        "threat":       "Threat map — components and flows with identified threats are shown in red",
        "zones":        "Zones of trust — shape colour = criticality zone of each component",
        "scope":        "Scope view — grey dashed components are OUT of scope (set them in the scope form above); everything else is in scope",
        "scoring":      "Inherent risk — colour = highest risk score (impact × likelihood) on each component or flow",
        "controls":     "Controls — colour = inherent risk · C×n = number of controls you selected for that component or flow",
        "residual":     "Residual risk — colour = risk that remains after your controls",
    }
    ws_id = st.session_state.selected_workshop
    items = get_annotations(ws_id)
    oos = get_scope(ws_id)["oos_components"]
    risk_map, ctrl_map = _risk_maps(mode) if mode in ("scoring", "controls", "residual") else ({}, {})
    svg = render_architecture_svg(workshop_config, highlighted_threats=threats or [], mode=mode, annotations=items,
                                  out_of_scope=oos, risk_map=risk_map, ctrl_map=ctrl_map)
    if mode in captions:
        st.caption("📐 " + captions[mode])
    est_h = _TOP + max(1, max(len([1 for c in workshop_config["scenario"]["components"] if _lane_of(c) == l])
                              for l in LANE_ORDER)) * _ROW_H + _LEG_H + 24
    components_html.html(
        f'<div style="overflow-x:auto;border:1px solid #E1E8EF;border-radius:10px;background:white">{svg}</div>',
        height=int(est_h + 30), scrolling=True)
    st.download_button("⬇️ Download diagram (SVG)", svg, file_name=f"workshop{ws_id}_{mode}.svg",
                       mime="image/svg+xml", key=f"dl_svg_{key_suffix}_{mode}")
    if editable:
        diagram_label_editor(workshop_config, key=f"ed_{key_suffix}", default_kind=default_kind)
        if items:
            st.markdown("**Label register**")
            st.dataframe(annotation_register_df(items), hide_index=True, use_container_width=True)
            open_threats = [i["id"] for i in items if i["kind"] == "threat"
                            and not any(c["kind"] == "control" and i["id"] in c.get("links", []) for c in items)]
            if open_threats:
                st.warning(f"Threat scenarios with no linked control yet: {', '.join(open_threats)}")
            elif any(i["kind"] == "threat" for i in items):
                st.success("Every labelled threat scenario has at least one linked control.")


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
# ─────────────────────────────────────────────────────────────────────────────
# PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────
def _progress_path():
    """Per-user progress file, keyed by an id kept in the URL (?sid=...)."""
    sid = st.session_state.get("_sid")
    if not sid:
        try:
            sid = st.query_params.get("sid")
            if isinstance(sid, list):
                sid = sid[0] if sid else None
            if not sid:
                sid = uuid.uuid4().hex[:16]
                st.query_params["sid"] = sid
        except Exception:
            sid = uuid.uuid4().hex[:16]
        sid = re.sub(r"[^A-Za-z0-9]", "", str(sid))[:32] or uuid.uuid4().hex[:16]
        st.session_state["_sid"] = sid
    return os.path.join(tempfile.gettempdir(), f"threat_progress_v3_{sid}.json")


def save_progress():
    try:
        with open(_progress_path(), "w") as f:
            json.dump({
                "completed_workshops": list(st.session_state.completed_workshops),
                "unlocked_workshops": list(st.session_state.unlocked_workshops),
                "selected_workshop": st.session_state.selected_workshop,
                "current_step": st.session_state.current_step,
                "threats": st.session_state.threats,
                "user_answers": st.session_state.user_answers,
                "total_score": st.session_state.total_score,
                "max_score": st.session_state.max_score,
                "annotations": st.session_state.annotations,
                "scope_models": st.session_state.scope_models,
                "open_questions": st.session_state.open_questions,
                "review_plans": st.session_state.review_plans,
            }, f)
    except Exception:
        pass


def load_progress():
    """Only load from disk once per browser session."""
    if st.session_state.get('_progress_loaded'):
        return
    try:
        path = _progress_path()
        if os.path.exists(path):
            with open(path) as f:
                p = json.load(f)
            st.session_state.completed_workshops = set(p.get("completed_workshops", []))
            st.session_state.unlocked_workshops = set(p.get("unlocked_workshops", ["1"])) | {"1"}
            sel = p.get("selected_workshop")
            st.session_state.selected_workshop = sel if sel in WORKSHOPS else None
            step = p.get("current_step", 1)
            st.session_state.current_step = step if isinstance(step, int) and 1 <= step <= 13 else 1
            st.session_state.threats = p.get("threats", [])
            st.session_state.user_answers = p.get("user_answers", [])
            st.session_state.total_score = p.get("total_score", 0)
            st.session_state.max_score = p.get("max_score", 0)
            st.session_state.annotations = p.get("annotations", {})
            st.session_state.scope_models = p.get("scope_models", {})
            st.session_state.open_questions = p.get("open_questions", {})
            st.session_state.review_plans = p.get("review_plans", {})
    except Exception:
        pass
    st.session_state['_progress_loaded'] = True


load_progress()


def is_workshop_unlocked(ws_id):
    return ws_id in st.session_state.unlocked_workshops


# ─────────────────────────────────────────────────────────────────────────────
# PDF GENERATORS
# ─────────────────────────────────────────────────────────────────────────────
def generate_user_threat_model_pdf(workshop_config, user_answers, total_score, max_score, extra=None):
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
            ['Methodology:', '7-Stage Threat Modeling'],
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

        story.append(Paragraph("7-Stage Process Applied", h2))
        for s_ in ["Stage 1: Scope – system, requirements, assumptions, exclusions, goals",
                   "Stage 2: DFD – elements, flows, trust boundaries and zones of trust",
                   "Stage 3: STRIDE – zone-direction rules to derive threats",
                   "Stage 4: Scoring – impact × likelihood on a 1–3 scale (risk 1–9)",
                   "Stage 5: Controls – guardrails, filtering, access rules, monitoring (OWASP-mapped)",
                   "Stage 6: Residual risk – risk after controls, decisions, open questions",
                   "Stage 7: Review – owner, cadence and update triggers"]:
            story.append(Paragraph(f"• {s_}", styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        def _para(txt, bold=False):
            txt = _html.escape(str(txt))
            return Paragraph(f"<b>{txt}</b>" if bold else txt, styles['Normal'])

        def _grid(rows, widths, header=True):
            tb = Table([[_para(c, header and i == 0) for c in r] for i, r in enumerate(rows)], colWidths=[w * inch for w in widths], repeatRows=1 if header else 0)
            tb.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                    ('BACKGROUND', (0, 0), (-1, 0 if header else -1), colors.HexColor('#E3F2FD')) if header else ('LEFTPADDING', (0, 0), (-1, -1), 4),
                                    ('LEFTPADDING', (0, 0), (-1, -1), 4), ('TOPPADDING', (0, 0), (-1, -1), 3)]))
            return tb

        ex = extra or {}
        sc_ = ex.get("scope") or {}
        if sc_:
            story.append(Paragraph("Stage 1 – Scope", h2))
            story.append(_para("System in scope: " + (sc_.get("statement") or "—")))
            for title_, key_ in (("Must do", "must_do"), ("Must never", "must_never"), ("Measurable goals", "goals")):
                if sc_.get(key_):
                    story.append(Spacer(1, 0.05 * inch)); story.append(_para(title_, True))
                    for x_ in sc_[key_]:
                        story.append(_para("• " + x_))
            if sc_.get("assumptions"):
                story.append(Spacer(1, 0.08 * inch)); story.append(_para("Assumptions", True))
                story.append(_grid([["Assumption", "How we will verify", "Status"]] + [[a_.get("Assumption", ""), a_.get("How we will verify", ""), a_.get("Status", "")] for a_ in sc_["assumptions"]], [2.6, 2.6, 1.0]))
            if sc_.get("exclusions") or sc_.get("oos_components"):
                story.append(Spacer(1, 0.08 * inch)); story.append(_para("Exclusions (out of scope)", True))
                if sc_.get("exclusions"):
                    story.append(_grid([["Excluded item", "Reason"]] + [[e_.get("Excluded item", ""), e_.get("Reason", "")] for e_ in sc_["exclusions"]], [3.0, 3.2]))
                if sc_.get("oos_components"):
                    story.append(_para("Out-of-scope components: " + ", ".join(sc_["oos_components"])))
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
                ['Risk:', (f"{answer['likelihood']} × {answer['impact']} = {rec_risk(answer)}/9 ({risk_band(rec_risk(answer))})" if rec_risk(answer) else "Not rated")
                          + (f"  →  residual {rec_residual(answer)}/9 ({answer['residual']['decision']})" if rec_residual(answer) else "")],
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
                    story.append(Paragraph(f"• [{control_category(m)}] {_html.escape(m)}", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))

        rated_ = [a_ for a_ in user_answers if rec_risk(a_)]
        if rated_:
            story.append(Paragraph("Stages 4–6 – Risk register (inherent → residual)", h2))
            story.append(_grid([["Threat", "Component / flow", "STRIDE", "Inherent", "Residual", "Decision"]] +
                               [[a_["matched_threat_id"], a_["component"], a_["stride"], str(rec_risk(a_)),
                                 str(rec_residual(a_) or "—"), (a_.get("residual") or {}).get("decision", "—")]
                                for a_ in sorted(rated_, key=lambda x: -rec_risk(x))], [0.7, 1.9, 1.3, 0.7, 0.7, 1.2]))
            story.append(Spacer(1, 0.15 * inch))
        oq_ = ex.get("open_questions") or {}
        if oq_.get("questions") or oq_.get("accepted"):
            story.append(Paragraph("Stage 6 – Open questions and accepted risk", h2))
            for q_ in oq_.get("questions", []):
                story.append(_para("• " + q_))
            if oq_.get("accepted"):
                story.append(Spacer(1, 0.05 * inch)); story.append(_para("Accepted-risk statement: " + oq_["accepted"]))
        rp_ = ex.get("review_plan") or {}
        if rp_.get("owner") or rp_.get("full"):
            story.append(Paragraph("Stage 7 – Review plan", h2))
            story.append(_para(f"Owner: {rp_.get('owner') or '—'}   |   Security role: {rp_.get('security_role') or '—'}   |   Next lightweight review: {rp_.get('next_review') or '—'}"))
            for title_, key_ in (("Full-workshop triggers", "full"), ("Lightweight review checks", "light"), ("Update triggers", "triggers")):
                if rp_.get(key_):
                    story.append(Spacer(1, 0.05 * inch)); story.append(_para(title_, True))
                    for x_ in rp_[key_]:
                        story.append(_para("• " + x_))
        labs_ = ex.get("labels") or []
        if labs_:
            story.append(Paragraph("Diagram labels (actors, assets, threat scenarios, controls)", h2))
            story.append(_grid([["ID", "Type", "Label", "Attached to"]] + [[l_["id"], ANNOTATION_KINDS[l_["kind"]]["title"], l_["label"], l_["target"]]
                                                                         for l_ in sorted(labs_, key=_ann_sort)], [0.6, 1.5, 2.7, 1.6]))

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
#  7-STAGE WORKFLOW:  Scope → DFD → STRIDE → Scoring → Controls → Residual risk → Review
#  Pages (current_step) 1-13 are grouped under these seven stages.
# ═══════════════════════════════════════════════════════════════════════════════
import html as _html
from datetime import date as _date, timedelta as _timedelta

STAGES = [
    ("scope",    "Scope",         "📐"),
    ("dfd",      "DFD",           "🗺️"),
    ("stride",   "STRIDE",        "⚡"),
    ("scoring",  "Scoring",       "📊"),
    ("controls", "Controls",      "🛡️"),
    ("residual", "Residual risk", "⚖️"),
    ("review",   "Review",        "🔁"),
]
STAGE_IDS = [s[0] for s in STAGES]
PAGES = {
    1:  ("Scope & goals",       "scope"),
    2:  ("Draw the DFD",        "dfd"),
    3:  ("Zones of trust",      "dfd"),
    4:  ("STRIDE rules",        "stride"),
    5:  ("Attack tree",         "stride"),
    6:  ("Identify threats",    "stride"),
    7:  ("Score the risk",      "scoring"),
    8:  ("OWASP mapping",       "controls"),
    9:  ("Select controls",     "controls"),
    10: ("Residual risk",       "residual"),
    11: ("Review plan",         "review"),
    12: ("Assessment & report", "review"),
    13: ("Complete",            "review"),
}


def _esc(x):
    return _html.escape(str(x if x is not None else ""))


def go_page(page):
    st.session_state.current_step = page
    save_progress()
    st.rerun()


def nav_buttons(back_page, back_label, next_page, next_label, next_ok=True, block_msg="", key="nav"):
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if back_page and st.button(back_label, use_container_width=True, key=f"{key}_back"):
            go_page(back_page)
    with c2:
        if next_page and st.button(next_label, type="primary", use_container_width=True, key=f"{key}_next"):
            if next_ok:
                go_page(next_page)
            else:
                st.error(block_msg or "Complete this step first.")


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCALE (1-3 × 1-3 = 1-9) AND THE PER-THREAT RECORD
# ─────────────────────────────────────────────────────────────────────────────
LEVELS = ["Low", "Medium", "High"]
_LEVEL_N = {"Low": 1, "Medium": 2, "High": 3, "Critical": 3}
BAND_COLORS = {"Low": ("#E8F5E9", "#2E7D32"), "Medium": ("#FFF3CD", "#E69500"), "High": ("#FFCDD2", "#C62828")}


def level_n(label):
    return _LEVEL_N.get(label, 0)


def risk_band(score):
    return "High" if score >= 6 else "Medium" if score >= 3 else "Low"


def rec_risk(rec):
    l, i = rec.get("likelihood_n"), rec.get("impact_n")
    return l * i if l and i else None


def rec_residual(rec):
    r = rec.get("residual")
    return r["likelihood_n"] * r["impact_n"] if r else None


def _score_identify(rec, pred):
    pts, fb = 0, []
    if rec["component"] == pred["component"]:
        pts += 2; fb.append("✓ Correct component identified")
    else:
        fb.append(f"✗ Wrong component. Expected: {pred['component']}")
    if rec["stride"] == pred["stride"]:
        pts += 2; fb.append("✓ Correct STRIDE category")
    else:
        fb.append(f"✗ Wrong STRIDE. Expected: {pred['stride']}")
    return pts, fb


def _score_rating(rec, pred):
    pts, fb = 0, []
    for fld in ("likelihood", "impact"):
        key_lbl = pred[fld]
        shown = "High" if key_lbl == "Critical" else key_lbl
        note = " (the key rates this Critical; Critical counts as High on the 1–3 scale)" if key_lbl == "Critical" else ""
        if level_n(rec.get(fld)) == level_n(key_lbl) and level_n(rec.get(fld)) > 0:
            pts += 1; fb.append(f"✓ Correct {fld}")
        else:
            fb.append(f"✗ {fld.capitalize()} should be: {shown}{note}")
    return pts, fb


def _score_controls(rec, pred):
    pts, fb = 0, []
    correct, incorrect = set(pred["correct_mitigations"]), set(pred.get("incorrect_mitigations", []))
    chosen = set(rec.get("selected_mitigations", []))
    ok, bad = chosen & correct, chosen & incorrect
    if len(ok) >= 3:
        pts += 4; fb.append(f"✓ Excellent control selection ({len(ok)} correct)")
    elif len(ok) == 2:
        pts += 3; fb.append(f"✓ Good control selection ({len(ok)} correct)")
    elif len(ok) == 1:
        pts += 2; fb.append(f"⚠ Partial control selection ({len(ok)} correct)")
    else:
        fb.append("✗ No correct controls selected")
    if bad:
        pts -= len(bad)
        fb.append(f"✗ Incorrect controls penalty: {', '.join(sorted(bad))}")
    return pts, fb


def rescore_record(rec):
    """Score a threat record from the stages completed so far (identify 4 pts, rating 2, controls 4)."""
    pred = rec["predefined_threat"]
    pts, mx = 0, 0
    p, rec["fb_identify"] = _score_identify(rec, pred); rec["pts_identify"] = p; pts += p; mx += 4
    fb = list(rec["fb_identify"])
    if rec.get("rated"):
        p, rec["fb_rating"] = _score_rating(rec, pred); pts += p; mx += 2; fb += rec["fb_rating"]
    if rec.get("controlled"):
        p, rec["fb_controls"] = _score_controls(rec, pred); pts += p; mx += 4; fb += rec["fb_controls"]
    rec["score"], rec["max_score"], rec["feedback"] = max(0, pts), mx, fb


def calculate_threat_score(user_threat, predefined_threat):
    """Compatibility helper: full score for a complete answer."""
    rec = {**user_threat, "predefined_threat": predefined_threat, "rated": True, "controlled": True}
    rescore_record(rec)
    return rec["score"], rec["max_score"], rec["feedback"]


def recalc_totals():
    ans = st.session_state.user_answers
    st.session_state.total_score = sum(a["score"] for a in ans)
    st.session_state.max_score = sum(a["max_score"] for a in ans)
    st.session_state.threats = [
        {k: a.get(k) for k in ("component", "stride", "likelihood", "impact", "selected_mitigations", "matched_threat_id")}
        for a in ans]


def new_record(component, stride, pred):
    rec = {"component": component, "stride": stride, "matched_threat_id": pred["id"],
           "likelihood": "Not rated", "impact": "Not rated", "likelihood_n": None, "impact_n": None,
           "rated": False, "selected_mitigations": [], "controlled": False, "residual": None,
           "predefined_threat": pred, "score": 0, "max_score": 4, "feedback": []}
    rescore_record(rec)
    return rec


# ─────────────────────────────────────────────────────────────────────────────
# CONTROL CATEGORIES (guardrails · filtering · access rules · monitoring)
# ─────────────────────────────────────────────────────────────────────────────
CONTROL_CATEGORIES = {
    "Guardrails":   ("🧱", "Secure-by-design defaults and architecture constraints: encryption, safe configuration, failure containment."),
    "Filtering":    ("🧪", "Checks on what goes in and out: validation, sanitisation, parameterised queries, output encoding, error hygiene."),
    "Access rules": ("🔑", "Limits on who/what can do what: authentication, authorisation, least privilege, rate limits, segmentation."),
    "Monitoring":   ("📡", "Detects what prevention misses: logging, audit trails, alerting, anomaly detection."),
}
_CAT_PATTERNS = [
    ("Monitoring", r"\b(?:log(?!in|ic)|audit|monitor|alert|siem|anomal|trac(?:e|ing)|detect|cloudtrail|forensic|telemetry|timestamp|nonce)"),
    ("Filtering",  r"\b(?:validat|sanitiz|sanitis|parameteri|prepared|orm\b|encod|escap|csp\b|content security|waf\b|filter|schema|allowlist|whitelist|blacklist|strip\b|dlp\b|mask|redact|generic error|avoid dangerously)"),
    ("Access rules", r"\b(?:auth|mfa|token|rbac|abac|least privilege|permission|role|tenant|limit|quota|throttl|mtls|mutual tls|spiffe|segment|isolation|vlan|firewall|security group|iam\b|ownership|deny|session|jwt|oauth|hmac|signature|certificate|pinning|access)"),
]


def control_category(text):
    t = str(text).lower()
    for cat, pat in _CAT_PATTERNS:
        if re.search(pat, t):
            return cat
    return "Guardrails"


def control_coverage(controls):
    cats = {}
    for c in controls:
        cats.setdefault(control_category(c), []).append(c)
    return cats


def _control_chips(controls):
    cats = control_coverage(controls)
    chips = []
    for cat, (ic, _) in CONTROL_CATEGORIES.items():
        n = len(cats.get(cat, []))
        bg, fg = ("#E8F5E9", "#1B5E20") if n else ("#F5F5F5", "#9E9E9E")
        chips.append(f'<span style="background:{bg};color:{fg};padding:2px 10px;border-radius:12px;font-size:0.8em;'
                     f'margin-right:6px;border:1px solid {fg}33">{ic} {cat}: {n}</span>')
    return "".join(chips)


def risk_matrix_html(items, title="Likelihood →"):
    """items: list of (likelihood_n, impact_n, label)."""
    cells = {}
    for l, i, lab in items:
        if l and i:
            cells.setdefault((l, i), []).append(lab)
    rows = []
    for i in (3, 2, 1):
        tds = [f'<td style="padding:6px 10px;font-weight:700;font-size:0.8em;color:#455A64;text-align:right;white-space:nowrap">{LEVELS[i-1]} impact</td>']
        for l in (1, 2, 3):
            fill, stroke = BAND_COLORS[risk_band(l * i)]
            labs = ", ".join(_esc(x) for x in cells.get((l, i), []))
            tds.append(f'<td style="background:{fill};border:2px solid {stroke};padding:8px;min-width:110px;height:62px;'
                       f'text-align:center;vertical-align:middle"><div style="font-size:0.7em;color:{stroke};font-weight:700">{l*i}</div>'
                       f'<div style="font-size:0.82em;font-weight:700;color:#222">{labs}</div></td>')
        rows.append("<tr>" + "".join(tds) + "</tr>")
    head = ('<tr><td></td>' + "".join(f'<td style="text-align:center;font-weight:700;font-size:0.8em;color:#455A64;padding:4px">{LEVELS[l-1]}</td>'
                                       for l in (1, 2, 3)) + "</tr>")
    foot = f'<tr><td></td><td colspan="3" style="text-align:center;font-size:0.75em;color:#78909C;padding-top:4px">{title}</td></tr>'
    return f'<table style="border-collapse:separate;border-spacing:4px;margin:6px 0">{head}{"".join(rows)}{foot}</table>'


# ─────────────────────────────────────────────────────────────────────────────
# SCOPE / OPEN QUESTIONS / REVIEW-PLAN MODELS (per workshop)
# ─────────────────────────────────────────────────────────────────────────────
def get_scope(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    sc = st.session_state.scope_models.setdefault(ws_id, {})
    for k, v in (("statement", ""), ("must_do", []), ("must_never", []), ("assumptions", []),
                 ("exclusions", []), ("oos_components", []), ("goals", [])):
        sc.setdefault(k, v)
    return sc


def get_open_questions(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    d = st.session_state.open_questions.setdefault(ws_id, {})
    d.setdefault("questions", []); d.setdefault("accepted", "")
    return d


def get_review_plan(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    d = st.session_state.review_plans.setdefault(ws_id, {})
    for k, v in (("owner", ""), ("security_role", "Security — expertise and challenge"), ("next_review", ""),
                 ("full", []), ("light", []), ("triggers", []), ("notes", "")):
        d.setdefault(k, v)
    return d


def scope_checks(sc):
    """(ok, text, required) — required items gate the Next button."""
    goal_ok = any(any(ch.isdigit() for ch in g) for g in sc["goals"])
    return [
        (len(sc["statement"].strip()) >= 25, "A specific scope statement (one deployed system, not “our platform”)", True),
        (len(sc["must_do"]) >= 1, "At least one thing the system MUST do", True),
        (len(sc["must_never"]) >= 1, "At least one thing the system must NEVER do (becomes a security requirement)", True),
        (len(sc["assumptions"]) >= 1, "At least one explicit assumption", True),
        (len(sc["exclusions"]) + len(sc["oos_components"]) >= 1, "At least one exclusion (what is out of scope)", True),
        (goal_ok, "A measurable success goal (contains a number or threshold)", False),
    ]


def scope_complete(sc):
    return all(ok for ok, _, req in scope_checks(sc) if req)


def scope_reminder():
    sc = get_scope()
    if sc["statement"].strip():
        st.caption(f"📐 **In scope:** {sc['statement'].strip()[:160]}  ·  {len(sc['assumptions'])} assumptions  ·  "
                   f"{len(sc['exclusions']) + len(sc['oos_components'])} exclusions")
    else:
        st.caption("📐 Scope not defined yet — Step 1 documents what is in scope, excluded and assumed.")


def scope_examples(cfg):
    s = cfg["scenario"]
    comps = s["components"]
    third = [c["name"] for c in comps if c["type"] == "external_entity" and _lane_of(c) == "Third-Party"]
    users = [c["name"] for c in comps if c["type"] == "external_entity" and _lane_of(c) != "Third-Party"]
    assets = s.get("assets", []) or ["sensitive data"]
    return {
        "statement": f"{s['title']} — {s['description']} ({cfg.get('architecture_type', 'architecture')})"
                     + (f", integrated with {', '.join(third)}" if third else "") + ".",
        "must_do": [f"Preserve: {o}" for o in s.get("objectives", [])[:3]],
        "must_never": [f"Never disclose {a} to unauthorised parties" for a in assets[:2]]
                      + ["Never accept state-changing requests from unauthenticated callers"],
        "assumptions": [
            {"Assumption": "All callers are authenticated before reaching internal services",
             "How we will verify": "Review gateway/auth configuration; test an unauthenticated request", "Status": "Unverified"},
            {"Assumption": f"{third[0]} is trustworthy and its integration is secured" if third else "Cloud provider controls are configured as documented",
             "How we will verify": "Vendor security report / contract review", "Status": "Unverified"},
        ],
        "exclusions": [
            {"Excluded item": "Physical security of data centres / provider facilities", "Reason": "Covered by the provider's shared-responsibility model"},
            {"Excluded item": "Security of end-user devices", "Reason": "Outside our control"},
        ],
        "goals": ["No high-severity security incident in production this quarter",
                  "Mean time to detect an attack under 4 hours",
                  "100% of Zone 7+ data stores have encryption and audit logging"],
    }


def _apply_scope_examples(ws_id):
    ex = scope_examples(WORKSHOPS[ws_id])
    sc = get_scope(ws_id)
    for fld, key in (("statement", f"w_stmt_{ws_id}"), ("must_do", f"w_must_do_{ws_id}"),
                     ("must_never", f"w_must_never_{ws_id}"), ("goals", f"w_goals_{ws_id}")):
        if not sc[fld]:
            sc[fld] = ex[fld]
            st.session_state[key] = ex[fld] if fld == "statement" else "\n".join(ex[fld])
    for kind, fld in (("assump", "assumptions"), ("excl", "exclusions")):
        if not sc[fld]:
            sc[fld] = ex[fld]
            st.session_state[f"_seed_{kind}_{ws_id}"] = pd.DataFrame(ex[fld])
            st.session_state.pop(f"w_ed_{kind}_{ws_id}", None)


def _lines(text):
    return [ln.strip(" -•\t") for ln in str(text).splitlines() if ln.strip(" -•\t")]


def _table_editor(ws_id, kind, cols, rows, column_config=None):
    sk = f"_seed_{kind}_{ws_id}"
    if sk not in st.session_state:
        st.session_state[sk] = pd.DataFrame(rows, columns=cols)
    df = st.data_editor(st.session_state[sk], num_rows="dynamic", key=f"w_ed_{kind}_{ws_id}",
                        use_container_width=True, hide_index=True, column_config=column_config or {})
    out = []
    for r in df.fillna("").to_dict("records"):
        row = {c: str(r.get(c, "")).strip() for c in cols}
        if row[cols[0]]:
            out.append(row)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 1 — SCOPE
# ═══════════════════════════════════════════════════════════════════════════════
def render_scope_page():
    ws = st.session_state.selected_workshop
    cfg = WORKSHOPS[ws]
    s = cfg["scenario"]
    sc = get_scope(ws)
    names = [c["name"] for c in s["components"]]

    st.header("Step 1: Define Scope & Goals")
    st.markdown("""
    <div class="methodology-step">
    <strong>📐 Stage 1 · Scope</strong><br>
    Draw a box around what you are protecting. A threat model cannot boil the ocean — pick <strong>one deployed system</strong>.
    Write down what it <strong>must do</strong> and <strong>must never do</strong> (these become your security requirements),
    document your <strong>assumptions</strong> and <strong>exclusions</strong> explicitly, and set <strong>measurable goals</strong>.
    <em>Half of security incidents come from violated assumptions nobody thought to verify.</em><br>
    ⏱️ Time-box: perfect clarity matters less than starting. Spend about 10 minutes here.
    </div>""", unsafe_allow_html=True)

    c1, c2 = st.columns([3, 2])
    with c1:
        st.markdown(f"**System:** {s['title']} — {s['description']}")
        st.markdown(f"**Business context:** {s['business_context']}")
        st.markdown("**Security objectives:** " + " · ".join(s["objectives"]))
    with c2:
        st.markdown("**Assets in play:** " + ", ".join(s.get("assets", [])))
        st.markdown("**Compliance drivers:** " + ", ".join(s.get("compliance", [])))

    st.button("💡 Fill empty fields with scenario-based examples", key="w_scope_examples",
              on_click=_apply_scope_examples, args=(ws,),
              help="Only fills fields that are still empty. Edit the examples so they reflect your own reasoning.")

    st.markdown("### 1️⃣ What exactly are you protecting?")
    st.caption("Bad: “Our platform”.  Good: one named system, its version/platform, key services and integrations.")
    statement = st.text_area("System in scope", value=sc["statement"], key=f"w_stmt_{ws}", height=90, max_chars=500,
                             placeholder=f"e.g. {s['title']} v2.0 — {s['description']}, integrated with ...")

    st.markdown("### 2️⃣ Security requirements")
    cc1, cc2 = st.columns(2)
    with cc1:
        must_do = st.text_area("The system MUST … (one per line)", value="\n".join(sc["must_do"]),
                               key=f"w_must_do_{ws}", height=130)
    with cc2:
        must_never = st.text_area("The system must NEVER … (one per line)", value="\n".join(sc["must_never"]),
                                  key=f"w_must_never_{ws}", height=130)

    st.markdown("### 3️⃣ Assumptions")
    st.caption("State what you are taking for granted, and how you would verify it. Unverified assumptions are risks.")
    assumptions = _table_editor(
        ws, "assump", ["Assumption", "How we will verify", "Status"], sc["assumptions"],
        {"Status": st.column_config.SelectboxColumn("Status", options=["Unverified", "Verified", "Disproved"], default="Unverified")})

    st.markdown("### 4️⃣ Exclusions (out of scope)")
    st.caption("Say what you are deliberately NOT analysing and why. Components marked out of scope are greyed on every diagram.")
    exclusions = _table_editor(ws, "excl", ["Excluded item", "Reason"], sc["exclusions"])
    oos = st.multiselect("Components that are OUT of scope", names,
                         default=[n for n in sc["oos_components"] if n in names], key=f"w_oos_{ws}")

    st.markdown("### 5️⃣ Measurable goals")
    goals = st.text_area("What does success look like? (one per line, with numbers)", value="\n".join(sc["goals"]),
                         key=f"w_goals_{ws}", height=90,
                         placeholder="e.g. Mean time to detect an attack under 4 hours")

    new = {"statement": statement.strip(), "must_do": _lines(must_do), "must_never": _lines(must_never),
           "assumptions": assumptions, "exclusions": exclusions, "oos_components": list(oos), "goals": _lines(goals)}
    if any(sc[k] != v for k, v in new.items()):
        sc.update(new)
        save_progress()

    st.markdown("---")
    st.subheader("🗺️ Scope view")
    show_architecture_diagram(cfg, mode="scope", key_suffix="s1_scope", editable=True, default_kind="asset")

    st.subheader("✅ Scope checklist")
    for ok, text, req in scope_checks(sc):
        st.markdown(f"{'✅' if ok else ('⚠️' if req else '➖')} {text}" + ("" if req else " *(recommended)*"))

    nav_buttons(None, "", 2, "Next: Draw the DFD ➡️", scope_complete(sc),
                "Complete the required scope items above before moving on.", key="p1")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 6 helper — record the learner's identified threats
# ═══════════════════════════════════════════════════════════════════════════════
def render_identified_threats():
    recs = st.session_state.user_answers
    if not recs:
        return
    st.subheader(f"📋 Threats you have identified ({len(recs)}/{current_workshop['target_threats']})")
    for idx, rec in enumerate(recs):
        pred = rec["predefined_threat"]
        pts = rec.get("pts_identify", 0) if "pts_identify" in rec else _score_identify(rec, pred)[0]
        icon = "✅" if pts == 4 else "⚠️" if pts >= 2 else "❌"
        with st.expander(f"{icon} {pred['id']} · {rec['stride']} on {rec['component']}  ({pts}/4)"):
            for fb in rec.get("fb_identify", []):
                (st.success if fb.startswith("✓") else st.error)(fb)
            st.markdown(f"""
            <div class="stride-rule-box">
            <strong>Threat scenario:</strong> {pred['threat']}<br>
            <strong>Zone rule applied:</strong> {pred.get('stride_rule_applied', 'N/A')}<br>
            <strong>From zone:</strong> {pred.get('zone_from', 'N/A')} → <strong>To zone:</strong> {pred.get('zone_to', 'N/A')}
            </div>""", unsafe_allow_html=True)
            if pred.get("explanation"):
                st.markdown(f"""
                <div style="background:#F0F4F8;border-radius:8px;padding:12px 16px;margin:6px 0">
                <strong style="color:#1A3A5C">📖 Explanation</strong><br>
                <span style="font-size:0.91em;color:#2C3E50">{pred['explanation']}</span></div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 7 — SCORING (impact × likelihood, 1-3 scale)
# ═══════════════════════════════════════════════════════════════════════════════
def render_scoring_page():
    cfg = current_workshop
    recs = st.session_state.user_answers
    st.header("Step 4: Score the Risk — Impact × Likelihood")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>📊 Stage 4 · Scoring</strong><br>
    Not all threats deserve equal attention. Score each one for <strong>impact</strong> and <strong>likelihood</strong> on a simple
    <strong>1–3 scale</strong> (Low / Medium / High) and multiply them for a <strong>risk score from 1 to 9</strong>.
    Do not spend hours debating whether something is a 2 or a 3 — the goal is rough prioritisation, not precision.
    </div>""", unsafe_allow_html=True)
    with st.expander("📏 How to judge impact and likelihood", expanded=False):
        g1, g2 = st.columns(2)
        g1.markdown("""**Impact** — technical *and* business consequences
- **High (3):** data breach affecting many customers, complete outage, regulatory violation
- **Medium (2):** individual privacy violation, degraded service, reputational damage
- **Low (1):** minor functionality issue, more support tickets""")
        g2.markdown("""**Likelihood** — attacker motivation and capability
- **High (3):** needs only public access, financially motivated, tools exist
- **Medium (2):** needs authenticated access or moderate skill
- **Low (1):** needs physical access or nation-state capability""")

    if not recs:
        st.warning("Identify at least one threat first.")
        nav_buttons(6, "⬅️ Back to Identify Threats", None, "", key="p7e")
        return

    with st.form("scoring_form"):
        st.subheader("➕ Rate each threat")
        vals = {}
        for rec in recs:
            pred = rec["predefined_threat"]
            st.markdown(f"**{pred['id']} · {rec['stride']} on {rec['component']}**")
            st.caption(pred["threat"])
            a, b = st.columns(2)
            lik = a.select_slider("Likelihood", options=LEVELS, key=f"w_lik_{pred['id']}",
                                  value=rec["likelihood"] if rec["likelihood"] in LEVELS else "Low")
            imp = b.select_slider("Impact", options=LEVELS, key=f"w_imp_{pred['id']}",
                                  value=rec["impact"] if rec["impact"] in LEVELS else "Low")
            vals[pred["id"]] = (lik, imp)
            st.markdown("---")
        if st.form_submit_button("📊 Score all threats", type="primary", use_container_width=True):
            for rec in recs:
                lik, imp = vals[rec["matched_threat_id"]]
                rec.update(likelihood=lik, impact=imp, likelihood_n=level_n(lik), impact_n=level_n(imp), rated=True)
                rescore_record(rec)
            recalc_totals()
            save_progress()
            st.rerun()

    rated = [r for r in recs if r.get("rated")]
    if rated:
        st.subheader("🎯 Risk register (highest first)")
        ordered = sorted(rated, key=lambda r: -rec_risk(r))
        st.dataframe(pd.DataFrame([{
            "Threat": r["matched_threat_id"], "Component / flow": r["component"], "STRIDE": r["stride"],
            "Likelihood": f"{r['likelihood']} ({r['likelihood_n']})", "Impact": f"{r['impact']} ({r['impact_n']})",
            "Risk (1–9)": rec_risk(r), "Band": risk_band(rec_risk(r)),
            "Priority": "Controls required" if rec_risk(r) >= 6 else "Plan controls" if rec_risk(r) >= 3 else "Accept / monitor"}
            for r in ordered]), use_container_width=True, hide_index=True)
        m1, m2 = st.columns([1, 1])
        with m1:
            st.markdown("**Risk matrix**")
            st.markdown(risk_matrix_html([(r["likelihood_n"], r["impact_n"], r["matched_threat_id"]) for r in rated]),
                        unsafe_allow_html=True)
        with m2:
            st.markdown("**How your ratings compare**")
            for r in ordered:
                fb = r.get("fb_rating", [])
                with st.expander(f"{r['matched_threat_id']} — risk {rec_risk(r)} ({risk_band(rec_risk(r))})"):
                    for line in fb:
                        (st.success if line.startswith("✓") else st.error)(line)
                    why = r["predefined_threat"].get("why_this_risk")
                    if why:
                        st.markdown(f"""<div style="background:#FFF8E1;border-left:4px solid #F9A825;border-radius:6px;padding:10px 14px">
                        <strong style="color:#E65100;font-size:0.85em">⚖️ WHY THIS RISK LEVEL</strong><br>
                        <span style="font-size:0.88em;color:#444">{why}</span></div>""", unsafe_allow_html=True)
        tabs = st.tabs(["🔥 Risk heat map", "🏗️ Clean architecture"])
        with tabs[0]:
            show_architecture_diagram(cfg, mode="scoring", key_suffix="s7_heat")
        with tabs[1]:
            show_architecture_diagram(cfg, mode="architecture", key_suffix="s7_arch")

    nav_buttons(6, "⬅️ Back to Identify Threats", 8, "Next: Map STRIDE to controls ➡️",
                bool(recs) and all(r.get("rated") for r in recs), "Rate every threat (press “Score all threats”) first.", key="p7")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 9 — SELECT CONTROLS
# ═══════════════════════════════════════════════════════════════════════════════
def sync_labels_from_analysis(include_controls=False):
    ws = st.session_state.selected_workshop
    items = get_annotations(ws)
    seen = {i.get("origin") for i in items}
    added = 0
    for r in st.session_state.user_answers:
        origin = f"threat:{r['matched_threat_id']}"
        if origin in seen:
            tid = next(i["id"] for i in items if i.get("origin") == origin)
        else:
            tid = _next_annotation_id(items, "threat")
            items.append({"id": tid, "kind": "threat", "label": _trunc(f"{r['stride']}: {r['predefined_threat'].get('threat', '')}", 80),
                          "target": r["component"], "links": [], "notes": "", "origin": origin})
            seen.add(origin); added += 1
        if include_controls and r.get("controlled"):
            for m in r.get("selected_mitigations", []):
                o2 = f"ctrl:{r['matched_threat_id']}:{m}"
                if o2 not in seen:
                    items.append({"id": _next_annotation_id(items, "control"), "kind": "control", "label": _trunc(m, 80),
                                  "target": r["component"], "links": [tid], "notes": "", "origin": o2})
                    seen.add(o2); added += 1
    return added


def render_controls_page():
    cfg = current_workshop
    recs = st.session_state.user_answers
    st.header("Step 5: Pick Controls for the Risks that Matter")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🛡️ Stage 5 · Controls</strong><br>
    For each high-risk threat choose practical controls, and be able to say <em>why</em> each one is there and which threat it addresses.
    Controls fall into four categories — aim for <strong>defence in depth</strong>: at least one preventive control
    (guardrails, filtering or access rules) <em>and</em> monitoring to detect what prevention misses.
    </div>""", unsafe_allow_html=True)
    cols = st.columns(4)
    for col, (cat, (ic, desc)) in zip(cols, CONTROL_CATEGORIES.items()):
        col.markdown(f"**{ic} {cat}**")
        col.caption(desc)

    rated = [r for r in recs if r.get("rated")]
    if not rated:
        st.warning("Score your threats first (Step 4).")
        nav_buttons(8, "⬅️ Back to OWASP mapping", None, "", key="p9e")
        return
    ordered = sorted(rated, key=lambda r: -rec_risk(r))

    with st.form("controls_form"):
        st.subheader("➕ Select controls (highest risk first)")
        chosen = {}
        for rec in ordered:
            pred = rec["predefined_threat"]
            band = risk_band(rec_risk(rec))
            fill, stroke = BAND_COLORS[band]
            st.markdown(f"""<div style="background:{fill};border-left:5px solid {stroke};border-radius:8px;padding:8px 14px;margin-top:6px">
            <strong>{pred['id']} · {rec['stride']} on {_esc(rec['component'])}</strong> — risk <strong>{rec_risk(rec)}</strong> ({band})<br>
            <span style="font-size:0.88em;color:#444">{pred['threat']}</span></div>""", unsafe_allow_html=True)
            owasp = OWASP_STRIDE_MAP.get(pred["stride"], {})
            if owasp:
                st.caption(f"OWASP: {', '.join(owasp['owasp'])} — {owasp.get('owasp_detail', '')}")
            correct, wrong = pred["correct_mitigations"], pred.get("incorrect_mitigations", [])
            options = correct + wrong
            seed = int(hashlib.md5(pred["id"].encode()).hexdigest(), 16) % 10000
            random.Random(seed).shuffle(options)
            st.markdown(f"*{len(correct)} correct controls, {len(wrong)} distractors — choose wisely*")
            chosen[pred["id"]] = st.multiselect(
                "Controls (select all that apply)", options, key=f"w_ctl_{pred['id']}",
                default=[m for m in rec.get("selected_mitigations", []) if m in options])
            st.markdown("---")
        if st.form_submit_button("🛡️ Submit controls", type="primary", use_container_width=True):
            for rec in ordered:
                rec["selected_mitigations"] = list(chosen[rec["matched_threat_id"]])
                rec["controlled"] = True
                rescore_record(rec)
            recalc_totals()
            save_progress()
            st.rerun()

    done = [r for r in ordered if r.get("controlled")]
    if done:
        st.subheader("🧭 Defence-in-depth check")
        for rec in done:
            pred = rec["predefined_threat"]
            cats = control_coverage(rec["selected_mitigations"])
            prevent = any(c in cats for c in ("Guardrails", "Filtering", "Access rules"))
            detect = "Monitoring" in cats
            band = risk_band(rec_risk(rec))
            if band == "High" and (not prevent or not detect):
                miss = "a preventive control" if not prevent else "monitoring to detect failures"
                badge = f"⚠️ High-risk threat is missing {miss}"
            elif not rec["selected_mitigations"]:
                badge = "⚠️ No controls selected"
            else:
                badge = "✅ Layered coverage" if prevent and detect else "ℹ️ Preventive only — consider monitoring" if prevent else "ℹ️ Detective only — consider a preventive control"
            with st.expander(f"{pred['id']} — {badge}"):
                st.markdown(_control_chips(rec["selected_mitigations"]), unsafe_allow_html=True)
                for line in rec.get("fb_controls", []):
                    (st.success if line.startswith("✓") else st.error if line.startswith("✗") else st.warning)(line)
                for m in rec["selected_mitigations"]:
                    st.markdown(f"- {CONTROL_CATEGORIES[control_category(m)][0]} **{control_category(m)}** — {m}")
                why = pred.get("why_these_controls")
                if why:
                    st.markdown(f"""<div style="background:#E8F5E9;border-left:4px solid #43A047;border-radius:6px;padding:10px 14px">
                    <strong style="color:#1B5E20;font-size:0.85em">🛡️ WHY THESE CONTROLS</strong><br>
                    <span style="font-size:0.88em;color:#444">{why}</span></div>""", unsafe_allow_html=True)

        st.subheader("🗺️ Controls on the architecture")
        if st.button("🏷️ Add my threats and controls to the diagram labels", key="w_sync_labels"):
            n = sync_labels_from_analysis(include_controls=True)
            save_progress()
            st.success(f"Added {n} label(s).") if n else st.info("Labels are already up to date.")
            st.rerun()
        show_architecture_diagram(cfg, mode="controls", key_suffix="s9_ctl", editable=True, default_kind="control")

    nav_buttons(8, "⬅️ Back to OWASP mapping", 10, "Next: Residual risk ➡️",
                bool(rated) and all(r.get("controlled") for r in rated), "Submit controls for every threat first.", key="p9")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 10 — RESIDUAL RISK
# ═══════════════════════════════════════════════════════════════════════════════
DECISIONS = ["Accept", "Reduce further", "Transfer (insurance / vendor)", "Avoid (remove the feature)"]
_CONTAINMENT = ["encrypt", "segment", "isolation", "backup", "quota", "least privilege", "row-level", "rls", "redact", "mask"]


def suggested_residual(rec):
    pred = rec["predefined_threat"]
    good = [m for m in rec.get("selected_mitigations", []) if m in set(pred["correct_mitigations"])]
    cats = {control_category(m) for m in good}
    lik, imp = rec["likelihood_n"], rec["impact_n"]
    if cats & {"Guardrails", "Filtering", "Access rules"}:
        lik = max(1, lik - (2 if len(good) >= 3 else 1))
    if any(any(k in m.lower() for k in _CONTAINMENT) for m in good):
        imp = max(1, imp - 1)
    return lik, imp


def render_residual_page():
    cfg = current_workshop
    recs = [r for r in st.session_state.user_answers if r.get("controlled")]
    oq = get_open_questions()
    st.header("Step 6: Residual Risk & Open Questions")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>⚖️ Stage 6 · Residual risk</strong><br>
    Controls reduce risk; they rarely remove it. For every threat, re-score <strong>what remains after your controls</strong>,
    decide what to do about it, and write down what you do <strong>not</strong> know. Documenting residual risk sets realistic
    expectations, guides incident response and gives future team members context.
    </div>""", unsafe_allow_html=True)
    if not recs:
        st.warning("Select controls first (Step 5).")
        nav_buttons(9, "⬅️ Back to Controls", None, "", key="p10e")
        return

    st.caption("Controls usually lower **likelihood**. Impact only drops with containment (segmentation, encryption, quotas, backups). "
               "The suggestion below is based on the *correct* controls you selected.")
    errors = []
    with st.form("residual_form"):
        vals = {}
        for rec in sorted(recs, key=lambda r: -rec_risk(r)):
            pred = rec["predefined_threat"]
            sl, si = suggested_residual(rec)
            cur = rec.get("residual") or {}
            st.markdown(f"**{pred['id']} · {rec['stride']} on {rec['component']}** — inherent risk **{rec_risk(rec)}** "
                        f"({rec['likelihood']} × {rec['impact']})")
            st.caption(f"Suggested residual: likelihood {LEVELS[sl-1]}, impact {LEVELS[si-1]} → {sl*si}")
            a, b, c = st.columns([1, 1, 1])
            rl = a.select_slider("Residual likelihood", LEVELS, key=f"w_rl_{pred['id']}", value=LEVELS[cur.get("likelihood_n", sl) - 1])
            ri = b.select_slider("Residual impact", LEVELS, key=f"w_ri_{pred['id']}", value=LEVELS[cur.get("impact_n", si) - 1])
            dec = c.selectbox("Decision", DECISIONS, key=f"w_dec_{pred['id']}",
                              index=DECISIONS.index(cur["decision"]) if cur.get("decision") in DECISIONS else 0)
            why = st.text_input("Rationale (why is this acceptable / what else is needed?)", value=cur.get("rationale", ""),
                                key=f"w_why_{pred['id']}", max_chars=200)
            vals[pred["id"]] = (rl, ri, dec, why)
            st.markdown("---")
        if st.form_submit_button("⚖️ Save residual risk", type="primary", use_container_width=True):
            for rec in recs:
                rl, ri, dec, why = vals[rec["matched_threat_id"]]
                rl_n, ri_n = level_n(rl), level_n(ri)
                pid = rec["matched_threat_id"]
                if rl_n > rec["likelihood_n"] or ri_n > rec["impact_n"]:
                    errors.append(f"{pid}: residual risk cannot be higher than inherent risk — your controls should not make things worse.")
                if rl_n * ri_n >= 6 and dec == DECISIONS[0] and len(why.strip()) < 10:
                    errors.append(f"{pid}: accepting a HIGH residual risk (≥ 6) needs a written rationale and a named owner.")
            if not errors:
                for rec in recs:
                    rl, ri, dec, why = vals[rec["matched_threat_id"]]
                    rec["residual"] = {"likelihood_n": level_n(rl), "impact_n": level_n(ri), "decision": dec, "rationale": why.strip()}
                save_progress()
                st.rerun()
    for e in errors:
        st.error(e)

    saved = [r for r in recs if r.get("residual")]
    if saved:
        st.subheader("📉 Inherent vs residual risk")
        st.dataframe(pd.DataFrame([{
            "Threat": r["matched_threat_id"], "Component / flow": r["component"],
            "Inherent": rec_risk(r), "Residual": rec_residual(r),
            "Reduction": rec_risk(r) - rec_residual(r), "Residual band": risk_band(rec_residual(r)),
            "Decision": r["residual"]["decision"], "Rationale": r["residual"]["rationale"]}
            for r in sorted(saved, key=lambda r: -rec_residual(r))]), use_container_width=True, hide_index=True)
        mc1, mc2 = st.columns(2)
        with mc1:
            st.markdown("**Before controls**")
            st.markdown(risk_matrix_html([(r["likelihood_n"], r["impact_n"], r["matched_threat_id"]) for r in saved]), unsafe_allow_html=True)
        with mc2:
            st.markdown("**After controls**")
            st.markdown(risk_matrix_html([(r["residual"]["likelihood_n"], r["residual"]["impact_n"], r["matched_threat_id"]) for r in saved]), unsafe_allow_html=True)
        tabs = st.tabs(["⚖️ Residual heat map", "🔥 Inherent heat map"])
        with tabs[0]:
            show_architecture_diagram(cfg, mode="residual", key_suffix="s10_res")
        with tabs[1]:
            show_architecture_diagram(cfg, mode="scoring", key_suffix="s10_inh")

    st.markdown("---")
    st.subheader("❓ Open questions and accepted risk")
    st.caption("List what you do not know and cannot fully control — dependencies, vendors, slow-moving threats, unverified assumptions.")
    third = [c["name"] for c in cfg["scenario"]["components"] if c["type"] == "external_entity" and _lane_of(c) == "Third-Party"]
    st.button("💡 Insert example questions", key="w_oq_examples", on_click=_apply_oq_examples, args=(cfg,))
    qs = st.text_area("Open questions (one per line)", value="\n".join(oq["questions"]), key=f"w_oq_{st.session_state.selected_workshop}", height=130,
                      placeholder=f"e.g. What happens if {third[0] if third else 'a third-party provider'} is compromised?")
    acc = st.text_area("Accepted-risk statement", value=oq["accepted"], key=f"w_acc_{st.session_state.selected_workshop}", height=90,
                       placeholder="e.g. We accept that a determined attacker may slow a single endpoint, but we alert within 4 hours and can fail over.")
    newq, newa = _lines(qs), acc.strip()
    if newq != oq["questions"] or newa != oq["accepted"]:
        oq["questions"], oq["accepted"] = newq, newa
        save_progress()

    ready = bool(recs) and all(r.get("residual") for r in recs) and len(oq["questions"]) >= 1
    nav_buttons(9, "⬅️ Back to Controls", 11, "Next: Plan the review ➡️", ready,
                "Save residual risk for every threat and list at least one open question.", key="p10")


def _apply_oq_examples(cfg):
    ws = st.session_state.selected_workshop
    oq = get_open_questions(ws)
    third = [c["name"] for c in cfg["scenario"]["components"] if c["type"] == "external_entity" and _lane_of(c) == "Third-Party"]
    ex = [f"What happens if {t} is compromised or changes its behaviour?" for t in third[:2]]
    ex += ["How quickly would we notice a slow, low-volume attack?", "Which assumptions from Step 1 are still unverified?",
           "How often do our dependencies change, and could an update introduce a vulnerability?"]
    if not oq["questions"]:
        oq["questions"] = ex
        st.session_state[f"w_oq_{ws}"] = "\n".join(ex)


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 11 — REVIEW PLAN
# ═══════════════════════════════════════════════════════════════════════════════
FULL_TRIGGERS = ["New system or a high-risk launch", "Major architecture change",
                 "A feature gives a component new access to sensitive data or privileged actions",
                 "A new trust boundary is introduced", "Move to a new hosting platform or cloud region"]
LIGHT_CHECKS = ["What changed since the last review?", "Which trust boundaries moved?",
                "Were new endpoints, data stores, integrations or outputs introduced?",
                "Do existing controls still cover the risk?", "Are the Step 1 assumptions still true?"]
UPDATE_TRIGGERS = ["A dependency or platform has a major version change", "A component gains new permissions",
                   "A data source or third-party integration is added or changed", "A security incident occurs",
                   "A new attack technique becomes relevant", "Regulation or compliance requirements change",
                   "An assumption is found to be violated"]


def stage_status():
    ws = st.session_state.selected_workshop
    cfg = WORKSHOPS[ws]
    sc, plan, oq = get_scope(ws), get_review_plan(ws), get_open_questions(ws)
    recs = st.session_state.user_answers
    n, tgt = len(recs), cfg["target_threats"]
    rated = sum(1 for r in recs if r.get("rated"))
    ctl = sum(1 for r in recs if r.get("controlled"))
    res = sum(1 for r in recs if r.get("residual"))
    plan_ok = bool(plan["owner"].strip() and plan["full"] and plan["light"] and plan["triggers"])
    return [
        ("scope", "Scope", "📐", scope_complete(sc),
         f"Scope statement, {len(sc['must_never'])} must-never rules, {len(sc['assumptions'])} assumptions, {len(sc['exclusions']) + len(sc['oos_components'])} exclusions"),
        ("dfd", "DFD", "🗺️", bool(st.session_state.get("zone_labelling_done")),
         f"{len(cfg['scenario']['components'])} components, {len(cfg['scenario']['data_flows'])} flows, zones of trust applied"),
        ("stride", "STRIDE", "⚡", n >= tgt, f"{n}/{tgt} threats identified with STRIDE zone rules"),
        ("scoring", "Scoring", "📊", n > 0 and rated == n, f"{rated}/{n} threats scored (impact × likelihood, 1–9)"),
        ("controls", "Controls", "🛡️", n > 0 and ctl == n, f"{ctl}/{n} threats have controls mapped"),
        ("residual", "Residual risk", "⚖️", n > 0 and res == n and len(oq["questions"]) >= 1,
         f"{res}/{n} residual risks recorded, {len(oq['questions'])} open questions"),
        ("review", "Review", "🔁", plan_ok, "Owner, review cadence and update triggers defined"),
    ]


def render_review_plan_page():
    ws = st.session_state.selected_workshop
    plan = get_review_plan(ws)
    st.header("Step 7: Schedule Reviews & Update Triggers")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🔁 Stage 7 · Review</strong><br>
    A threat model is a <strong>living document</strong>, not a compliance artefact. Systems evolve too quickly for an annual ceremony,
    so use three levels of review. <strong>Ownership stays with product and engineering</strong> — security provides expertise and
    challenge, but the people building and running the system must keep the model useful. If it becomes paperwork theatre, teams route around it.
    </div>""", unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    owner = c1.text_input("Owner (product / engineering)", value=plan["owner"], key=f"w_owner_{ws}", max_chars=80,
                          placeholder="e.g. Checkout team tech lead")
    sec = c2.text_input("Security's role", value=plan["security_role"], key=f"w_secrole_{ws}", max_chars=80)
    try:
        default_date = _date.fromisoformat(plan["next_review"]) if plan["next_review"] else _date.today() + _timedelta(days=30)
    except ValueError:
        default_date = _date.today() + _timedelta(days=30)
    nxt = st.date_input("Next lightweight review", value=default_date, key=f"w_nextrev_{ws}")

    st.markdown("### 1️⃣ Full workshop — when?")
    st.caption("A full workshop is for a new system, a high-risk launch, a major architecture change, or new access to sensitive data or tools.")
    full = st.multiselect("Triggers for a full workshop", FULL_TRIGGERS, default=[x for x in plan["full"] if x in FULL_TRIGGERS], key=f"w_full_{ws}")
    st.markdown("### 2️⃣ Lightweight review — what do you check? (≈30 minutes, for ordinary feature work)")
    light = st.multiselect("Lightweight review checklist", LIGHT_CHECKS, default=[x for x in plan["light"] if x in LIGHT_CHECKS], key=f"w_light_{ws}")
    st.markdown("### 3️⃣ Trigger-based update — what forces an update?")
    trig = st.multiselect("Update triggers", UPDATE_TRIGGERS, default=[x for x in plan["triggers"] if x in UPDATE_TRIGGERS], key=f"w_trig_{ws}")
    notes = st.text_input("How will you keep this from becoming paperwork?", value=plan["notes"], key=f"w_pnotes_{ws}", max_chars=200,
                          placeholder="e.g. Review is part of the sprint-planning checklist")

    new = {"owner": owner.strip(), "security_role": sec.strip(), "next_review": nxt.isoformat() if hasattr(nxt, "isoformat") else "",
           "full": list(full), "light": list(light), "triggers": list(trig), "notes": notes.strip()}
    if any(plan[k] != v for k, v in new.items()):
        plan.update(new)
        save_progress()

    st.markdown("---")
    st.subheader("✅ Threat-model readiness")
    status = stage_status()
    for sid, label, icon, done, detail in status:
        st.markdown(f"{'✅' if done else '⚠️'} {icon} **{label}** — {detail}")
    st.progress(sum(1 for s in status if s[3]) / len(status))

    nav_buttons(10, "⬅️ Back to Residual risk", 12, "Next: Assessment & report ➡️", status[-1][3],
                "Set an owner and choose at least one full-workshop trigger, one lightweight check and one update trigger.", key="p11")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 12 — STAGE-BY-STAGE REVIEW (replaces the old 4-step review)
# ═══════════════════════════════════════════════════════════════════════════════
def render_stage_review():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    sc, oq, plan = get_scope(ws), get_open_questions(ws), get_review_plan(ws)
    recs = st.session_state.user_answers
    tabs = st.tabs([f"{ic} {lbl}" for _, lbl, ic in STAGES])

    with tabs[0]:
        st.markdown(f"**System in scope:** {sc['statement'] or '—'}")
        a, b = st.columns(2)
        a.markdown("**Must do**\n" + ("\n".join(f"- {x}" for x in sc["must_do"]) or "—"))
        b.markdown("**Must never**\n" + ("\n".join(f"- {x}" for x in sc["must_never"]) or "—"))
        if sc["assumptions"]:
            st.markdown("**Assumptions**"); st.dataframe(pd.DataFrame(sc["assumptions"]), hide_index=True, use_container_width=True)
        if sc["exclusions"] or sc["oos_components"]:
            st.markdown("**Exclusions**")
            if sc["exclusions"]:
                st.dataframe(pd.DataFrame(sc["exclusions"]), hide_index=True, use_container_width=True)
            if sc["oos_components"]:
                st.markdown("Out-of-scope components: " + ", ".join(sc["oos_components"]))
        if sc["goals"]:
            st.markdown("**Goals**\n" + "\n".join(f"- {x}" for x in sc["goals"]))
    with tabs[1]:
        st.dataframe(pd.DataFrame([{"Component": c["name"], "Type": c["type"].replace("_", " ").title(), "Lane": _lane_of(c),
                                    "Zone": c.get("zone", "N/A"), "Score (0-9)": c.get("zone_score", "?")}
                                   for c in s["components"]]), use_container_width=True, hide_index=True)
    with tabs[2]:
        for a in recs:
            pred = a.get("predefined_threat", {})
            pts = a.get("pts_identify", 0)
            css = "correct-answer" if pts == 4 else "partial-answer" if pts >= 2 else "incorrect-answer"
            st.markdown(f"""<div class="{css}"><strong>{a['matched_threat_id']}</strong>: {pred.get('threat', '')}<br>
            Your answer: {a['stride']} on {_esc(a['component'])} · Zone rule: {pred.get('stride_rule_applied', 'N/A')}</div>""", unsafe_allow_html=True)
    with tabs[3]:
        rated = [r for r in recs if r.get("rated")]
        if rated:
            st.markdown(risk_matrix_html([(r["likelihood_n"], r["impact_n"], r["matched_threat_id"]) for r in rated]), unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "Likelihood": r["likelihood"], "Impact": r["impact"],
                                        "Risk": rec_risk(r), "Band": risk_band(rec_risk(r))}
                                       for r in sorted(rated, key=lambda r: -rec_risk(r))]), hide_index=True, use_container_width=True)
        else:
            st.info("No threats were scored.")
    with tabs[4]:
        for a in recs:
            if not a.get("controlled"):
                continue
            correct = set(a["predefined_threat"]["correct_mitigations"])
            st.markdown(f"**{a['matched_threat_id']}** — {_control_chips(a['selected_mitigations'])}", unsafe_allow_html=True)
            for m in a["selected_mitigations"]:
                st.markdown(f"- {'✅' if m in correct else '❌'} {control_category(m)}: {m}")
        for stride_cat, owasp_info in OWASP_STRIDE_MAP.items():
            used = any(a["stride"] == stride_cat for a in recs)
            st.markdown(f"""<div class="owasp-box">{'✅' if used else '⭕'} <strong>{stride_cat}</strong> → {', '.join(owasp_info['owasp'])}<br>
            Key controls: {'; '.join(owasp_info['controls'][:2])}</div>""", unsafe_allow_html=True)
    with tabs[5]:
        res = [r for r in recs if r.get("residual")]
        if res:
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "Inherent": rec_risk(r), "Residual": rec_residual(r),
                                        "Decision": r["residual"]["decision"], "Rationale": r["residual"]["rationale"]} for r in res]),
                         hide_index=True, use_container_width=True)
        if oq["questions"]:
            st.markdown("**Open questions**\n" + "\n".join(f"- {q}" for q in oq["questions"]))
        if oq["accepted"]:
            st.markdown(f"**Accepted-risk statement:** {oq['accepted']}")
    with tabs[6]:
        st.markdown(f"**Owner:** {plan['owner'] or '—'}  ·  **Security's role:** {plan['security_role'] or '—'}  ·  **Next lightweight review:** {plan['next_review'] or '—'}")
        for title, key in (("Full-workshop triggers", "full"), ("Lightweight review checks", "light"), ("Update triggers", "triggers")):
            if plan[key]:
                st.markdown(f"**{title}**\n" + "\n".join(f"- {x}" for x in plan[key]))
        if plan["notes"]:
            st.markdown(f"**Keeping it alive:** {plan['notes']}")


def render_stage_summary():
    for sid, label, icon, done, detail in stage_status():
        bg = "linear-gradient(135deg,#E8F5E9,#F1F8E9)" if done else "#F5F5F5"
        clr = "#2E7D32" if done else "#9E9E9E"
        st.markdown(f"""
        <div style="background:{bg};border-left:4px solid {clr};border-radius:8px;padding:12px 16px;margin:6px 0;display:flex;align-items:center;gap:12px">
          <span style="font-size:1.3em">{'✅' if done else '⭕'}</span>
          <div><strong style="color:{clr}">{icon} {label}</strong><br><span style="font-size:0.85em;color:#555">{_esc(detail)}</span></div>
        </div>""", unsafe_allow_html=True)


def build_pdf_extra():
    ws = st.session_state.selected_workshop
    return {"scope": get_scope(ws), "open_questions": get_open_questions(ws), "review_plan": get_review_plan(ws),
            "labels": list(get_annotations(ws))}



# ═══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:10px 0 8px 0">
      <div style="font-size:2em">🔒</div>
      <div style="font-weight:700;font-size:1.05em;margin:4px 0">Threat Modeling Lab</div>
      <div style="font-size:0.78em;opacity:0.7">Scope → DFD → STRIDE → Scoring → Controls → Residual → Review</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("**🗺️ The 7 Stages**")
    st.markdown("""
    1. 📐 **Scope** – goals, assumptions, exclusions
    2. 🗺️ **DFD** – elements, flows, zones of trust
    3. ⚡ **STRIDE** – rule-based discovery
    4. 📊 **Scoring** – impact × likelihood
    5. 🛡️ **Controls** – OWASP-mapped
    6. ⚖️ **Residual risk** – what remains
    7. 🔁 **Review** – owners and triggers
    """)
    st.markdown("---")

    if st.session_state.selected_workshop:
        ws_name = WORKSHOPS.get(st.session_state.selected_workshop,{}).get("name","")
        step_names = {p: v[0] for p, v in PAGES.items()}
        cur_step_name = step_names.get(st.session_state.current_step,"")
        ws_level = WORKSHOPS.get(st.session_state.selected_workshop,{}).get("level","")
        st.markdown(f"""
        <div style="background:rgba(79,195,247,0.12);border:1px solid rgba(79,195,247,0.3);
                    border-radius:8px;padding:10px 12px;margin:6px 0">
          <div style="font-size:0.7em;text-transform:uppercase;letter-spacing:1.5px;color:#4FC3F7;margin-bottom:4px">NOW STUDYING</div>
          <div style="font-weight:700;font-size:0.92em;color:#E8F4FD">{ws_name}</div>
          <div style="font-size:0.78em;color:#90CAF9;margin-top:2px">{ws_level} · {cur_step_name}</div>
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
    for ws_id, ws_config in WORKSHOPS.items():
        unlocked = is_workshop_unlocked(ws_id)
        completed = ws_id in st.session_state.completed_workshops
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"Workshop {ws_id}", key=f"ws_{ws_id}",
                         disabled=not unlocked, use_container_width=True):
                start_workshop(ws_id)
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
                        if verify_unlock_code(ws_id, code):
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
    home_tabs = st.tabs(["🗺️ Learning Path", "🧠 What You'll Master", "📋 The 7-Stage Process", "🏆 Skill Tree"])

    with home_tabs[0]:
        st.markdown("### Your Journey from Novice to Expert")
        st.markdown("""
        <div class="info-box">
        This lab uses the <strong>Infosec Institute 4-Step Methodology</strong> — the same framework used
        by Microsoft, OWASP, and enterprise security teams. Each workshop adds a new layer of complexity,
        building on what you've learned before.<br><br>
        Every workshop follows the same <strong>7 stages</strong>: Scope → DFD → STRIDE → Scoring → Controls → Residual risk → Review.
        </div>
        """, unsafe_allow_html=True)

        ws_data = list(WORKSHOPS.items())
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
        st.markdown("### The 7 stages you follow in every workshop")
        st.markdown("""
| Stage | What you produce | Where the Infosec 4-step method fits |
|---|---|---|
| 1. 📐 **Scope** | System in scope, must-do / must-never rules, assumptions, exclusions, measurable goals | — (added up front) |
| 2. 🗺️ **DFD** | Data-flow diagram, trust boundaries, zones of trust (0–9) | Step 1 *Design* + Step 2 *Zones of Trust* |
| 3. ⚡ **STRIDE** | Specific threats derived with the zone-direction rules (plus an attack tree) | Step 3 *Discover threats* |
| 4. 📊 **Scoring** | Impact × likelihood on a 1–3 scale → risk score 1–9, prioritised register | — (added) |
| 5. 🛡️ **Controls** | Guardrails, filtering, access rules and monitoring, mapped to OWASP | Step 4 *Mitigations* |
| 6. ⚖️ **Residual risk** | Risk after controls, accept / reduce / transfer / avoid, open questions | — (added) |
| 7. 🔁 **Review** | Owner, review cadence, full-workshop and update triggers | — (added) |
""")
        st.markdown("### The Infosec 4-step method in detail")
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

    ws1_config = WORKSHOPS["1"]
    if st.button("▶ Start Workshop 1: TechMart E-Commerce →", type="primary", use_container_width=True):
        st.session_state.selected_workshop = "1"
        st.session_state.current_step = 1
        save_progress()
        st.rerun()
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
#  WORKSHOP SELECTED – STEP NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════════
current_workshop = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

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

# ── Stage tracker: Scope → DFD → STRIDE → Scoring → Controls → Residual risk → Review ──
_page = int(st.session_state.current_step)
_page_name, _stage_id = PAGES.get(_page, ("", "scope"))
_stage_idx = STAGE_IDS.index(_stage_id)
_parts = []
for _i, (_sid, _label, _icon) in enumerate(STAGES):
    if _i < _stage_idx:
        _bg, _fg, _ring, _content, _lc = "#1B5E20", "white", "#43A047", "✓", "#1B5E20"
    elif _i == _stage_idx:
        _bg, _fg, _ring, _content, _lc = "#0D1B2A", "white", "#4FC3F7", _icon, "#0D1B2A"
    else:
        _bg, _fg, _ring, _content, _lc = "#ECEFF1", "#78909C", "#B0BEC5", str(_i + 1), "#78909C"
    _parts.append(
        '<div style="display:flex;flex-direction:column;align-items:center;gap:3px;min-width:64px">'
        f'<div style="width:30px;height:30px;border-radius:50%;background:{_bg};color:{_fg};border:2px solid {_ring};'
        f'display:flex;align-items:center;justify-content:center;font-family:Sora,Arial;font-weight:700;font-size:12px">{_content}</div>'
        f'<div style="font-family:DM Sans,Arial;font-size:10px;color:{_lc};font-weight:{700 if _i == _stage_idx else 500};text-align:center">{_label}</div></div>')
_conn = '<div style="flex:1;height:2px;background:#E0E7EF;margin-top:15px;min-width:8px"></div>'
st.markdown(f'<div style="display:flex;align-items:flex-start;padding:10px 0 4px 0;overflow-x:auto">{_conn.join(_parts)}</div>',
            unsafe_allow_html=True)
st.caption(f"Stage {_stage_idx + 1} of {len(STAGES)} · **{STAGES[_stage_idx][1]}** — {_page_name}")
st.progress(min(max(_page, 1), 13) / 13)
st.markdown("---")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1 · STAGE 1 SCOPE (NEW)
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.current_step == 1:
    render_scope_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2 · STAGE 2 DFD — DRAW THE DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 2:
    st.header("Step 2: Draw the Data-Flow Diagram (DFD)")
    scope_reminder()

    st.markdown("""
    <div class="methodology-step">
    <strong>🗺️ Stage 2 · DFD (Infosec Step 1: Design)</strong><br>
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
        show_architecture_diagram(current_workshop, mode="architecture", key_suffix="s1_arch", editable=True, default_kind="actor")
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

    nav_buttons(1, "⬅️ Back to Scope", 3, "Next: Apply Zones of Trust ➡️", key="p2")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3 · STAGE 2 DFD — ZONES OF TRUST
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 3:
    st.header("Step 2 (cont.): Apply Zones of Trust")
    scope_reminder()

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
        The zone boundaries (the dotted lane dividers and Z-chips) are where data crosses trust levels —
        these are the highest-risk areas for your threat analysis in Step 3.
        </div>
        """, unsafe_allow_html=True)

        show_architecture_diagram(current_workshop, mode="zones", key_suffix="s2_zones")

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

    nav_buttons(2, "⬅️ Back to Design", 4, "Next: STRIDE Rules ➡️", key="p3")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 4 · STAGE 3 STRIDE — ZONE RULES
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 4:
    st.header("Step 3: STRIDE — Zone Rules & Threat Discovery")
    scope_reminder()

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

    st.markdown("""
    <div class="practical-task">
    <strong>✅ STRIDE rules understood</strong><br>
    You can now derive STRIDE threats mechanically from the zone relationships on your DFD.
    Next: build an <strong>attack tree</strong> to see <em>how</em> an attacker would reach the threat, then identify your own threats.
    </div>
    """, unsafe_allow_html=True)
    nav_buttons(3, "⬅️ Back to Zones", 5, "Next: Build Attack Tree ➡️", key="p4")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 5 · STAGE 3 STRIDE — ATTACK TREE
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 5:
    st.header("🌳 Step 3 (cont.): Attack Tree")
    scope_reminder()

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

    nav_buttons(4, "⬅️ Back to STRIDE Rules", 6, "Ready: Identify Threats ➡️", key="p5")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 6 · STAGE 3 STRIDE — IDENTIFY THREATS
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 6:
    st.header("Step 3 (cont.): Identify Threats with STRIDE")
    scope_reminder()

    st.markdown(f"""
    <div class="info-box">
    <strong>⚡ Stage 3 · STRIDE — apply the zone rules to your DFD</strong><br>
    For each threat: (1) pick the <strong>component or flow</strong> affected, (2) apply the zone-direction rule to choose the
    <strong>STRIDE category</strong>. Be specific — “attacker alters the order total in the API call”, not just “tampering”.<br>
    Scoring (Stage 4) and controls (Stage 5) come next, using the threats you identify here.<br><br>
    <strong>Goal:</strong> identify {current_workshop['target_threats']} threats
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
        show_architecture_diagram(current_workshop, threats=st.session_state.threats, mode="threat", key_suffix="step4_live", editable=True, default_kind="threat")
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
        st.subheader("➕ Identify a Threat Scenario")

        available_threats = remaining_threats if remaining_threats else workshop_threats
        threat_options = {f"{t_['id']}: {t_['threat'][:65]}...": t_ for t_ in available_threats}
        if not threat_options:
            st.error("No threats available for this workshop")
            st.stop()

        selected_threat_key = st.selectbox(
            "Choose a threat scenario to analyze:", list(threat_options.keys()),
            help="Each threat can only be identified once. Select from the remaining threats.")
        selected_predefined = threat_options[selected_threat_key]

        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>Zone context for this threat:</strong><br>
        From zone: <strong>{selected_predefined.get('zone_from', 'N/A')}</strong> →
        To zone: <strong>{selected_predefined.get('zone_to', 'N/A')}</strong>
        </div>
        """, unsafe_allow_html=True)

        zf, zt = selected_predefined.get("zone_from", ""), selected_predefined.get("zone_to", "")
        comps_ = current_workshop["scenario"]["components"]
        if zf and zt:
            fs = next((c.get("zone_score", 3) for c in comps_ if c["name"] == zf.replace(" Zone", "")),
                      CRITICALITY_ZONES.get(zf, {}).get("score", 3))
            ts = next((c.get("zone_score", 3) for c in comps_ if c["name"] == zt.replace(" Zone", "")),
                      CRITICALITY_ZONES.get(zt, {}).get("score", 3))
            if fs < ts:
                direction_hint = "⬆ Flow goes **less → more** critical zone → primary risk: **Tampering**"
            elif fs > ts:
                direction_hint = "⬇ Flow goes **more → less** critical zone → primary risk: **Information Disclosure**"
            else:
                direction_hint = "↔ Flow within the **same zone** → check node-level rules (Spoofing, EoP)"
            if fs == 0:
                direction_hint += " | Zone-0 source → also watch for **Denial of Service** and **Spoofing**"
        else:
            direction_hint = "Review the zone labels to determine the applicable STRIDE rule."
        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>🧭 Zone-Direction Guidance:</strong> {direction_hint}<br>
        <em>Use this rule to select the most appropriate STRIDE category below.</em>
        </div>
        """, unsafe_allow_html=True)

        all_options = [c["name"] for c in comps_] + [f"{f['source']} → {f['destination']}" for f in current_workshop["scenario"]["data_flows"]]
        c_a, c_b = st.columns(2)
        user_component = c_a.selectbox("Which component/flow is affected?", ["— select —"] + all_options, index=0)
        user_stride = c_b.selectbox(
            "STRIDE category — apply the zone-direction rule:",
            ["— select —", "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
            index=0)

        if st.form_submit_button("✅ Record threat & get STRIDE feedback", type="primary", use_container_width=True):
            errs = []
            if user_component == "— select —":
                errs.append("Select a component or data flow")
            if user_stride == "— select —":
                errs.append("Select a STRIDE category")
            if errs:
                st.error("⚠️ Please complete all selections: " + " · ".join(errs))
            else:
                st.session_state.user_answers.append(new_record(user_component, user_stride, selected_predefined))
                recalc_totals()
                save_progress()
                st.rerun()

    render_identified_threats()

    if st.session_state.user_answers and st.button("🏷️ Add my identified threats to the diagram labels", key="w_sync_threats"):
        n_added = sync_labels_from_analysis(include_controls=False)
        save_progress()
        st.rerun()

    st.progress(min(len(st.session_state.user_answers) / current_workshop['target_threats'], 1.0))
    if len(st.session_state.user_answers) < current_workshop['target_threats']:
        st.info(f"⚠️ {current_workshop['target_threats'] - len(st.session_state.user_answers)} more threats needed to complete this workshop.")
    else:
        st.success("✅ All required threats identified — continue to scoring.")

    nav_buttons(5, "⬅️ Back to Attack Tree", 7, "Next: Score the risk ➡️", bool(st.session_state.user_answers),
                "Identify at least one threat first.", key="p6")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 7 · STAGE 4 SCORING (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 7:
    render_scoring_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 8 · STAGE 5 CONTROLS — OWASP MAPPING
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 8:
    st.header("Step 5 (start): Map STRIDE Threats to Controls")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🛡️ Stage 5 · Controls</strong><br>
    Before you pick controls for your own threats, learn how each STRIDE category maps to OWASP Top 10 risks and to the
    four control categories: <strong>🧱 Guardrails</strong>, <strong>🧪 Filtering</strong>, <strong>🔑 Access rules</strong>
    and <strong>📡 Monitoring</strong>.
    </div>
    """, unsafe_allow_html=True)

    # OWASP MAPPING SECTION
    st.markdown("---")
    st.subheader("🛡️ STRIDE → OWASP Top 10 Mapping")

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

    nav_buttons(7, "⬅️ Back to Scoring", 9, "Next: Select controls ➡️", key="p8")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 9 · STAGE 5 CONTROLS — SELECT CONTROLS (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 9:
    render_controls_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 10 · STAGE 6 RESIDUAL RISK (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 10:
    render_residual_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 11 · STAGE 7 REVIEW PLAN (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 11:
    render_review_plan_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 12 · STAGE 7 REVIEW — ASSESSMENT & REPORT
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 12:
    st.header("Step 7 (cont.): Assessment & Threat-Mapped Architecture Review")
    recalc_totals()
    scope_reminder()

    if not st.session_state.user_answers:
        st.warning("No answers to assess")
        if st.button("⬅️ Back"):
            go_page(6)
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
        "🏷️ Zone-Labelled DFD"
    ])
    with assess_diag_tabs[0]:
        show_architecture_diagram(current_workshop,
                                  threats=st.session_state.threats,
                                  mode="threat", key_suffix="s5_threat", editable=True)
    with assess_diag_tabs[1]:
        show_architecture_diagram(current_workshop,
                                  threats=st.session_state.threats,
                                  mode="stride", key_suffix="s5_stride")
    with assess_diag_tabs[2]:
        show_architecture_diagram(current_workshop,
                                  mode="architecture", key_suffix="s5_arch")
    with assess_diag_tabs[3]:
        show_architecture_diagram(current_workshop, threats=st.session_state.threats,
                                  mode="zones", key_suffix="s6_zones")

    st.markdown("---")
    st.subheader("📋 7-Stage Threat Model Review")
    render_stage_review()

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
        "Risk_1to9": rec_risk(a) or "",
        "Residual_1to9": rec_residual(a) or "",
        "Decision": (a.get("residual") or {}).get("decision", ""),
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
                    st.session_state.total_score, st.session_state.max_score, extra=build_pdf_extra()
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

    nav_buttons(11, "⬅️ Back to Review plan", 13, "Complete Workshop ➡️", key="p12")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 13 · STAGE 7 REVIEW — COMPLETE
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 13:
    recalc_totals()
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

    # ── 7-stage mastery review ──────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📋 7-Stage Threat Modeling Summary")
    render_stage_summary()

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
                start_workshop(next_ws)
                save_progress()
                st.rerun()
    else:
        st.success("🏆 **All Workshops Completed! Full 7-Stage Process Mastered!**")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review Assessment", use_container_width=True):
            go_page(12)
    with col2:
        if st.button("🏠 Return to Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            save_progress()
            st.rerun()

st.markdown("---")
st.caption("STRIDE Threat Modeling Learning Lab | Scope → DFD → STRIDE → Scoring → Controls → Residual risk → Review")
