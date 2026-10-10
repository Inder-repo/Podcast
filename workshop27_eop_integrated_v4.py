"""
STRIDE Threat Modeling - COMPLETE PRODUCTION VERSION (ENHANCED)
All 4 Workshops | Hidden Unlock Codes | Full Decompose | Threat Mapping | Enhanced Assessment
Nine-step flow: Scope → DFD → STRIDE → Trust boundaries → ATT&CK/CAPEC/threat statements → Scoring → Controls → Residual risk → Review.
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
    layout="wide",
    initial_sidebar_state="expanded"
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
/* ═══ Design system: warm neutrals + one teal accent ═══════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root{
  color-scheme: light;
  --bg:#F7F6F3; --surface:#FFFFFF; --surface-2:#FBFAF8; --sunken:#EFEDE8;
  --line:#E6E3DC; --line-2:#D5D1C8;
  --ink:#1E2522; --ink-2:#48524D; --muted:#7D857F;
  --accent:#1F6F66; --accent-hover:#185A53; --accent-ink:#0E3D38; --accent-soft:#E3EFEC; --accent-line:#B9D6D0;
  --ok:#3F7D5A;   --ok-soft:#EAF2EC;   --ok-line:#CFE3D6;
  --warn:#A8741A; --warn-soft:#F8F0DE; --warn-line:#EBDBB5;
  --bad:#B0413A;  --bad-soft:#F8E8E5;  --bad-line:#EBCBC6;
  --info:#3F6F8F; --info-soft:#E9EFF3; --info-line:#CBDCE6;
  --learn:#6A5A94; --learn-soft:#EFECF5; --learn-line:#D8D1E8;
  --dark:#232B28;
  --r:12px; --r-lg:16px;
  --shadow:0 1px 2px rgba(30,37,34,.04), 0 4px 14px rgba(30,37,34,.05);
  --shadow-hover:0 2px 4px rgba(30,37,34,.06), 0 8px 24px rgba(30,37,34,.08);
}

/* ── Base ─────────────────────────────────────────────────────────────────────────── */
html, body, [class*="css"], .stApp, button, input, textarea, select {
  font-family:'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
}
html body .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] { background:var(--bg); color:var(--ink); }
header[data-testid="stHeader"] { background:transparent; }
footer { visibility:hidden; }
.block-container { max-width:1240px; padding-top:2.2rem; padding-bottom:4rem; }
p, li { line-height:1.62; }
a { color:var(--accent); text-underline-offset:3px; }
code, pre, kbd, .mono { font-family:'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace !important; font-size:0.88em; }
::selection { background:var(--accent-soft); }

h1,h2,h3,h4,h5,h6 { font-family:'Inter', system-ui, sans-serif !important; color:var(--ink) !important; letter-spacing:-0.022em; }
h1 { font-size:2rem !important; font-weight:700 !important; line-height:1.15; }
h2 { font-size:1.5rem !important; font-weight:650 !important; padding-bottom:0; border:none; }
h3 { font-size:1.18rem !important; font-weight:650 !important; }
h4 { font-size:1.02rem !important; font-weight:650 !important; }
[data-testid="stCaptionContainer"], .stCaption { color:var(--muted) !important; }
hr { border:none; border-top:1px solid var(--line); margin:1.4rem 0; }

/* ── Buttons ──────────────────────────────────────────────────────────────────────── */
.stButton>button, .stDownloadButton>button, [data-testid="stFormSubmitButton"]>button {
  width:100%; border-radius:10px; font-weight:600; font-size:0.9rem; padding:0.55rem 1rem;
  background:var(--surface); color:var(--ink); border:1px solid var(--line-2);
  box-shadow:0 1px 0 rgba(30,37,34,.03); transition:background .15s, border-color .15s, box-shadow .15s;
}
.stButton>button:hover, .stDownloadButton>button:hover, [data-testid="stFormSubmitButton"]>button:hover {
  background:var(--surface-2); border-color:var(--ink-2); box-shadow:var(--shadow);
}
.stButton>button[kind="primary"], [data-testid="stBaseButton-primary"], [data-testid="stFormSubmitButton"]>button[kind="primaryFormSubmit"] {
  background:var(--accent) !important; color:#fff !important; border:1px solid var(--accent) !important;
}
.stButton>button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover, [data-testid="stFormSubmitButton"]>button[kind="primaryFormSubmit"]:hover {
  background:var(--accent-hover) !important; border-color:var(--accent-hover) !important;
}
.stButton>button:disabled { opacity:.5; cursor:not-allowed; }
button:focus-visible, a:focus-visible, [role="tab"]:focus-visible { outline:3px solid var(--accent-soft); outline-offset:1px; box-shadow:0 0 0 1px var(--accent); }

/* ── Inputs ───────────────────────────────────────────────────────────────────────── */
[data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div { border-radius:10px !important; background:var(--surface) !important; border-color:var(--line-2) !important; }
[data-baseweb="input"]:focus-within, [data-baseweb="textarea"]:focus-within, [data-baseweb="select"] > div:focus-within { border-color:var(--accent) !important; box-shadow:0 0 0 3px var(--accent-soft) !important; }
[data-baseweb="tag"] { background:var(--accent-soft) !important; color:var(--accent-ink) !important; border-radius:8px !important; }
[data-baseweb="slider"] [role="slider"] { background:var(--accent) !important; border-color:var(--accent) !important; }
[data-testid="stWidgetLabel"] p { color:var(--ink-2); font-weight:500; }

/* ── Containers ───────────────────────────────────────────────────────────────────── */
[data-testid="stForm"] { background:var(--surface); border:1px solid var(--line); border-radius:var(--r-lg); padding:1.1rem 1.3rem; }
[data-testid="stExpander"] { background:var(--surface); border:1px solid var(--line) !important; border-radius:var(--r) !important; }
details { border-radius:var(--r) !important; border:1px solid var(--line) !important; background:var(--surface); }
details summary { font-weight:600; }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:var(--r); overflow:hidden; }
[data-testid="stAlert"] { border-radius:var(--r); border:1px solid var(--line); }
[data-testid="stMetric"] { background:var(--surface); border:1px solid var(--line); border-radius:var(--r); padding:12px 16px; }
.dataframe { border-radius:8px; overflow:hidden; }
.stProgress > div > div, [data-testid="stProgress"] div[role="progressbar"] > div { background:var(--accent) !important; border-radius:999px; }
.stProgress > div, [data-testid="stProgress"] div[role="progressbar"] { background:var(--sunken) !important; border-radius:999px; }

/* ── Tabs ─────────────────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] { gap:2px; border-bottom:1px solid var(--line); }
.stTabs [data-baseweb="tab"] { font-weight:500; font-size:0.9rem; padding:10px 14px; color:var(--ink-2); background:transparent; border-radius:8px 8px 0 0; }
.stTabs [data-baseweb="tab"]:hover { color:var(--ink); background:var(--sunken); }
.stTabs [aria-selected="true"] { color:var(--accent) !important; font-weight:650 !important; }
.stTabs [data-baseweb="tab-highlight"] { background:var(--accent) !important; height:2px; }
.stTabs [data-baseweb="tab-border"] { background:transparent !important; }

/* ── Cards ────────────────────────────────────────────────────────────────────────── */
.premium-card { background:var(--surface); border-radius:var(--r-lg); padding:20px 22px; margin:10px 0; border:1px solid var(--line); box-shadow:var(--shadow); transition:box-shadow .2s; }
.premium-card:hover { box-shadow:var(--shadow-hover); }
.concept-card { border-radius:var(--r); padding:16px 18px; margin:8px 0; border-left:4px solid; border-top:1px solid var(--line); border-right:1px solid var(--line); border-bottom:1px solid var(--line); background:var(--surface); }
.component-card { background:var(--surface); padding:14px 16px; border-radius:var(--r); border:1px solid var(--line); border-left:4px solid var(--accent); margin:6px 0; }
.zone-card { border-radius:var(--r); padding:14px 16px; margin:6px 0; border:1px solid var(--line); border-left:4px solid; }
.methodology-step { background:var(--surface); padding:18px 22px; border-radius:var(--r-lg); border:1px solid var(--line); margin:12px 0; box-shadow:var(--shadow); line-height:1.62; }
.methodology-step:hover { box-shadow:var(--shadow-hover); }
.metric-card { background:var(--surface); border-radius:var(--r); padding:16px; text-align:center; border:1px solid var(--line); box-shadow:var(--shadow); }
.metric-card .value { font-size:2rem; font-weight:700; color:var(--accent); letter-spacing:-0.02em; }
.metric-card .label { font-size:0.82rem; color:var(--muted); margin-top:4px; }
.diagram-container { overflow-x:auto; border:1px solid var(--line); border-radius:var(--r); padding:12px; background:var(--surface); box-shadow:var(--shadow); }
.flow-arrow { background:var(--accent-soft); color:var(--accent-ink); padding:6px 16px; border-radius:999px; display:inline-block; margin:4px; font-weight:500; font-size:0.88rem; }

/* ── Callouts (flat tint + accent bar) ────────────────────────────────────────────── */
.info-box, .success-box, .warning-box, .learning-box, .callout-box, .stride-rule-box, .owasp-box, .knowledge-check, .mitigation-card {
  padding:16px 20px; border-radius:var(--r); margin:12px 0; border:1px solid var(--line); border-left-width:4px; color:var(--ink); line-height:1.62;
}
.info-box { background:var(--info-soft); border-color:var(--info-line); border-left-color:var(--info); }
.success-box { background:var(--ok-soft); border-color:var(--ok-line); border-left-color:var(--ok); }
.warning-box { background:var(--warn-soft); border-color:var(--warn-line); border-left-color:var(--warn); }
.learning-box { background:var(--learn-soft); border-color:var(--learn-line); border-left-color:var(--learn); }
.callout-box { background:var(--warn-soft); border-color:var(--warn-line); border-left-color:var(--warn); }
.stride-rule-box { background:var(--learn-soft); border-color:var(--learn-line); border-left-color:var(--learn); }
.owasp-box { background:var(--accent-soft); border-color:var(--accent-line); border-left-color:var(--accent); }
.knowledge-check { background:var(--learn-soft); border-color:var(--learn-line); border-left-color:var(--learn); }
.knowledge-check h4 { color:var(--learn); margin-top:0; }
.mitigation-card { background:var(--warn-soft); border-color:var(--warn-line); border-left-color:var(--warn); padding:14px 16px; }
.practical-task { background:var(--surface); padding:18px 22px; border-radius:var(--r); border:1.5px dashed var(--accent-line); margin:12px 0; line-height:1.62; }
.expert-box { background:var(--dark); color:#ECEAE4; padding:18px 22px; border-radius:var(--r); border-left:4px solid #6FB3A8; margin:12px 0; line-height:1.62; }
.expert-box *, .real-world-box *, .key-concept *, .mastery-badge * { color:inherit; }
.key-concept { background:var(--accent); color:#fff; padding:16px 20px; border-radius:var(--r); margin:10px 0; box-shadow:var(--shadow); }
.key-concept h4 { color:#CDE7E2 !important; margin:0 0 6px 0; font-size:0.78rem !important; text-transform:uppercase; letter-spacing:1.2px; }
.real-world-box { background:var(--dark); color:#ECEAE4; padding:16px 20px; border-radius:var(--r); border-left:4px solid #8F86B8; margin:10px 0; }
.real-world-box strong { color:#CBC5E6; }

/* ── Threat severity + answers + scores ───────────────────────────────────────────── */
.threat-critical { background:var(--bad); color:#fff; padding:14px 16px; border-radius:var(--r); margin:8px 0; }
.threat-high { background:var(--bad-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--bad-line); border-left:4px solid var(--bad); margin:8px 0; }
.threat-medium { background:var(--warn-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--warn-line); border-left:4px solid var(--warn); margin:8px 0; }
.threat-low { background:var(--ok-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--ok-line); border-left:4px solid var(--ok); margin:8px 0; }
.correct-answer { background:var(--ok-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--ok-line); border-left:4px solid var(--ok); margin:8px 0; }
.incorrect-answer { background:var(--bad-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--bad-line); border-left:4px solid var(--bad); margin:8px 0; }
.partial-answer { background:var(--warn-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--warn-line); border-left:4px solid var(--warn); margin:8px 0; }
.score-excellent, .score-good, .score-fair, .score-poor { color:#fff; padding:22px; border-radius:var(--r-lg); text-align:center; font-size:1.25rem; font-weight:650; letter-spacing:-0.01em; box-shadow:var(--shadow); }
.score-excellent { background:var(--ok); }
.score-good { background:#5E8A47; }
.score-fair { background:var(--warn); }
.score-poor { background:var(--bad); }
.mastery-badge { background:var(--dark); color:#F1E7C8; padding:14px 22px; border-radius:var(--r-lg); text-align:center; font-weight:650; font-size:1.05rem; margin:10px 0; border:1px solid #3A4541; }

/* ── Badges + chips ───────────────────────────────────────────────────────────────── */
.badge-completed, .badge-locked, .badge-available { padding:3px 12px; border-radius:999px; font-size:.78rem; font-weight:600; display:inline-block; }
.badge-completed { background:var(--ok-soft); color:var(--ok); border:1px solid var(--ok-line); }
.badge-locked { background:var(--sunken); color:var(--muted); border:1px solid var(--line); }
.badge-available { background:var(--accent-soft); color:var(--accent); border:1px solid var(--accent-line); }
.step-active { background:var(--accent); color:#fff; padding:8px 12px; border-radius:10px; font-weight:650; font-size:.82rem; text-align:center; }
.step-done { background:var(--ok-soft); color:var(--ok); padding:8px 12px; border-radius:10px; font-weight:600; font-size:.82rem; text-align:center; border:1px solid var(--ok-line); }
.step-todo { background:var(--sunken); color:var(--muted); padding:8px 12px; border-radius:10px; font-size:.82rem; text-align:center; border:1px solid var(--line); }

/* ── Hero (home) ──────────────────────────────────────────────────────────────────── */
.hero { background:var(--surface); border:1px solid var(--line); border-radius:20px; padding:38px 40px; margin-bottom:26px; box-shadow:var(--shadow); position:relative; overflow:hidden; }
.hero:before { content:""; position:absolute; right:-70px; top:-70px; width:260px; height:260px; border-radius:50%; background:var(--accent-soft); opacity:.9; }
.hero:after { content:""; position:absolute; right:60px; bottom:-90px; width:160px; height:160px; border-radius:50%; background:var(--sunken); opacity:.9; }
.hero > * { position:relative; z-index:1; }
.hero .eyebrow { display:inline-block; font-size:.74rem; font-weight:650; letter-spacing:1.4px; text-transform:uppercase; color:var(--accent); background:var(--accent-soft); border:1px solid var(--accent-line); padding:4px 12px; border-radius:999px; margin-bottom:14px; }
.hero h1 { margin:0 0 10px 0 !important; font-size:2.35rem !important; max-width:760px; }
.hero p { color:var(--ink-2); font-size:1.08rem; margin:0 0 20px 0; max-width:700px; }
.chips { display:flex; gap:8px; flex-wrap:wrap; }
.chip { background:var(--surface-2); color:var(--ink-2); border:1px solid var(--line); padding:6px 14px; border-radius:999px; font-size:.82rem; font-weight:500; }

/* ── Stage tracker ────────────────────────────────────────────────────────────────── */
.stepper { display:flex; align-items:flex-start; padding:6px 2px 2px; overflow-x:auto; }
.stg { display:flex; flex-direction:column; align-items:center; gap:6px; min-width:78px; }
.stg-dot { width:30px; height:30px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:600; font-size:12px; border:1.5px solid var(--line-2); background:var(--surface); color:var(--muted); }
.stg-label { font-size:11px; color:var(--muted); text-align:center; font-weight:500; line-height:1.25; }
.stg-done .stg-dot { background:var(--accent-soft); border-color:var(--accent-line); color:var(--accent); }
.stg-done .stg-label { color:var(--ink-2); }
.stg-active .stg-dot { background:var(--accent); border-color:var(--accent); color:#fff; box-shadow:0 0 0 4px var(--accent-soft); }
.stg-active .stg-label { color:var(--ink); font-weight:650; }
.stg-line { flex:1; height:2px; background:var(--line); margin-top:15px; min-width:10px; }

/* ── Sidebar ──────────────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] { background:var(--sunken); border-right:1px solid var(--line); }
[data-testid="stSidebar"] .stButton>button { background:var(--surface); color:var(--ink); border:1px solid var(--line-2); margin:2px 0; }
[data-testid="stSidebar"] .stButton>button:hover { border-color:var(--accent); color:var(--accent-ink); }
[data-testid="stSidebar"] hr { border-color:var(--line); }
[data-testid="stSidebar"] h3 { font-size:0.8rem !important; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted) !important; font-weight:650 !important; margin-top:.4rem; }
.brand { padding:6px 2px 10px 2px; }
.brand .logo { display:inline-flex; align-items:center; justify-content:center; width:38px; height:38px; border-radius:11px; background:var(--accent); color:#fff; font-size:1.15rem; margin-bottom:10px; }
.brand .name { font-weight:700; font-size:1.05rem; letter-spacing:-0.02em; color:var(--ink); }
.brand .tag { font-size:.74rem; color:var(--muted); margin-top:3px; line-height:1.45; }
.now-card { background:var(--surface); border:1px solid var(--line); border-left:4px solid var(--accent); border-radius:var(--r); padding:10px 14px; margin:8px 0; }
.now-eyebrow { font-size:.66rem; text-transform:uppercase; letter-spacing:1.4px; color:var(--accent); font-weight:650; margin-bottom:3px; }
.now-title { font-weight:650; font-size:.92rem; color:var(--ink); }
.now-meta { font-size:.78rem; color:var(--muted); margin-top:2px; }
.score-line { margin:6px 0 2px 0; font-size:.82rem; color:var(--ink-2); }
.score-line strong { color:var(--ink); }

/* ── Motion + scrollbars ──────────────────────────────────────────────────────────── */
@media (prefers-reduced-motion: reduce) { * { transition:none !important; animation:none !important; } }
::-webkit-scrollbar { height:8px; width:8px; }
::-webkit-scrollbar-thumb { background:var(--line-2); border-radius:8px; }
::-webkit-scrollbar-track { background:transparent; }
@media (max-width: 760px) { .hero { padding:26px 22px; } .hero h1 { font-size:1.7rem !important; } .block-container { padding-left:1rem; padding-right:1rem; } }
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
        'stride_map': {},           # {workshop_id: {element key: [STRIDE letters]}}
        'boundary_checked': {},     # {workshop_id: True once the trust-boundary exercise was submitted}
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
        'eop_card_logs': {},
        'eop_active_cards': {},
        # Each workshop retains its own threat register and downstream assessments.
        'workshop_workspaces': {},
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


WORKSHOP_STATE_FIELDS = (
    "threats", "user_answers", "total_score", "max_score", "zone_labels",
    "zone_scores", "zone_labelling_done", "stride_rules_answers",
    "stride_rules_submitted", "owasp_mapping_answers", "owasp_mapping_submitted",
)


def _snapshot_active_workshop():
    """Save the active workshop's complete working set before switching scenarios."""
    ws = st.session_state.get("selected_workshop")
    if not ws or ws not in WORKSHOPS:
        return
    workspaces = st.session_state.setdefault("workshop_workspaces", {})
    workspaces[str(ws)] = {field: st.session_state.get(field) for field in WORKSHOP_STATE_FIELDS}
    # These collections are workshop-scoped already; copy them into the snapshot too
    # so a scenario can be restored as a coherent unit after switching/reloading.
    for field in ("annotations", "scope_models", "open_questions", "review_plans", "stride_map", "boundary_checked"):
        workspaces[str(ws)][field] = st.session_state.get(field, {}).get(str(ws), st.session_state.get(field, {}).get(ws))
    workspaces[str(ws)]["eop_cards"] = st.session_state.get(f"eop_cards_{ws}", [])
    workspaces[str(ws)]["eop_active_card"] = st.session_state.get(f"eop_active_card_{ws}")


def _restore_workshop_workspace(ws_id):
    """Restore one scenario's own register and workflow state; never mix scenarios."""
    snap = st.session_state.get("workshop_workspaces", {}).get(str(ws_id))
    if not snap:
        # New scenario: initialise clean state without borrowing another scenario's data.
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
        for field, default in (("annotations", []), ("scope_models", {}), ("open_questions", {}), ("review_plans", {}), ("stride_map", {}), ("boundary_checked", False)):
            st.session_state.setdefault(field, {})[str(ws_id)] = default
        st.session_state[f"eop_cards_{ws_id}"] = []
        st.session_state[f"eop_active_card_{ws_id}"] = None
        return
    for field in WORKSHOP_STATE_FIELDS:
        if field in snap and snap[field] is not None:
            st.session_state[field] = snap[field]
    for field in ("annotations", "scope_models", "open_questions", "review_plans", "stride_map", "boundary_checked"):
        if snap.get(field) is not None:
            st.session_state.setdefault(field, {})[str(ws_id)] = snap[field]
    st.session_state[f"eop_cards_{ws_id}"] = snap.get("eop_cards", st.session_state.get(f"eop_cards_{ws_id}", []))
    st.session_state[f"eop_active_card_{ws_id}"] = snap.get("eop_active_card", st.session_state.get(f"eop_active_card_{ws_id}"))


def start_workshop(ws_id):
    """Switch to a distinct scenario workspace, resuming it when previously started."""
    if ws_id not in WORKSHOPS:
        return
    previous = st.session_state.get("selected_workshop")
    if previous in WORKSHOPS:
        _snapshot_active_workshop()
    st.session_state.selected_workshop = ws_id
    st.session_state.current_step = 1
    _restore_workshop_workspace(ws_id)
    # Clear only transient widget keys. Scenario data and EoP links remain intact.
    for k in [k for k in list(st.session_state.keys()) if str(k).startswith(("w_", "_seed_", "ed_"))]:
        del st.session_state[k]
    recalc_totals()


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
        "color": "#F6F5F4",
        "border": "#7F786B",
        "description": "External actors (users, third-party services) – no trust assumed",
        "examples": "End users, external APIs, third-party payment providers",
        "stride_applicability": "Source of Spoofing, DoS, and Repudiation threats"
    },
    "Minimal Trust": {
        "range": "1–2",
        "score": 1,
        "color": "#EFEFEE",
        "border": "#418544",
        "description": "Entry points with basic authentication – low criticality",
        "examples": "Web frontend, mobile app, CDN edge",
        "stride_applicability": "Tampering and Information Disclosure via unvalidated input/output"
    },
    "Standard Application": {
        "range": "3–4",
        "score": 3,
        "color": "#F9F4CA",
        "border": "#E4A33A",
        "description": "Application-layer services with authentication enforced",
        "examples": "API backend, microservices, application servers",
        "stride_applicability": "All STRIDE categories – most complex threat surface"
    },
    "Elevated Trust": {
        "range": "5–6",
        "score": 5,
        "color": "#F7DEBA",
        "border": "#CF5817",
        "description": "Services with privileged access or sensitive business logic",
        "examples": "Payment services, auth services, admin APIs",
        "stride_applicability": "Elevation of Privilege, Tampering, and Information Disclosure are highest risk"
    },
    "Critical": {
        "range": "7–8",
        "score": 7,
        "color": "#FAD2D6",
        "border": "#C33F3F",
        "description": "Data stores and systems containing sensitive/regulated data",
        "examples": "Databases, data warehouses, encryption key stores",
        "stride_applicability": "Information Disclosure and Tampering are existential risks"
    },
    "Maximum Security": {
        "range": "9",
        "score": 9,
        "color": "#A82B2B",
        "border": "#6F0C0C",
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
    "Not in Control of System": "#F6F5F4",
    "Minimal Trust": "#CAE4CB",
    "Standard Application": "#FBF5C8",
    "Elevated Trust": "#F9DFB8",
    "Critical": "#FBD1D5",
    "Maximum Security": "#C73B3B"
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
        "Not in Control of System": "#EFEEED",
        "Minimal Trust":            "#CAE4CB",
        "Standard Application":     "#FBF5C8",
        "Elevated Trust":           "#F9DFB8",
        "Critical":                 "#FBD1D5",
        "Maximum Security":         "#F7AF99",
    }.get(zone_name, "#F1F0EF")


def _zone_stroke(zone_name):
    return {
        "Not in Control of System": "#A6A196",
        "Minimal Trust":            "#3E8842",
        "Standard Application":     "#E9A435",
        "Elevated Trust":           "#D55611",
        "Critical":                 "#BA3434",
        "Maximum Security":         "#B23D19",
    }.get(zone_name, "#35A091")


def _xml(s):
    """Escape string for SVG text content."""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

# ── Zone visual config ─────────────────────────────────────────────────────
_ZONE_STYLE = {
    "Not in Control of System": {"fill":"#EFEFEE","stroke":"#948D80","dark":"#48453E","band":"#D8D6D3"},
    "Minimal Trust":            {"fill":"#EFEFEE","stroke":"#418544","dark":"#225726","band":"#CBE3CC"},
    "Standard Application":     {"fill":"#FDFBE9","stroke":"#E4A33A","dark":"#CF5817","band":"#F9F4CA"},
    "Elevated Trust":           {"fill":"#FCF2E3","stroke":"#D2552E","dark":"#AD401E","band":"#F8D0C3"},
    "Critical":                 {"fill":"#FDEDEF","stroke":"#B63838","dark":"#A82B2B","band":"#FAD2D6"},
    "Maximum Security":         {"fill":"#F7EAEB","stroke":"#7C1A4E","dark":"#44142A","band":"#F2C1D9"},
}
_ZONE_ORDER = [
    "Not in Control of System",
    "Minimal Trust",
    "Standard Application",
    "Elevated Trust",
    "Critical",
    "Maximum Security",
]
STRIDE_LETTERS = ["S", "T", "R", "I", "D", "E"]
STRIDE_NAMES = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information Disclosure",
                "D": "Denial of Service", "E": "Elevation of Privilege"}
STRIDE_LETTER_OF = {v: k for k, v in STRIDE_NAMES.items()}
_STRIDE_TAG_COLOR = {"S": "#762C95", "T": "#CF5817", "R": "#0C6D62", "I": "#2666AF", "D": "#B1295F", "E": "#5B574E"}
_STRIDE_TAG_TIP = STRIDE_NAMES
# STRIDE-per-element: which categories can apply to which kind of DFD element
STRIDE_PER_ELEMENT = {"external_entity": "SR", "process": "STRIDE", "datastore": "TRID", "flow": "TID"}
STRIDE_ELEMENT_NOTE = {
    "external_entity": "External entities can be spoofed (S) and can deny their actions (R); you do not control their internals.",
    "process": "Processes are exposed to all six categories.",
    "datastore": "Data stores: tampering (T), information disclosure (I) and DoS (D); repudiation (R) only when the store holds logs/audit data.",
    "flow": "Data flows: tampering (T), information disclosure (I) and DoS (D). Spoofing and EoP belong to the endpoints, not the line.",
}

# ── Nested trust-boundary trees (one per lab). Strings are component names. ─────────────────
BOUNDARY_TREES = {
    "1": {"children": [
        {"name": "Internet", "trust": "untrusted", "kind": "internet", "children": ["Customer"]},
        {"name": "User's Browser", "trust": "minimal trust", "children": ["Web Frontend"]},
        {"name": "TechMart Cloud (AWS)", "trust": "our infrastructure", "kind": "cloud", "dir": "col", "children": [
            {"name": "Application Tier", "children": ["API Backend"]},
            {"name": "Data Tier", "children": ["Database"]}]},
        {"name": "Third-Party Services", "trust": "vendor-controlled", "kind": "third_party", "dir": "col",
         "children": ["Stripe", "SendGrid"]}]},
    "2": {"children": [
        {"name": "Mobile Device", "trust": "untrusted device", "kind": "internet", "children": [
            {"name": "App Sandbox", "children": ["Mobile App"]}]},
        {"name": "CloudBank Cloud (AWS)", "trust": "our infrastructure", "kind": "cloud", "dir": "row", "children": [
            {"name": "Edge", "children": ["API Gateway"]},
            {"name": "Service Mesh (ECS)", "dir": "col", "children": ["User Service", "Payment Service"]},
            {"name": "Data Layer", "dir": "col", "children": ["User DB", "Transaction DB"]}]}]},
    "3": {"children": [
        {"name": "Tenant Users (Internet)", "trust": "untrusted", "kind": "internet", "children": ["Web Dashboard"]},
        {"name": "SaaS Platform (AWS)", "trust": "shared infrastructure", "kind": "cloud", "dir": "row", "children": [
            {"name": "Edge", "children": ["API Gateway"]},
            {"name": "Tenant-Aware Services", "dir": "col", "children": ["Ingestion Service", "Query Service"]},
            {"name": "Shared Data Plane", "dir": "col", "children": ["Kafka", "Data Warehouse"]}]}]},
    "4": {"children": [
        {"name": "Patient Home", "trust": "physical access", "kind": "internet", "dir": "col",
         "children": ["Glucose Monitor", "IoT Gateway"]},
        {"name": "HealthMonitor Cloud", "trust": "our infrastructure", "kind": "cloud", "dir": "row", "children": [
            {"name": "Cloud Processing", "children": ["Device Data Svc"]},
            {"name": "Safety-Critical Zone", "trust": "life-critical", "dir": "col", "children": ["Alert Service", "Patient DB"]}]},
        {"name": "Hospital / Clinic", "trust": "partner network", "kind": "third_party", "dir": "col",
         "children": ["Web Portal", "Legacy EHR"]}]},
}

_FONT = "'Inter','Segoe UI',Helvetica,Arial,sans-serif"
_MONO = "'JetBrains Mono',Consolas,'Courier New',monospace"
LEAF_W, PADG, TITLE_H, PADB = 156, 16, 52, 34
GAP_ROW_IN, GAP_COL_IN, GAP_TOP, MARG_X = 84, 72, 112, 34
_TOP = 34

ANNOTATION_KINDS = {
    "actor":   {"prefix": "TA", "title": "Threat Actor",         "icon": "🎭", "fill": "#D34A47", "stroke": "#A82B2B", "text": "#121110"},
    "asset":   {"prefix": "A",  "title": "Asset",                "icon": "💎", "fill": "#6EB272", "stroke": "#367539", "text": "#121110"},
    "threat":  {"prefix": "TS", "title": "Threat Scenario",      "icon": "⚡", "fill": "#E4BB55", "stroke": "#A77F1C", "text": "#121110"},
    "control": {"prefix": "C",  "title": "Control / Mitigation", "icon": "🛡️", "fill": "#E0A138", "stroke": "#A06712", "text": "#121110"},
}
_KIND_ORDER = ["actor", "asset", "threat", "control"]


def _trunc(s, n):
    s = str(s or "")
    return s if len(s) <= n else s[: max(1, n - 1)] + "…"


def _flow_key(flow):
    return f"{flow['source']} → {flow['destination']}"


def _ann_sort(item):
    try:
        num = int(re.sub(r"\D", "", item["id"]) or 0)
    except ValueError:
        num = 0
    return (_KIND_ORDER.index(item["kind"]) if item["kind"] in _KIND_ORDER else 9, num)


def _ws_id_of(cfg):
    t = cfg["scenario"]["title"]
    return next((k for k, v in WORKSHOPS.items() if v["scenario"]["title"] == t), None)


def _tree_for(cfg):
    ws = _ws_id_of(cfg)
    if ws in BOUNDARY_TREES:
        return BOUNDARY_TREES[ws]
    zones = {}
    for c in cfg["scenario"]["components"]:
        zones.setdefault(c.get("zone", "Zone"), []).append(c["name"])
    return {"children": [{"name": z, "children": names} for z, names in zones.items()]}


def element_ids(scn):
    pre = {"external_entity": "E", "process": "P", "datastore": "D"}
    ctr, ids = {}, {}
    for c in scn["components"]:
        ctr[c["type"]] = ctr.get(c["type"], 0) + 1
        ids[c["name"]] = f"{pre.get(c['type'], 'X')}{ctr[c['type']]}"
    for i, f in enumerate(scn["data_flows"], 1):
        ids[_flow_key(f)] = f"F{i}"
    return ids


def element_kind(scn, key):
    if "→" in key:
        return "flow"
    return next((c["type"] for c in scn["components"] if c["name"] == key), "process")


def _leaf_h(ctype):
    return 66 if ctype == "datastore" else 58


def _measure(node, cmap):
    if isinstance(node, str):
        return {"leaf": True, "name": node, "w": LEAF_W, "h": _leaf_h(cmap[node]["type"])}
    kids = [_measure(k, cmap) for k in node["children"]]
    d = node.get("dir", "col")
    if d == "row":
        cw = sum(k["w"] for k in kids) + GAP_ROW_IN * (len(kids) - 1)
        ch = max(k["h"] for k in kids)
    else:
        cw = max(k["w"] for k in kids)
        ch = sum(k["h"] for k in kids) + GAP_COL_IN * (len(kids) - 1)
    title_w = len(node["name"]) * 6.9 + (len(node.get("trust", "")) * 5.6 + 26 if node.get("trust") else 0) + 2 * PADG
    cw = max(cw, title_w - 2 * PADG)
    return {"leaf": False, "node": node, "kids": kids, "dir": d, "cw": cw, "ch": ch, "w": cw + 2 * PADG, "h": ch + TITLE_H + PADB}


def _place(m, x, y, path, leaves, groups):
    if m["leaf"]:
        leaves[m["name"]] = {"x": x, "y": y, "w": m["w"], "h": m["h"], "cx": x + m["w"] / 2, "cy": y + m["h"] / 2, "path": list(path)}
        return
    nd = m["node"]
    groups.append({"name": nd["name"], "trust": nd.get("trust", ""), "kind": nd.get("kind", ""), "x": x, "y": y,
                   "w": m["w"], "h": m["h"], "depth": len(path), "path": list(path) + [nd["name"]]})
    inner_x, inner_y = x + PADG, y + TITLE_H
    sub = list(path) + [nd["name"]]
    if m["dir"] == "row":
        total = sum(k["w"] for k in m["kids"]) + GAP_ROW_IN * (len(m["kids"]) - 1)
        cx_ = inner_x + (m["cw"] - total) / 2
        for k in m["kids"]:
            _place(k, cx_, inner_y + (m["ch"] - k["h"]) / 2, sub, leaves, groups)
            cx_ += k["w"] + GAP_ROW_IN
    else:
        cy_ = inner_y
        for k in m["kids"]:
            _place(k, inner_x + (m["cw"] - k["w"]) / 2, cy_, sub, leaves, groups)
            cy_ += k["h"] + GAP_COL_IN


def layout_tree(cfg):
    """Return {'leaves': {name: rect}, 'groups': [rect...], 'W', 'H'} with y starting at 0."""
    cmap = {c["name"]: c for c in cfg["scenario"]["components"]}
    tree = _tree_for(cfg)
    kids = [_measure(k, cmap) for k in tree["children"]]
    total = sum(k["w"] for k in kids) + GAP_TOP * (len(kids) - 1)
    maxh = max(k["h"] for k in kids)
    leaves, groups = {}, []
    x = MARG_X
    for k in kids:
        _place(k, x, (maxh - k["h"]) / 2, [], leaves, groups)
        x += k["w"] + GAP_TOP
    return {"leaves": leaves, "groups": groups, "W": total + 2 * MARG_X, "H": maxh}


def component_boundaries(cfg):
    lay = layout_tree(cfg)
    return {n: r["path"] for n, r in lay["leaves"].items()}


def third_party_components(cfg):
    lay = layout_tree(cfg)
    kinds = {g["name"]: g["kind"] for g in lay["groups"]}
    return {n for n, r in lay["leaves"].items() if any(kinds.get(p) == "third_party" for p in r["path"])}


def _is_third_party(cfg, comp):
    return comp["name"] in third_party_components(cfg)


def flow_crossings(cfg):
    """{flow_key: [boundary names crossed]} — a boundary is crossed when exactly one endpoint is inside it."""
    paths = component_boundaries(cfg)
    out = {}
    for f in cfg["scenario"]["data_flows"]:
        a, b = set(paths.get(f["source"], [])), set(paths.get(f["destination"], []))
        out[_flow_key(f)] = sorted(a ^ b, key=lambda n: (-len(n), n))
    return out


# ── geometry helpers ─────────────────────────────────────────────────────────────────────────
def _exit_rect(r, ox, oy, tx, ty):
    dx, dy = tx - ox, ty - oy
    ts = []
    if dx > 1e-9:
        ts.append((r["x"] + r["w"] - ox) / dx)
    elif dx < -1e-9:
        ts.append((r["x"] - ox) / dx)
    if dy > 1e-9:
        ts.append((r["y"] + r["h"] - oy) / dy)
    elif dy < -1e-9:
        ts.append((r["y"] - oy) / dy)
    t = min([x for x in ts if x > 0] or [0])
    return ox + dx * t, oy + dy * t


def _quad_pts(p1, c, p2, n=20):
    return [((1 - t) ** 2 * p1[0] + 2 * (1 - t) * t * c[0] + t * t * p2[0],
             (1 - t) ** 2 * p1[1] + 2 * (1 - t) * t * c[1] + t * t * p2[1]) for t in [i / n for i in range(n + 1)]]


def _inside(p, r, m=0):
    return r["x"] - m <= p[0] <= r["x"] + r["w"] + m and r["y"] - m <= p[1] <= r["y"] + r["h"] + m


def _route(a, b, off, obstacles):
    ax, ay, bx, by = a["cx"], a["cy"], b["cx"], b["cy"]
    dx, dy = bx - ax, by - ay
    L = math.hypot(dx, dy) or 1.0
    nx, ny = -dy / L, dx / L
    ax, ay, bx, by = ax + nx * off, ay + ny * off, bx + nx * off, by + ny * off
    first = None
    for bow in (0, 64, -64, 110, -110, 160, -160):
        cx_, cy_ = (ax + bx) / 2 + nx * bow, (ay + by) / 2 + ny * bow
        p1 = _exit_rect(a, ax, ay, cx_, cy_)
        p2 = _exit_rect(b, bx, by, cx_, cy_)
        pts = _quad_pts(p1, (cx_, cy_), p2)
        cand = (p1, (cx_, cy_), p2, pts)
        if first is None:
            first = cand
        if not any(_inside(p, o, 8) for p in pts[2:-2] for o in obstacles):
            return cand
    return first


def _route_actor(start, rect, obstacles):
    sx, sy = start
    tx, ty = rect["cx"], rect["cy"]
    dx, dy = tx - sx, ty - sy
    L = math.hypot(dx, dy) or 1.0
    nx, ny = -dy / L, dx / L
    first = None
    for bow in (0, 90, -90, 150, -150, 210, -210):
        cx_, cy_ = (sx + tx) / 2 + nx * bow, (sy + ty) / 2 + ny * bow
        end = _exit_rect(rect, tx, ty, cx_, cy_)
        pts = _quad_pts(start, (cx_, cy_), end)
        cand = (start, (cx_, cy_), end)
        if first is None:
            first = cand
        if not any(_inside(q, o, 6) for q in pts[1:-2] for o in obstacles):
            return cand
    return first


def _devil_svg(cx, cy, tip=""):
    t = f"<title>{_xml(tip)}</title>" if tip else ""
    return (f'<g transform="translate({cx:.1f},{cy:.1f})">{t}'
            '<path d="M-15,-9 L-23,-28 L-6,-18 Z" fill="#35332E"/><path d="M15,-9 L23,-28 L6,-18 Z" fill="#35332E"/>'
            '<circle r="19" fill="white" stroke="#35332E" stroke-width="2.6"/>'
            '<circle cx="-6.5" cy="-3" r="2.6" fill="#35332E"/><circle cx="6.5" cy="-3" r="2.6" fill="#35332E"/>'
            '<path d="M-12,-10 L-3,-6.5 M12,-10 L3,-6.5" stroke="#35332E" stroke-width="2" stroke-linecap="round" fill="none"/>'
            '<path d="M-9,6 Q0,15 9,6" fill="none" stroke="#35332E" stroke-width="2.4" stroke-linecap="round"/></g>')


def _badge_w(code, kind=None):
    return max(32, 7.2 * len(code) + 12)


def _badge_svg(x, y, code, kind, tip="", h=18):
    k = ANNOTATION_KINDS[kind]
    w = _badge_w(code, kind)
    t = f"<title>{_xml(tip)}</title>" if tip else ""
    return (f'<g>{t}<rect x="{x:.1f}" y="{y - h / 2:.1f}" width="{w:.1f}" height="{h}" rx="2" fill="{k["fill"]}" stroke="{k["stroke"]}" stroke-width="1.4"/>'
            f'<text x="{x + w / 2:.1f}" y="{y + 3.6:.1f}" text-anchor="middle" class="t-badge" fill="{k["text"]}">{_xml(code)}</text></g>')


def _item_tip(it):
    k = ANNOTATION_KINDS[it["kind"]]
    tip = f"{it['id']} · {k['title']}: {it['label']}"
    if it.get("stride"):
        tip += f" [{STRIDE_NAMES.get(it['stride'], it['stride'])}]"
    if it.get("capability"):
        tip += f" (capability: {it['capability']})"
    if it.get("notes"):
        tip += f" — {it['notes']}"
    if it.get("links"):
        tip += f" (linked: {', '.join(it['links'])})"
    return tip


def _actor_targets(a):
    return [a["target"]] + [e for e in a.get("entries", []) if e != a["target"]]


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  RENDERER
#  modes: architecture · dfd · boundaries · actors · stride · mitre · zonerules · threat · zones ·
#         scope · scoring · controls · residual
# ═════════════════════════════════════════════════════════════════════════════════════════════
TRUST_MODES = ("boundaries", "actors", "stride", "mitre", "threat", "zonerules")
ID_MODES = ("dfd", "boundaries", "actors", "stride", "mitre")
MODE_TITLES = {
    "architecture": "Architecture: what runs where", "dfd": "Data-flow diagram (DFD)", "boundaries": "Trust boundaries",
    "actors": "Threat actors and entry points", "stride": "STRIDE mapping aligned to the architecture",
    "mitre": "MITRE ATT&CK mapping", "zonerules": "Zone-direction rules (STRIDE hints)", "threat": "Threat impact map",
    "zones": "Zones of trust", "scope": "Scope view: in scope vs out of scope", "scoring": "Inherent risk heat map",
    "controls": "Controls applied to risks", "residual": "Residual risk heat map",
}


def render_architecture_svg(workshop_config, highlighted_threats=None, mode="architecture", annotations=None,
                            out_of_scope=(), risk_map=None, ctrl_map=None, stride_map=None, mitre_map=None, flat=False, reveal_cross=True):
    highlighted_threats = highlighted_threats or []
    annotations = annotations or []
    oos = set(out_of_scope or ())
    risk_map, ctrl_map = risk_map or {}, ctrl_map or {}
    stride_map, mitre_map = stride_map or {}, mitre_map or {}
    heat = mode in ("scoring", "controls", "residual")
    scn = workshop_config["scenario"]
    comps, flows = scn["components"], scn["data_flows"]
    cmap = {c["name"]: c for c in comps}
    eid = element_ids(scn)
    third = third_party_components(workshop_config)
    crossings = flow_crossings(workshop_config)
    lay = layout_tree(workshop_config)
    leaves, groups = lay["leaves"], lay["groups"]

    # layers: `flat` = elements + flows only (no boundaries, zones or crossings), used before Step 4
    show_groups = mode != "dfd" and not flat
    trust_mode = mode in TRUST_MODES and not flat
    show_ids = mode in ID_MODES or flat
    dfd_shapes = mode != "architecture"                      # one shape language (DFD notation) in every step
    zone_chips = mode not in ("dfd", "architecture", "scope", "boundaries") and not flat
    actors = [a for a in annotations if a["kind"] == "actor"] if mode not in ("dfd",) else []
    others = ([a for a in annotations if a["kind"] != "actor"] if mode != "dfd"
              else [a for a in annotations if a["kind"] == "asset"])
    by_target = {}
    for it in others:
        by_target.setdefault(it.get("target"), []).append(it)

    W = max(1000, lay["W"])
    shift_x = (W - lay["W"]) / 2
    rows_needed = 0
    if actors:
        per_row = max(1, int((W - 120) // 190))
        rows_needed = min(3, math.ceil(len(actors) / per_row))
    actor_band = (rows_needed * 118 + 26) if actors else 0
    oy = _TOP + actor_band + 18
    for r in list(leaves.values()) + groups:
        r["x"] += shift_x
        r["cx"] = r.get("cx", 0) + (shift_x if "cx" in r else 0)
        r["y"] += oy
        if "cy" in r:
            r["cy"] += oy
    diagram_bottom = oy + lay["H"]

    threat_nodes, threat_flows = set(), set()
    for t in highlighted_threats:
        c = t.get("component", "")
        (threat_flows if "→" in c else threat_nodes).add(c)

    # ── edges ────────────────────────────────────────────────────────────────────────────
    pair_n, pair_seen = {}, {}
    for f in flows:
        k = tuple(sorted([f["source"], f["destination"]]))
        pair_n[k] = pair_n.get(k, 0) + 1
    edges = []
    for f in flows:
        src, dst = f["source"], f["destination"]
        if src not in leaves or dst not in leaves:
            continue
        pk = tuple(sorted([src, dst]))
        oi = pair_seen.get(pk, 0)
        pair_seen[pk] = oi + 1
        off = (oi - (pair_n[pk] - 1) / 2) * 16
        obstacles = [r for n, r in leaves.items() if n not in (src, dst)]
        p1, c, p2, pts = _route(leaves[src], leaves[dst], off, obstacles)
        key = _flow_key(f)
        mid = ((p1[0] + 2 * c[0] + p2[0]) / 4, (p1[1] + 2 * c[1] + p2[1]) / 4)
        edges.append({"f": f, "key": key, "p1": p1, "c": c, "p2": p2, "pts": pts, "mid": mid, "crossed": crossings.get(key, [])})
    flow_mid = {e["key"]: e["mid"] for e in edges}

    s = []
    # canvas size is finalised after registers/legend are measured; placeholder replaced at the end
    s.append("@@SVGOPEN@@")
    s.append(f"""<defs><style>
.t-title{{font:700 14px {_FONT};fill:#1D1C1A}}
.t-mode{{font:500 10.5px {_FONT};fill:#948D80}}
.t-gt{{font:700 11.5px {_FONT};fill:#35332E}}
.t-gs{{font:italic 500 9px {_FONT};fill:#948D80}}
.t-name{{font:700 11.5px {_FONT};fill:#2E2C28}}
.t-desc{{font:400 8.6px {_FONT};fill:#6F6A5F}}
.t-edge{{font:500 9px {_FONT}}}
.t-badge{{font:700 9.5px {_MONO}}}
.t-zone{{font:600 8.5px {_MONO};fill:white}}
.t-id{{font:700 8.5px {_MONO};fill:#5B574E}}
.t-leg{{font:400 9px {_FONT};fill:#5B574E}}
.t-legt{{font:700 9.5px {_FONT};fill:#35332E}}
.t-reg{{font:400 9.2px {_FONT};fill:#32302C}}
.t-actor{{font:600 9px {_FONT};fill:#752727}}
</style>
<marker id="mk-n" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#48453E"/></marker>
<marker id="mk-r" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#B63838"/></marker>
<marker id="mk-a" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#CF8E17"/></marker>
<marker id="mk-g" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#367539"/></marker>
<marker id="mk-o" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#BFBCB6"/></marker>
<marker id="mk-ta" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#752727"/></marker>
<filter id="sh" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="1.4" stdDeviation="1.8" flood-color="#000" flood-opacity="0.14"/></filter>
</defs>""")
    s.append(f'<rect x="0" y="0" width="{W}" height="@@H@@" fill="white"/>')
    s.append(f'<text x="14" y="21" class="t-title">{_xml(scn.get("title", "System architecture"))}</text>')
    s.append(f'<text x="{W - 14}" y="21" text-anchor="end" class="t-mode">{_xml(MODE_TITLES.get(mode, ""))}</text>')

    # ── trust boundaries / environments ────────────────────────────────────────────────
    if show_groups:
        for g in sorted(groups, key=lambda r: r["depth"]):
            kind_fill = {"third_party": "#FDF9ED", "internet": "#F7F7F6", "cloud": "#FAFAF9"}.get(g["kind"], "#FFFFFF" if g["depth"] else "#FDFDFC")
            dash = ' stroke-dasharray="9,5"' if trust_mode else ""
            stroke = "#843434" if (trust_mode and g["kind"] == "internet") else "#35332E"
            sw = 1.9 if g["depth"] == 0 else 1.5
            s.append(f'<rect x="{g["x"]:.1f}" y="{g["y"]:.1f}" width="{g["w"]:.1f}" height="{g["h"]:.1f}" rx="18" fill="{kind_fill}" stroke="{stroke}" stroke-width="{sw}"{dash}><title>{_xml(g["name"])} — {_xml(g["trust"] or "environment")}</title></rect>')
            s.append(f'<text x="{g["x"] + 14:.1f}" y="{g["y"] + 20:.1f}" class="t-gt">{_xml(g["name"])}</text>')
            if g["trust"] and mode != "architecture":
                s.append(f'<text x="{g["x"] + g["w"] - 14:.1f}" y="{g["y"] + 20:.1f}" text-anchor="end" class="t-gs">{_xml(g["trust"])}</text>')

    # ── edges ──────────────────────────────────────────────────────────────────────────
    zsc = {c["name"]: c.get("zone_score", 3) for c in comps}
    label_items = []
    for e in edges:
        f, key = e["f"], e["key"]
        src, dst = f["source"], f["destination"]
        is_thr = key in threat_flows
        crossing = bool(e["crossed"]) and reveal_cross
        col, mk, sw, dash = "#48453E", "mk-n", 1.8, ""
        if trust_mode and crossing:
            col, mk, sw, dash = "#A82B2B", "mk-r", 2.1, ' stroke-dasharray="7,4"'
        if is_thr:
            col, mk, sw = "#B63838", "mk-r", 2.8
        xb = []
        if heat and key in risk_map:
            band = risk_band(risk_map[key])
            col, mk, sw, dash = BAND_COLORS[band][1], {"High": "mk-r", "Medium": "mk-a", "Low": "mk-g"}[band], 3, ""
            xb.append(("risk", (f"R{risk_map[key]}", band), 30))
            if mode == "controls" and ctrl_map.get(key):
                xb.append(("ctl", ctrl_map[key], 30))
        if src in oos or dst in oos:
            col, mk, sw, dash = "#BFBCB6", "mk-o", 1.3, ' stroke-dasharray="3,4"'
        d = f'M{e["p1"][0]:.1f},{e["p1"][1]:.1f} Q{e["c"][0]:.1f},{e["c"][1]:.1f} {e["p2"][0]:.1f},{e["p2"][1]:.1f}'
        s.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="{sw}"{dash} marker-end="url(#{mk})"/>')
        tags = []
        if mode == "zonerules":
            sz, dz = zsc.get(src, 3), zsc.get(dst, 3)
            if sz < dz: tags.append("T")
            if sz > dz: tags.append("I")
            if sz == 0: tags.append("D")
        if mode in ("stride", "mitre"):
            tags += [ch for ch in stride_map.get(key, []) if ch in STRIDE_LETTERS]
        if mode == "mitre":
            for tid in mitre_map.get(key, [])[:3]:
                xb.append(("mitre", tid, 40))
        label_items.append({"key": key, "mid": e["mid"], "col": col, "tags": tags, "xb": xb, "crossed": e["crossed"],
                            "data": f.get("data", "") or "", "proto": f.get("protocol", "")})

    # crossing markers
    if trust_mode and reveal_cross:
        gmap = {g["name"]: g for g in groups}
        for e in edges:
            for gname in e["crossed"]:
                g = gmap.get(gname)
                if not g:
                    continue
                st_ = [_inside(p, g) for p in e["pts"]]
                for i in range(1, len(st_)):
                    if st_[i] != st_[i - 1]:
                        mx = (e["pts"][i][0] + e["pts"][i - 1][0]) / 2
                        my = (e["pts"][i][1] + e["pts"][i - 1][1]) / 2
                        s.append(f'<g><title>{_xml(e["key"])} crosses {_xml(gname)}</title><circle cx="{mx:.1f}" cy="{my:.1f}" r="5.5" fill="white" stroke="#A82B2B" stroke-width="2"/>'
                                 f'<circle cx="{mx:.1f}" cy="{my:.1f}" r="1.8" fill="#A82B2B"/></g>')
                        break

    # ── nodes ──────────────────────────────────────────────────────────────────────────
    for comp in comps:
        name = comp["name"]
        if name not in leaves:
            continue
        r = leaves[name]
        ctype = comp.get("type", "process")
        zone = comp.get("zone", "Standard Application")
        zs = _ZONE_STYLE.get(zone, _ZONE_STYLE["Standard Application"])
        is_thr = name in threat_nodes
        in_oos = name in oos
        r_here = risk_map.get(name) if heat else None
        x0, y0, w, h = r["x"], r["y"], r["w"], r["h"]
        cx, cy = r["cx"], r["cy"]
        tp = name in third
        if dfd_shapes:
            fill = "#EFEFEE" if ctype == "external_entity" else "white"
            stroke, dark = "#32302C", True
        else:
            if ctype == "datastore":
                fill, stroke, dark = "#374D74", "#20304D", False
            elif ctype == "external_entity":
                fill, stroke, dark = ("#FAF0D1", "#A77F1C", True) if tp else ("#F0F0EF", "#53719C", True)
            else:
                fill, stroke, dark = "#D8E4C8", "#5B7440", True
        swn = 1.9
        if mode == "zones":
            fill, stroke, dark = zs["band"], zs["stroke"], True
        if is_thr:
            fill, stroke, swn, dark = "#FAD2D6", "#B63838", 3, True
        if r_here:
            fill, stroke, swn, dark = BAND_COLORS[risk_band(r_here)][0], BAND_COLORS[risk_band(r_here)][1], 3, True
        if in_oos:
            fill, stroke, swn, dark = "#EFEFEE", "#A7A297", 1.5, True
        sd = ' stroke-dasharray="5,3"' if in_oos else ""
        tcol = "#A7A297" if in_oos else ("#2E2C28" if dark else "#FFFFFF")
        dcol = "#A7A297" if in_oos else ("#6F6A5F" if dark else "#EAE9E7")
        tip = f"<title>{_xml(name)} — {_xml(comp.get('description', ''))} · {_xml(zone)} (Z{comp.get('zone_score', 0)})</title>"
        if dfd_shapes and ctype == "process":
            s.append(f'<g filter="url(#sh)">{tip}<ellipse cx="{cx}" cy="{cy}" rx="{w / 2}" ry="{h / 2 + 2}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        elif dfd_shapes and ctype == "datastore":
            s.append(f'<g>{tip}<rect x="{x0}" y="{y0 + 4}" width="{w}" height="{h - 8}" fill="{fill}" stroke="none"/>'
                     f'<line x1="{x0}" y1="{y0 + 4}" x2="{x0 + w}" y2="{y0 + 4}" stroke="{stroke}" stroke-width="2.4"/>'
                     f'<line x1="{x0}" y1="{y0 + h - 4}" x2="{x0 + w}" y2="{y0 + h - 4}" stroke="{stroke}" stroke-width="2.4"/></g>')
        elif dfd_shapes:
            s.append(f'<g filter="url(#sh)">{tip}<rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="2" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        elif ctype == "datastore":
            cap = 9
            body = f'M{x0},{y0 + cap} L{x0},{y0 + h - cap} A{w / 2},{cap} 0 0 0 {x0 + w},{y0 + h - cap} L{x0 + w},{y0 + cap} Z'
            s.append(f'<g filter="url(#sh)">{tip}<path d="{body}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/>'
                     f'<ellipse cx="{cx}" cy="{y0 + cap}" rx="{w / 2}" ry="{cap}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/>'
                     f'<path d="M{x0 + 1},{y0 + cap + 9} A{w / 2 - 1},{cap} 0 0 0 {x0 + w - 1},{y0 + cap + 9}" fill="none" stroke="{"#A5B6D4" if not dark else stroke}" stroke-width="0.8" opacity="0.7"/></g>')
        else:
            rx = 9 if ctype != "external_entity" else 14
            s.append(f'<g filter="url(#sh)">{tip}<rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        desc = zone if mode == "zones" else comp.get("description", "")
        yb = cy + (7 if ctype == "datastore" else 0)
        s.append(f'<text x="{cx}" y="{yb - 2}" text-anchor="middle" class="t-name" style="fill:{tcol}">{_xml(_trunc(name, 22))}</text>')
        s.append(f'<text x="{cx}" y="{yb + 11}" text-anchor="middle" class="t-desc" style="fill:{dcol}">{_xml(_trunc(desc, 32))}</text>')
        if show_ids:
            s.append(f'<text x="{x0 + 6}" y="{y0 + 11}" class="t-id">{eid.get(name, "")}</text>')
        if zone_chips:
            s.append(f'<rect x="{cx - 16}" y="{y0 + h - 7}" width="32" height="14" rx="7" fill="{zs["stroke"]}"/>'
                     f'<text x="{cx}" y="{y0 + h + 3}" text-anchor="middle" class="t-zone">Z{_xml(comp.get("zone_score", 0))}</text>')
        if is_thr:
            s.append(f'<circle cx="{x0 + w}" cy="{y0}" r="9" fill="#B63838"/><text x="{x0 + w}" y="{y0 + 4}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="700" fill="white">!</text>')
        if in_oos:
            s.append(f'<rect x="{x0 + w - 78}" y="{y0 - 8}" width="78" height="15" rx="7" fill="#948D80"/>'
                     f'<text x="{x0 + w - 39}" y="{y0 + 2.5}" text-anchor="middle" class="t-zone">OUT OF SCOPE</text>')
        if r_here:
            rs = BAND_COLORS[risk_band(r_here)][1]
            s.append(f'<g><title>Risk score {r_here} ({risk_band(r_here)})</title><rect x="{x0 + w - 30}" y="{y0 - 9}" width="34" height="18" rx="7" fill="{rs}"/>'
                     f'<text x="{x0 + w - 13}" y="{y0 + 3.5}" text-anchor="middle" class="t-zone">R{r_here}</text></g>')
            if mode == "controls" and ctrl_map.get(name):
                s.append(f'<g><title>{ctrl_map[name]} control(s) selected</title><rect x="{x0 + w - 66}" y="{y0 - 9}" width="32" height="18" rx="7" fill="#367539"/>'
                         f'<text x="{x0 + w - 50}" y="{y0 + 3.5}" text-anchor="middle" class="t-zone">C×{ctrl_map[name]}</text></g>')
        # STRIDE chips and ATT&CK pills under the node
        below = y0 + h + 16
        if mode in ("stride", "mitre"):
            letters = [ch for ch in stride_map.get(name, []) if ch in STRIDE_LETTERS]
            if letters:
                bx = cx - (len(letters) * 18 - 2) / 2
                for ch in letters:
                    s.append(f'<g><title>{STRIDE_NAMES[ch]}</title><rect x="{bx:.1f}" y="{below - 8:.1f}" width="16" height="16" rx="3" fill="{_STRIDE_TAG_COLOR[ch]}"/>'
                             f'<text x="{bx + 8:.1f}" y="{below + 3.6:.1f}" text-anchor="middle" class="t-badge" fill="white">{ch}</text></g>')
                    bx += 18
                below += 19
        if mode == "mitre":
            ids = mitre_map.get(name, [])
            if ids:
                shown = ids[:3]
                pill_w = 44
                bx = cx - (len(shown) * (pill_w + 3) - 3) / 2
                for tid in shown:
                    s.append(f'<g><title>ATT&amp;CK {_xml(tid)}</title><rect x="{bx:.1f}" y="{below - 8:.1f}" width="{pill_w}" height="15" rx="7" fill="#4B3394"/>'
                             f'<text x="{bx + pill_w / 2:.1f}" y="{below + 2.8:.1f}" text-anchor="middle" class="t-zone">{_xml(tid)}</text></g>')
                    bx += pill_w + 3
        # learner labels (assets / threat scenarios / controls) in a row above the node
        items = sorted(by_target.get(name, []), key=_ann_sort)
        if items:
            bx0, row = x0, 0
            bx = bx0
            for it in items:
                bw = _badge_w(it["id"])
                if bx > bx0 and bx + bw > x0 + w + 40:
                    bx, row = bx0, row + 1
                s.append(_badge_svg(bx, y0 - 14 - row * 22, it["id"], it["kind"], _item_tip(it)))
                bx += bw + 4

    # ── flow labels + their extras ─────────────────────────────────────────────────────
    placed = []

    def _free(box):
        return not any(box[0] < q[2] + 3 and box[2] > q[0] - 3 and box[1] < q[3] + 3 and box[3] > q[1] - 3 for q in placed)

    node_rects = [(r["x"], r["y"], r["x"] + r["w"], r["y"] + r["h"]) for r in leaves.values()]
    done_keys = set()
    for L in label_items:
        key, (lx, ly) = L["key"], L["mid"]
        base = L["data"]
        txt = _trunc((f"{eid.get(key, '')} · " if show_ids else "") + base, 28)
        lw = len(txt) * 5.3 + 12 if txt else 0
        extras = [("chip", tg, 16) for tg in L["tags"]]
        for kind_, val, wd in L["xb"]:
            extras.append((kind_, val, wd))
        if key not in done_keys:
            done_keys.add(key)
            for it in sorted(by_target.get(key, []), key=_ann_sort):
                extras.append(("ann", it, _badge_w(it["id"])))
        total = sum(e[2] for e in extras) + 4 * max(0, len(extras) - 1)
        dy_choice = 0
        for cand in (0, -20, 20, -40, 40, -60, 60):
            ty = ly + cand
            box = [min(lx - lw / 2, lx - total / 2 if extras else 1e9), ty - 10, max(lx + lw / 2, lx + total / 2 if extras else -1e9),
                   ty + (24 if extras else 7)]
            hit_node = any(box[0] < n[2] and box[2] > n[0] and box[1] < n[3] and box[3] > n[1] for n in node_rects)
            if _free(box) and not hit_node:
                dy_choice = cand
                break
            dy_choice = cand if cand == 0 else dy_choice
        ty = ly + dy_choice
        placed.append([min(lx - lw / 2, lx - total / 2 if extras else 1e9), ty - 10, max(lx + lw / 2, lx + total / 2 if extras else -1e9),
                       ty + (24 if extras else 7)])
        L["anchor"] = (lx, ty)
        if txt:
            tip = f"{key} · {base}" + (f" · {L['proto']}" if L["proto"] else "") + (f" · crosses: {', '.join(L['crossed'])}" if (L["crossed"] and reveal_cross and not flat and mode not in ("dfd", "scope")) else "")
            s.append(f'<g><title>{_xml(tip)}</title><rect x="{lx - lw / 2:.1f}" y="{ty - 9:.1f}" width="{lw:.1f}" height="14" rx="4" fill="white" stroke="#D8D6D3" stroke-width="0.8"/>'
                     f'<text x="{lx:.1f}" y="{ty + 1:.1f}" text-anchor="middle" class="t-edge" fill="{L["col"]}">{_xml(txt)}</text></g>')
        bx, by = lx - total / 2, ty + 19
        for typ, obj, wd in extras:
            if typ == "risk":
                rs = BAND_COLORS[obj[1]][1]
                s.append(f'<g><title>Risk score {obj[0][1:]} ({obj[1]})</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="30" height="16" rx="6" fill="{rs}"/>'
                         f'<text x="{bx + 15:.1f}" y="{by + 3.5:.1f}" text-anchor="middle" class="t-zone">{obj[0]}</text></g>')
            elif typ == "ctl":
                s.append(f'<g><title>{obj} control(s) selected</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="30" height="16" rx="6" fill="#367539"/>'
                         f'<text x="{bx + 15:.1f}" y="{by + 3.5:.1f}" text-anchor="middle" class="t-zone">C×{obj}</text></g>')
            elif typ == "mitre":
                s.append(f'<g><title>ATT&amp;CK {_xml(obj)}</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="40" height="15" rx="7" fill="#4B3394"/>'
                         f'<text x="{bx + 20:.1f}" y="{by + 2.8:.1f}" text-anchor="middle" class="t-zone">{_xml(obj)}</text></g>')
            elif typ == "chip":
                s.append(f'<g><title>{STRIDE_NAMES.get(obj, obj)}</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="16" height="16" rx="3" fill="{_STRIDE_TAG_COLOR.get(obj, "#555")}"/>'
                         f'<text x="{bx + 8:.1f}" y="{by + 3.6:.1f}" text-anchor="middle" class="t-badge" fill="white">{obj}</text></g>')
            else:
                s.append(_badge_svg(round(bx, 1), round(by, 1), obj["id"], obj["kind"], _item_tip(obj)))
            bx += wd + 4
    flow_anchor = {L["key"]: L["anchor"] for L in label_items}

    # ── threat actors band ─────────────────────────────────────────────────────────────
    if actors:
        def anchor_x(a):
            xs = []
            for t_ in _actor_targets(a):
                if t_ in leaves:
                    xs.append(leaves[t_]["cx"])
                elif t_ in flow_anchor:
                    xs.append(flow_anchor[t_][0])
            return sum(xs) / len(xs) if xs else W / 2
        order = sorted(actors, key=anchor_x)
        row, prev = 0, -1e9
        pos = {}
        for a in order:
            x = max(anchor_x(a), prev + 190, 70)
            if x > W - 110 and row < rows_needed - 1:
                row, prev = row + 1, -1e9
                x = max(anchor_x(a), 70)
            pos[a["id"]] = (min(x, W - 120), _TOP + 46 + row * 118)
            prev = x
        for a in order:
            ax, ay = pos[a["id"]]
            for t_ in _actor_targets(a):
                if t_ in leaves:
                    others_ = [q for n_, q in leaves.items() if n_ != t_]
                    p1, c_, p2 = _route_actor((ax, ay + 24), leaves[t_], others_)
                elif t_ in flow_anchor:
                    p1, p2 = (ax, ay + 24), (flow_anchor[t_][0], flow_anchor[t_][1] - 10)
                    c_ = ((p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2)
                else:
                    continue
                s.append(f'<path d="M{p1[0]:.1f},{p1[1]:.1f} Q{c_[0]:.1f},{c_[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}" stroke="#752727" stroke-width="2" fill="none" marker-end="url(#mk-ta)"><title>{_xml(a["id"])} → {_xml(t_)}</title></path>')
        for a in order:
            ax, ay = pos[a["id"]]
            s.append(_devil_svg(ax, ay, _item_tip(a)))
            s.append(f'<text x="{ax:.1f}" y="{ay + 40:.1f}" text-anchor="middle" class="t-actor">{_xml(_trunc(a["label"], 30))}</text>')
            tx, ty = ax + 30, ay - 30
            s.append(_badge_svg(tx, ty, a["id"], "actor", _item_tip(a), h=20))
            ts_ = [t for t in others if t["kind"] == "threat" and a["id"] in t.get("links", [])]
            for i, t in enumerate(ts_[:3]):
                s.append(_badge_svg(tx, ty + 22 * (i + 1), t["id"], "threat", _item_tip(t), h=20))
            if len(ts_) > 3:
                s.append(f'<text x="{tx:.1f}" y="{ty + 22 * 4 + 4:.1f}" class="t-leg">+{len(ts_) - 3} more</text>')

    # ── registers (assets / actors / scenarios / controls), as in the reference style ──
    y_cursor = diagram_bottom + 22
    reg_groups = [(k, [i for i in sorted(annotations, key=_ann_sort) if i["kind"] == k]) for k in ("asset", "actor", "threat", "control")]
    reg_groups = [(k, v) for k, v in reg_groups if v] if mode != "dfd" else []
    if reg_groups:
        n = len(reg_groups)
        gap = 14
        bw = (W - 2 * 14 - gap * (n - 1)) / n
        maxlines = min(8, max(len(v) for _, v in reg_groups))
        bh = 28 + maxlines * 14 + 8
        titles = {"asset": "Assets", "actor": "Threat actors", "threat": "Threat scenarios", "control": "Controls / mitigations"}
        for idx, (k, v) in enumerate(reg_groups):
            x = 14 + idx * (bw + gap)
            kk = ANNOTATION_KINDS[k]
            s.append(f'<rect x="{x:.1f}" y="{y_cursor:.1f}" width="{bw:.1f}" height="{bh}" rx="3" fill="white" stroke="#35332E" stroke-width="1.4"/>')
            s.append(f'<rect x="{x:.1f}" y="{y_cursor:.1f}" width="{bw:.1f}" height="20" rx="3" fill="{kk["fill"]}" opacity="0.35"/>')
            s.append(f'<text x="{x + 8:.1f}" y="{y_cursor + 14:.1f}" class="t-legt">{titles[k]}</text>')
            for i, it in enumerate(v[:8]):
                lab = _trunc(it["label"], int(bw / 5.4) - len(it["id"]) - 3 - (6 if it.get("stride") else 0))
                pre = f"[{it['stride']}] " if it.get("stride") else ""
                s.append(f'<text x="{x + 8:.1f}" y="{y_cursor + 36 + i * 14:.1f}" class="t-reg"><tspan font-weight="700">{_xml(it["id"])}</tspan>: {_xml(pre + lab)}</text>')
            if len(v) > 8:
                s.append(f'<text x="{x + bw - 8:.1f}" y="{y_cursor + bh - 6:.1f}" text-anchor="end" class="t-leg">+{len(v) - 8} more</text>')
        y_cursor += bh + 16

    # ── symbol legend ──────────────────────────────────────────────────────────────────
    leg_y = y_cursor
    s.append(f'<rect x="0" y="{leg_y:.1f}" width="{W}" height="@@LEG@@" fill="#FAFAF9"/><line x1="0" y1="{leg_y:.1f}" x2="{W}" y2="{leg_y:.1f}" stroke="#E9E8E6"/>')
    s.append(f'<text x="14" y="{leg_y + 15:.1f}" class="t-legt">LEGEND</text>')

    def ic_shape_proc(x, y):
        if dfd_shapes:
            return f'<ellipse cx="{x + 10}" cy="{y}" rx="10" ry="6" fill="white" stroke="#32302C" stroke-width="1.3"/>', 20
        return f'<rect x="{x}" y="{y - 6}" width="20" height="12" rx="3" fill="#D8E4C8" stroke="#5B7440" stroke-width="1.3"/>', 20

    def ic_shape_ext(x, y):
        if dfd_shapes:
            return f'<rect x="{x}" y="{y - 6}" width="20" height="12" fill="#EFEFEE" stroke="#32302C" stroke-width="1.3"/>', 20
        return f'<rect x="{x}" y="{y - 6}" width="20" height="12" rx="5" fill="#F0F0EF" stroke="#53719C" stroke-width="1.3"/>', 20

    def ic_shape_ds(x, y):
        if dfd_shapes:
            return f'<line x1="{x}" y1="{y - 5}" x2="{x + 20}" y2="{y - 5}" stroke="#32302C" stroke-width="2"/><line x1="{x}" y1="{y + 5}" x2="{x + 20}" y2="{y + 5}" stroke="#32302C" stroke-width="2"/>', 20
        return (f'<path d="M{x},{y - 3} L{x},{y + 4} A10,3 0 0 0 {x + 20},{y + 4} L{x + 20},{y - 3} Z" fill="#374D74" stroke="#20304D"/>'
                f'<ellipse cx="{x + 10}" cy="{y - 3}" rx="10" ry="3" fill="#374D74" stroke="#20304D"/>'), 20

    def ic_boundary(x, y):
        return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="5" fill="none" stroke="#35332E" stroke-width="1.5" stroke-dasharray="4,2"/>', 22

    def ic_cross(x, y):
        return f'<circle cx="{x + 7}" cy="{y}" r="5.5" fill="white" stroke="#A82B2B" stroke-width="2"/><circle cx="{x + 7}" cy="{y}" r="1.8" fill="#A82B2B"/>', 14

    def ic_zone(x, y):
        return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="6" fill="#E4A33A"/><text x="{x + 11}" y="{y + 3}" text-anchor="middle" class="t-zone">Z3</text>', 22

    def ic_oos(x, y):
        return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="5" fill="#EFEFEE" stroke="#A7A297" stroke-dasharray="3,2"/>', 22

    def ic_risk(band):
        return lambda x, y: (f'<rect x="{x}" y="{y - 7}" width="22" height="14" rx="6" fill="{BAND_COLORS[band][1]}"/>', 22)

    def ic_ctl(x, y):
        return f'<rect x="{x}" y="{y - 7}" width="26" height="14" rx="6" fill="#367539"/><text x="{x + 13}" y="{y + 3}" text-anchor="middle" class="t-zone">C×n</text>', 26

    def ic_stride(x, y):
        return f'<rect x="{x}" y="{y - 8}" width="16" height="16" rx="3" fill="#CF5817"/><text x="{x + 8}" y="{y + 3.6}" text-anchor="middle" class="t-badge" fill="white">T</text>', 16

    def ic_mitre(x, y):
        return f'<rect x="{x}" y="{y - 7}" width="40" height="15" rx="7" fill="#4B3394"/><text x="{x + 20}" y="{y + 3}" text-anchor="middle" class="t-zone">T1190</text>', 40

    def ic_devil(x, y):
        return _devil_svg(x + 9, y + 1).replace('transform="translate(', 'transform="scale(0.45) translate(').replace(f'{x + 9:.1f},{y + 1:.1f})"', f'{(x + 9) / 0.45:.1f},{(y + 1) / 0.45:.1f})"'), 20

    def ic_badge(kind, code):
        return lambda x, y: (_badge_svg(x, y, code, kind, h=16), _badge_w(code))

    def ic_bang(x, y):
        return f'<circle cx="{x + 8}" cy="{y}" r="8" fill="#B63838"/><text x="{x + 8}" y="{y + 4}" text-anchor="middle" font-family="Arial" font-size="11" font-weight="700" fill="white">!</text>', 16

    items = [(ic_shape_ext, "External entity"), (ic_shape_proc, "Process"), (ic_shape_ds, "Data store")]
    if show_groups:
        items.append((ic_boundary, "Trust boundary / environment"))
    if trust_mode and reveal_cross:
        items.append((ic_cross, "Boundary crossing"))
    if zone_chips:
        items.append((ic_zone, "Criticality zone (0–9)"))
    if actors or mode == "actors":
        items.append((ic_devil, "Threat actor → entry point"))
    if mode == "dfd":
        if others:
            items.append((ic_badge("asset", "A01"), "Asset"))
    elif flat:
        if actors:
            items.append((ic_badge("actor", "TA01"), "Threat actor"))
        items += [(ic_badge("asset", "A01"), "Asset"), (ic_badge("threat", "TS01"), "Threat scenario")]
    else:
        items += [(ic_badge("actor", "TA01"), "Threat actor"), (ic_badge("asset", "A01"), "Asset"),
                  (ic_badge("threat", "TS01"), "Threat scenario"), (ic_badge("control", "C01"), "Control")]
    if mode in ("stride", "mitre"):
        items.append((ic_stride, "STRIDE category (S T R I D E)"))
    if mode == "zonerules":
        items.append((ic_stride, "Zone-rule hint (T / I / D)"))
    if mode == "mitre":
        items.append((ic_mitre, "ATT&CK technique"))
    if threat_nodes or threat_flows:
        items.append((ic_bang, "Threat identified"))
    if oos:
        items.append((ic_oos, "Out of scope"))
    if heat:
        items += [(ic_risk("Low"), "Low risk (1–2)"), (ic_risk("Medium"), "Medium (3–4)"), (ic_risk("High"), "High (6–9)")]
    if mode == "controls":
        items.append((ic_ctl, "Controls selected"))
    lx_, ly_ = 14, leg_y + 34
    for fn, text in items:
        w_item = 34 + len(text) * 5.1
        if lx_ + w_item > W - 10:
            lx_, ly_ = 14, ly_ + 20
        svg_i, iw = fn(lx_, ly_)
        s.append(svg_i)
        s.append(f'<text x="{lx_ + iw + 6}" y="{ly_ + 3}" class="t-leg">{_xml(text)}</text>')
        lx_ += iw + 6 + len(text) * 5.1 + 18
    leg_h = (ly_ - leg_y) + 22
    H = leg_y + leg_h
    out = "\n".join(s).replace("@@H@@", f"{H:.0f}").replace("@@LEG@@", f"{leg_h:.0f}")
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H:.0f}" viewBox="0 0 {W:.0f} {H:.0f}" '
            f'style="width:100%;height:auto;max-width:{W:.0f}px;background:white" role="img">')
    return out.replace("@@SVGOPEN@@", head) + "\n</svg>"


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  DYNAMIC LABELS: threat actors · assets · threat scenarios · controls
# ═════════════════════════════════════════════════════════════════════════════════════════════
def get_annotations(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    return st.session_state.annotations.setdefault(ws_id, [])


def _next_annotation_id(items, kind):
    pre = ANNOTATION_KINDS[kind]["prefix"]
    nums = [int(re.sub(r"\D", "", i["id"]) or 0) for i in items if i["kind"] == kind]
    return f"{pre}{max(nums, default=0) + 1:02d}"


def annotation_register_df(items):
    rows = []
    for it in sorted(items, key=_ann_sort):
        rows.append({
            "ID": it["id"], "Type": ANNOTATION_KINDS[it["kind"]]["title"], "Label": it["label"],
            "Attached to": ", ".join(_actor_targets(it)) if it["kind"] == "actor" else it["target"],
            "STRIDE": STRIDE_NAMES.get(it.get("stride", ""), ""), "Capability": it.get("capability", ""),
            "Linked to": ", ".join(it.get("links", [])), "Notes": it.get("notes", "")})
    return pd.DataFrame(rows, columns=["ID", "Type", "Label", "Attached to", "STRIDE", "Capability", "Linked to", "Notes"])


def diagram_label_editor(workshop_config, key, default_kind=None):
    ws_id = st.session_state.selected_workshop
    items = get_annotations(ws_id)
    sc = workshop_config["scenario"]
    targets = [c["name"] for c in sc["components"]] + list(dict.fromkeys(_flow_key(f) for f in sc["data_flows"]))
    nonce = st.session_state.annot_nonce
    with st.expander(f"✏️ Label this diagram — threat actors · assets · threat scenarios · controls  ({len(items)} labels)", expanded=False):
        st.caption("Labels appear on every diagram of this lab. Threat actors are drawn outside the system with arrows to their entry points; "
                   "link threat scenarios to actors and assets, and controls to the scenarios they mitigate.")
        c1, c2 = st.columns([1, 2])
        kind = c1.selectbox("Label type", _KIND_ORDER, key=f"{key}_kind",
                            index=_KIND_ORDER.index(default_kind) if default_kind in _KIND_ORDER else 0,
                            format_func=lambda k: f"{ANNOTATION_KINDS[k]['icon']} {ANNOTATION_KINDS[k]['title']}")
        target = c2.selectbox("Attach to (component, entry point or data flow)", targets, key=f"{key}_target_{nonce}")
        extra = {}
        if kind == "actor":
            extra["entries"] = st.multiselect("Additional entry points", [t for t in targets if t != target], key=f"{key}_entries_{nonce}")
            extra["capability"] = st.select_slider("Capability", ["Low", "Medium", "High"], value="Medium", key=f"{key}_cap_{nonce}")
        suggestion = None
        if kind == "asset" and sc.get("assets"):
            pick = st.selectbox("Suggestions from this scenario", ["(type your own)"] + list(sc["assets"]), key=f"{key}_sugg_{nonce}")
            suggestion = None if pick == "(type your own)" else pick
        if kind == "threat":
            sel = st.selectbox("STRIDE category", ["—"] + [f"{k} · {v}" for k, v in STRIDE_NAMES.items()], key=f"{key}_stride_{nonce}")
            extra["stride"] = "" if sel == "—" else sel.split(" · ")[0]
        label = st.text_input("Label", max_chars=80, key=f"{key}_label_{nonce}",
                              placeholder={"actor": "e.g. Adversary with network access", "asset": "e.g. Customer PII",
                                           "threat": "e.g. SQL injection alters order totals", "control": "e.g. Parameterised queries"}[kind])
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
                items.append({"id": _next_annotation_id(items, kind), "kind": kind, "label": final, "target": target,
                              "links": links, "notes": (notes or "").strip(), **extra})
                st.session_state.annot_nonce += 1
                save_progress()
                st.rerun()
        if items:
            st.markdown("**Current labels**")
            for it in sorted(items, key=_ann_sort):
                a, b, c, d = st.columns([1, 5, 4, 1])
                a.markdown(f"**{it['id']}**")
                b.text(f"{ANNOTATION_KINDS[it['kind']]['title']}: {it['label']}")
                where = ", ".join(_actor_targets(it)) if it["kind"] == "actor" else it["target"]
                c.text(f"on {where}" + (f"  ↔ {', '.join(it['links'])}" if it.get("links") else ""))
                if d.button("🗑", key=f"{key}_del_{it['id']}", help=f"Remove {it['id']}"):
                    items[:] = [x for x in items if x["id"] != it["id"]]
                    for x in items:
                        x["links"] = [l for l in x.get("links", []) if l != it["id"]]
                    save_progress()
                    st.rerun()
            b1, b2 = st.columns(2)
            b1.download_button("⬇️ Export label register (CSV)", annotation_register_df(items).to_csv(index=False),
                               file_name=f"workshop{ws_id}_labels.csv", mime="text/csv", key=f"{key}_csv", use_container_width=True)
            if b2.button("🧹 Clear all labels", key=f"{key}_clear", use_container_width=True):
                st.session_state.annotations[ws_id] = []
                save_progress()
                st.rerun()


_IFRAME_FONTS = ("<style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700"
                 "&family=JetBrains+Mono:wght@500;700&display=swap');body{margin:0;background:transparent}</style>")


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


def get_stride_map(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    return st.session_state.stride_map.setdefault(ws_id, {})


def _mitre_map():
    out = {}
    for r in st.session_state.user_answers:
        for tid in r.get("mitre", []):
            out.setdefault(r["component"], [])
            if tid not in out[r["component"]]:
                out[r["component"]].append(tid)
    return out


DIAGRAM_CAPTIONS = {
    "architecture": "Architecture — boxes group what runs where. Green = process, navy cylinder = data store, blue/yellow = external parties. Hover for details.",
    "dfd":          "Data-flow diagram — rectangles are external entities, ovals are processes, parallel lines are data stores. IDs (E/P/D/F) are used in later steps.",
    "boundaries":   "Trust boundaries — dashed boxes are boundaries; red dashed flows cross at least one boundary (● marks where). Focus your analysis on those flows.",
    "actors":       "Threat actors — devils sit outside the system; arrows show the entry points they can reach. TA = actor, TS = threat scenario linked to them.",
    "stride":       "STRIDE aligned to the architecture — coloured letters are the categories YOU mapped to each element and flow; TA/TS tags show who attacks and how.",
    "mitre":        "MITRE ATT&CK — purple pills are the techniques you mapped to each element, on top of your STRIDE mapping and threat actors.",
    "zonerules":    "Zone-direction hints — T = tampering (low→high zone), I = information disclosure (high→low), D = DoS (Zone-0 source).",
    "threat":       "Threat map — components and flows with identified threats are shown in red.",
    "zones":        "Zones of trust — fill colour = criticality zone of each component.",
    "scope":        "Scope view — grey dashed components are OUT of scope (set them in the scope form above).",
    "scoring":      "Inherent risk — colour = highest risk score (impact × likelihood) on each component or flow.",
    "controls":     "Controls — colour = inherent risk · C×n = number of controls you selected for that component or flow.",
    "residual":     "Residual risk — colour = risk that remains after your controls.",
}


def show_architecture_diagram(workshop_config, threats=None, mode="architecture", key_suffix="", editable=False, default_kind=None, flat=False, reveal_cross=True):
    ws_id = st.session_state.selected_workshop
    items = get_annotations(ws_id)
    oos = get_scope(ws_id)["oos_components"]
    risk_map, ctrl_map = _risk_maps(mode) if mode in ("scoring", "controls", "residual") else ({}, {})
    smap = get_stride_map(ws_id) if mode in ("stride", "mitre") else {}
    mmap = _mitre_map() if mode == "mitre" else {}
    svg = render_architecture_svg(workshop_config, highlighted_threats=threats or [], mode=mode, annotations=items,
                                  out_of_scope=oos, risk_map=risk_map, ctrl_map=ctrl_map, stride_map=smap, mitre_map=mmap, flat=flat, reveal_cross=reveal_cross)
    if mode == "boundaries" and not reveal_cross:
        st.caption("📐 Trust boundaries — dashed boxes mark where trust changes. Decide which flows cross them; the crossings are highlighted once you check your answer.")
    elif mode in DIAGRAM_CAPTIONS:
        st.caption("📐 " + DIAGRAM_CAPTIONS[mode])
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    est_h = float(m.group(2)) if m else 600
    components_html.html(
        f'{_IFRAME_FONTS}<div style="overflow-x:auto;border:1px solid #E9E8E7;border-radius:12px;background:white">{svg}</div>',
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
                fill, shape = "#FBD1D5", "oval"
                lbl = node["label"]
            elif ntype == "and":
                fill, shape = "#C7EFEA", "box"
                lbl = f"{node['label']}\\n[AND – all steps required]"
            elif ntype == "or":
                fill, shape = "#CAE4CB", "box"
                lbl = f"{node['label']}\\n[OR – any path succeeds]"
            else:
                fill, shape = "#FBF5C8", "box"
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
    return os.path.join(tempfile.gettempdir(), f"threat_progress_v4_{sid}.json")


def save_progress():
    try:
        _snapshot_active_workshop()
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
                "stride_map": st.session_state.stride_map,
                "boundary_checked": st.session_state.boundary_checked,
                "eop_card_logs": {str(k): v for k, v in st.session_state.items() if str(k).startswith("eop_cards_")},
                "eop_active_cards": {str(k): v for k, v in st.session_state.items() if str(k).startswith("eop_active_card_")},
                "workshop_workspaces": st.session_state.get("workshop_workspaces", {}),
                "flow_version": 3,
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
            if p.get("flow_version") not in (2, 3):   # progress saved by the old 18-page flow
                step = {1: 1, 14: 2, 2: 2, 15: 4, 3: 4, 16: 5, 4: 3, 17: 3, 5: 5, 6: 3, 18: 5, 7: 6, 8: 7, 9: 7, 10: 8, 11: 9, 12: 10, 13: 11}.get(step, 1)
            st.session_state.current_step = step if isinstance(step, int) and 1 <= step <= 11 else 1
            st.session_state.threats = p.get("threats", [])
            st.session_state.user_answers = p.get("user_answers", [])
            st.session_state.total_score = p.get("total_score", 0)
            st.session_state.max_score = p.get("max_score", 0)
            st.session_state.annotations = p.get("annotations", {})
            st.session_state.scope_models = p.get("scope_models", {})
            st.session_state.open_questions = p.get("open_questions", {})
            st.session_state.review_plans = p.get("review_plans", {})
            st.session_state.stride_map = p.get("stride_map", {})
            st.session_state.boundary_checked = p.get("boundary_checked", {})
            st.session_state.workshop_workspaces = p.get("workshop_workspaces", {})
            for k, v in p.get("eop_card_logs", {}).items():
                st.session_state[k] = v
            for k, v in p.get("eop_active_cards", {}).items():
                st.session_state[k] = v
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
                                     textColor=colors.HexColor('#3CAFA0'),
                                     spaceAfter=20, alignment=TA_CENTER)
        h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                            textColor=colors.HexColor('#217166'), spaceAfter=10, spaceBefore=10)

        story.append(Paragraph("STRIDE Threat Model Report", title_style))
        story.append(Paragraph(workshop_config['name'], styles['Heading2']))
        story.append(Spacer(1, 0.2 * inch))

        final_pct = (total_score / max_score * 100) if max_score else 0
        meta = [
            ['Report Type:', 'User Submission'],
            ['Workshop Level:', workshop_config['level']],
            ['Architecture:', workshop_config.get('architecture_type', 'N/A')],
            ['Methodology:', '10-Stage Threat Modeling'],
            ['Date:', datetime.now().strftime('%Y-%m-%d %H:%M')],
            ['Score:', f"{total_score}/{max_score} ({final_pct:.1f}%)"]
        ]
        t = Table(meta, colWidths=[2 * inch, 4 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F1F0EF')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(PageBreak())

        story.append(Paragraph("9-Step Process Applied", h2))
        for s_ in ["Step 1: Scope & goals – system, requirements, assumptions, exclusions, goals",
                   "Step 2: Data-flow diagram – components, assets, elements (E, P, D) and data flows (F)",
                   "Step 3: Apply STRIDE – per-element mapping and threat scenarios",
                   "Step 4: Trust boundaries – crossings, zones of trust, zone-direction rules",
                   "Step 5: ATT&CK, CAPEC and threat statements – actors, techniques, attack patterns",
                   "Step 6: Risk scoring – impact × likelihood on a 1–3 scale (risk 1–9)",
                   "Step 7: Control selection – guardrails, filtering, access rules, monitoring (OWASP-mapped)",
                   "Step 8: Residual risk and open questions – risk after controls, decisions",
                   "Step 9: Review schedule – owner, cadence and update triggers"]:
            story.append(Paragraph(f"• {s_}", styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        def _para(txt, bold=False):
            txt = _html.escape(str(txt))
            return Paragraph(f"<b>{txt}</b>" if bold else txt, styles['Normal'])

        def _grid(rows, widths, header=True):
            tb = Table([[_para(c, header and i == 0) for c in r] for i, r in enumerate(rows)], colWidths=[w * inch for w in widths], repeatRows=1 if header else 0)
            tb.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                    ('BACKGROUND', (0, 0), (-1, 0 if header else -1), colors.HexColor('#F1F0EF')) if header else ('LEFTPADDING', (0, 0), (-1, -1), 4),
                                    ('LEFTPADDING', (0, 0), (-1, -1), 4), ('TOPPADDING', (0, 0), (-1, -1), 3)]))
            return tb

        ex = extra or {}
        sc_ = ex.get("scope") or {}
        if sc_:
            story.append(Paragraph("Step 1 – Scope & goals", h2))
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
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FBF5C8')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(rt)
            scenario_text = answer.get('threat_text') or pred.get('threat', '')
            story.append(Paragraph("<b>Threat scenario:</b> " + _html.escape(str(scenario_text)), styles['Normal']))
            if answer.get('source') == 'EoP card activity':
                story.append(Paragraph("<b>Discovery source:</b> EoP-inspired card — " + _html.escape(str(answer.get('eop_card_title', ''))), styles['Normal']))
                story.append(Paragraph("<b>Evidence / attack path:</b> " + _html.escape(str(answer.get('eop_evidence') or 'Not recorded')), styles['Normal']))
                story.append(Paragraph("<b>Candidate mitigation:</b> " + _html.escape(str(answer.get('eop_candidate_mitigation') or 'Not recorded')), styles['Normal']))
                story.append(Paragraph("<b>ATT&amp;CK / CAPEC note:</b> " + _html.escape(str(answer.get('eop_attack_mapping') or 'Not mapped')), styles['Normal']))
            story.append(Spacer(1, 0.1 * inch))

            if answer.get('selected_mitigations'):
                story.append(Paragraph("<b>Selected Mitigations:</b>", styles['Normal']))
                for m in answer['selected_mitigations']:
                    story.append(Paragraph(f"• [{control_category(m)}] {_html.escape(m)}", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))

        ac_ = [l_ for l_ in (ex.get("labels") or []) if l_["kind"] == "actor"]
        if ac_:
            story.append(Paragraph("Step 5 – Threat actors and entry points", h2))
            story.append(_grid([["ID", "Threat actor", "Capability", "Entry points"]] +
                               [[a_["id"], a_["label"], a_.get("capability", ""), ", ".join(_actor_targets(a_))] for a_ in sorted(ac_, key=_ann_sort)],
                               [0.6, 2.4, 0.9, 2.6]))
            story.append(Spacer(1, 0.15 * inch))
        sm_ = ex.get("stride_map") or {}
        if sm_:
            story.append(Paragraph("Step 3 – STRIDE mapping per element", h2))
            story.append(_grid([["Element", "STRIDE categories"]] +
                               [[k_, ", ".join(STRIDE_NAMES.get(l_, l_) for l_ in v_)] for k_, v_ in sm_.items()], [2.8, 3.7]))
            story.append(Spacer(1, 0.15 * inch))
        mt_ = [a_ for a_ in user_answers if a_.get("mitre")]
        if mt_:
            story.append(Paragraph("Step 5 – ATT&amp;CK and CAPEC mapping (Enterprise v19)", h2))
            story.append(_grid([["Threat", "STRIDE", "ATT&CK techniques (tactics)", "CAPEC patterns"]] +
                               [[a_["matched_threat_id"], a_["stride"],
                                 "; ".join(f"{t_} {ATTACK_BY_ID[t_]['name']} ({', '.join(ATTACK_BY_ID[t_]['tactics'])})" for t_ in a_["mitre"] if t_ in ATTACK_BY_ID),
                                 "; ".join(f"{c_} {CAPEC_BY_ID[c_]['name']}" for c_ in a_.get("capec", []) if c_ in CAPEC_BY_ID) or "—"]
                                for a_ in mt_], [0.7, 1.0, 2.8, 2.0]))
            st_ = [a_ for a_ in mt_ if statement_complete(a_)]
            if st_:
                story.append(Spacer(1, 0.1 * inch)); story.append(_para("Threat statements", True))
                for a_ in st_:
                    story.append(_para(f"{a_['matched_threat_id']}: " + compose_statement(a_["statement"])))
            story.append(Spacer(1, 0.15 * inch))
        rated_ = [a_ for a_ in user_answers if rec_risk(a_)]
        if rated_:
            story.append(Paragraph("Steps 6–8 – Risk register (inherent → residual)", h2))
            story.append(_grid([["Threat", "Component / flow", "STRIDE", "Inherent", "Residual", "Decision"]] +
                               [[a_["matched_threat_id"], a_["component"], a_["stride"], str(rec_risk(a_)),
                                 str(rec_residual(a_) or "—"), (a_.get("residual") or {}).get("decision", "—")]
                                for a_ in sorted(rated_, key=lambda x: -rec_risk(x))], [0.7, 1.9, 1.3, 0.7, 0.7, 1.2]))
            story.append(Spacer(1, 0.15 * inch))
        oq_ = ex.get("open_questions") or {}
        if oq_.get("questions") or oq_.get("accepted"):
            story.append(Paragraph("Step 8 – Open questions and accepted risk", h2))
            for q_ in oq_.get("questions", []):
                story.append(_para("• " + q_))
            if oq_.get("accepted"):
                story.append(Spacer(1, 0.05 * inch)); story.append(_para("Accepted-risk statement: " + oq_["accepted"]))
        rp_ = ex.get("review_plan") or {}
        if rp_.get("owner") or rp_.get("full"):
            story.append(Paragraph("Step 9 – Review schedule", h2))
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
                                     textColor=colors.HexColor('#3CAFA0'),
                                     spaceAfter=20, alignment=TA_CENTER)
        h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                            textColor=colors.HexColor('#217166'), spaceAfter=10, spaceBefore=10)
        h3 = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12,
                            textColor=colors.HexColor('#305B31'), spaceAfter=8, spaceBefore=8)

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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#217166')),
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
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FBF5C8')),
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

def _esc(x):
    return _html.escape(str(x if x is not None else ""))


def go_page(page):
    # drop cached editor state so tables rebuild from saved data when a page is re-entered
    for k in [k for k in st.session_state.keys() if str(k).startswith(("_seed_stride_", "w_ed_stride_"))]:
        del st.session_state[k]
    st.session_state.current_step = page
    save_progress()
    st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCALE (1-3 × 1-3 = 1-9) AND THE PER-THREAT RECORD
# ─────────────────────────────────────────────────────────────────────────────
LEVELS = ["Low", "Medium", "High"]
_LEVEL_N = {"Low": 1, "Medium": 2, "High": 3, "Critical": 3}
BAND_COLORS = {"Low": ("#EFEFEE", "#367539"), "Medium": ("#FAF0D2", "#CF8E17"), "High": ("#FAD2D6", "#B63838")}


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
        bg, fg = ("#EFEFEE", "#205924") if n else ("#F6F5F4", "#A6A196")
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
        tds = [f'<td style="padding:6px 10px;font-weight:700;font-size:0.8em;color:#5B574E;text-align:right;white-space:nowrap">{LEVELS[i-1]} impact</td>']
        for l in (1, 2, 3):
            fill, stroke = BAND_COLORS[risk_band(l * i)]
            labs = ", ".join(_esc(x) for x in cells.get((l, i), []))
            tds.append(f'<td style="background:{fill};border:2px solid {stroke};padding:8px;min-width:110px;height:62px;'
                       f'text-align:center;vertical-align:middle"><div style="font-size:0.7em;color:{stroke};font-weight:700">{l*i}</div>'
                       f'<div style="font-size:0.82em;font-weight:700;color:#222">{labs}</div></td>')
        rows.append("<tr>" + "".join(tds) + "</tr>")
    head = ('<tr><td></td>' + "".join(f'<td style="text-align:center;font-weight:700;font-size:0.8em;color:#5B574E;padding:4px">{LEVELS[l-1]}</td>'
                                       for l in (1, 2, 3)) + "</tr>")
    foot = f'<tr><td></td><td colspan="3" style="text-align:center;font-size:0.75em;color:#948D80;padding-top:4px">{title}</td></tr>'
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
    third = [c["name"] for c in comps if c["type"] == "external_entity" and _is_third_party(cfg, c)]
    users = [c["name"] for c in comps if c["type"] == "external_entity" and not _is_third_party(cfg, c)]
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

    step_header(1, "Define scope & goals")
    st.caption("⏱️ Time-box: about 10 minutes. Clarity matters less than starting. Half of security incidents come from violated assumptions nobody verified.")

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
    show_architecture_diagram(cfg, mode="scope", key_suffix="s1_scope", editable=True, default_kind="asset", flat=True)

    st.subheader("✅ Scope checklist")
    for ok, text, req in scope_checks(sc):
        st.markdown(f"{'✅' if ok else ('⚠️' if req else '➖')} {text}" + ("" if req else " *(recommended)*"))

    nav_buttons(None, "", 2, "Next: Draw the DFD ➡️", scope_complete(sc),
                "Complete the required scope items above before moving on.", key="p1")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 6 helper — record the learner's identified threats
# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 7 — SCORING (impact × likelihood, 1-3 scale)
# ═══════════════════════════════════════════════════════════════════════════════
def render_scoring_page():
    cfg = current_workshop
    recs = st.session_state.user_answers
    step_header(6, "Risk scoring")
    render_eop_integration_status("risk scoring")
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
        st.warning("Identify threat scenarios first (Step 3).")
        nav_buttons(6, "⬅️ Back to Identify Threats", None, "", key="p7e")
        return

    with st.form("scoring_form"):
        st.subheader("➕ Rate each threat")
        vals = {}
        for rec in recs:
            pred = rec["predefined_threat"]
            st.markdown(f"**{pred['id']} · {rec['stride']} on {rec['component']}**")
            st.caption(rec.get("threat_text") or pred["threat"])
            if rec.get("source") == "EoP card activity":
                st.caption(f"🃏 From card: {rec.get('eop_card_title', 'EoP-inspired prompt')} · Evidence: {rec.get('eop_evidence') or 'not recorded'}")
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
            "Threat": r["matched_threat_id"], "Scenario": r.get("threat_text") or r["predefined_threat"].get("threat", ""), "Source": r.get("source", "STRIDE exercise"), "Component / flow": r["component"], "STRIDE": r["stride"],
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
                        st.markdown(f"""<div style="background:#FDF7E3;border-left:4px solid #E9A435;border-radius:6px;padding:10px 14px">
                        <strong style="color:#D55611;font-size:0.85em">⚖️ WHY THIS RISK LEVEL</strong><br>
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
def render_controls_page():
    cfg = current_workshop
    recs = st.session_state.user_answers
    render_eop_integration_status("control selection")
    cols = st.columns(4)
    for col, (cat, (ic, desc)) in zip(cols, CONTROL_CATEGORIES.items()):
        col.markdown(f"**{ic} {cat}**")
        col.caption(desc)

    rated = [r for r in recs if r.get("rated")]
    if not rated:
        st.warning("Score your threats first (Step 6).")
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
            <span style="font-size:0.88em;color:#444">{_esc(rec.get('threat_text') or pred['threat'])}</span></div>""", unsafe_allow_html=True)
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
                _hints = attack_mitigation_hints(rec)
                if _hints:
                    st.caption("🎯 ATT&CK mitigations for the techniques you mapped: " +
                               "; ".join((f"{k} {v}" if k.startswith("M") else f"{k}: {v}") for k, v in _hints.items()))
                for line in rec.get("fb_controls", []):
                    (st.success if line.startswith("✓") else st.error if line.startswith("✗") else st.warning)(line)
                for m in rec["selected_mitigations"]:
                    st.markdown(f"- {CONTROL_CATEGORIES[control_category(m)][0]} **{control_category(m)}** — {m}")
                why = pred.get("why_these_controls")
                if why:
                    st.markdown(f"""<div style="background:#EFEFEE;border-left:4px solid #4A994D;border-radius:6px;padding:10px 14px">
                    <strong style="color:#205924;font-size:0.85em">🛡️ WHY THESE CONTROLS</strong><br>
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
    step_header(8, "Open questions & residual risk")
    render_eop_integration_status("residual-risk review")
    if not recs:
        st.warning("Select controls first (Step 7).")
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
    third = [c["name"] for c in cfg["scenario"]["components"] if c["type"] == "external_entity" and _is_third_party(cfg, c)]
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
    third = [c["name"] for c in cfg["scenario"]["components"] if c["type"] == "external_entity" and _is_third_party(cfg, c)]
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


def render_review_plan_page():
    ws = st.session_state.selected_workshop
    plan = get_review_plan(ws)
    step_header(9, "Review schedule")

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
def render_stage_summary():
    for sid, label, icon, done, detail in stage_status():
        bg = "#EFEFEE" if done else "#F6F5F4"
        clr = "#347737" if done else "#A6A196"
        st.markdown(f"""
        <div style="background:{bg};border-left:4px solid {clr};border-radius:8px;padding:12px 16px;margin:6px 0;display:flex;align-items:center;gap:12px">
          <span style="font-size:1.3em">{'✅' if done else '⭕'}</span>
          <div><strong style="color:{clr}">{icon} {label}</strong><br><span style="font-size:0.85em;color:#555">{_esc(detail)}</span></div>
        </div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  9-STEP FLOW  (page id == step number; 10 = report, 11 = completion)
#  Scope → DFD → STRIDE → Trust boundaries → ATT&CK/CAPEC/threat statements → Scoring → Controls → Residual risk → Review
# ═══════════════════════════════════════════════════════════════════════════════
STAGES = [
    ("scope",      "Scope & goals",     "📐"),
    ("dfd",        "Data-flow diagram", "🗺️"),
    ("stride",     "Apply STRIDE",      "⚡"),
    ("boundaries", "Trust boundaries",  "🚧"),
    ("mitre",      "ATT&CK · CAPEC",    "🎯"),
    ("scoring",    "Risk scoring",      "📊"),
    ("controls",   "Controls",          "🛡️"),
    ("residual",   "Residual risk",     "⚖️"),
    ("review",     "Review schedule",   "🔁"),
]
STAGE_IDS = [s[0] for s in STAGES]
PAGES = {
    1:  ("Scope & goals",              "scope"),
    2:  ("Data-flow diagram",          "dfd"),
    3:  ("Apply STRIDE",               "stride"),
    4:  ("Trust boundaries & zones",   "boundaries"),
    5:  ("ATT&CK, CAPEC & statements", "mitre"),
    6:  ("Risk scoring",               "scoring"),
    7:  ("Control selection",          "controls"),
    8:  ("Residual risk & questions",  "residual"),
    9:  ("Review schedule",            "review"),
    10: ("Assessment & report",        "wrapup"),
    11: ("Complete",                   "wrapup"),
}
PAGE_ORDER = list(range(1, 12))


def nav_buttons(back_page, back_label, next_page, next_label, next_ok=True, block_msg="", key="nav"):
    """Back/next follow PAGE_ORDER; the page ids and labels passed by older call sites are ignored."""
    cur = int(st.session_state.current_step)
    i = PAGE_ORDER.index(cur) if cur in PAGE_ORDER else 0
    prev_p = PAGE_ORDER[i - 1] if (back_page is not None and i > 0) else None
    next_p = PAGE_ORDER[i + 1] if (next_page is not None and i + 1 < len(PAGE_ORDER)) else None
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if prev_p and st.button(f"⬅️ Back to {PAGES[prev_p][0]}", use_container_width=True, key=f"{key}_back"):
            go_page(prev_p)
    with c2:
        if next_p and st.button(f"Next: {PAGES[next_p][0]} ➡️", type="primary", use_container_width=True, key=f"{key}_next"):
            if next_ok:
                go_page(next_p)
            else:
                st.error(block_msg or "Complete this step first.")


# ═══════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK (Enterprise v19: Defense Evasion was split into Stealth and Defense Impairment)
# ═══════════════════════════════════════════════════════════════════════════════
ATTACK_VERSION = "v19"
ATTACK_TACTICS = [
    ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"), ("TA0112", "Defense Impairment"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
ATTACK_MITIGATIONS = {
    "M1048": "Application Isolation and Sandboxing", "M1050": "Exploit Protection", "M1030": "Network Segmentation",
    "M1026": "Privileged Account Management", "M1051": "Update Software", "M1016": "Vulnerability Scanning",
    "M1032": "Multi-factor Authentication", "M1027": "Password Policies", "M1018": "User Account Management",
    "M1036": "Account Use Policies", "M1017": "User Training", "M1035": "Limit Access to Resource Over Network",
    "M1042": "Disable or Remove Feature or Program", "M1021": "Restrict Web-Based Content", "M1034": "Limit Hardware Installation",
    "M1038": "Execution Prevention", "M1047": "Audit", "M1022": "Restrict File and Directory Permissions",
    "M1041": "Encrypt Sensitive Information", "M1029": "Remote Data Storage", "M1054": "Software Configuration",
    "M1031": "Network Intrusion Prevention", "M1037": "Filter Network Traffic", "M1057": "Data Loss Prevention",
    "M1053": "Data Backup",
}


def _T(tid, name, tactics, stride, mits, hint, domain="Enterprise"):
    return {"id": tid, "name": name, "tactics": tactics, "stride": stride, "m": mits, "hint": hint, "domain": domain}


ATTACK_TECHNIQUES = [
    _T("T1190", "Exploit Public-Facing Application", ["Initial Access"], "TIE", ["M1048", "M1050", "M1030", "M1026", "M1051", "M1016"], "Patch and harden internet-facing apps; validate all input."),
    _T("T1078", "Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation"], "SE", ["M1032", "M1027", "M1026", "M1018", "M1036", "M1017"], "Stolen or default credentials make the attacker look legitimate."),
    _T("T1566", "Phishing", ["Initial Access"], "S", ["M1017"], "Train users, filter email and verify senders."),
    _T("T1199", "Trusted Relationship", ["Initial Access"], "SE", ["M1030", "M1032", "M1018"], "A compromised partner or vendor connection becomes the way in."),
    _T("T1195", "Supply Chain Compromise", ["Initial Access"], "T", ["M1051", "M1016"], "Verify dependencies, build pipelines and update channels."),
    _T("T1133", "External Remote Services", ["Initial Access", "Persistence"], "S", ["M1032", "M1030", "M1042", "M1035"], "Expose remote access only through MFA-protected, segmented paths."),
    _T("T1189", "Drive-by Compromise", ["Initial Access"], "TE", ["M1048", "M1050", "M1051", "M1021"], "Harden browsers and restrict web content."),
    _T("T1200", "Hardware Additions", ["Initial Access"], "ST", ["M1034"], "Control which devices may attach or enrol."),
    _T("T1059", "Command and Scripting Interpreter", ["Execution"], "TE", ["M1038", "M1026", "M1042"], "Restrict interpreters and never pass user input to a shell."),
    _T("T1203", "Exploitation for Client Execution", ["Execution"], "TE", ["M1048", "M1050", "M1051"], "Keep clients patched and sandboxed."),
    _T("T1505", "Server Software Component", ["Persistence"], "TE", ["M1047", "M1026", "M1022"], "Monitor and lock down server extensions (for example web shells)."),
    _T("T1098", "Account Manipulation", ["Persistence", "Privilege Escalation"], "E", ["M1032", "M1026", "M1018"], "Alert on permission and credential changes."),
    _T("T1136", "Create Account", ["Persistence"], "SE", ["M1032", "M1026", "M1018"], "Control and audit account creation."),
    _T("T1068", "Exploitation for Privilege Escalation", ["Privilege Escalation"], "E", ["M1048", "M1050", "M1051", "M1016"], "Patch, sandbox and scan for vulnerable components."),
    _T("T1548", "Abuse Elevation Control Mechanism", ["Privilege Escalation"], "E", ["M1026", "M1022", "M1047"], "Enforce least privilege and audit elevation."),
    _T("T1134", "Access Token Manipulation", ["Privilege Escalation"], "SE", ["M1026", "M1018"], "Limit who can mint or impersonate tokens."),
    _T("T1611", "Escape to Host", ["Privilege Escalation"], "E", ["M1048", "M1038", "M1026"], "Isolate containers and drop unnecessary privileges."),
    _T("T1070", "Indicator Removal", ["Stealth"], "R", ["M1041", "M1029", "M1022"], "Forward logs off-host quickly and protect them with permissions."),
    _T("T1685", "Disable or Modify Tools", ["Defense Impairment"], "R", [], "Protect logging and security tooling; alert when it stops reporting (this includes clearing or disabling logs)."),
    _T("T1689", "Downgrade Attack", ["Defense Impairment"], "TI", [], "Disable legacy protocol and cipher fallback (for example TLS downgrade)."),
    _T("T1599", "Network Boundary Bridging", ["Defense Impairment"], "TE", ["M1030"], "Protect the devices that separate trusted and untrusted networks."),
    _T("T1556", "Modify Authentication Process", ["Credential Access", "Persistence", "Defense Impairment"], "SE", ["M1032", "M1026", "M1047"], "Protect and audit the authentication path."),
    _T("T1553", "Subvert Trust Controls", ["Defense Impairment"], "ST", [], "Protect signing keys; enforce certificate and code-signing validation."),
    _T("T1110", "Brute Force", ["Credential Access"], "S", ["M1032", "M1036", "M1027", "M1018"], "Lock out, rate-limit and require MFA."),
    _T("T1528", "Steal Application Access Token", ["Credential Access"], "SI", ["M1032", "M1018", "M1017"], "Short-lived, scoped tokens; monitor consent and usage."),
    _T("T1539", "Steal Web Session Cookie", ["Credential Access"], "SI", ["M1017", "M1054"], "Harden session cookies (HttpOnly, Secure, SameSite) and expiry."),
    _T("T1552", "Unsecured Credentials", ["Credential Access"], "I", ["M1041", "M1027", "M1022", "M1047"], "Keep secrets in a vault, never in code, config or logs."),
    _T("T1555", "Credentials from Password Stores", ["Credential Access"], "I", ["M1027"], "Protect and rotate credential stores."),
    _T("T1606", "Forge Web Credentials", ["Credential Access"], "S", ["M1047", "M1026"], "Protect signing keys and validate tokens strictly."),
    _T("T1557", "Adversary-in-the-Middle", ["Credential Access", "Collection"], "STI", ["M1041", "M1030", "M1031"], "Encrypt and authenticate traffic end to end."),
    _T("T1040", "Network Sniffing", ["Credential Access", "Discovery"], "I", ["M1041"], "Encrypt data in transit."),
    _T("T1087", "Account Discovery", ["Discovery"], "I", [], "Limit directory and user enumeration."),
    _T("T1046", "Network Service Discovery", ["Discovery"], "I", ["M1030", "M1031"], "Segment networks and detect scanning."),
    _T("T1021", "Remote Services", ["Lateral Movement"], "SE", ["M1032", "M1030", "M1035"], "Restrict remote services between zones; require MFA."),
    _T("T1550", "Use Alternate Authentication Material", ["Lateral Movement"], "S", ["M1026", "M1018"], "Short-lived credentials and token binding."),
    _T("T1530", "Data from Cloud Storage", ["Collection"], "I", ["M1047", "M1041", "M1032", "M1018"], "Private buckets, least privilege and access logging."),
    _T("T1213", "Data from Information Repositories", ["Collection"], "I", ["M1047", "M1018"], "Restrict and audit access to wikis, tickets and shared repositories."),
    _T("T1005", "Data from Local System", ["Collection"], "I", ["M1057"], "Encrypt local data; apply data-loss prevention."),
    _T("T1119", "Automated Collection", ["Collection"], "I", [], "Rate limits and anomaly detection on bulk access."),
    _T("T1114", "Email Collection", ["Collection"], "I", ["M1032"], "Protect mail access with MFA and audit rules."),
    _T("T1185", "Browser Session Hijacking", ["Collection"], "STI", ["M1017"], "Short sessions, re-authentication for sensitive actions."),
    _T("T1041", "Exfiltration Over C2 Channel", ["Exfiltration"], "I", ["M1031"], "Monitor and filter outbound traffic."),
    _T("T1567", "Exfiltration Over Web Service", ["Exfiltration"], "I", ["M1021"], "Restrict outbound web destinations."),
    _T("T1048", "Exfiltration Over Alternative Protocol", ["Exfiltration"], "I", ["M1037", "M1031", "M1030"], "Egress filtering and protocol allow-lists."),
    _T("T1537", "Transfer Data to Cloud Account", ["Exfiltration"], "I", [], "Restrict cross-account sharing; alert on snapshots and copies."),
    _T("T1499", "Endpoint Denial of Service", ["Impact"], "D", ["M1037"], "Rate limiting, quotas and request-cost limits."),
    _T("T1498", "Network Denial of Service", ["Impact"], "D", ["M1037"], "Upstream filtering and capacity planning."),
    _T("T1496", "Resource Hijacking", ["Impact"], "D", [], "Quotas, budget alerts and workload monitoring."),
    _T("T1489", "Service Stop", ["Impact"], "D", ["M1022", "M1018"], "Protect service control; alert on stopped services."),
    _T("T1485", "Data Destruction", ["Impact"], "DT", ["M1053"], "Tested, isolated backups."),
    _T("T1486", "Data Encrypted for Impact", ["Impact"], "D", ["M1053"], "Offline backups and tested recovery."),
    _T("T1531", "Account Access Removal", ["Impact"], "D", [], "Protect admin accounts; alert on mass password resets or deletions."),
    _T("T1565", "Data Manipulation", ["Impact"], "T", ["M1041", "M1030", "M1022"], "Integrity checks, signing and strict write permissions (includes stored and transmitted data)."),
    _T("T1491", "Defacement", ["Impact"], "T", ["M1053"], "Integrity monitoring and restorable content."),
    _T("T1657", "Financial Theft", ["Impact"], "TS", [], "Out-of-band verification for payment changes; transaction monitoring."),
    # ICS-domain techniques that matter for connected medical / IoT devices (new naming in v19)
    _T("T1692", "Unauthorized Message", ["ICS"], "ST", [], "Authenticate and integrity-protect device commands and reports.", "ICS"),
    _T("T1693", "Modify Firmware", ["ICS"], "T", [], "Signed firmware and secure boot.", "ICS"),
    _T("T1694", "Insecure Credentials", ["ICS"], "S", [], "No default or hard-coded device credentials.", "ICS"),
    _T("T1691", "Block Operational Technology Message", ["ICS"], "D", [], "Detect missing or blocked device messages.", "ICS"),
    _T("T1695", "Block Communications", ["ICS"], "D", [], "Redundant paths and heartbeat monitoring.", "ICS"),
]
ATTACK_BY_ID = {t["id"]: t for t in ATTACK_TECHNIQUES}


def attack_label(t, aligned=False):
    return f"{'⭐ ' if aligned else ''}{t['id']} · {t['name']} — {' / '.join(t['tactics'])}"


def attack_mitigation_hints(rec):
    out = {}
    for tid in rec.get("mitre", []):
        t = ATTACK_BY_ID.get(tid)
        if not t:
            continue
        for m in t["m"]:
            out[m] = ATTACK_MITIGATIONS[m]
        if not t["m"]:
            out[tid] = t["hint"]
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  THREAT ACTOR CATALOG
# ═══════════════════════════════════════════════════════════════════════════════
ACTOR_CATALOG = [
    {"name": "External attacker (opportunistic)", "capability": "Low", "motivation": "Financial gain, vandalism", "entry": "public"},
    {"name": "Malicious or compromised user", "capability": "Medium", "motivation": "Fraud or data theft using legitimate access", "entry": "public"},
    {"name": "Skilled external attacker (targeted)", "capability": "High", "motivation": "Targeted data theft or extortion", "entry": "public"},
    {"name": "Adversary with network access", "capability": "Medium", "motivation": "Intercept or alter data in transit", "entry": "flows"},
    {"name": "Malicious insider / privileged admin", "capability": "High", "motivation": "Abuse of privileged access", "entry": "internal"},
    {"name": "Compromised third party / supply chain", "capability": "Medium", "motivation": "Pivot through a trusted integration", "entry": "third_party"},
    {"name": "Adversary with physical or device access", "capability": "Medium", "motivation": "Tamper with or extract from devices", "entry": "device"},
    {"name": "Automated bot / botnet", "capability": "Low", "motivation": "Credential stuffing, scraping, denial of service", "entry": "public"},
]


def suggest_entries(kind, cfg):
    comps = cfg["scenario"]["components"]
    third = third_party_components(cfg)
    zs = {c["name"]: c.get("zone_score", 3) for c in comps}
    cross = [k for k, v in flow_crossings(cfg).items() if v]
    if kind == "public":
        return [c["name"] for c in comps if (c["type"] == "external_entity" and c["name"] not in third)
                or (c["type"] == "process" and zs[c["name"]] <= 2)][:3]
    if kind == "flows":
        return cross[:2]
    if kind == "internal":
        return [c["name"] for c in comps if c["type"] != "external_entity" and zs[c["name"]] >= 5][:2]
    if kind == "third_party":
        return [c["name"] for c in comps if c["name"] in third][:2]
    if kind == "device":
        return [c["name"] for c in comps if c["type"] != "datastore" and zs[c["name"]] <= 1][:2]
    return []


def get_actors(ws_id=None):
    return [a for a in get_annotations(ws_id) if a["kind"] == "actor"]


def boundary_checked(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    return bool(st.session_state.boundary_checked.get(ws_id))


def zone_rule_expectation(cfg, f):
    zs = {c["name"]: c.get("zone_score", 3) for c in cfg["scenario"]["components"]}
    sz, dz = zs.get(f["source"], 3), zs.get(f["destination"], 3)
    letters = ""
    if sz < dz:
        letters += "T"
    if sz > dz:
        letters += "I"
    if sz == 0:
        letters += "D"
    return letters


def element_rows(cfg):
    scn = cfg["scenario"]
    eid = element_ids(scn)
    cross = flow_crossings(cfg)
    rows = []
    for c in scn["components"]:
        rows.append({"key": c["name"], "id": eid[c["name"]], "name": c["name"], "kind": c["type"], "cross": ""})
    for f in scn["data_flows"]:
        k = _flow_key(f)
        rows.append({"key": k, "id": eid[k], "name": k, "kind": "flow", "cross": ", ".join(cross.get(k, []))})
    return rows


KIND_LABEL = {"external_entity": "External entity", "process": "Process", "datastore": "Data store", "flow": "Data flow"}


def stride_applicability_html():
    head = "".join(f'<th style="padding:4px 10px;color:white;background:{_STRIDE_TAG_COLOR[l]}">{l}</th>' for l in STRIDE_LETTERS)
    rows = []
    for kind in ("external_entity", "process", "datastore", "flow"):
        cells = "".join(f'<td style="text-align:center;padding:4px 10px;border:1px solid #E9E8E6">{"✔" if l in STRIDE_PER_ELEMENT[kind] else "·"}</td>' for l in STRIDE_LETTERS)
        rows.append(f'<tr><td style="padding:4px 10px;border:1px solid #E9E8E6;font-weight:600">{KIND_LABEL[kind]}</td>{cells}</tr>')
    names = "".join(f'<td style="font-size:0.72em;color:#80796B;text-align:center">{STRIDE_NAMES[l].split()[0]}</td>' for l in STRIDE_LETTERS)
    return (f'<table style="border-collapse:collapse;font-size:0.85em"><tr><th></th>{head}</tr><tr><td></td>{names}</tr>{"".join(rows)}</table>')










# ═══════════════════════════════════════════════════════════════════════════════
#  ATT&CK MATRIX HELPER
# ═══════════════════════════════════════════════════════════════════════════════
def attack_matrix_html(records):
    cols = [t for _, t in ATTACK_TACTICS] + ["ICS"]
    cells = {c: [] for c in cols}
    for r in records:
        for tid in r.get("mitre", []):
            t = ATTACK_BY_ID.get(tid)
            if not t:
                continue
            for tac in t["tactics"]:
                if tac in cells:
                    cells[tac].append((tid, r["matched_threat_id"]))
    head = "".join(f'<th style="padding:6px 8px;background:{"#3E897F" if cells[c] else "#EFEFEE"};color:{"white" if cells[c] else "#948D80"};'
                   f'font-size:0.72em;min-width:92px;border:1px solid #fff">{_esc(c)}</th>' for c in cols)
    body = "".join(
        f'<td style="vertical-align:top;padding:6px;border:1px solid #E9E8E6;background:{"#F5F4F3" if cells[c] else "#FAFAFA"};font-size:0.75em">'
        + ("<br>".join(f'<b>{_esc(tid)}</b> <span style="color:#948D80">({_esc(th)})</span>' for tid, th in sorted(set(cells[c]))) or "&nbsp;")
        + "</td>" for c in cols)
    return f'<div style="overflow-x:auto"><table style="border-collapse:collapse"><tr>{head}</tr><tr>{body}</tr></table></div>'




# ═══════════════════════════════════════════════════════════════════════════════
#  REPLACEMENTS: identified threats, label sync, status, review, PDF extras
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
            if rec.get("actors"):
                st.markdown("**Threat actor(s):** " + ", ".join(rec["actors"]))
            _zr = (f"<br><strong>Zone rule applied:</strong> {pred.get('stride_rule_applied', 'N/A')}<br>"
                   f"<strong>From zone:</strong> {pred.get('zone_from', 'N/A')} → <strong>To zone:</strong> {pred.get('zone_to', 'N/A')}"
                   if int(st.session_state.current_step) >= 4 else "")
            st.markdown(f"""<div class="stride-rule-box"><strong>Threat scenario:</strong> {_esc(rec.get('threat_text') or pred['threat'])}{_zr}</div>""", unsafe_allow_html=True)
            if rec.get("source") == "EoP card activity":
                st.caption(f"🃏 EoP-inspired card: {rec.get('eop_card_title', '—')} · Evidence: {rec.get('eop_evidence') or 'not recorded'} · ATT&CK/CAPEC note: {rec.get('eop_attack_mapping') or 'not mapped'}")
            if pred.get("explanation"):
                st.markdown(f"""
                <div style="background:#F5F4F3;border-radius:8px;padding:12px 16px;margin:6px 0">
                <strong style="color:#274F4A">📖 Explanation</strong><br>
                <span style="font-size:0.91em;color:#423F3A">{pred['explanation']}</span></div>""", unsafe_allow_html=True)


def sync_labels_from_analysis(include_controls=False):
    ws = st.session_state.selected_workshop
    items = get_annotations(ws)
    seen = {i.get("origin") for i in items}
    added = 0
    for r in st.session_state.user_answers:
        origin = f"threat:{r['matched_threat_id']}"
        links = list(r.get("actors", []))
        if origin in seen:
            lab = next(i for i in items if i.get("origin") == origin)
            tid = lab["id"]
            lab["links"] = sorted(set(lab.get("links", [])) | set(links))
            lab["stride"] = STRIDE_LETTER_OF.get(r["stride"], lab.get("stride", ""))
        else:
            tid = _next_annotation_id(items, "threat")
            items.append({"id": tid, "kind": "threat", "label": _trunc(r["predefined_threat"].get("threat", ""), 80),
                          "target": r["component"], "links": links, "notes": "", "origin": origin,
                          "stride": STRIDE_LETTER_OF.get(r["stride"], "")})
            seen.add(origin); added += 1
        if include_controls and r.get("controlled"):
            for m in r.get("selected_mitigations", []):
                o2 = f"ctrl:{r['matched_threat_id']}:{m}"
                if o2 not in seen:
                    items.append({"id": _next_annotation_id(items, "control"), "kind": "control", "label": _trunc(m, 80),
                                  "target": r["component"], "links": [tid], "notes": "", "origin": o2})
                    seen.add(o2); added += 1
    return added






def build_pdf_extra():
    ws = st.session_state.selected_workshop
    return {"scope": get_scope(ws), "open_questions": get_open_questions(ws), "review_plan": get_review_plan(ws),
            "labels": list(get_annotations(ws)), "stride_map": dict(get_stride_map(ws))}



# ═══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div class="brand">
      <div class="logo">🔒</div>
      <div class="name">Threat Modeling Lab</div>
      <div class="tag">Scope → DFD → STRIDE → Trust boundaries → ATT&amp;CK · CAPEC → Scoring → Controls → Residual risk → Review</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.caption("Build: EoP-integrated threat register · 2026-10-11 · revision 4")
    st.markdown("**🗺️ The 9 Steps**")
    st.markdown("""
    1. 📐 **Scope & goals** – what, assumptions, exclusions
    2. 🗺️ **Data-flow diagram** – system, assets, elements, flows
    3. ⚡ **Apply STRIDE** – map every element, write scenarios
    4. 🚧 **Trust boundaries** – crossings, zones, zone rules
    5. 🎯 **ATT&CK · CAPEC** – actors, attack patterns, threat statements
    6. 📊 **Risk scoring** – impact × likelihood
    7. 🛡️ **Control selection** – OWASP-mapped controls
    8. ⚖️ **Residual risk** – what remains, open questions
    9. 🔁 **Review schedule** – owner, cadence, triggers
    """)
    st.markdown("---")

    if st.session_state.selected_workshop:
        ws_name = WORKSHOPS.get(st.session_state.selected_workshop,{}).get("name","")
        step_names = {p: v[0] for p, v in PAGES.items()}
        cur_step_name = step_names.get(st.session_state.current_step,"")
        ws_level = WORKSHOPS.get(st.session_state.selected_workshop,{}).get("level","")
        st.markdown(f"""
        <div class="now-card">
          <div class="now-eyebrow">Now studying</div>
          <div class="now-title">{ws_name}</div>
          <div class="now-meta">{ws_level} · {cur_step_name}</div>
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.max_score > 0:
            pct = st.session_state.total_score / st.session_state.max_score * 100
            bar_color = "#4A994D" if pct >= 80 else "#E9A435" if pct >= 60 else "#D84642"
            st.markdown(f"""
            <div class="score-line">
            Score: <strong>{st.session_state.total_score}/{st.session_state.max_score}</strong>
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
    _lab_step = int(st.session_state.current_step) if st.session_state.selected_workshop else 99
    _stride_ok, _zone_ok = _lab_step >= 3, _lab_step >= 4     # reference material appears only once its step is reached
    if _stride_ok:
        with st.expander("⚡ STRIDE Quick Reference"):
            stride_items = [
                ("S","Spoofing","#FBD1D5","Identity impersonation — pretending to be someone else","Zone-0 reachable nodes"),
                ("T","Tampering","#F9DFB8","Data modification — altering data or code","Less→more critical flows"),
                ("R","Repudiation","#FBF5C8","Denying actions — no proof of who did what","Nodes with Spoofing+Tampering"),
                ("I","Info Disclosure","#E5F5F3","Data exposure — secrets reaching wrong party","More→less critical flows"),
                ("D","DoS","#F1E8F2","Availability — crashing or degrading services","Zone-0→any node flows"),
                ("E","EoP","#EFEFEE","Privilege escalation — gaining unauthorized access","Higher nodes adj to lower"),
            ]
            for letter, name, bg, desc, rule in stride_items:
                st.markdown(f"""
                <div style="background:{bg};border-radius:6px;padding:8px 10px;margin:3px 0;font-size:0.82em">
                  <strong style="font-size:1em">{letter} — {name}</strong><br>
                  <span style="color:#444">{desc}</span><br>
                  {'<span style="color:#777;font-size:0.85em">Rule: ' + rule + '</span>' if _zone_ok else ''}
                </div>
                """, unsafe_allow_html=True)

    if _zone_ok:
        with st.expander("🏷️ Zone Scale (0–9)"):
            zone_mini = [
                (0,"Not in Control","#EFEEED","#7F786B"),
                (1,"Minimal Trust","#CAE4CB","#3E8842"),
                (3,"Standard App","#FBF5C8","#E9A435"),
                (5,"Elevated Trust","#F9DFB8","#D55611"),
                (7,"Critical","#FBD1D5","#BA3434"),
                (9,"Maximum Security","#F7AF99","#B23D19"),
            ]
            for score, label, bg, border in zone_mini:
                st.markdown(f"""
                <div style="background:{bg};border-left:3px solid {border};border-radius:4px;
                            padding:5px 8px;margin:2px 0;font-size:0.8em">
                  <strong>z{score}</strong> — {label}
                </div>
                """, unsafe_allow_html=True)

    if _zone_ok:
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
    <div class="hero">
      <div class="eyebrow">Threat modeling lab</div>
      <h1>STRIDE Threat Modeling Mastery Lab</h1>
      <p>From security novice to professional threat modeler in four progressive workshops, following a nine-step process from scope to review.</p>
      <div class="chips">
        <span class="chip">4 hands-on workshops</span>
        <span class="chip">30 real-world threats</span>
        <span class="chip">Live architecture diagrams</span>
        <span class="chip">MITRE ATT&amp;CK mapping</span>
        <span class="chip">OWASP Top 10 aligned</span>
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
    home_tabs = st.tabs(["🗺️ Learning Path", "🧠 What You'll Master", "📋 The 9-Step Process", "🏆 Skill Tree"])

    with home_tabs[0]:
        st.markdown("### Your Journey from Novice to Expert")
        st.markdown("""
        <div class="info-box">
        This lab uses the <strong>Infosec Institute 4-Step Methodology</strong> — the same framework used
        by Microsoft, OWASP, and enterprise security teams. Each workshop adds a new layer of complexity,
        building on what you've learned before.<br><br>
        Every workshop follows the same <strong>9 steps</strong>: Scope → DFD → STRIDE → Trust boundaries → ATT&amp;CK · CAPEC · threat statements → Risk scoring → Controls → Residual risk → Review schedule.
        </div>
        """, unsafe_allow_html=True)

        ws_data = list(WORKSHOPS.items())
        level_colors = {"Foundation":"#368D82","Intermediate":"#347737","Advanced":"#D55611","Expert":"#703988"}
        level_icons  = {"Foundation":"🌱","Intermediate":"🌿","Advanced":"🌳","Expert":"🔥"}
        for idx, (ws_id, ws) in enumerate(ws_data):
            unlocked  = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            lc = level_colors.get(ws["level"], "#226259")
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
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">📊 {ws['level']}</span>
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">⏱️ {ws['duration']}</span>
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">🎯 {ws['target_threats']} threats</span>
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">🏗️ {ws.get('architecture_type','')}</span>
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
        st.markdown("### The 9 steps you follow in every workshop")
        st.markdown("""
| Step | What you produce | Where the Infosec 4-step method fits |
|---|---|---|
| 1. 📐 **Scope & goals** | System in scope, must-do / must-never rules, assumptions, exclusions, measurable goals | — (added up front) |
| 2. 🗺️ **Data-flow diagram** | Assets, elements (E, P, D) and flows (F) | Step 1 *Design* |
| 3. ⚡ **Apply STRIDE** | STRIDE mapped to every element, plus written threat scenarios | Step 3 *Discover threats* |
| 4. 🚧 **Trust boundaries** | Boundary-crossing flows, zones of trust (0–9), STRIDE re-checked with zone rules | Step 2 *Zones of Trust* |
| 5. 🎯 **ATT&CK · CAPEC** | Threat actors, ATT&CK techniques, CAPEC patterns and one threat statement per threat | — (added) |
| 6. 📊 **Risk scoring** | Impact × likelihood on a 1–3 scale → risk score 1–9 | — (added) |
| 7. 🛡️ **Control selection** | Guardrails, filtering, access rules and monitoring, mapped to OWASP | Step 4 *Mitigations* |
| 8. ⚖️ **Residual risk** | Risk after controls, decisions, open questions | — (added) |
| 9. 🔁 **Review schedule** | Owner, review cadence, full-workshop and update triggers | — (added) |
""")
        st.markdown("### The Infosec 4-step method in detail")
        steps_detail = [
            ("1", "Design the Threat Model", "#F1F0EF", "#35A091",
             "Create a Data Flow Diagram (DFD) that captures the complete system architecture.",
             ["Identify all <strong>Interactors</strong> — external people and systems you don't control",
              "Map all <strong>Modules</strong> — processes that transform data + data stores that persist it",
              "Draw all <strong>Connections</strong> — every data flow, its protocol, and what data it carries",
              "Document <strong>Trust Boundaries</strong> — the lines where control or ownership changes"],
             "Before you can find threats you must know exactly what you're protecting. A missing component in the diagram means a missed threat.",
             "Microsoft Threat Modeling Tool, STRIDE-per-Element, DFD Level 0/1/2"),
            ("2", "Apply Zones of Trust", "#FBF5C8", "#E48028",
             "Assign every component a criticality level from 0 (untrusted) to 9 (life-critical).",
             ["Zone 0: Not in system control (external users, 3rd party services)",
              "Zone 1–2: Entry points — minimal authentication enforced",
              "Zone 3–4: Application layer — standard security controls",
              "Zone 5–6: Elevated trust — privileged services, payment processing",
              "Zone 7–8: Critical — databases, regulated data stores",
              "Zone 9: Maximum security — safety-critical, life-critical systems"],
             "Zones turn threat discovery from art into science. The zone difference between source and destination tells you which STRIDE categories mechanically apply.",
             "Microsoft SDL Zone of Trust, NIST 800-207 Zero Trust"),
            ("3", "Discover Threats with STRIDE", "#F9DFB8", "#D55611",
             "Apply zone-direction rules to systematically derive applicable STRIDE threats.",
             ["<strong>Flows:</strong> Tampering on less→more critical flows; Info Disclosure on more→less",
              "<strong>Flows from Zone 0:</strong> Always check Denial of Service",
              "<strong>Nodes reachable from Zone 0:</strong> Spoofing applies",
              "<strong>Nodes where Spoofing + Tampering both apply:</strong> Repudiation applies",
              "<strong>Higher-zone nodes adjacent to lower-zone nodes:</strong> Elevation of Privilege"],
             "These rules come from Microsoft's original STRIDE paper. They make threat discovery repeatable — two analysts working independently produce the same threat list.",
             "STRIDE-per-Element, SAFECode Threat Modeling, OWASP Threat Dragon"),
            ("4", "Explore Mitigations and Controls", "#EFEFEE", "#347737",
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
            "Foundation":  "#368D82",
            "Intermediate":"#205924",
            "Advanced":    "#D55611",
            "Expert":      "#4C2C74",
        }
        cols_tree = st.columns(4)
        for col, (ws_label, level, skills_list, done) in zip(cols_tree, skill_tree):
            with col:
                grad = level_grad.get(level,"#226259")
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
ws_level_color = {"Foundation":"#368D82","Intermediate":"#347737","Advanced":"#D55611","Expert":"#703988"}.get(current_workshop["level"],"#226259")
st.markdown(f"""
<div style="display:flex;align-items:center;gap:16px;margin-bottom:4px">
  <div>
    <h1 style="margin:0;color:#226259">{current_workshop['name']}</h1>
    <div style="display:flex;gap:8px;margin-top:6px;flex-wrap:wrap">
      <span style="background:{ws_level_color};color:white;padding:3px 12px;border-radius:12px;font-size:0.82em;font-weight:600">{current_workshop['level']}</span>
      <span style="background:#F5F4F3;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">⏱️ {current_workshop['duration']}</span>
      <span style="background:#F5F4F3;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">🎯 {current_workshop['target_threats']} threats</span>
      <span style="background:#F5F4F3;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">🏗️ {current_workshop.get('architecture_type','')}</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Step tracker: 9 steps, then wrap-up ──
_page = int(st.session_state.current_step)
_page_name, _stage_id = PAGES.get(_page, ("", "scope"))
_stage_idx = STAGE_IDS.index(_stage_id) if _stage_id in STAGE_IDS else len(STAGES)   # wrap-up pages: every step is done
_parts = []
for _i, (_sid, _label, _icon) in enumerate(STAGES):
    _state = "done" if _i < _stage_idx else ("active" if _i == _stage_idx else "todo")
    _dot = "✓" if _state == "done" else (_icon if _state == "active" else str(_i + 1))
    _parts.append(f'<div class="stg stg-{_state}"><div class="stg-dot">{_dot}</div><div class="stg-label">{_label}</div></div>')
_sep = '<div class="stg-line"></div>'
st.markdown('<div class="stepper">' + _sep.join(_parts) + '</div>', unsafe_allow_html=True)
if _stage_idx < len(STAGES):
    st.caption(f"Step {_stage_idx + 1} of {len(STAGES)} · **{STAGES[_stage_idx][1]}**")
else:
    st.caption(f"All {len(STAGES)} steps complete · **{_page_name}**")
st.progress(((PAGE_ORDER.index(_page) + 1) / len(PAGE_ORDER)) if _page in PAGE_ORDER else 0.05)
st.markdown("---")



# ═════════════════════════════════════════════════════════════════════════════════════════════
#  9-STEP LAB FLOW — scaffolding shared by every step
#  Each step page = header card (goal / output / why) → numbered sub-steps → checkpoint → navigation.
#  The same IDs (A01 assets, E/P/D elements, F flows, TS threats) follow the learner through all nine steps.
# ═════════════════════════════════════════════════════════════════════════════════════════════
STEP_CSS = """<style>
.step-card{background:var(--surface);border:1px solid var(--line);border-left:5px solid var(--accent);border-radius:12px;padding:14px 20px;margin:6px 0 10px}
.step-card .row{display:flex;gap:22px;flex-wrap:wrap}
.step-card .cell{flex:1 1 230px;font-size:.93rem;line-height:1.5}
.step-card .lbl{font-size:.7rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--accent);margin-bottom:2px}
.substep{display:flex;align-items:center;gap:10px;margin:28px 0 2px;font-weight:650;font-size:1.14rem;color:var(--ink)}
.substep .n{background:var(--accent);color:#fff;border-radius:8px;padding:2px 9px;font-size:.84rem;font-weight:700}
.checkpoint{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px 18px;margin:22px 0 4px;line-height:1.7}
.threat-stmt{background:var(--learn-soft);border:1px solid var(--learn-line);border-radius:10px;padding:10px 14px;margin:6px 0;font-size:.95rem;line-height:1.6}
.threat-stmt b{color:var(--learn)}
</style>"""

STEP_TEXT = {
    1: ("Draw a box around the one system you are protecting and agree what “secure” means for it.",
        "System statement, must-do / must-never rules, assumptions, exclusions, measurable goals.",
        "Every later step is judged against this. Unstated assumptions are the most common source of missed threats."),
    2: ("Turn the deployed system into a simple diagram built from four element types.",
        "Labelled assets (A01…), element IDs (E / P / D) and data-flow IDs (F…).",
        "You can only find threats on things you have drawn. The IDs follow you through every later step."),
    3: ("Ask the six STRIDE questions of every element, then write concrete threat scenarios.",
        "A STRIDE map for each element and a list of threat scenarios (TS…).",
        "STRIDE turns “what could go wrong?” into a repeatable checklist, so results do not depend on intuition."),
    4: ("Mark where trust changes, give each element a zone, and use zone direction to re-check your STRIDE map.",
        "Boundary-crossing flows, zone labels (0–9) and a STRIDE map checked against the zone rules.",
        "Most serious threats sit where data crosses a boundary. Zones tell you which STRIDE categories to expect there."),
    5: ("Name who would attack, show how they would do it (ATT&CK and CAPEC) and write every threat as one clear statement.",
        "Threat actors, ATT&CK techniques, CAPEC attack patterns and one threat statement per threat.",
        "Real attacker behaviour makes a threat testable and links it to published mitigations and detection ideas."),
    6: ("Rank the threats so you spend effort where it matters.",
        "Impact × likelihood score (1–9) for every threat and a risk register.",
        "You cannot fix everything. A rough, shared ranking beats a perfect one nobody finishes."),
    7: ("Choose practical controls for the risks that matter and show they are layered.",
        "Controls per threat across four categories, with a defence-in-depth check.",
        "A control without a named threat is guesswork; a threat without a control is an open risk."),
    8: ("Record what risk remains after the controls and what you still do not know.",
        "Residual risk and a decision per threat, open questions and an accepted-risk statement.",
        "Controls rarely remove risk. Writing down the remainder sets realistic expectations for the whole team."),
    9: ("Keep the model alive: owner, review cadence and the events that force an update.",
        "Owner, next review date, full-workshop triggers, lightweight checks and update triggers.",
        "A threat model that is never revisited becomes false comfort as the system changes."),
}


def step_header(n, title):
    goal, produce, why = STEP_TEXT[n]
    st.markdown(STEP_CSS, unsafe_allow_html=True)
    st.header(f"Step {n} of {len(STAGES)} · {title}")
    st.markdown('<div class="step-card"><div class="row">'
                f'<div class="cell"><div class="lbl">Goal</div>{goal}</div>'
                f'<div class="cell"><div class="lbl">You will produce</div>{produce}</div>'
                f'<div class="cell"><div class="lbl">Why it matters</div>{why}</div>'
                '</div></div>', unsafe_allow_html=True)
    scope_reminder()


def substep(code, title, hint=""):
    st.markdown(f'<div class="substep"><span class="n">{code}</span>{title}</div>', unsafe_allow_html=True)
    if hint:
        st.caption(hint)


def checkpoint(items):
    """items = [(done, text)]. Shows what is still missing and returns True when everything is done."""
    rows = "".join(f"<div>{'✅' if ok else '⬜'} {_esc(t)}</div>" for ok, t in items)
    st.markdown(f'<div class="checkpoint"><strong>Checkpoint — finish these to continue</strong>{rows}</div>', unsafe_allow_html=True)
    return all(ok for ok, _ in items)


# ─────────────────────────────────────────────────────────────────────────────
#  STRIDE quick reference (Step 3)
# ─────────────────────────────────────────────────────────────────────────────
STRIDE_INFO = [
    ("S", "Spoofing", "Authenticity", "Can someone pretend to be a user, device or service they are not?",
     "A stolen session token is used to act as another customer"),
    ("T", "Tampering", "Integrity", "Can data or code be changed in transit, at rest or in memory?",
     "The order total is altered in the API request"),
    ("R", "Repudiation", "Non-repudiation", "Could someone deny an action because nothing proves who did it?",
     "An admin deletes records and the audit log has no user ID"),
    ("I", "Information disclosure", "Confidentiality", "Can data reach someone who should not see it?",
     "A verbose error page exposes SQL and customer data"),
    ("D", "Denial of service", "Availability", "Can the service be made slow, unavailable or too costly to run?",
     "The login endpoint is flooded with requests"),
    ("E", "Elevation of privilege", "Authorization", "Can someone do more than they are allowed to?",
     "A normal user calls an admin API by changing an ID"),
]
GOAL_OF_STRIDE = {l: g.lower() for l, _, g, _, _ in STRIDE_INFO}
STATEMENT_HINTS = {
    "S": ("replay a stolen session token against the order API", "access to another customer's account"),
    "T": ("change the price field in a request before it reaches the API", "orders processed at the wrong price"),
    "R": ("delete records without a user ID being logged", "no proof of who performed the action"),
    "I": ("read other tenants' rows through a missing filter", "customer data exposed to the wrong party"),
    "D": ("flood the login endpoint with requests", "legitimate users unable to sign in"),
    "E": ("change an object ID to call an admin function", "full control of data they should not reach"),
}


# ─────────────────────────────────────────────────────────────────────────────
#  CAPEC attack patterns (MITRE Common Attack Pattern Enumeration and Classification)
#  ATT&CK = what adversaries DO (techniques); CAPEC = HOW a weakness is exploited (patterns).
#  `stride` = categories the pattern usually serves; `kw` = words that signal a scenario match.
#  Verify details at https://capec.mitre.org/ before quoting an ID in a formal report.
# ─────────────────────────────────────────────────────────────────────────────
def _C(num, name, stride, kw):
    return {"id": f"CAPEC-{num}", "num": num, "name": name, "stride": stride, "kw": kw}


CAPEC_PATTERNS = [
    _C(151, "Identity Spoofing", "S", ["impersonat", "spoof", "fake", "forge", "device identity", "clone"]),
    _C(194, "Fake the Source of Data", "S", ["spoof", "forged", "fake", "unsigned", "unauthenticated", "sensor"]),
    _C(633, "Token Impersonation", "SE", ["token", "jwt", "oauth", "bearer", "api key", "service account"]),
    _C(593, "Session Hijacking", "S", ["session", "cookie", "hijack", "xss"]),
    _C(60, "Reusing Session IDs (Session Replay)", "ST", ["replay", "captured", "session id", "reuse"]),
    _C(600, "Credential Stuffing", "S", ["credential", "password", "stuffing", "login"]),
    _C(49, "Password Brute Forcing", "S", ["brute", "password", "guess", "pin", "login"]),
    _C(560, "Use of Known Domain Credentials", "SE", ["credential", "stolen", "leaked", "valid account"]),
    _C(98, "Phishing", "S", ["phish", "social engineering", "email", "lure"]),
    _C(225, "Exploiting Multi-Factor Authentication", "S", ["mfa", "2fa", "otp", "second factor"]),
    _C(115, "Authentication Bypass", "SE", ["bypass", "authentication", "unauthenticated", "missing auth", "no auth"]),
    _C(114, "Authentication Abuse", "S", ["authentication", "auth", "login", "trust"]),
    _C(657, "Malicious Automated Software Update via Spoofing", "ST", ["update", "firmware", "ota", "package", "patch"]),
    _C(186, "Malicious Software Update", "T", ["update", "firmware", "ota", "supply chain", "dependency", "package"]),
    _C(184, "Software Integrity Attack", "T", ["integrity", "supply chain", "build", "pipeline", "dependency", "tamper"]),
    _C(66, "SQL Injection", "TIE", ["sql", "injection", "query", "database"]),
    _C(248, "Command Injection", "TE", ["command", "shell", "os command", "exec"]),
    _C(242, "Code Injection", "TE", ["code injection", "script", "eval", "deserial"]),
    _C(586, "Object Injection", "TE", ["deserial", "object", "serializ"]),
    _C(63, "Cross-Site Scripting (XSS)", "TSI", ["xss", "script", "cross-site", "frontend", "browser"]),
    _C(62, "Cross Site Request Forgery", "T", ["csrf", "forged request", "browser", "cross-site"]),
    _C(153, "Input Data Manipulation", "T", ["input", "parameter", "price", "payload", "validation", "manipulat"]),
    _C(39, "Manipulating Opaque Client-based Data Tokens", "TS", ["client-side", "hidden field", "cookie", "token", "tamper"]),
    _C(22, "Exploiting Trust in Client", "T", ["client-side", "client", "trust", "validation", "mobile app"]),
    _C(272, "Protocol Manipulation", "T", ["protocol", "mqtt", "ble", "bluetooth", "grpc", "message", "header"]),
    _C(216, "Communication Channel Manipulation", "TI", ["channel", "mitm", "intercept", "in transit", "plaintext", "unencrypted"]),
    _C(94, "Adversary in the Middle (AiTM)", "TI", ["mitm", "in the middle", "intercept", "tls", "certificate", "in transit"]),
    _C(165, "File Manipulation", "T", ["file", "config", "configuration", "log file", "modif"]),
    _C(176, "Configuration/Environment Manipulation", "TE", ["configuration", "misconfig", "environment", "settings", "feature flag"]),
    _C(268, "Audit Log Manipulation", "TR", ["audit", "log", "tamper", "delete log", "logging"]),
    _C(93, "Log Injection-Tampering-Forging", "TR", ["log", "forg", "audit trail", "repudiat"]),
    _C(157, "Sniffing Attacks", "I", ["sniff", "plaintext", "unencrypted", "eavesdrop", "wifi", "ble"]),
    _C(158, "Sniffing Network Traffic", "I", ["network traffic", "packet", "unencrypted", "plaintext", "tls", "in transit"]),
    _C(117, "Interception", "I", ["intercept", "capture", "in transit", "eavesdrop"]),
    _C(54, "Query System for Information", "I", ["error message", "verbose", "enumerat", "metadata", "stack trace", "debug"]),
    _C(116, "Excavation", "I", ["probe", "enumerat", "discover", "reconnaissance"]),
    _C(150, "Collect Data from Common Resource Locations", "I", ["backup", "bucket", "storage", "snapshot", "config file", "secret"]),
    _C(37, "Retrieve Embedded Sensitive Data", "I", ["hardcoded", "embedded", "secret", "api key", "firmware", "binary"]),
    _C(204, "Lifting Sensitive Data Embedded in Cache", "I", ["cache", "cached", "redis", "memory"]),
    _C(126, "Path Traversal", "IT", ["path", "traversal", "../", "file access", "directory"]),
    _C(131, "Resource Leak Exposure", "DI", ["leak", "exhaust", "memory", "connection pool"]),
    _C(125, "Flooding", "D", ["flood", "ddos", "dos", "overload", "burst", "rate limit", "exhaust"]),
    _C(488, "HTTP Flood", "D", ["http", "flood", "request", "api", "rate limit"]),
    _C(130, "Excessive Allocation", "D", ["allocation", "memory", "resource", "quota", "unbounded", "exhaust", "noisy neighbor", "noisy neighbour"]),
    _C(197, "Exponential Data Expansion", "D", ["payload", "xml", "json", "expansion", "bomb", "large"]),
    _C(492, "Regular Expression Exponential Blowup", "D", ["regex", "regular expression", "cpu"]),
    _C(1, "Accessing Functionality Not Properly Constrained by ACLs", "E", ["admin", "acl", "access control", "authorization", "function", "idor", "bola", "role"]),
    _C(122, "Privilege Abuse", "E", ["privilege", "insider", "excessive", "least privilege", "role"]),
    _C(233, "Privilege Escalation", "E", ["escalat", "privilege", "root", "admin", "lateral"]),
    _C(180, "Exploiting Incorrectly Configured Access Control Security Levels", "E", ["misconfig", "permission", "policy", "iam", "rbac", "tenant"]),
    _C(87, "Forceful Browsing", "EI", ["enumerat", "predictable", "direct object", "idor", "url", "guess"]),
    _C(121, "Exploit Non-Production Interfaces", "EI", ["debug", "test", "staging", "maintenance", "non-production", "diagnostic"]),
    _C(36, "Using Unpublished Interfaces or Functionality", "EI", ["undocumented", "hidden", "internal api", "shadow", "unpublished"]),
    _C(212, "Functionality Misuse", "TDE", ["abuse", "misuse", "business logic", "workflow", "feature"]),
    _C(510, "SaaS User Request Forgery", "T", ["saas", "tenant", "cross-tenant", "forged request"]),
]
CAPEC_BY_ID = {c["id"]: c for c in CAPEC_PATTERNS}


def capec_label(c, tag=""):
    return f"{tag}{c['id']} · {c['name']}  [{c['stride']}]"


def _threat_words(rec):
    p = rec["predefined_threat"]
    return " ".join([p.get("threat", ""), rec.get("component", ""), p.get("explanation", "")[:240]]).lower()


def capec_ranked(rec):
    """CAPEC patterns ordered by fit to this scenario: keyword hits in the threat text first, then STRIDE category."""
    letter = STRIDE_LETTER_OF.get(rec["stride"], "")
    txt = _threat_words(rec)
    out = []
    for c in CAPEC_PATTERNS:
        hits = sum(1 for k in c["kw"] if k in txt)
        out.append((-(2 * hits + (3 if letter in c["stride"] else 0)), c["num"], c, hits, letter in c["stride"]))
    out.sort(key=lambda x: (x[0], x[1]))
    return [(c, hits, fit) for _, _, c, hits, fit in out]


def attack_ranked(rec):
    """ATT&CK techniques ordered by fit: scenario words in the technique text, STRIDE category, Enterprise first."""
    letter = STRIDE_LETTER_OF.get(rec["stride"], "")
    words = {w for w in re.findall(r"[a-z]{5,}", _threat_words(rec))}
    out = []
    for t in ATTACK_TECHNIQUES:
        tw = set(re.findall(r"[a-z]{5,}", (t["name"] + " " + t["hint"]).lower()))
        out.append((-len(words & tw), letter not in t["stride"], t["domain"] != "Enterprise", t["id"], t))
    out.sort(key=lambda x: x[:4])
    return [x[4] for x in out]


# ─────────────────────────────────────────────────────────────────────────────
#  Threat statements — AWS Threat Composer grammar
#  "A [threat source] [with prerequisites] can [threat action], which leads to [threat impact],
#   resulting in reduced [impacted goal] of [impacted assets]."
# ─────────────────────────────────────────────────────────────────────────────
STATEMENT_GOALS = ["confidentiality", "integrity", "availability", "authenticity", "authorization", "non-repudiation"]


def compose_statement(stm):
    src = re.sub(r"\s*\(.*?\)", "", (stm.get("source") or "…")).strip() or "…"
    if len(src) > 1 and not src[1].isupper():
        src = src[0].lower() + src[1:]          # "External attacker" -> "external attacker"
    art = "An" if src[:1].lower() in "aeiou" else "A"
    pre = (stm.get("prereq") or "").strip()
    act = (stm.get("action") or "…").strip().rstrip(".")
    imp = (stm.get("impact") or "…").strip().rstrip(".")
    goal = stm.get("goal") or "…"
    assets = ", ".join(stm.get("assets") or []) or "…"
    return f"{art} {src}{(' ' + pre) if pre else ''} can {act}, which leads to {imp}, resulting in reduced {goal} of {assets}."


def statement_complete(rec):
    s_ = rec.get("statement") or {}
    return all(s_.get(k) for k in ("source", "action", "impact", "goal")) and bool(s_.get("assets"))


def statement_html(rec):
    s_ = rec.get("statement") or {}
    return '<div class="threat-stmt">' + _esc(compose_statement(s_)) + "</div>" if s_ else ""



# ═════════════════════════════════════════════════════════════════════════════════════════════
#  STEP 2 · DATA-FLOW DIAGRAM   (architecture + assets + elements + flows in one page)
# ═════════════════════════════════════════════════════════════════════════════════════════════
def render_dfd_step():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    items = get_annotations(ws)
    eid = element_ids(s)
    step_header(2, "Data-flow diagram")

    # 2.1 ─ vocabulary: the four element types
    substep("2.1", "Learn the four DFD building blocks",
            "Every DFD uses only these four shapes. Classify each thing in the system as one of them.")
    sym = {"external_entity": ("Rectangle", "E", "A person or system outside your control that sends or receives data"),
           "process": ("Circle / oval", "P", "Code that receives, transforms or forwards data"),
           "datastore": ("Two parallel lines", "D", "Anything that keeps data at rest"),
           "flow": ("Arrow", "F", "Data moving from one element to another, over a protocol")}
    rows = []
    for kind in ("external_entity", "process", "datastore", "flow"):
        if kind == "flow":
            here = f"{len(s['data_flows'])} flows (see 2.2)"
        else:
            here = ", ".join(c["name"] for c in s["components"] if c["type"] == kind) or "—"
        rows.append({"Element": KIND_LABEL[kind], "Shape": sym[kind][0], "ID": sym[kind][1] + "n", "What it is": sym[kind][2], "In this system": here})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # 2.2 ─ the diagram itself
    substep("2.2", "Read the data-flow diagram",
            "Elements and flows only — no boundaries or zones yet. Those are added on top of this same diagram in Step 4.")
    show_architecture_diagram(cfg, mode="dfd", key_suffix="s2_dfd", editable=True, default_kind="asset", flat=True)
    with st.expander("📊 Elements and flows with IDs", expanded=False):
        st.dataframe(pd.DataFrame([{"ID": eid[c["name"]], "Element": c["name"], "Type": KIND_LABEL[c["type"]],
                                    "Description": c["description"]} for c in s["components"]]), use_container_width=True, hide_index=True)
        st.dataframe(pd.DataFrame([{"ID": eid[_flow_key(f)], "Flow": _flow_key(f), "Data": f["data"], "Protocol": f["protocol"]}
                                   for f in s["data_flows"]]), use_container_width=True, hide_index=True)
    with st.expander("🔍 Three questions to ask about every flow", expanded=False):
        st.markdown("1. **What data** does it carry, and how sensitive is it?\n"
                    "2. **Which protocol** carries it, and is that protocol encrypted and authenticated?\n"
                    "3. **Which direction** does it go, and which side starts it?\n\n"
                    "Keep the answers: you will use them in Steps 3 and 4.")

    # 2.3 ─ assets
    substep("2.3", "Map your assets onto the diagram",
            "An asset is what you are protecting. Attach each one from your scope to the element or flow that holds or carries it. "
            "Asset labels (A01, A02…) appear on the diagram above.")
    targets = [c["name"] for c in s["components"]] + list(dict.fromkeys(_flow_key(f) for f in s["data_flows"]))
    existing = {i.get("origin"): i for i in items if i["kind"] == "asset" and i.get("origin")}
    with st.form("asset_map_form"):
        picks = {}
        for idx, asset in enumerate(s.get("assets", [])):
            cur = existing.get(f"asset:{asset}", {}).get("target")
            opts = ["— not mapped —"] + targets
            picks[asset] = st.selectbox(asset, opts, index=opts.index(cur) if cur in opts else 0, key=f"w_asset_{ws}_{idx}")
        if st.form_submit_button("💎 Save asset map", type="primary"):
            for asset, tgt in picks.items():
                origin = f"asset:{asset}"
                if tgt == "— not mapped —":
                    items[:] = [i for i in items if i.get("origin") != origin]
                elif origin in existing:
                    existing[origin]["target"] = tgt
                else:
                    items.append({"id": _next_annotation_id(items, "asset"), "kind": "asset", "label": asset, "target": tgt,
                                  "links": [], "notes": "", "origin": origin})
            save_progress()
            st.rerun()

    n_assets = sum(1 for i in items if i["kind"] == "asset")
    ok = checkpoint([(True, f"DFD ready: {len(s['components'])} elements and {len(s['data_flows'])} data flows"),
                     (n_assets >= 2, f"Map at least two assets to elements or flows ({n_assets} mapped)")])
    nav_buttons(1, "", 3, "", ok, "Label at least two assets (use the asset map above or the label editor).", key="p2")


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  STEP 3 · APPLY STRIDE   (learn → map every element → write threat scenarios)
# ═════════════════════════════════════════════════════════════════════════════════════════════
def _stride_mapping_section():
    """STRIDE-per-element table. Returns (elements mapped, total elements)."""
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    smap = get_stride_map(ws)
    rows = element_rows(cfg)
    cols = ["ID", "Element", "Kind", "Crosses boundary"] + STRIDE_LETTERS
    sk = f"_seed_stride_{ws}"
    if sk not in st.session_state:
        st.session_state[sk] = pd.DataFrame(
            [{"ID": r["id"], "Element": r["name"], "Kind": KIND_LABEL[r["kind"]],
              "Crosses boundary": (("✔ " + r["cross"]) if r["cross"] else "—"),
              **{l: (l in smap.get(r["key"], [])) for l in STRIDE_LETTERS}} for r in rows], columns=cols)
    cfgcols = {l: st.column_config.CheckboxColumn(l, help=STRIDE_NAMES[l], default=False) for l in STRIDE_LETTERS}
    df = st.data_editor(st.session_state[sk], key=f"w_ed_stride_{ws}", hide_index=True, use_container_width=True,
                        disabled=["ID", "Element", "Kind", "Crosses boundary"], column_config=cfgcols,
                        column_order=["ID", "Element", "Kind"] + STRIDE_LETTERS)
    new_map, invalid = {}, []
    by_name = {r["name"]: r for r in rows}
    for rec in df.to_dict("records"):
        r = by_name.get(rec["Element"])
        if not r:
            continue
        ticked = [l for l in STRIDE_LETTERS if rec.get(l)]
        ok_l = [l for l in ticked if l in STRIDE_PER_ELEMENT[r["kind"]]]
        bad = [l for l in ticked if l not in STRIDE_PER_ELEMENT[r["kind"]]]
        if bad:
            invalid.append((r["id"], r["name"], bad, r["kind"]))
        if ok_l:
            new_map[r["key"]] = ok_l
    if new_map != smap:
        st.session_state.stride_map[ws] = new_map
        smap = new_map
        save_progress()
    for rid, nm, bad, kind in invalid:
        st.warning(f"{rid} {nm}: {', '.join(STRIDE_NAMES[b] for b in bad)} do(es) not apply to a {KIND_LABEL[kind].lower()} "
                   "and is ignored on the diagram. " + STRIDE_ELEMENT_NOTE[kind])
    mapped = sum(1 for r in rows if smap.get(r["key"]))
    st.progress(mapped / len(rows))
    st.caption(f"{mapped}/{len(rows)} elements mapped")
    st.caption("Same DFD as Step 2. Letters are your STRIDE ticks; elements turn red when a threat scenario is recorded on them.")
    show_architecture_diagram(cfg, threats=st.session_state.threats, mode="stride", key_suffix="s3_stride", editable=True, default_kind="threat", flat=True)
    return mapped, len(rows)




# ─────────────────────────────────────────────────────────────────────────────
# ELEVATION OF PRIVILEGE (EoP)-INSPIRED THREAT DISCOVERY CARD GAME
# Facilitator-led prompt cards; inspired by the Microsoft EoP approach.
# These prompts support discovery and do not replace STRIDE validation.
# ─────────────────────────────────────────────────────────────────────────────
EOP_CARD_DECK = [
    {"suit":"Spoofing","letter":"S","title":"Who can I pretend to be?","prompt":"Could an attacker impersonate a user, service, device, or trusted partner?","follow_up":"What identity proof would stop this, and where is it checked?"},
    {"suit":"Spoofing","letter":"S","title":"Can trust be forged?","prompt":"Could a token, session, API key, email, or service identity be stolen, replayed, or forged?","follow_up":"How are credentials issued, scoped, rotated, and revoked?"},
    {"suit":"Tampering","letter":"T","title":"What can I change?","prompt":"Could an attacker alter a request, message, configuration, dependency, or stored record?","follow_up":"Where are integrity checks and server-side validation enforced?"},
    {"suit":"Tampering","letter":"T","title":"Can I influence the data?","prompt":"Can untrusted input change how a downstream component interprets or processes data?","follow_up":"Are parameterisation, schema validation, signatures, or safe parsing needed?"},
    {"suit":"Repudiation","letter":"R","title":"Can I deny doing it?","prompt":"Could a user or attacker perform a sensitive action and plausibly deny it later?","follow_up":"Do logs record who, what, when, where, outcome, and correlation ID?"},
    {"suit":"Repudiation","letter":"R","title":"Can I erase my tracks?","prompt":"Could someone modify, disable, or bypass the audit trail needed to investigate this action?","follow_up":"Are audit events centralised, access-controlled, time-synchronised, and tamper-resistant?"},
    {"suit":"Information Disclosure","letter":"I","title":"What can I learn?","prompt":"Could an unauthorised party read sensitive data, secrets, metadata, or internal system details?","follow_up":"What is the least data this component should expose?"},
    {"suit":"Information Disclosure","letter":"I","title":"Can data escape its boundary?","prompt":"Could data flow to a less-trusted component, external service, log, export, or error response?","follow_up":"Are access controls, redaction, encryption, and egress controls appropriate?"},
    {"suit":"Denial of Service","letter":"D","title":"Can I exhaust it?","prompt":"Could repeated, oversized, expensive, or highly concurrent requests exhaust compute, memory, queues, or third-party quotas?","follow_up":"What limits, timeouts, quotas, back-pressure, and recovery paths exist?"},
    {"suit":"Denial of Service","letter":"D","title":"What fails together?","prompt":"Could failure or overload in one dependency cascade into other services or critical business functions?","follow_up":"Are bulkheads, circuit breakers, graceful degradation, and tested recovery in place?"},
    {"suit":"Elevation of Privilege","letter":"E","title":"Can I become more powerful?","prompt":"Could a lower-privileged identity or component invoke a higher-privileged action or access another tenant's data?","follow_up":"Is authorisation checked server-side for every action and object?"},
    {"suit":"Elevation of Privilege","letter":"E","title":"Can I cross a trust boundary?","prompt":"Could compromising a lower-trust component provide a path into a more-trusted service, admin function, or data store?","follow_up":"Are service identities, least privilege, segmentation, and explicit trust checks enforced?"},
]
EOP_SUIT_COLORS = {
    "Spoofing":"#762C95", "Tampering":"#CF5817", "Repudiation":"#0C6D62",
    "Information Disclosure":"#2666AF", "Denial of Service":"#B1295F",
    "Elevation of Privilege":"#5B574E",
}


def _eop_record_for_main(entry):
    """Create a standard risk/control record from a card-game discovery."""
    tid = entry["id"]
    stride = entry.get("stride", entry.get("card_suit", "Tampering"))
    threat_text = entry.get("threat", "")
    candidate = entry.get("mitigation", "").strip()
    # Candidate controls become selectable controls in the existing controls workflow.
    suggested = [candidate] if candidate else []
    defaults = OWASP_STRIDE_MAP.get(stride, {}).get("controls", [])
    for control in defaults:
        if control not in suggested:
            suggested.append(control)
    pred = {
        "id": tid, "threat": threat_text, "stride": stride,
        "component": entry.get("component", ""),
        "explanation": "Discovered during the EoP-inspired card activity. Validate assumptions and evidence.",
        "correct_mitigations": suggested or ["Define and test a threat-specific preventive control"],
        "incorrect_mitigations": [], "why_this_risk": "Risk rating should be justified against the scenario and evidence.",
        "why_these_controls": "Validate that selected controls directly address the captured attack path.",
        "owasp_categories": OWASP_STRIDE_MAP.get(stride, {}).get("owasp", []),
        "stride_rule_applied": "EoP-inspired card discovery; validate against the DFD and trust boundaries.",
    }
    likelihood = entry.get("likelihood", "Not rated")
    impact = entry.get("impact", "Not rated")
    ws_id = str(entry.get("workshop_id") or st.session_state.get("selected_workshop") or "unknown")
    rec = {
        "workshop_id": ws_id,
        "scenario_title": WORKSHOPS.get(ws_id, {}).get("scenario", {}).get("title", "Unknown scenario"),
        "component": entry.get("component", ""), "stride": stride,
        "matched_threat_id": tid, "likelihood": likelihood, "impact": impact,
        "likelihood_n": level_n(likelihood) or None, "impact_n": level_n(impact) or None,
        "rated": bool(level_n(likelihood) and level_n(impact)),
        "selected_mitigations": list(entry.get("selected_mitigations", [])),
        "controlled": bool(entry.get("controlled", False)), "residual": entry.get("residual"),
        "predefined_threat": pred, "threat_text": threat_text,
        "source": "EoP card activity", "eop_card_title": entry.get("card_title", ""),
        "eop_card_suit": entry.get("card_suit", stride), "eop_evidence": entry.get("evidence", ""),
        "eop_candidate_mitigation": entry.get("mitigation", ""),
        "eop_attack_mapping": entry.get("attack_mapping", ""),
        "eop_initial_priority": entry.get("priority", "Unassessed"),
        "score": 0, "max_score": 4, "feedback": [], "actors": [],
        "mitre": [], "capec": [], "statement": {},
    }
    rec["residual"] = rec.get("residual") or None
    rescore_record(rec)
    return rec


def _link_eop_entry_to_main(entry):
    """Idempotently link a card-log item into the shared threat/risk/control register."""
    ws_answers = st.session_state.user_answers
    tid = entry.get("linked_threat_id") or entry.get("id") or f"EOP-{uuid.uuid4().hex[:8].upper()}"
    entry["workshop_id"] = str(entry.get("workshop_id") or st.session_state.get("selected_workshop") or "unknown")
    # If the learner has switched workshops or restored an older save, rebuild the
    # main-register record when the card-log link exists but its record does not.
    existing = next((r for r in ws_answers if r.get("matched_threat_id") == tid), None)
    if existing:
        entry["linked_threat_id"] = tid
        return tid
    entry["id"] = tid
    rec = _eop_record_for_main(entry)
    ws_answers.append(rec)
    entry["linked_threat_id"] = tid
    entry["status"] = "Linked to main threat register"
    _tick_stride_map(entry.get("component", ""), entry.get("stride", "Tampering"))
    recalc_totals()
    return tid


def render_eop_integration_status(stage_label):
    """Show card-discovered threats from the one shared register at downstream stages."""
    recs = [r for r in st.session_state.get("user_answers", [])
            if r.get("source") == "EoP card activity"]
    if not recs:
        return
    rated = sum(1 for r in recs if r.get("rated"))
    controlled = sum(1 for r in recs if r.get("controlled"))
    residual = sum(1 for r in recs if r.get("residual"))
    st.info(
        f"🃏 **EoP integration · {stage_label}:** {len(recs)} card-discovered threat(s) "
        f"in the shared threat register · {rated} risk-scored · {controlled} with controls selected · "
        f"{residual} with residual-risk decisions. Threat IDs: "
        + ", ".join(str(r.get("matched_threat_id", "—")) for r in recs)
    )
    rows = []
    for r in recs:
        pred = r.get("predefined_threat", {})
        residual_obj = r.get("residual") or {}
        rows.append({
            "Threat ID": r.get("matched_threat_id", "—"),
            "Scenario": r.get("scenario_title") or WORKSHOPS.get(str(r.get("workshop_id", "")), {}).get("scenario", {}).get("title", "Current scenario"),
            "Card": r.get("eop_card_title", "—"),
            "Scenario": r.get("threat_text") or pred.get("threat", ""),
            "STRIDE": r.get("stride", "—"),
            "Inherent risk": rec_risk(r) if r.get("rated") else "Not scored",
            "Controls": "; ".join(r.get("selected_mitigations", [])) or "Not selected",
            "Residual risk": rec_residual(r) if residual_obj else "Not assessed",
            "Decision": residual_obj.get("decision", "Not decided"),
        })
    with st.expander(f"View the same EoP threat records at {stage_label}", expanded=False):
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_eop_card_game():
    """Interactive, single-player EoP-inspired card exercise embedded in threat discovery."""
    ws = str(st.session_state.selected_workshop)
    key = f"eop_cards_{ws}"
    active_key = f"eop_active_card_{ws}"
    st.markdown("### 🃏 Threat discovery card game")
    st.markdown(f"**Active scenario:** {current_workshop['scenario']['title']} · **Workspace:** Workshop {ws}")
    st.caption("Each of the four scenarios has its own threat register, EoP card log, risk scores, controls and residual-risk decisions. Switching scenarios resumes that scenario without merging its data with the others.")
    st.markdown(
        "Use a prompt card to challenge the architecture from an attacker's perspective. "
        "Discuss the scenario, capture the affected element and map the result to STRIDE. "
        "This is an EoP-inspired digital exercise—not an official reproduction of the copyrighted card deck."
    )
    st.caption("Suggested play: 10–15 minutes · draw a card · discuss the attack path · record evidence and a defensive action.")
    if key not in st.session_state:
        st.session_state[key] = []
    if active_key not in st.session_state:
        st.session_state[active_key] = None

    left, right = st.columns([1, 2])
    with left:
        suit_filter = st.selectbox(
            "Card suit", ["Any suit"] + [c["suit"] for c in EOP_CARD_DECK],
            key=f"eop_suit_filter_{ws}"
        )
        available = [c for c in EOP_CARD_DECK if suit_filter == "Any suit" or c["suit"] == suit_filter]
        if st.button("🎴 Draw a prompt card", type="primary", key=f"eop_draw_{ws}", use_container_width=True):
            st.session_state[active_key] = random.choice(available)
            st.rerun()
        if st.button("Clear card log only", key=f"eop_clear_{ws}", use_container_width=True,
                      help="Removes the card activity list only. Threats already linked to the main register remain there, including their scores and controls."):
            st.session_state[key] = []
            st.session_state[active_key] = None
            save_progress()
            st.rerun()

    with right:
        card = st.session_state.get(active_key)
        if card:
            color = EOP_SUIT_COLORS.get(card["suit"], "#1F6F66")
            st.markdown(
                f"""<div style="border:1px solid {color};border-left:7px solid {color};
                border-radius:12px;padding:18px 20px;background:#fff;margin-bottom:10px">
                <div style="font-size:.78rem;text-transform:uppercase;letter-spacing:1px;color:{color};font-weight:700">
                {card['letter']} · {card['suit']}</div>
                <h3 style="margin:8px 0">{card['title']}</h3>
                <p style="font-size:1.02rem;margin-bottom:8px">{card['prompt']}</p>
                <p style="color:#59625D;margin:0"><strong>Probe further:</strong> {card['follow_up']}</p>
                </div>""", unsafe_allow_html=True
            )
        else:
            st.info("Draw a card to start. Each suit maps to a STRIDE threat category.")

    scenario = current_workshop["scenario"]
    ids = element_ids(scenario)
    component_options = list(ids.keys())
    if not component_options:
        component_options = ["Architecture component not yet modelled"]

    with st.form(f"eop_capture_form_{ws}", clear_on_submit=True):
        st.markdown("**Capture the threat you discussed**")
        component = st.selectbox("Affected component or flow", component_options, key=f"eop_component_{ws}")
        threat = st.text_area(
            "Threat scenario (what could happen, how, and with what consequence?)",
            placeholder="An attacker could ... by ... resulting in ...",
            key=f"eop_threat_{ws}", height=90
        )
        evidence = st.text_input(
            "Assumption, evidence, or attack-path detail",
            placeholder="e.g. public endpoint reaches privileged API without object-level authorisation",
            key=f"eop_evidence_{ws}"
        )
        mitigation = st.text_area(
            "Candidate defensive control",
            placeholder="e.g. enforce server-side object-level authorisation and add a negative test",
            key=f"eop_mitigation_{ws}", height=70
        )
        cols = st.columns(2)
        with cols[0]:
            severity = st.selectbox("Initial priority", ["Unassessed", "Low", "Medium", "High", "Critical"], key=f"eop_severity_{ws}")
        with cols[1]:
            attack_mapping = st.text_input(
                "MITRE ATT&CK / CAPEC mapping (optional)",
                placeholder="Technique ID/name or CAPEC ID",
                key=f"eop_attackmap_{ws}"
            )
        submitted = st.form_submit_button("Add to card-game threat log", type="primary", use_container_width=True)
        if submitted:
            if not st.session_state.get(active_key):
                st.error("Draw a prompt card first so the threat has a discovery prompt.")
            elif not threat.strip():
                st.error("Describe a plausible threat scenario before adding it.")
            else:
                active_card = st.session_state[active_key]
                entry = {
                    "id": f"EOP-{str(ws).zfill(1)}-{uuid.uuid4().hex[:8].upper()}",
                    "workshop_id": ws,
                    "scenario_title": current_workshop["scenario"]["title"],
                    "card_suit": active_card["suit"],
                    "card_title": active_card["title"],
                    "stride": active_card["suit"],
                    "component": component,
                    "threat": threat.strip(),
                    "evidence": evidence.strip(),
                    "mitigation": mitigation.strip(),
                    "priority": severity,
                    "attack_mapping": attack_mapping.strip(),
                    "captured_at": datetime.now().isoformat(timespec="minutes"),
                }
                st.session_state[key].append(entry)
                _link_eop_entry_to_main(entry)
                save_progress()
                st.success(f"Added {entry['id']} to the shared threat register. It will now appear in risk scoring, control selection, residual-risk review, and exports.")
                st.rerun()

    entries = st.session_state[key]
    # Migrate card discoveries saved by the earlier version into the shared register once.
    for entry in entries:
        if not entry.get("linked_threat_id"):
            _link_eop_entry_to_main(entry)
    if entries:
        save_progress()
    st.markdown(f"**Card discoveries: {len(entries)} · linked to main threat register**")
    if entries:
        # Read live scoring/control state from the main register, rather than keeping a second copy.
        main_by_id = {r.get("matched_threat_id"): r for r in st.session_state.user_answers}
        display_entries = []
        for entry in entries:
            main = main_by_id.get(entry.get("linked_threat_id") or entry.get("id"), {})
            display_entries.append({
                "Threat ID": entry.get("linked_threat_id") or entry.get("id"),
                "Card / STRIDE": f"{entry.get('card_title', '')} · {entry.get('card_suit', '')}",
                "Component / flow": entry.get("component", ""),
                "Threat scenario": entry.get("threat", ""),
                "Initial priority": entry.get("priority", "Unassessed"),
                "Inherent risk (1–9)": rec_risk(main) if main else None,
                "Residual risk (1–9)": rec_residual(main) if main else None,
                "Candidate mitigation": entry.get("mitigation", ""),
                "Controls selected": "; ".join(main.get("selected_mitigations", [])) if main else "",
                "Decision": (main.get("residual") or {}).get("decision", "") if main else "",
                "Evidence / attack path": entry.get("evidence", ""),
                "ATT&CK / CAPEC note": entry.get("attack_mapping", ""),
            })
        card_df = pd.DataFrame(display_entries)
        st.dataframe(card_df, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Export card-game threats (CSV)",
            data=card_df.to_csv(index=False).encode("utf-8"),
            file_name=f"eop_threats_workshop_{ws}_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv", key=f"eop_export_{ws}", use_container_width=True
        )
        with st.expander("Review a captured card", expanded=False):
            choices = [f"{r['id']} · {r['card_title']}" for r in entries]
            chosen = st.selectbox("Select captured threat", choices, key=f"eop_review_pick_{ws}")
            selected = entries[choices.index(chosen)]
            st.markdown(f"**Scenario:** {selected['threat']}")
            st.markdown(f"**Evidence / attack path:** {selected['evidence'] or 'Not recorded'}")
            st.markdown(f"**Candidate control:** {selected['mitigation'] or 'Not recorded'}")
            st.markdown(f"**ATT&CK / CAPEC:** {selected['attack_mapping'] or 'Not mapped yet'}")
            st.caption(f"Main register ID: {selected.get('linked_threat_id', selected['id'])}. Risk score, selected controls and residual-risk decision are managed in the existing workflow; no second entry is required.")
    else:
        st.caption("Your captured threats will appear here and can be exported for follow-up.")


def render_stride_step():
    cfg = current_workshop
    recs = st.session_state.user_answers
    tgt = cfg["target_threats"]
    step_header(3, "Apply STRIDE")

    with st.expander("🃏 Optional activity: Elevation of Privilege-inspired card game", expanded=True):
        render_eop_card_game()

    substep("3.1", "Learn the six questions",
            "STRIDE is six questions, one per letter. Each letter breaks one security property.")
    st.dataframe(pd.DataFrame([{"": l, "Threat": n, "Property broken": p, "Ask yourself": q, "Example": e}
                               for l, n, p, q, e in STRIDE_INFO]), use_container_width=True, hide_index=True)
    with st.expander("📘 Which categories apply to which element? (STRIDE-per-element)", expanded=False):
        st.markdown(stride_applicability_html(), unsafe_allow_html=True)
        for k, v in STRIDE_ELEMENT_NOTE.items():
            st.markdown(f"- **{KIND_LABEL[k]}** — {v}")

    substep("3.2", "Map STRIDE to every element",
            "Walk the diagram element by element. Tick the categories that realistically apply. Your ticks appear as coloured letters on the diagram.")
    mapped, total = _stride_mapping_section()

    substep("3.3", "Write threat scenarios",
            f"Pick a scenario, then say which element it hits and which STRIDE category it is. Goal: {tgt} scenarios. "
            "Recording a scenario also ticks its category in the map above, so the two stay in sync.")
    if st.session_state.get("_stride_note"):
        st.info(st.session_state.pop("_stride_note"))
    _identify_section()

    ok = checkpoint([(mapped >= max(1, int(0.6 * total)), f"Map at least 60% of the elements ({mapped}/{total})"),
                     (len(recs) >= tgt, f"Identify {tgt} threat scenarios ({len(recs)}/{tgt})")])
    nav_buttons(2, "", 4, "", ok, "Map at least 60% of the elements and identify every required threat scenario.", key="p3")


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  STEP 4 · TRUST BOUNDARIES & ZONES   (boundaries → zones → zone rules → re-check STRIDE)
# ═════════════════════════════════════════════════════════════════════════════════════════════
def _crossing_section():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    revealed = boundary_checked(ws)
    show_architecture_diagram(cfg, mode="boundaries", key_suffix="s4_tb", reveal_cross=revealed)
    lay = layout_tree(cfg)
    cross = flow_crossings(cfg)
    eid = element_ids(s)
    rows = []
    for g in sorted(lay["groups"], key=lambda r: (r["depth"], r["x"])):
        inside = [n for n, r in lay["leaves"].items() if g["name"] in r["path"]]
        row = {"Boundary": ("   " * g["depth"]) + g["name"], "Trust level": g["trust"] or "—", "Contains": ", ".join(inside)}
        if revealed:
            row["Flows crossing it"] = sum(1 for k, v in cross.items() if g["name"] in v)
        rows.append(row)
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown("**Exercise:** select every data flow that crosses at least one boundary. A flow crosses when its two ends sit in different boxes.")
    flow_opts = [f"{eid[_flow_key(f)]} · {_flow_key(f)}" for f in s["data_flows"]]
    truth = {f"{eid[k]} · {k}" for k, v in cross.items() if v}
    with st.form("boundary_check_form"):
        picked = st.multiselect("Flows that cross a trust boundary", flow_opts, key=f"w_xflows_{ws}")
        if st.form_submit_button("Check my answer", type="primary"):
            st.session_state.boundary_checked[ws] = True
            save_progress()
            fp, fn = len(set(picked) - truth), len(truth - set(picked))
            if fp == 0 and fn == 0:
                st.success("✅ Exactly right — every one of those flows needs explicit controls and a close STRIDE look.")
            else:
                if fn:
                    st.warning("Missed: " + "; ".join(sorted(truth - set(picked))))
                if fp:
                    st.warning("These stay inside one boundary: " + "; ".join(sorted(set(picked) - truth)))
    if boundary_checked(ws):
        st.markdown("**Boundary-crossing flows (answer key)**")
        st.dataframe(pd.DataFrame([{"ID": eid[k], "Flow": k, "Crosses": ", ".join(v) if v else "— (stays inside one boundary)",
                                    "# boundaries": len(v)} for k, v in sorted(cross.items(), key=lambda kv: -len(kv[1]))]),
                     use_container_width=True, hide_index=True)


def _zone_direction_check():
    """Compare the learner's STRIDE map with the zone-direction rules. Returns the IDs of crossing flows still unmapped."""
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    smap = get_stride_map(ws)
    rows = element_rows(cfg)
    flows = [r for r in rows if r["kind"] == "flow"]
    fl = {_flow_key(f): f for f in s["data_flows"]}
    table, review = [], []
    for r in flows:
        exp = zone_rule_expectation(cfg, fl[r["key"]])
        got = "".join(smap.get(r["key"], []))
        match = (not exp) or set(exp) <= set(got)
        if not match:
            review.append(r["id"])
        table.append({"ID": r["id"], "Flow": r["name"], "Crosses boundary": ("✔ " + r["cross"]) if r["cross"] else "—",
                      "Zone rule expects": exp or "same zone", "You mapped (Step 3)": got or "—", "Match": "✅" if match else "⚠️ review"})
    st.dataframe(pd.DataFrame(table), use_container_width=True, hide_index=True)
    st.caption("T = data flows from a lower to a higher zone · I = from a higher to a lower zone · D = the source is an untrusted Zone-0 entity.")
    missing = [r["id"] for r in flows if r["cross"] and not smap.get(r["key"])]
    if missing:
        st.warning("Boundary-crossing flows with no STRIDE category yet: " + ", ".join(missing))
    if review:
        st.info("Flows to review: " + ", ".join(review) + ". Add the missing categories in Step 3, or decide why the rule does not apply.")
    if missing or review:
        if st.button("⬅️ Go back to Step 3 and update the STRIDE map", key="w_back_stride"):
            go_page(3)
    show_architecture_diagram(cfg, mode="stride", key_suffix="s4_stride")
    return missing


def render_boundaries_step():
    ws = st.session_state.selected_workshop
    step_header(4, "Trust boundaries & zones of trust")

    substep("4.1", "Draw the trust boundaries on your DFD",
            "Same elements and flows as Step 2, now with boundaries added. A trust boundary is a line where the level of trust changes — "
            "device to cloud, internet to your network, your code to a vendor. Decide which flows cross one, then check your answer.")
    _crossing_section()

    substep("4.2", "Give every element a zone of trust (0–9)",
            "Zones rank how critical and trusted an element is. Zone 0 = outside your control; higher numbers = more critical.")
    _zones_section()

    substep("4.3", "Learn the zone-direction rules",
            "Zone direction tells you which STRIDE categories to expect on a flow. A worked example comes first, then the rule table.")
    _zone_rules_reference()

    substep("4.4", "Re-check your STRIDE map against the rules",
            "Compare what you ticked in Step 3 with what the zone rules expect. Fix gaps now — this is the loop that makes the model more complete.")
    if not boundary_checked(ws) or not st.session_state.get("zone_labelling_done"):
        st.info("Finish 4.1 and 4.2 first — the comparison uses your boundary and zone answers.")
        missing = ["(complete 4.1 and 4.2 first)"]
    else:
        missing = _zone_direction_check()

    ok = checkpoint([(boundary_checked(ws), "Submit the boundary-crossing exercise (4.1)"),
                     (bool(st.session_state.get("zone_labelling_done")), "Submit the zone labelling exercise (4.2)"),
                     (not missing, "Every boundary-crossing flow has at least one STRIDE category (4.4)")])
    nav_buttons(3, "", 5, "", ok, "Complete the three checkpoint items first.", key="p4")


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  STEP 5 · ATT&CK + CAPEC + THREAT STATEMENTS
# ═════════════════════════════════════════════════════════════════════════════════════════════
def _actors_section():
    """Threat actors and entry points (who attacks, where they get in). Returns True when the minimum is met."""
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    items = get_annotations(ws)
    targets = [c["name"] for c in s["components"]] + list(dict.fromkeys(_flow_key(f) for f in s["data_flows"]))
    profiles = [p["name"] for p in ACTOR_CATALOG] + ["Custom actor…"]
    c1, c2 = st.columns([3, 2])
    with c1:
        prof = st.selectbox("Actor profile", profiles, key=f"w_actprof_{ws}")
        pidx = profiles.index(prof)
        base = ACTOR_CATALOG[pidx] if pidx < len(ACTOR_CATALOG) else {"name": "", "capability": "Medium", "motivation": "", "entry": ""}
        name = prof if pidx < len(ACTOR_CATALOG) else st.text_input("Name of the custom actor", key=f"w_actname_{ws}", max_chars=70)
        motive = st.text_input("Motivation", value=base["motivation"], key=f"w_actmot_{ws}_{pidx}", max_chars=120)
    with c2:
        cap = st.select_slider("Capability", LEVELS, value=base["capability"], key=f"w_actcap_{ws}_{pidx}")
        st.caption("Low: opportunistic, public tools · Medium: skilled, some access · High: well-resourced or privileged.")
    sugg = [t for t in suggest_entries(base.get("entry", ""), cfg) if t in targets]
    entries = st.multiselect("Entry points (first one is the main arrow; add more if the actor can reach several)", targets,
                             default=sugg, key=f"w_actent_{ws}_{pidx}")
    if st.button("➕ Add threat actor", type="primary", key="w_actadd"):
        if not (name or "").strip():
            st.warning("Give the actor a name.")
        elif not entries:
            st.warning("Choose at least one entry point.")
        else:
            items.append({"id": _next_annotation_id(items, "actor"), "kind": "actor", "label": name.strip(), "target": entries[0],
                          "entries": list(entries[1:]), "links": [], "notes": motive.strip(), "capability": cap})
            save_progress()
            st.rerun()
    actors = get_actors(ws)
    for a in sorted(actors, key=_ann_sort):
        x1, x2, x3, x4 = st.columns([1, 4, 5, 1])
        x1.markdown(f"**{a['id']}**")
        x2.text(f"{a['label']} ({a.get('capability', '—')})")
        x3.text("→ " + ", ".join(_actor_targets(a)))
        if x4.button("🗑", key=f"w_actdel_{a['id']}", help=f"Remove {a['id']}"):
            items[:] = [i for i in items if i["id"] != a["id"]]
            for i in items:
                i["links"] = [l for l in i.get("links", []) if l != a["id"]]
            for r in st.session_state.user_answers:
                r["actors"] = [x for x in r.get("actors", []) if x != a["id"]]
            save_progress()
            st.rerun()
    show_architecture_diagram(cfg, mode="actors", key_suffix="s5_act", editable=True, default_kind="actor")
    return len(actors) >= 2 and all(a["target"] for a in actors)


def _threat_statement_guide():
    st.markdown(
        "**Grammar** (from the AWS Threat Composer approach to threat statements):\n\n"
        "> A **[threat source]** **[with prerequisites]** can **[threat action]**, which leads to **[threat impact]**, "
        "resulting in reduced **[impacted goal]** of **[impacted assets]**.")
    st.dataframe(pd.DataFrame([
        {"Part": "Threat source", "Answers": "Who?", "Take it from": "Your threat actors (5.1)", "Weak → strong": "“hacker” → “external attacker with a stolen customer login”"},
        {"Part": "Prerequisites", "Answers": "What do they need first?", "Take it from": "Entry point, capability, boundary crossed", "Weak → strong": "(blank) → “with network access to the public API”"},
        {"Part": "Threat action", "Answers": "What exactly do they do?", "Take it from": "Your STRIDE scenario + ATT&CK technique", "Weak → strong": "“attack the site” → “replay a captured session token”"},
        {"Part": "Threat impact", "Answers": "What happens as a result?", "Take it from": "STRIDE category", "Weak → strong": "“bad things” → “unauthorised access to another customer's orders”"},
        {"Part": "Impacted goal", "Answers": "Which security property?", "Take it from": "The STRIDE letter (S→authenticity, T→integrity, …)", "Weak → strong": "—"},
        {"Part": "Impacted assets", "Answers": "What is harmed?", "Take it from": "Your asset map (2.1)", "Weak → strong": "“data” → “customer order history”"},
    ]), use_container_width=True, hide_index=True)
    st.markdown("**Worked example.**  *Weak:* “Hackers could steal data.”  \n"
                "*Strong:* “An external attacker with a stolen customer session token can replay it against the order API, which leads to "
                "unauthorised access to another customer's orders, resulting in reduced confidentiality of customer order data.”")
    st.markdown("**Check yourself:** one actor, one action you could test, one clear impact, one goal, named assets. "
                "If you cannot imagine a control that would stop it, the statement is still too vague.")


def render_attack_step():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    recs = st.session_state.user_answers
    step_header(5, "ATT&CK, CAPEC & threat statements")
    render_eop_integration_status("ATT&CK / CAPEC mapping")
    if not recs:
        st.warning("Identify threat scenarios first (Step 3).")
        nav_buttons(4, "", None, "", key="p5e")
        return

    substep("5.1", "Who would attack, and where do they get in?",
            "STRIDE says what can go wrong; the threat actor says who would make it happen and where they enter. "
            "Add at least two actors with different capability.")
    actors_ok = _actors_section()

    substep("5.2", "See the attack path",
            "An attack tree shows the steps an attacker takes. Each step crosses a trust boundary from Step 4.")
    with st.expander("🌳 Attack tree for this scenario", expanded=False):
        _attack_tree_section()

    substep("5.3", "Map each threat to attacker behaviour and write the threat statement",
            "Three views of the same threat — pick from each, then combine them into one sentence.")
    st.dataframe(pd.DataFrame([
        {"View": "ATT&CK technique", "Question": "What does the adversary do?", "Catalogue": f"MITRE ATT&CK Enterprise {ATTACK_VERSION}", "Use it for": "Detection ideas and mitigations"},
        {"View": "CAPEC pattern", "Question": "How is the weakness exploited?", "Catalogue": "MITRE CAPEC", "Use it for": "Test cases and secure design"},
        {"View": "Threat statement", "Question": "Who does what, with what result?", "Catalogue": "AWS Threat Composer grammar", "Use it for": "A clear, reviewable threat for scoring and controls"},
    ]), use_container_width=True, hide_index=True)
    with st.expander("✍️ How to write a threat statement", expanded=False):
        _threat_statement_guide()
    st.caption(f"ATT&CK {ATTACK_VERSION}: Defense Evasion was split into Stealth and Defense Impairment, so log tampering sits under Defense Impairment. "
               "⭐ marks patterns that match words in your scenario or its STRIDE category.")

    actors = get_actors(ws)
    a_label = {a["id"]: a["label"] for a in actors}
    asset_opts = list(dict.fromkeys(list(s.get("assets", [])) + [i["label"] for i in get_annotations(ws) if i["kind"] == "asset"]))
    first_open = next((i for i, r in enumerate(recs) if not (r.get("mitre") and r.get("capec") and statement_complete(r))), -1)
    with st.form("attack_map_form"):
        vals = {}
        for idx, rec in enumerate(recs):
            pred = rec["predefined_threat"]
            tid = rec["matched_threat_id"]
            letter = STRIDE_LETTER_OF.get(rec["stride"], "")
            done = bool(rec.get("mitre") and rec.get("capec")) and statement_complete(rec)
            with st.expander(f"{'✅' if done else '⬜'} {tid} · {rec['stride']} on {rec['component']}", expanded=(idx == first_open)):
                st.caption(pred["threat"])
                att_labels = {attack_label(t, letter in t["stride"]): t["id"] for t in attack_ranked(rec)}
                cur_att = [lbl for lbl, t_ in att_labels.items() if t_ in rec.get("mitre", [])]
                att = st.multiselect("ATT&CK technique(s) — what the adversary does", list(att_labels), default=cur_att, key=f"w_mitre_{tid}")
                ranked = capec_ranked(rec)
                cap_labels = {capec_label(c, "⭐ " if (hits or fit) else ""): c["id"] for c, hits, fit in ranked}
                best = [c["id"] for c, hits, fit in ranked[:3]]
                cur_cap = [lbl for lbl, c_ in cap_labels.items() if c_ in rec.get("capec", [])]
                cap = st.multiselect(f"CAPEC pattern(s) — how it is exploited   (best fits: {', '.join(best)})", list(cap_labels),
                                     default=cur_cap, key=f"w_capec_{tid}")
                note = st.text_input("Attack path in one line (entry → impact)", value=rec.get("mitre_note", ""), key=f"w_mnote_{tid}", max_chars=200)

                st.markdown("**Threat statement**")
                stm = rec.get("statement") or {}
                hint_a, hint_i = STATEMENT_HINTS.get(letter, ("", ""))
                src = None
                if actors:
                    ids = [a["id"] for a in actors]
                    cur_src = (rec.get("actors") or [None])[0]
                    src = st.selectbox("Threat source (from 5.1)", ids, index=ids.index(cur_src) if cur_src in ids else 0,
                                       format_func=lambda i: f"{i} — {a_label[i]}", key=f"w_tsrc_{tid}")
                else:
                    st.warning("Add a threat actor in 5.1 to choose a threat source.")
                pre = st.text_input("Prerequisites (optional): what do they need first?", value=stm.get("prereq", ""), key=f"w_tpre_{tid}",
                                    max_chars=160, placeholder="with network access to the public API and a low-privilege account")
                act = st.text_input("Threat action: what exactly do they do?  (starts after “can …”)", value=stm.get("action", ""),
                                    key=f"w_tact_{tid}", max_chars=200, placeholder=f"e.g. {hint_a}")
                imp = st.text_input("Threat impact: what happens as a result?", value=stm.get("impact", ""), key=f"w_timp_{tid}",
                                    max_chars=200, placeholder=f"e.g. {hint_i}")
                g1, g2 = st.columns(2)
                dflt = GOAL_OF_STRIDE.get(letter, "confidentiality")
                goal = g1.selectbox("Impacted goal", STATEMENT_GOALS, index=STATEMENT_GOALS.index(stm.get("goal", dflt)) if stm.get("goal", dflt) in STATEMENT_GOALS else 0,
                                    key=f"w_tgoal_{tid}")
                ast_ = g2.multiselect("Impacted assets", asset_opts, default=[a for a in stm.get("assets", []) if a in asset_opts], key=f"w_tast_{tid}")
                if stm:
                    st.markdown(statement_html(rec), unsafe_allow_html=True)
                vals[tid] = {"att": att, "att_labels": att_labels, "cap": cap, "cap_labels": cap_labels, "note": note,
                             "src": src, "pre": pre, "act": act, "imp": imp, "goal": goal, "assets": ast_}
        if st.form_submit_button("💾 Save mappings and statements", type="primary", use_container_width=True):
            for rec in recs:
                v = vals[rec["matched_threat_id"]]
                rec["mitre"] = [v["att_labels"][x] for x in v["att"] if x in v["att_labels"]]
                rec["capec"] = [v["cap_labels"][x] for x in v["cap"] if x in v["cap_labels"]]
                rec["mitre_note"] = (v["note"] or "").strip()
                if v["src"]:
                    rec["actors"] = [v["src"]]
                rec["statement"] = {"source": a_label.get(v["src"], ""), "prereq": (v["pre"] or "").strip(), "action": (v["act"] or "").strip(),
                                    "impact": (v["imp"] or "").strip(), "goal": v["goal"], "assets": list(v["assets"])}
            sync_labels_from_analysis(False)
            save_progress()
            st.rerun()

    substep("5.4", "Check your coverage")
    mapped = [r for r in recs if r.get("mitre")]
    if mapped:
        st.markdown("**ATT&CK matrix coverage**")
        st.markdown(attack_matrix_html(mapped), unsafe_allow_html=True)
        for rec in mapped:
            letter = STRIDE_LETTER_OF.get(rec["stride"], "")
            techs = [ATTACK_BY_ID[t] for t in rec["mitre"] if t in ATTACK_BY_ID]
            tactics = sorted({tac for t in techs for tac in t["tactics"]})
            weak = [t["id"] for t in techs if letter not in t["stride"]]
            with st.expander(f"{rec['matched_threat_id']} — {', '.join(t['id'] for t in techs)}"):
                if weak:
                    st.warning(f"Weak fit with {rec['stride']}: {', '.join(weak)}. Fine if the technique is a step in the attack path rather than the end goal.")
                else:
                    st.success(f"Every technique is commonly associated with {rec['stride']}.")
                if len([t for t in tactics if t != "ICS"]) < 2:
                    st.info("Consider adding a technique from a second tactic (how the attacker gets in, then what they achieve).")
                st.markdown("**Tactics covered:** " + (", ".join(tactics) or "—"))
                for t in techs:
                    st.markdown(f"- **{t['id']} {t['name']}** ({', '.join(t['tactics'])}) — {t['hint']}")
                hints = attack_mitigation_hints(rec)
                mits = [f"{k} {v}" for k, v in hints.items() if k.startswith("M")]
                if mits:
                    st.markdown("**ATT&CK mitigations:** " + "; ".join(mits))
    done_stm = [r for r in recs if statement_complete(r)]
    if done_stm:
        st.markdown("**Your threat statements**")
        for r in done_stm:
            st.markdown(f"**{r['matched_threat_id']}** · {r['stride']}  \n" + statement_html(r)
                        + (f"<small>CAPEC: {', '.join(CAPEC_BY_ID[c]['id'] + ' ' + CAPEC_BY_ID[c]['name'] for c in r.get('capec', []) if c in CAPEC_BY_ID)}</small>" if r.get("capec") else ""),
                        unsafe_allow_html=True)
    if mapped:
        show_architecture_diagram(cfg, mode="mitre", key_suffix="s5_mitre")

    n = len(recs)
    ok = checkpoint([(actors_ok, "Add at least two threat actors, each with an entry point (5.1)"),
                     (sum(1 for r in recs if r.get("mitre")) == n, f"Pick an ATT&CK technique for every threat ({sum(1 for r in recs if r.get('mitre'))}/{n})"),
                     (sum(1 for r in recs if r.get("capec")) == n, f"Pick a CAPEC pattern for every threat ({sum(1 for r in recs if r.get('capec'))}/{n})"),
                     (sum(1 for r in recs if statement_complete(r)) == n, f"Complete a threat statement for every threat ({sum(1 for r in recs if statement_complete(r))}/{n})")])
    nav_buttons(4, "", 6, "", ok, "Complete the four checkpoint items first.", key="p5")


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  STEP 7 · CONTROL SELECTION   (OWASP reference → pick controls)
# ═════════════════════════════════════════════════════════════════════════════════════════════
def render_controls_step():
    step_header(7, "Control selection")
    substep("7.1", "Know your control menu",
            "Each STRIDE category maps to OWASP Top 10 weaknesses and to typical controls. Open the one you need, then choose controls below.")
    _owasp_reference()
    substep("7.2", "Select controls for each threat, highest risk first")
    render_controls_page()


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  READINESS + REVIEW (9 steps)
# ═════════════════════════════════════════════════════════════════════════════════════════════
def stage_status():
    ws = st.session_state.selected_workshop
    cfg = WORKSHOPS[ws]
    sc, plan, oq = get_scope(ws), get_review_plan(ws), get_open_questions(ws)
    recs = st.session_state.user_answers
    n, tgt = len(recs), cfg["target_threats"]
    items = get_annotations(ws)
    smap = get_stride_map(ws)
    elems = element_rows(cfg)
    rated = sum(1 for r in recs if r.get("rated"))
    ctl = sum(1 for r in recs if r.get("controlled"))
    res = sum(1 for r in recs if r.get("residual"))
    mit = sum(1 for r in recs if r.get("mitre"))
    cap = sum(1 for r in recs if r.get("capec"))
    stm = sum(1 for r in recs if statement_complete(r))
    plan_ok = bool(plan["owner"].strip() and plan["full"] and plan["light"] and plan["triggers"])
    n_assets = sum(1 for i in items if i["kind"] == "asset")
    n_actors = len(get_actors(ws))
    mapped = sum(1 for r in elems if smap.get(r["key"]))
    unmapped_cross = [r for r in elems if r["kind"] == "flow" and r["cross"] and not smap.get(r["key"])]
    return [
        ("scope", "Scope & goals", "📐", scope_complete(sc),
         f"Scope statement, {len(sc['must_never'])} must-never rules, {len(sc['assumptions'])} assumptions, {len(sc['exclusions']) + len(sc['oos_components'])} exclusions"),
        ("dfd", "Data-flow diagram", "🗺️", n_assets >= 2,
         f"{len(cfg['scenario']['components'])} elements, {len(cfg['scenario']['data_flows'])} data flows, {n_assets} assets labelled"),
        ("stride", "Apply STRIDE", "⚡", n >= tgt and mapped >= max(1, int(0.6 * len(elems))),
         f"{mapped}/{len(elems)} elements STRIDE-mapped, {n}/{tgt} threat scenarios"),
        ("boundaries", "Trust boundaries", "🚧", boundary_checked(ws) and bool(st.session_state.get("zone_labelling_done")) and not unmapped_cross,
         "Crossing flows identified, zones applied, every crossing flow STRIDE-mapped"),
        ("mitre", "ATT&CK · CAPEC", "🎯", n > 0 and n_actors >= 2 and mit == n and cap == n and stm == n,
         f"{n_actors} threat actors · {mit}/{n} ATT&CK · {cap}/{n} CAPEC · {stm}/{n} threat statements"),
        ("scoring", "Risk scoring", "📊", n > 0 and rated == n, f"{rated}/{n} threats scored (impact × likelihood, 1–9)"),
        ("controls", "Controls", "🛡️", n > 0 and ctl == n, f"{ctl}/{n} threats have controls mapped"),
        ("residual", "Residual risk", "⚖️", n > 0 and res == n and len(oq["questions"]) >= 1,
         f"{res}/{n} residual risks recorded, {len(oq['questions'])} open questions"),
        ("review", "Review schedule", "🔁", plan_ok, "Owner, review cadence and update triggers defined"),
    ]


def render_stage_review():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    sc, oq, plan = get_scope(ws), get_open_questions(ws), get_review_plan(ws)
    recs = st.session_state.user_answers
    items = get_annotations(ws)
    smap = get_stride_map(ws)
    eid = element_ids(s)
    tabs = st.tabs([f"{ic} {lbl}" for _, lbl, ic in STAGES])
    with tabs[0]:
        st.markdown(f"**System in scope:** {sc['statement'] or '—'}")
        a, b = st.columns(2)
        a.markdown("**Must do**\n" + ("\n".join(f"- {x}" for x in sc["must_do"]) or "—"))
        b.markdown("**Must never**\n" + ("\n".join(f"- {x}" for x in sc["must_never"]) or "—"))
        if sc["assumptions"]:
            st.markdown("**Assumptions**")
            st.dataframe(pd.DataFrame(sc["assumptions"]), hide_index=True, use_container_width=True)
        if sc["exclusions"] or sc["oos_components"]:
            st.markdown("**Exclusions**")
            if sc["exclusions"]:
                st.dataframe(pd.DataFrame(sc["exclusions"]), hide_index=True, use_container_width=True)
            if sc["oos_components"]:
                st.markdown("Out-of-scope components: " + ", ".join(sc["oos_components"]))
        if sc["goals"]:
            st.markdown("**Goals**\n" + "\n".join(f"- {x}" for x in sc["goals"]))
    with tabs[1]:
        paths = component_boundaries(cfg)
        st.dataframe(pd.DataFrame([{"ID": eid[c["name"]], "Element": c["name"], "Kind": KIND_LABEL[c["type"]],
                                    "Runs in": " › ".join(paths.get(c["name"], [])), "Description": c["description"]} for c in s["components"]]),
                     use_container_width=True, hide_index=True)
        st.dataframe(pd.DataFrame([{"ID": eid[_flow_key(f)], "Flow": _flow_key(f), "Data": f["data"], "Protocol": f["protocol"]}
                                   for f in s["data_flows"]]), use_container_width=True, hide_index=True)
        assets = [i for i in items if i["kind"] == "asset"]
        if assets:
            st.markdown("**Assets:** " + "; ".join(f"{i['id']} {i['label']} (on {i['target']})" for i in assets))
    with tabs[2]:
        if smap:
            st.markdown("**STRIDE mapping per element**")
            st.dataframe(pd.DataFrame([{"ID": eid.get(k, ""), "Element": k, "STRIDE": " ".join(v)} for k, v in smap.items()]),
                         hide_index=True, use_container_width=True)
        for a in recs:
            pred = a.get("predefined_threat", {})
            pts = a.get("pts_identify", 0)
            css = "correct-answer" if pts == 4 else "partial-answer" if pts >= 2 else "incorrect-answer"
            st.markdown(f"""<div class="{css}"><strong>{a['matched_threat_id']}</strong>: {_esc(a.get('threat_text') or pred.get('threat', ''))}<br>
            Your answer: {a['stride']} on {_esc(a['component'])} · Zone rule: {pred.get('stride_rule_applied', 'N/A')}</div>""", unsafe_allow_html=True)
    with tabs[3]:
        cross = flow_crossings(cfg)
        st.dataframe(pd.DataFrame([{"ID": eid[k], "Flow": k, "Boundaries crossed": ", ".join(v) or "—"} for k, v in cross.items()]),
                     use_container_width=True, hide_index=True)
        st.dataframe(pd.DataFrame([{"ID": eid[c["name"]], "Element": c["name"], "Zone": c.get("zone", "N/A"), "Score (0-9)": c.get("zone_score", "?")}
                                   for c in s["components"]]), use_container_width=True, hide_index=True)
    with tabs[4]:
        actors = get_actors(ws)
        if actors:
            st.markdown("**Threat actors**")
            st.dataframe(pd.DataFrame([{"ID": a["id"], "Actor": a["label"], "Capability": a.get("capability", ""),
                                        "Entry points": ", ".join(_actor_targets(a))} for a in actors]), hide_index=True, use_container_width=True)
        mp = [r for r in recs if r.get("mitre")]
        if mp:
            st.markdown(attack_matrix_html(mp), unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "STRIDE": r["stride"],
                                        "ATT&CK": ", ".join(f"{t} {ATTACK_BY_ID[t]['name']}" for t in r["mitre"] if t in ATTACK_BY_ID),
                                        "CAPEC": ", ".join(f"{c} {CAPEC_BY_ID[c]['name']}" for c in r.get("capec", []) if c in CAPEC_BY_ID),
                                        "Attack path": r.get("mitre_note", "")} for r in mp]), hide_index=True, use_container_width=True)
        else:
            st.info("No threats were mapped to ATT&CK.")
        for r in recs:
            if statement_complete(r):
                st.markdown(f"**{r['matched_threat_id']}** " + statement_html(r), unsafe_allow_html=True)
            if r.get("source") == "EoP card activity":
                st.caption(f"🃏 {r['matched_threat_id']} · {r.get('eop_card_title', '')} · {r.get('threat_text', '')}")
    with tabs[5]:
        rated = [r for r in recs if r.get("rated")]
        if rated:
            st.markdown(risk_matrix_html([(r["likelihood_n"], r["impact_n"], r["matched_threat_id"]) for r in rated]), unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "Likelihood": r["likelihood"], "Impact": r["impact"],
                                        "Risk": rec_risk(r), "Band": risk_band(rec_risk(r))}
                                       for r in sorted(rated, key=lambda r: -rec_risk(r))]), hide_index=True, use_container_width=True)
        else:
            st.info("No threats were scored.")
    with tabs[6]:
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
    with tabs[7]:
        res = [r for r in recs if r.get("residual")]
        if res:
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "Inherent": rec_risk(r), "Residual": rec_residual(r),
                                        "Decision": r["residual"]["decision"], "Rationale": r["residual"]["rationale"]} for r in res]),
                         hide_index=True, use_container_width=True)
        if oq["questions"]:
            st.markdown("**Open questions**\n" + "\n".join(f"- {q}" for q in oq["questions"]))
        if oq["accepted"]:
            st.markdown(f"**Accepted-risk statement:** {oq['accepted']}")
    with tabs[8]:
        st.markdown(f"**Owner:** {plan['owner'] or '—'}  ·  **Security's role:** {plan['security_role'] or '—'}  ·  **Next lightweight review:** {plan['next_review'] or '—'}")
        for title, key in (("Full-workshop triggers", "full"), ("Lightweight review checks", "light"), ("Update triggers", "triggers")):
            if plan[key]:
                st.markdown(f"**{title}**\n" + "\n".join(f"- {x}" for x in plan[key]))
        if plan["notes"]:
            st.markdown(f"**Keeping it alive:** {plan['notes']}")


def _tick_stride_map(key, stride_name):
    """A recorded threat scenario ticks its STRIDE category on that element in the Step 3 map (keeps both views in sync)."""
    ws = st.session_state.selected_workshop
    letter = STRIDE_LETTER_OF.get(stride_name)
    kind = element_kind(current_workshop["scenario"], key)
    if letter and kind in STRIDE_PER_ELEMENT and letter in STRIDE_PER_ELEMENT[kind]:
        cur = dict(get_stride_map(ws))
        have = set(cur.get(key, []))
        have.add(letter)
        cur[key] = [l for l in STRIDE_LETTERS if l in have]
        st.session_state.stride_map[ws] = cur
    elif letter:
        st.session_state["_stride_note"] = (f"**{stride_name}** on **{key}** was recorded as a scenario, but it is not ticked in the map: "
                                            f"{STRIDE_ELEMENT_NOTE.get(kind, '')} Consider which element at the end of the flow the scenario really hits.")
    for k in [k for k in st.session_state.keys() if str(k).startswith((f"_seed_stride_{ws}", f"w_ed_stride_{ws}"))]:
        del st.session_state[k]


def _zone_rules_reference():
    """Zone-direction rules plus a worked example computed from the learner's own system."""
    cfg = current_workshop
    s = cfg["scenario"]
    zs = {c["name"]: c.get("zone_score", 0) for c in s["components"]}
    flows = s["data_flows"]
    st.dataframe(pd.DataFrame([
        {"Applies to": "Data flow", "STRIDE": "Tampering", "Rule": "Flows from a lower zone to a higher zone", "Why": "Data from a less trusted place enters a more critical one"},
        {"Applies to": "Data flow", "STRIDE": "Information disclosure", "Rule": "Flows from a higher zone to a lower zone", "Why": "Sensitive data travels toward a less trusted place"},
        {"Applies to": "Data flow", "STRIDE": "Denial of service", "Rule": "The source is Zone 0", "Why": "Outsiders can flood whatever they can reach"},
        {"Applies to": "Element", "STRIDE": "Spoofing", "Rule": "Reachable from a Zone 0 entity", "Why": "Outsiders can pretend to be a legitimate user or system"},
        {"Applies to": "Element", "STRIDE": "Denial of service", "Rule": "Reachable from a Zone 0 entity", "Why": "Outsiders can exhaust its resources"},
        {"Applies to": "Element", "STRIDE": "Repudiation", "Rule": "Both Spoofing and Tampering apply", "Why": "Identity can be faked and data changed, so actions leave no trustworthy trace"},
        {"Applies to": "Element", "STRIDE": "Elevation of privilege", "Rule": "Connected to a lower-zone element", "Why": "Compromising the lower zone may give a path to higher privileges"},
    ]), use_container_width=True, hide_index=True)

    st.markdown("**Worked example from your system**")
    shown = []
    for f in flows:
        exp = zone_rule_expectation(cfg, f)
        if exp and not any(set(exp) == set(x[1]) for x in shown):
            shown.append((f, exp))
        if len(shown) == 2:
            break
    names = {"T": "Tampering", "I": "Information disclosure", "D": "Denial of service"}
    for f, exp in shown:
        a, b = zs.get(f["source"], 0), zs.get(f["destination"], 0)
        direction = "up (less → more critical)" if b > a else "down (more → less critical)" if b < a else "sideways (same zone)"
        reasons = []
        if b > a:
            reasons.append(f"zone {a} → {b} goes **up**, so **Tampering**")
        if b < a:
            reasons.append(f"zone {a} → {b} goes **down**, so **Information disclosure**")
        if a == 0:
            reasons.append("the source is **Zone 0**, so **Denial of service**")
        st.markdown(f"- **{_flow_key(f)}** ({f['protocol']}): {f['source']} is zone {a}, {f['destination']} is zone {b}. Direction: {direction}. "
                    + "; ".join(reasons) + f". Expected: {', '.join(names[l] for l in exp)}.")
    node = flows[0]["destination"] if flows else None
    if node:
        reach0 = any(zs.get(f["source"], 1) == 0 and f["destination"] == node for f in flows)
        lower = any((f["destination"] == node and zs.get(f["source"], 0) < zs[node]) or (f["source"] == node and zs.get(f["destination"], 0) < zs[node]) for f in flows)
        incoming_lower = any(f["destination"] == node and zs.get(f["source"], 0) < zs[node] for f in flows)
        got = [n for n, ok in (("Spoofing", reach0), ("Denial of service", reach0), ("Tampering", incoming_lower),
                               ("Repudiation", reach0 and incoming_lower), ("Elevation of privilege", lower)) if ok]
        st.markdown(f"- **Element {node}** (zone {zs[node]}): reachable from Zone 0? {'yes' if reach0 else 'no'}. Receives data from a lower zone? "
                    f"{'yes' if incoming_lower else 'no'}. Connected to a lower-zone element? {'yes' if lower else 'no'}. "
                    f"Rules give: {', '.join(got) if got else 'no extra categories from the zone rules'}.")
    st.caption("Zone rules are a prompt, not a verdict: use them to find categories you missed, then decide whether each one is realistic.")


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  SECTIONS REUSED BY THE STEP PAGES (formerly separate pages)
# ═════════════════════════════════════════════════════════════════════════════════════════════
def _zones_section():
    scenario = current_workshop["scenario"]
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
    <div style="background:#FDF7E3;border-radius:10px;
                padding:18px 22px;border:2px dashed #ECAB13;margin:12px 0">
    <div style="font-size:0.75em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                color:#D55611;margin-bottom:8px">🎯 PRACTICAL EXERCISE — ZONE LABELLING</div>
    <p style="margin:0 0 10px 0;color:#333;font-size:0.95em">
    For each component, ask yourself three questions before selecting a zone:
    </p>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;font-size:0.85em">
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #D55611">
        <strong style="color:#D55611">1. Who controls it?</strong><br>
        <span style="color:#555">Your org = higher zone. External party = Zone 0.</span>
      </div>
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #D55611">
        <strong style="color:#D55611">2. What data passes through?</strong><br>
        <span style="color:#555">PII/financial/health = higher zone. Public content = lower.</span>
      </div>
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #D55611">
        <strong style="color:#D55611">3. What's the breach impact?</strong><br>
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
                    <div style="background:#FAFAF9;border:1px solid #E9E8E6;border-radius:8px;
                                padding:10px 12px;margin:0 0 8px 0">
                    <strong>{comp['name']}</strong><br>
                    <small style="color:#80796B">{comp['description']}</small>
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
            zone_color = zinfo.get('color','#F6F5F4')
            zone_border = zinfo.get('border','#A6A196')
            st.markdown(f"""
            <div class="{css_class}" style="margin:6px 0">
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
              <div>
                {status} <strong>{name}</strong>
                &nbsp;·&nbsp; <span style="font-size:0.85em">
                  Your: <em>{user_zone_val}</em> (z{user_score_val})
                  &nbsp;→&nbsp;
                  Correct: <strong style="color:{"#347737" if zone_match else "#BA3434"}">{correct_zone}</strong> (z{correct_score})
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



def _attack_tree_section():
    scenario = current_workshop["scenario"]
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
        <div style="background:#2D6B63;color:white;
                    padding:18px 22px;border-radius:10px;margin:10px 0;border-left:5px solid #89BBB5">
        <div style="font-size:0.7em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                    color:#AACFCA;margin-bottom:10px">HOW TO READ THIS ATTACK TREE</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div>
          <strong style="color:#A4E5DC">🎯 GOAL node (root, pink)</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">The attacker's final objective. Everything below is a path toward this goal.</span>
        </div>
        <div>
          <strong style="color:#A4E5DC">🔵 OR gates (green)</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">ANY child path succeeds = goal reached. Each OR branch is a separate attack surface you must defend.</span>
        </div>
        <div>
          <strong style="color:#A4E5DC">🔗 AND gates (blue)</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">ALL children must succeed. Block ANY single step → entire path blocked. This is defense-in-depth.</span>
        </div>
        <div>
          <strong style="color:#A4E5DC">🟡 Leaf nodes</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">Atomic attack steps. <strong style="color:#E9A0A0">Easy</strong>=automated tools, no skill. <strong style="color:#F5E980">Medium</strong>=technical knowledge. <strong style="color:#A9D2AA">Hard</strong>=expert + resources.</span>
        </div>
        </div>
        <hr style="border-color:rgba(255,255,255,0.2);margin:12px 0">
        <strong style="color:#A4E5DC">Prioritization rule:</strong>
        <span style="color:#DAD8D4"> Find the path with the most "Easy" leaf nodes and the fewest AND gates.
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



def _identify_section():
    scenario = current_workshop["scenario"]
    st.markdown("---")
    # Already-analyzed threat IDs — prevents duplicate inflation
    analyzed_ids = {a["matched_threat_id"] for a in st.session_state.user_answers}
    remaining_threats = [t for t in workshop_threats if t["id"] not in analyzed_ids]

    if not remaining_threats:
        st.success("✅ All threats for this workshop have been analyzed!")
    else:
        st.markdown(f"""
        <div style="background:#F1F0EF;padding:10px 16px;border-radius:8px;border-left:4px solid #3CAFA0;margin:8px 0">
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

        comps_ = current_workshop["scenario"]["components"]
        all_options = [c["name"] for c in comps_] + [f"{f['source']} → {f['destination']}" for f in current_workshop["scenario"]["data_flows"]]
        c_a, c_b = st.columns(2)
        user_component = c_a.selectbox("Which component/flow is affected?", ["— select —"] + all_options, index=0)
        user_stride = c_b.selectbox(
            "STRIDE category:",
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
                _rec = new_record(user_component, user_stride, selected_predefined)
                st.session_state.user_answers.append(_rec)
                _tick_stride_map(user_component, user_stride)
                sync_labels_from_analysis(False)
                recalc_totals()
                save_progress()
                st.rerun()

    render_identified_threats()

    st.progress(min(len(st.session_state.user_answers) / current_workshop['target_threats'], 1.0))
    if len(st.session_state.user_answers) < current_workshop['target_threats']:
        st.info(f"⚠️ {current_workshop['target_threats'] - len(st.session_state.user_answers)} more threats needed to complete this workshop.")
    else:
        st.success("✅ All required threat scenarios identified — continue to Step 4.")



def _owasp_reference():
    scenario = current_workshop["scenario"]
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



def render_report_page():
    scenario = current_workshop["scenario"]
    st.header("Wrap-up · Assessment & threat-mapped architecture review")
    render_eop_integration_status("final report")
    recalc_totals()
    scope_reminder()

    if not st.session_state.user_answers:
        st.warning("No answers to assess")
        if st.button("⬅️ Back"):
            go_page(3)
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
    <b>Coloured letters (S T R I D E)</b> = the STRIDE categories you mapped to each element.
    </div>
    """, unsafe_allow_html=True)

    assess_diag_tabs = st.tabs([
        "🔴 Threat-Highlighted Map",
        "🔵 STRIDE-Annotated Map",
        "🏗️ Clean Architecture",
        "🏷️ Zone-Labelled DFD",
        "🎯 ATT&CK Map"
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
    with assess_diag_tabs[4]:
        show_architecture_diagram(current_workshop, mode="mitre", key_suffix="s6_mitre")

    st.markdown("---")
    st.subheader("📋 9-Step Threat Model Review")
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
        "Source": a.get("source", "STRIDE exercise"),
        "Threat_Scenario": a.get("threat_text") or a.get("predefined_threat", {}).get("threat", ""),
        "EoP_Card": a.get("eop_card_title", ""),
        "Evidence_Attack_Path": a.get("eop_evidence", ""),
        "Candidate_Mitigation": a.get("eop_candidate_mitigation", ""),
        "ATTACK_CAPEC_Note": a.get("eop_attack_mapping", ""),
        "EoP_Initial_Priority": a.get("eop_initial_priority", ""),
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


def render_complete_page():
    scenario = current_workshop["scenario"]
    recalc_totals()
    # Mark completed
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()

    final_pct  = st.session_state.total_score / st.session_state.max_score * 100 if st.session_state.max_score > 0 else 0
    grade      = "A+" if final_pct >= 95 else "A" if final_pct >= 90 else "B" if final_pct >= 80 else "C" if final_pct >= 70 else "D" if final_pct >= 60 else "F"
    grade_grad = ("#AB8118" if final_pct >= 90 else
                  "#205924" if final_pct >= 80 else
                  "#D55611" if final_pct >= 70 else
                  "#B23D19")

    if final_pct >= 90:
        st.balloons()

    # ── Certificate-style completion banner ─────────────────────────────────
    from datetime import date
    today = date.today().strftime("%B %d, %Y")
    st.markdown(f"""
    <div style="background:#1D1C1A;border-radius:14px;
                padding:32px 36px;text-align:center;box-shadow:0 6px 24px rgba(0,0,0,0.3);
                border:2px solid rgba(255,255,255,0.1)">
      <div style="color:#A4E5DC;font-size:0.85em;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px">
        Certificate of Completion
      </div>
      <h1 style="color:white;margin:0 0 8px 0;font-size:2em">🏆 {current_workshop['name']}</h1>
      <div style="color:#C0EAE4;font-size:1em;margin-bottom:16px">
        {current_workshop['scenario']['title']} · {current_workshop['level']}
      </div>
      <div style="display:inline-block;background:{grade_grad};color:white;
                  padding:12px 32px;border-radius:30px;font-size:1.8em;font-weight:700;
                  box-shadow:0 3px 12px rgba(0,0,0,0.4);margin-bottom:16px">
        Grade: {grade} &nbsp;|&nbsp; {final_pct:.1f}%
      </div>
      <div style="color:#A4E5DC;font-size:0.85em">{today}</div>
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
    st.subheader("📋 9-Step Threat Modeling Summary")
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
            <div style="background:#F1F0EF;padding:10px 14px;
                        border-radius:8px;border-left:4px solid #3CAFA0;margin:4px 0;font-size:0.88em">
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
            <div style="background:#FAFAFA;border-left:4px solid #E35E5C;border-radius:8px;
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
        st.success("🏆 **All Workshops Completed! Full 9-Step Process Mastered!**")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review Assessment", use_container_width=True):
            go_page(10)
    with col2:
        if st.button("🏠 Return to Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            save_progress()
            st.rerun()



# ═════════════════════════════════════════════════════════════════════════════════════════════
#  PAGE DISPATCH — nine steps, then the report and completion pages
# ═════════════════════════════════════════════════════════════════════════════════════════════
# Visible runtime marker: confirms which source file Streamlit is executing.
st.sidebar.markdown("---")
st.sidebar.markdown("### 🧩 Lab build")
st.sidebar.success("EoP integration v4 · scenario-isolated shared registers")
st.sidebar.caption("If this marker is absent, Streamlit is running a different/older file. Stop the server and launch workshop27_eop_integrated_v4.py.")

STEP_RENDERERS = {
    1: render_scope_page, 2: render_dfd_step, 3: render_stride_step, 4: render_boundaries_step, 5: render_attack_step,
    6: render_scoring_page, 7: render_controls_step, 8: render_residual_page, 9: render_review_plan_page,
    10: render_report_page, 11: render_complete_page,
}
STEP_RENDERERS.get(int(st.session_state.current_step), render_scope_page)()

st.markdown("---")
st.caption("STRIDE Threat Modeling Learning Lab · EoP integration v4 | Scope → DFD → STRIDE → Trust boundaries → ATT&CK · CAPEC → Scoring → Controls → Residual risk → Review")
