"""
STRIDE Threat Modeling Mastery Lab — Streamlit Edition
Run: streamlit run app.py
"""
import streamlit as st
import json
import hashlib
import re
from pathlib import Path
import plotly.graph_objects as go

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Modeling Mastery Lab",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Load data ─────────────────────────────────────────────────────────────────
DATA = Path(__file__).parent / "data"

@st.cache_data
def load_json(name):
    return json.loads((DATA / name).read_text())

WS           = load_json("ws_data.json")
STRIDE_GUIDE = load_json("stride_guide.json")
C4_LAYOUTS   = load_json("c4_layouts.json")
GLOSSARY     = load_json("glossary.json")
WS_STRIDE    = load_json("ws_stride.json")

# ── Constants ─────────────────────────────────────────────────────────────────
ADMIN_EMAIL    = "admin@threatlab.com"
ADMIN_PASSWORD = "ThreatLab-Admin-2025!"

STRIDE_COLORS = {
    "S": "#00e5ff", "T": "#ffa726", "R": "#66bb6a",
    "I": "#5c6bc0", "D": "#ef5350", "E": "#ab47bc",
    "Spoofing": "#00e5ff", "Tampering": "#ffa726", "Repudiation": "#66bb6a",
    "Information Disclosure": "#5c6bc0", "Denial of Service": "#ef5350",
    "Elevation of Privilege": "#ab47bc",
}

ZONE_COLORS = {
    "Not in Control": "#ef5350",
    "Minimal Trust":  "#ffa726",
    "Standard":       "#5c6bc0",
    "Elevated":       "#ab47bc",
    "Critical":       "#ef5350",
    "Max Security":   "#66bb6a",
}

STEPS = [
    ("why",      "① Why TM?",         "Foundations"),
    ("s101",     "② STRIDE 101",       "Foundations"),
    ("q1",       "Q1 The System",      "Q1 — What?"),
    ("q2zones",  "③ Zone Labels",      "Q2 — Wrong?"),
    ("q2arch",   "Q2 Architecture",    "Q2 — Wrong?"),
    ("q2stride", "④ Find Threats",     "Q2 — Wrong?"),
    ("q2tree",   "⑤ Attack Paths",     "Q2 — Wrong?"),
    ("q3",       "Q3 Mitigations",     "Q3 — Do about?"),
    ("q4",       "Q4 Validate",        "Q4 — Good job?"),
    ("cert",     "🏆 Certificate",     "Complete"),
]

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&family=Inter:wght@400;600;700&display=swap');

:root {
    --bg:       #060912;
    --panel:    #090d14;
    --card:     #0d1219;
    --raised:   #111827;
    --border:   #1e2d42;
    --borderHi: #2a3f58;
    --text:     #e8eaf6;
    --sub:      #8899aa;
    --muted:    #4a5568;
    --accent:   #00e5ff;
    --blue:     #5c6bc0;
    --amber:    #ffa726;
    --red:      #ef5350;
    --green:    #66bb6a;
    --purple:   #ab47bc;
    --redD:     #1a0505;
    --greenD:   #051a08;
}

/* Hide default Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1rem; max-width: 1100px; }
section[data-testid="stSidebar"] { background: var(--panel) !important; }

html, body, .stApp { background: var(--bg) !important; color: var(--text) !important; }

/* Typography */
h1, h2, h3 { font-family: 'JetBrains Mono', monospace !important; color: var(--text); }
p, li, div  { font-family: 'Inter', sans-serif; color: var(--sub); }
code        { font-family: 'JetBrains Mono', monospace; color: var(--accent); }

/* Buttons */
.stButton > button {
    background: transparent !important;
    border: 1.5px solid var(--accent) !important;
    color: var(--accent) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    letter-spacing: 0.8px !important;
    border-radius: 5px !important;
    transition: all 0.15s !important;
}
.stButton > button:hover {
    background: rgba(0,229,255,0.1) !important;
}
.btn-primary > button {
    background: var(--accent) !important;
    color: #000 !important;
}
.btn-danger > button {
    border-color: var(--red) !important;
    color: var(--red) !important;
}
.btn-success > button {
    border-color: var(--green) !important;
    color: var(--green) !important;
}
.btn-ghost > button {
    border-color: var(--border) !important;
    color: var(--muted) !important;
}

/* Inputs */
.stTextInput input, .stTextArea textarea, .stSelectbox select {
    background: var(--raised) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    font-family: 'Inter', sans-serif !important;
    border-radius: 5px !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px rgba(0,229,255,0.15) !important;
}

/* Radio buttons */
.stRadio > div { background: transparent !important; }
.stRadio label { color: var(--sub) !important; font-family: 'Inter', sans-serif !important; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: var(--raised) !important;
    border-radius: 8px !important;
    padding: 4px !important;
    gap: 2px !important;
    border-bottom: none !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--muted) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 11px !important;
    font-weight: 700 !important;
    border-radius: 5px !important;
    border: none !important;
}
.stTabs [aria-selected="true"] {
    background: rgba(0,229,255,0.15) !important;
    color: var(--accent) !important;
}
.stTabs [data-baseweb="tab-panel"] {
    background: transparent !important;
    padding-top: 16px !important;
}

/* Progress bar */
.stProgress > div > div { background: var(--accent) !important; }

/* Expander */
.streamlit-expanderHeader {
    background: var(--card) !important;
    color: var(--text) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* Metric cards */
.metric-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}

/* Alert boxes */
.alert-info    { background: rgba(92,107,192,0.1); border-left: 4px solid #5c6bc0; padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 8px 0; }
.alert-success { background: rgba(102,187,106,0.1); border-left: 4px solid #66bb6a; padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 8px 0; }
.alert-warn    { background: rgba(255,167,38,0.1);  border-left: 4px solid #ffa726; padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 8px 0; }
.alert-error   { background: rgba(239,83,80,0.1);   border-left: 4px solid #ef5350; padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 8px 0; }

/* Tag pills */
.tag {
    display: inline-flex; align-items: center;
    padding: 2px 8px; border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px; font-weight: 700;
    margin-right: 4px;
}

/* Cards */
.ws-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    transition: border-color 0.2s;
    cursor: pointer;
}
.ws-card:hover { border-color: var(--accent); }

/* Step bar */
.step-item {
    display: flex; align-items: center; gap: 6px;
    padding: 6px 10px; border-radius: 5px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px; font-weight: 700;
}

/* Scrollable containers */
.scroll-y { overflow-y: auto; max-height: 400px; }

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
}
.pulse { animation: pulse 1.5s ease-in-out infinite; }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def alert(msg, kind="info", title=None):
    title_html = f"<strong style='color:var(--text)'>{title}</strong><br>" if title else ""
    st.markdown(f'<div class="alert-{kind}">{title_html}{msg}</div>', unsafe_allow_html=True)

def tag(label, color="#00e5ff"):
    return f'<span class="tag" style="background:{color}20;border:1px solid {color}44;color:{color}">{label}</span>'

def card_html(content, border_color="var(--border)", bg="var(--card)", extra=""):
    return f'<div style="background:{bg};border:1px solid {border_color};border-radius:8px;padding:16px;{extra}">{content}</div>'

def stride_color(letter_or_name):
    return STRIDE_COLORS.get(letter_or_name, STRIDE_COLORS.get(str(letter_or_name)[:1] if letter_or_name else "S", "#aaa"))

def zone_color(zone):
    for k, v in ZONE_COLORS.items():
        if k.split()[0].lower() in (zone or "").lower():
            return v
    return "#aaa"

def get_ws_stride(ws_id):
    return WS_STRIDE.get(str(ws_id), STRIDE_GUIDE)

def skey(*parts):
    """Namespaced session state key"""
    return "_".join(str(p) for p in parts)

def ss(key, default=None):
    return st.session_state.get(key, default)

def set_ss(key, value):
    st.session_state[key] = value


# ═══════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════

def get_users():
    return ss("tm_users", {})

def save_users(u):
    set_ss("tm_users", u)

def seed_admin():
    users = get_users()
    if ADMIN_EMAIL not in users:
        users[ADMIN_EMAIL] = {"name": "Admin", "pw": ADMIN_PASSWORD, "role": "admin"}
        save_users(users)

def get_released():
    return set(ss("tm_released", {"1"}))

def set_released(s):
    set_ss("tm_released", s)

def is_admin():
    u = ss("tm_user")
    return u and u.get("role") == "admin"

def render_auth():
    seed_admin()
    st.markdown("""
    <div style='text-align:center;padding:32px 0 16px'>
        <div style='font-family:JetBrains Mono,monospace;font-size:44px;color:var(--accent);
            letter-spacing:4px;line-height:1;margin-bottom:8px'>THREAT MODELING</div>
        <div style='font-family:JetBrains Mono,monospace;font-size:28px;color:var(--text);
            letter-spacing:2px;margin-bottom:12px'>MASTERY LAB</div>
        <div style='font-size:13px;color:var(--sub)'>5 workshops · Shostack 4Q · STRIDE + MAESTRO · Attack simulation</div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        mode = st.radio("", ["Sign In", "Register"], horizontal=True,
                        label_visibility="collapsed")
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        if mode == "Register":
            name  = st.text_input("Full Name", placeholder="Your name")
            email = st.text_input("Email Address", placeholder="you@example.com")
            pw    = st.text_input("Password", type="password", placeholder="Min. 8 characters")
            pw2   = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
            if st.button("CREATE ACCOUNT ▶", use_container_width=True):
                if not name.strip():
                    st.error("Enter your name.")
                elif not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                    st.error("Enter a valid email address.")
                elif len(pw) < 8:
                    st.error("Password must be at least 8 characters.")
                elif pw != pw2:
                    st.error("Passwords do not match.")
                elif email.lower() in get_users():
                    st.error("Account already exists — sign in instead.")
                else:
                    users = get_users()
                    users[email.lower()] = {"name": name.strip(), "pw": pw, "role": "student"}
                    save_users(users)
                    user = {"email": email.lower(), "name": name.strip(), "role": "student"}
                    set_ss("tm_user", user)
                    st.success("Account created! Welcome.")
                    st.rerun()
        else:
            email = st.text_input("Email Address", placeholder="you@example.com", key="li_email")
            pw    = st.text_input("Password", type="password", placeholder="Your password", key="li_pw")
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
            if st.button("SIGN IN ▶", use_container_width=True):
                if not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                    st.error("Enter a valid email address.")
                elif not pw:
                    st.error("Enter your password.")
                else:
                    u = get_users().get(email.lower())
                    if not u:
                        st.error("No account found — please register.")
                    elif u["pw"] != pw:
                        st.error("Incorrect password.")
                    else:
                        user = {"email": email.lower(), "name": u["name"], "role": u["role"]}
                        set_ss("tm_user", user)
                        st.rerun()

            alert("Use admin credentials provided by your facilitator to access the Admin Panel and release workshops for all students.", "info", "Admin access")

        # Feature tags
        st.markdown("""
        <div style='display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-top:20px'>
        """ + "".join([
            tag(l, "#00e5ff") for l in ["5 Workshops","STRIDE + MAESTRO","Attack Simulation","Shostack 4Q"]
        ]) + """</div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# ADMIN PANEL
# ═══════════════════════════════════════════════════════════════════════════

def render_admin():
    st.markdown("---")
    st.markdown("### ⚙ Admin Panel")
    user = ss("tm_user")
    st.caption(f"Signed in as {user['email']} · Admin")

    tab1, tab2 = st.tabs(["Workshop Visibility", "Student Roster"])

    released = get_released()
    WS_META = {
        "1": ("WS1 — TechMart E-Commerce",      "FOUNDATION",   "#66bb6a"),
        "2": ("WS2 — NeuralAPI LLM Platform",   "INTERMEDIATE", "#5c6bc0"),
        "3": ("WS3 — DataInsight Analytics",    "ADVANCED",     "#ffa726"),
        "4": ("WS4 — ClinicalMind AI Diagnosis","EXPERT",       "#ef5350"),
        "5": ("WS5 — AI Safety Infrastructure", "CAPSTONE",     "#00e5ff"),
    }

    with tab1:
        alert("Released workshops appear on every student's homepage. Students still need access codes to enter WS2–WS5. WS1 is always visible and free.", "info")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Released", f"{len(released)}/5")
        with c2:
            students = [u for u in get_users().values() if u.get("role") == "student"]
            st.metric("Students", len(students))
        with c3:
            st.metric("Workshops", 5)

        for ws_id, (label, level, col) in WS_META.items():
            is_on = ws_id in released
            locked = ws_id == "1"
            cols = st.columns([3, 1])
            with cols[0]:
                st.markdown(f"""
                <div style='padding:10px 14px;background:var(--card);border-radius:7px;
                    border:1.5px solid {col if is_on else "var(--border)"};margin-bottom:6px;
                    transition:all .15s'>
                    <strong style='color:var(--text)'>{label}</strong>
                    {tag(level, col)}
                    <span style='font-size:11px;font-family:JetBrains Mono,monospace;
                        color:{"#66bb6a" if is_on else "var(--muted)"}'>
                        {"● Visible to all students" if is_on else "○ Hidden"}
                    </span>
                </div>""", unsafe_allow_html=True)
            with cols[1]:
                if locked:
                    st.caption("ALWAYS ON")
                else:
                    if is_on:
                        if st.button(f"HIDE", key=f"hide_{ws_id}"):
                            released.discard(ws_id)
                            set_released(released)
                            st.rerun()
                    else:
                        if st.button(f"RELEASE", key=f"rel_{ws_id}"):
                            released.add(ws_id)
                            set_released(released)
                            st.rerun()

        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("RELEASE ALL WORKSHOPS", use_container_width=True):
                set_released({"1","2","3","4","5"})
                st.rerun()
        with col_b:
            if st.button("RESET (WS1 only)", use_container_width=True):
                set_released({"1"})
                st.rerun()

    with tab2:
        all_users = get_users()
        students = [(e, u) for e, u in all_users.items() if u.get("role") == "student"]
        if not students:
            st.info("No student accounts registered yet.")
        for email, u in students:
            cols = st.columns([1, 3, 1, 1])
            with cols[0]:
                st.markdown(f"""<div style='width:36px;height:36px;border-radius:18px;
                    background:rgba(92,107,192,0.2);border:1.5px solid #5c6bc0;
                    display:flex;align-items:center;justify-content:center;
                    font-family:JetBrains Mono,monospace;font-weight:700;color:#5c6bc0;
                    font-size:14px'>{(u.get('name','?'))[0].upper()}</div>""",
                    unsafe_allow_html=True)
            with cols[1]:
                st.markdown(f"**{u.get('name','—')}**")
                st.caption(email)
            with cols[2]:
                st.markdown(tag("student", "#5c6bc0"), unsafe_allow_html=True)
            with cols[3]:
                if st.button("REMOVE", key=f"rm_{email}"):
                    users = get_users()
                    del users[email]
                    save_users(users)
                    st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# HOMEPAGE
# ═══════════════════════════════════════════════════════════════════════════

def render_home():
    user = ss("tm_user")
    released = get_released()
    completed = ss("tm_completed", set())

    # Header bar
    hc1, hc2 = st.columns([3, 1])
    with hc1:
        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace;font-size:28px;
            color:var(--accent);letter-spacing:2px'>
            THREAT MODELING MASTERY LAB
        </div>""", unsafe_allow_html=True)
    with hc2:
        ucols = st.columns([2, 1])
        with ucols[0]:
            st.caption(f"👤 {user.get('name','?')}")
        with ucols[1]:
            if st.button("Sign out", key="signout"):
                set_ss("tm_user", None)
                st.rerun()

    if is_admin():
        if st.button("⚙ ADMIN PANEL", key="admin_btn"):
            set_ss("show_admin", not ss("show_admin", False))

    if ss("show_admin", False) and is_admin():
        render_admin()
        st.markdown("---")

    # Skill progression strip
    st.markdown("### Skill Progression — complete in order")
    prog_cols = st.columns(4)
    WS_PROG = [
        ("1", "FOUNDATION",   "#66bb6a", "4Q framework · 6 STRIDE categories · Zone labelling · Attack trees"),
        ("2", "INTERMEDIATE", "#5c6bc0", "AI/LLM threats · MAESTRO framework · Prompt injection · Compliance"),
        ("3", "ADVANCED",     "#ffa726", "Multi-tenant isolation · Event streaming · SOC 2 audit requirements"),
        ("4", "EXPERT",       "#ef5350", "Safety-critical AI · SaMD regulatory · Adversarial ML attacks"),
    ]
    for i, (wid, level, col, skills) in enumerate(WS_PROG):
        done = wid in completed
        with prog_cols[i]:
            st.markdown(f"""
            <div style='padding:12px;background:var(--card);border-radius:7px;
                border:1.5px solid {col if done else "var(--border)"};
                opacity:{1.0 if (done or wid=="1" or str(int(wid)-1) in completed) else 0.55}'>
                {tag(level, col)}
                <div style='font-family:JetBrains Mono,monospace;font-weight:700;
                    color:{col if done else "var(--text)"};font-size:12px;margin:6px 0 4px'>
                    WS{wid} {"✓" if done else ""}
                </div>
                <div style='font-size:10px;color:var(--muted);line-height:1.5'>{skills}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # Workshop cards
    WS_ACCESS = {
        "1": None, "2": "MICRO2025", "3": "TENANT2025",
        "4": "HEALTH2025", "5": None,
    }
    WS_DURATION = {"1":"90 min","2":"90 min","3":"90 min","4":"90 min","5":"90 min"}
    WS_LEVEL_COL = {
        "FOUNDATION":"#66bb6a","INTERMEDIATE":"#5c6bc0","ADVANCED":"#ffa726",
        "EXPERT":"#ef5350","CAPSTONE":"#00e5ff",
    }

    unlocked = ss("tm_unlocked", set())
    visible_ws = [
        (wid, ws) for wid, ws in WS.items()
        if wid in released or wid in completed or wid in unlocked
    ]

    for i in range(0, len(visible_ws), 3):
        row = visible_ws[i:i+3]
        cols = st.columns(len(row))
        for j, (wid, ws) in enumerate(row):
            with cols[j]:
                level = ws.get("level", "")
                col = WS_LEVEL_COL.get(level, "#aaa")
                done = wid in completed
                code_needed = WS_ACCESS.get(wid) and wid not in unlocked and wid not in completed

                st.markdown(f"""
                <div class='ws-card' style='border-top:3px solid {col}'>
                    <div style='display:flex;gap:8px;align-items:center;margin-bottom:10px'>
                        {tag(level, col)}
                        {"" if not done else tag("✓ Done", "#66bb6a")}
                        <span style='font-size:10px;color:var(--muted);
                            font-family:JetBrains Mono,monospace;margin-left:auto'>
                            {WS_DURATION.get(wid,"")}
                        </span>
                    </div>
                    <div style='font-weight:700;color:var(--text);font-size:15px;margin-bottom:4px'>
                        {ws.get("name","")}
                    </div>
                    <div style='font-size:11px;color:var(--muted);margin-bottom:10px'>
                        {ws.get("subtitle","")}
                    </div>
                </div>""", unsafe_allow_html=True)

                if code_needed:
                    code_inp = st.text_input(f"Access code", key=f"code_{wid}",
                                             placeholder="Enter code")
                    if st.button(f"UNLOCK", key=f"unlock_{wid}"):
                        if code_inp == WS_ACCESS[wid]:
                            unlocked = ss("tm_unlocked", set())
                            unlocked.add(wid)
                            set_ss("tm_unlocked", unlocked)
                            st.success("Unlocked!")
                            st.rerun()
                        else:
                            st.error("Incorrect code.")
                elif st.button(f"{'CONTINUE' if done else 'START'} WS{wid} ▶", key=f"start_{wid}"):
                    set_ss("current_ws", wid)
                    set_ss("current_step", "why")
                    # Reset step states
                    for key in list(st.session_state.keys()):
                        if key.startswith(f"ws{wid}_"):
                            del st.session_state[key]
                    st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# STEP BAR
# ═══════════════════════════════════════════════════════════════════════════

def render_step_bar(ws_id, current_step):
    step_ids = [s[0] for s in STEPS]
    cur_idx  = step_ids.index(current_step) if current_step in step_ids else 0
    phases = {}
    for sid, label, phase in STEPS:
        phases.setdefault(phase, []).append((sid, label))

    phase_colors = {
        "Foundations": "#00e5ff",
        "Q1 — What?": "#00e5ff",
        "Q2 — Wrong?": "#5c6bc0",
        "Q3 — Do about?": "#ffa726",
        "Q4 — Good job?": "#66bb6a",
        "Complete": "#66bb6a",
    }

    html = '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px">'
    for sid, label, phase in STEPS:
        idx = step_ids.index(sid)
        col = phase_colors.get(phase, "#aaa")
        if idx < cur_idx:
            bg, fg, bc = f"rgba({','.join(str(int(col[i:i+2],16)) for i in (1,3,5))},0.15)", col, col
        elif idx == cur_idx:
            bg, fg, bc = f"rgba({','.join(str(int(col[i:i+2],16)) for i in (1,3,5))},0.25)", col, col
        else:
            bg, fg, bc = "var(--raised)", "var(--muted)", "var(--border)"
        html += f'<div class="step-item" style="background:{bg};border:1px solid {bc};color:{fg}">{label}</div>'
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# ARCHITECTURE DIAGRAM (Plotly)
# ═══════════════════════════════════════════════════════════════════════════

def render_architecture(ws, hot_nodes=None, hot_flows=None, sim_mode="attack",
                        reveal_nodes=None, reveal_flows=None, height=420, key="arch"):
    """Render the workshop architecture as an animated Plotly figure."""
    ws_id = ws.get("id", "1")
    layout = C4_LAYOUTS.get(str(ws_id), C4_LAYOUTS.get("1", {}))
    nodes_pos = layout.get("nodes", {})
    boundaries = layout.get("boundaries", [])
    W = layout.get("W", 820)
    H = layout.get("H", 600)

    hot_nodes   = hot_nodes   or set()
    hot_flows   = hot_flows   or set()
    reveal_nodes = reveal_nodes or set()
    reveal_flows = reveal_flows or set()

    components = ws.get("components", [])
    flows      = ws.get("flows", [])

    fig = go.Figure()
    fig.update_layout(
        paper_bgcolor="#060912", plot_bgcolor="#060912",
        xaxis=dict(range=[0, W], showgrid=False, zeroline=False, visible=False),
        yaxis=dict(range=[H, 0], showgrid=False, zeroline=False, visible=False,
                   scaleanchor="x", scaleratio=1),
        margin=dict(l=0, r=0, t=0, b=0),
        height=height, showlegend=False,
        font=dict(family="JetBrains Mono, monospace", color="#e8eaf6"),
        hovermode="closest",
    )

    # Boundary swim lanes
    for b in boundaries:
        zcol = zone_color(b.get("zone", b.get("label", "")))
        # Border rect via shapes
        fig.add_shape(type="rect",
            x0=b["x"], y0=b["y"], x1=b["x"]+b["w"], y1=b["y"]+b["h"],
            line=dict(color=zcol, width=1, dash="dot"),
            fillcolor="rgba(0,0,0,0)", opacity=0.3, layer="below")
        fig.add_annotation(
            x=b["x"]+8, y=b["y"]+12, text=b.get("label",""),
            font=dict(size=9, color=zcol, family="JetBrains Mono, monospace"),
            showarrow=False, xanchor="left", yanchor="top", opacity=0.7)

    # Flows
    def get_center(name):
        p = nodes_pos.get(name)
        if not p: return None
        return p["x"] + p["w"]/2, p["y"] + p["h"]/2

    for f in flows:
        src_c = get_center(f["src"])
        dst_c = get_center(f["dst"])
        if not src_c or not dst_c: continue
        fk = f"{f['src']}→{f['dst']}"
        is_hot = fk in hot_flows
        is_rev = fk in reveal_flows
        col = ("#66bb6a" if sim_mode == "mitigated" else "#ef5350") if is_hot else \
              ("#ffa726" if is_rev else "#2a3f58")
        width = 2.5 if is_hot else (2.0 if is_rev else 1.5)
        dash = "dot" if (is_hot and sim_mode == "mitigated") else "solid"
        opacity = 1.0 if (is_hot or is_rev) else 0.4

        mx = (src_c[0]+dst_c[0])/2
        my = (src_c[1]+dst_c[1])/2 - 20

        fig.add_trace(go.Scatter(
            x=[src_c[0], mx, dst_c[0]],
            y=[src_c[1], my, dst_c[1]],
            mode="lines+markers",
            line=dict(color=col, width=width, dash=dash, shape="spline"),
            marker=dict(size=[0, 0, 8], symbol=["circle","circle","arrow-wide"],
                       color=col, angle=0),
            opacity=opacity,
            hoverinfo="text",
            hovertext=f"{f['src']} → {f['dst']}<br>{f.get('data','')}",
            showlegend=False,
        ))

        # Data label on hot/revealed flows
        if is_hot or is_rev:
            fig.add_annotation(
                x=(src_c[0]+dst_c[0])/2, y=(src_c[1]+dst_c[1])/2 - 14,
                text=f.get("data","")[:22], showarrow=False,
                font=dict(size=8, color=col, family="JetBrains Mono, monospace"),
                bgcolor="#060912", borderpad=2)

    # Nodes
    for comp in components:
        name = comp["name"]
        p = nodes_pos.get(name)
        if not p: continue
        zcol = zone_color(comp.get("zone",""))
        is_hot = name in hot_nodes
        is_rev = name in reveal_nodes

        fill = (("#66bb6a" if sim_mode=="mitigated" else "#ef5350")+"22") if is_hot else \
               ("#ffa72618" if is_rev else "#0d1219")
        border_col = ("#66bb6a" if sim_mode=="mitigated" else "#ef5350") if is_hot else \
                     ("#ffa726" if is_rev else zcol)
        border_w = 2.5 if is_hot else (2.0 if is_rev else 1.0)
        text_col = ("#66bb6a" if sim_mode=="mitigated" else "#ef5350") if is_hot else zcol

        # Node rectangle
        fig.add_shape(type="rect",
            x0=p["x"], y0=p["y"], x1=p["x"]+p["w"], y1=p["y"]+p["h"],
            line=dict(color=border_col, width=border_w),
            fillcolor=fill, layer="above")

        # Mitigation bar
        if is_hot and sim_mode == "mitigated":
            fig.add_shape(type="rect",
                x0=p["x"], y0=p["y"]+p["h"]-3,
                x1=p["x"]+p["w"], y1=p["y"]+p["h"],
                fillcolor="#66bb6a", line=dict(color="#66bb6a", width=0))

        # STRIDE badge on hot nodes
        if is_hot:
            badge_text = "✓" if sim_mode == "mitigated" else "!"
            badge_col  = "#66bb6a" if sim_mode == "mitigated" else "#ef5350"
            fig.add_shape(type="rect",
                x0=p["x"]+p["w"]-24, y0=p["y"]-10,
                x1=p["x"]+p["w"], y1=p["y"]+8,
                fillcolor=badge_col, line=dict(color=badge_col, width=0))
            fig.add_annotation(
                x=p["x"]+p["w"]-12, y=p["y"]-1,
                text=badge_text, showarrow=False,
                font=dict(size=10, color="#fff", family="JetBrains Mono, monospace"))

        # Node label
        fig.add_annotation(
            x=p["x"]+p["w"]/2, y=p["y"]+p["h"]/2 - 6,
            text=f"<b>{name}</b>", showarrow=False,
            font=dict(size=10, color=text_col, family="JetBrains Mono, monospace"),
            xanchor="center", yanchor="middle")
        fig.add_annotation(
            x=p["x"]+p["w"]/2, y=p["y"]+p["h"]/2 + 9,
            text=comp.get("zone","").split()[0], showarrow=False,
            font=dict(size=8, color=text_col+"88" if is_hot else "#4a5568",
                     family="JetBrains Mono, monospace"),
            xanchor="center", yanchor="middle")

    # Legend
    for lbl, col in [("Hot/Attack","#ef5350"),("Mitigated","#66bb6a"),("Discovered","#ffa726"),("Normal","#2a3f58")]:
        fig.add_trace(go.Scatter(
            x=[None], y=[None], mode="markers",
            marker=dict(size=10, color=col, symbol="square"),
            name=lbl, showlegend=True))
    fig.update_layout(
        legend=dict(orientation="h", x=0, y=-0.02,
                   font=dict(size=9, color="#4a5568"),
                   bgcolor="rgba(0,0,0,0)"))

    st.plotly_chart(fig, use_container_width=True, key=f"arch_{key}_{ws_id}")


# ═══════════════════════════════════════════════════════════════════════════
# STEPS
# ═══════════════════════════════════════════════════════════════════════════

def render_step_why(ws):
    sk = f"ws{ws['id']}_why"
    panel = ss(sk+"_panel", 0)

    # Panel selector
    cols = st.columns(3)
    panels = [("01","The Case"), ("02","The Method"), ("03","Real Breach")]
    for i,(num,lbl) in enumerate(panels):
        with cols[i]:
            active = panel == i
            if st.button(f"{num} {lbl}", key=f"why_p{i}", use_container_width=True):
                set_ss(sk+"_panel", i)
                st.rerun()

    st.markdown("---")

    if panel == 0:
        st.markdown("## WHY THREAT MODELING?")
        st.markdown("IBM Systems Sciences measured the cost of fixing a security defect at each phase:")
        c1,c2,c3 = st.columns(3)
        with c1:
            st.markdown(card_html("""
            <div style='font-size:10px;color:#66bb6a;font-family:JetBrains Mono,monospace;
                font-weight:700;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px'>
                Design Time</div>
            <div style='font-family:JetBrains Mono,monospace;font-size:26px;color:#66bb6a;
                font-weight:900;margin-bottom:4px'>$80–$960</div>
            <div style='font-size:11px;color:var(--muted);margin-bottom:8px'>1× baseline</div>
            <div style='font-size:12px;color:var(--sub)'>Cheapest — catch it in a diagram before a line of code is written</div>
            """, "#66bb6a33"), unsafe_allow_html=True)
        with c2:
            st.markdown(card_html("""
            <div style='font-size:10px;color:#ffa726;font-family:JetBrains Mono,monospace;
                font-weight:700;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px'>
                Pre-release</div>
            <div style='font-family:JetBrains Mono,monospace;font-size:26px;color:#ffa726;
                font-weight:900;margin-bottom:4px'>$7.6K–$15K</div>
            <div style='font-size:11px;color:var(--muted);margin-bottom:8px'>10–15× baseline</div>
            <div style='font-size:12px;color:var(--sub)'>Code already written and tested — expensive to refactor</div>
            """, "#ffa72633"), unsafe_allow_html=True)
        with c3:
            st.markdown(card_html("""
            <div style='font-size:10px;color:#ef5350;font-family:JetBrains Mono,monospace;
                font-weight:700;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px'>
                Post-release</div>
            <div style='font-family:JetBrains Mono,monospace;font-size:26px;color:#ef5350;
                font-weight:900;margin-bottom:4px'>Up to $93K</div>
            <div style='font-size:11px;color:var(--muted);margin-bottom:8px'>100× baseline</div>
            <div style='font-size:12px;color:var(--sub)'>Customers affected, patches required, regulatory notification</div>
            """, "#ef535033"), unsafe_allow_html=True)
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        alert("Every hour spent in a threat modeling session saves an estimated <strong>10–100 hours</strong> of post-release remediation. Threat modeling is not a security activity — it is a <strong>cost reduction activity.</strong>", "info")
        if st.button("THE METHOD ▶"):
            set_ss(sk+"_panel", 1); st.rerun()

    elif panel == 1:
        st.markdown("## SHOSTACK'S 4-QUESTION FRAMEWORK")
        st.markdown("Every threat modeling session answers exactly four questions, in order:")
        for q, lbl, desc, col in [
            ("Q1","What are we working on?","System · Assets · Trust boundaries · Assumptions","#00e5ff"),
            ("Q2","What can go wrong?","STRIDE per component · Attack trees · Paths","#5c6bc0"),
            ("Q3","What are we doing about it?","Mitigate · Eliminate · Transfer · Accept","#ffa726"),
            ("Q4","Did we do a good enough job?","Coverage · Gaps · Validation · Score","#66bb6a"),
        ]:
            st.markdown(f"""<div style='display:flex;gap:14px;padding:16px;margin-bottom:8px;
                background:var(--card);border-radius:8px;border:1px solid {col}22;
                border-left:4px solid {col}'>
                <div style='width:40px;height:40px;border-radius:6px;background:{col}18;
                    border:1.5px solid {col};display:flex;align-items:center;
                    justify-content:center;font-family:JetBrains Mono,monospace;
                    font-size:18px;color:{col};font-weight:900;flex-shrink:0'>{q}</div>
                <div>
                    <div style='font-weight:700;color:var(--text);font-size:15px;margin-bottom:4px'>{lbl}</div>
                    <div style='font-size:11.5px;color:var(--sub);font-family:JetBrains Mono,monospace'>{desc}</div>
                </div>
            </div>""", unsafe_allow_html=True)
        alert("STRIDE is the tool you'll use to answer Q2. It gives every component a systematic checklist of 6 threat categories.", "info")
        if st.button("SEE A REAL BREACH ▶"):
            set_ss(sk+"_panel", 2); st.rerun()

    else:
        st.markdown("## 2019 CAPITAL ONE BREACH")
        st.markdown("**$80M fine · 106M records** · A 3-step attack that a threat model would have caught.")
        for q, col, lbl, text in [
            ("Q1","#00e5ff","What were they working on?",
             "Capital One deployed a WAF on AWS EC2 with an over-permissioned IAM role attached — it had S3 read permissions across the entire account. A proper Q1 asset list would have flagged the IAM role credentials as a critical asset."),
            ("Q2","#5c6bc0","What could go wrong?",
             "STRIDE on the WAF: T (Tampering) — user-supplied URLs forwarded without validation enables SSRF. I (Information Disclosure) — EC2 metadata endpoint returns AWS credentials to any process that reaches 169.254.x.x. E (EoP) — over-permissioned role elevates the WAF compromise into full S3 access."),
            ("Q3","#ffa726","What should they have done?",
             "Any single control would have stopped it: (1) Block RFC-1918/link-local URLs in WAF input validation. (2) IMDSv2 required — metadata only responds to PUT-initiated sessions, blocking SSRF GET. (3) Least-privilege IAM — WAF role writes logs only, no S3 read."),
            ("Q4","#66bb6a","Did they do a good enough job?",
             "No — the breach ran undetected for months. Q4 failed on detection: breach discovered externally via GitHub. A complete Q4 adds CloudTrail alerts, GuardDuty credential anomaly detection, and IAM Access Analyzer. Prevention without detection is incomplete."),
        ]:
            st.markdown(f"""<div style='display:flex;gap:14px;padding:14px 16px;margin-bottom:8px;
                background:var(--card);border-radius:8px;border:1px solid {col}22;border-left:4px solid {col}'>
                <div style='width:36px;height:36px;border-radius:5px;background:{col}18;
                    border:1.5px solid {col};display:flex;align-items:center;justify-content:center;
                    font-family:JetBrains Mono,monospace;font-size:16px;color:{col};
                    font-weight:900;flex-shrink:0'>{q}</div>
                <div>
                    <div style='font-weight:700;color:var(--text);font-size:13px;margin-bottom:5px'>{lbl}</div>
                    <div style='font-size:12.5px;color:var(--sub);line-height:1.75'>{text}</div>
                </div>
            </div>""", unsafe_allow_html=True)
        if st.button("START: STRIDE 101 ▶"):
            set_ss("current_step", "s101"); st.rerun()


def render_step_s101(ws):
    sk = f"ws{ws['id']}_s101"
    guide = get_ws_stride(ws["id"])
    idx = ss(sk+"_idx", -1)  # -1=intro, 0-5=letters, 6=done
    passed = ss(sk+"_passed", set())
    revealed = ss(sk+"_revealed", False)
    chosen = ss(sk+"_chosen", None)

    if idx == -1:
        st.markdown("## STRIDE 101")
        st.markdown(f"Six threat categories. One per component in your architecture diagram. Each letter taught through a **{ws['name']}** scenario.")
        cols = st.columns(6)
        for i, rule in enumerate(STRIDE_GUIDE):
            col = stride_color(rule["letter"])
            with cols[i]:
                st.markdown(f"""<div style='padding:12px 8px;background:var(--card);border-radius:7px;
                    border:1px solid {col}33;text-align:center'>
                    <div style='font-family:JetBrains Mono,monospace;font-size:28px;color:{col};
                        font-weight:900;margin-bottom:4px'>{rule["letter"]}</div>
                    <div style='font-size:10px;color:var(--text);font-weight:700;margin-bottom:2px'>{rule["name"]}</div>
                    <div style='font-size:9px;color:var(--muted);font-family:JetBrains Mono,monospace'>
                        {rule.get("oneLiner","")[:30]}...</div>
                </div>""", unsafe_allow_html=True)
        alert(f"Each letter gets its own real scenario from <strong>{ws['name']}</strong>, followed by a knowledge check.", "info")
        if st.button("BEGIN: SPOOFING ▶", key=sk+"_begin"):
            set_ss(sk+"_idx", 0); set_ss(sk+"_revealed", False)
            set_ss(sk+"_chosen", None); st.rerun()
        return

    if idx == 6:
        st.markdown("## STRIDE 101 — Complete")
        score = len(passed)
        st.markdown(f"""<div style='text-align:center;padding:32px;background:var(--card);
            border-radius:10px;border:1px solid {"#66bb6a" if score>=4 else "#ffa726"}44;margin-bottom:20px'>
            <div style='font-family:JetBrains Mono,monospace;font-size:44px;
                color:{"#66bb6a" if score>=4 else "#ffa726"};font-weight:900'>{score}/6</div>
            <div style='font-size:16px;color:var(--text);font-weight:700;margin-top:8px'>STRIDE 101 Complete</div>
            <div style='font-size:13px;color:var(--sub);margin-top:6px'>
                {"Strong foundation — ready to find threats." if score>=4 else "Review any letter before proceeding."}
            </div>
        </div>""", unsafe_allow_html=True)
        cols = st.columns(6)
        for i, rule in enumerate(guide):
            col = stride_color(rule["letter"])
            done = i in passed
            with cols[i]:
                if st.button(rule["letter"]+" ✓" if done else rule["letter"], key=sk+f"_rev{i}",
                             use_container_width=True):
                    set_ss(sk+"_idx", i); set_ss(sk+"_revealed", False)
                    set_ss(sk+"_chosen", None); st.rerun()
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("REVIEW ALL ↺", key=sk+"_reall"):
                set_ss(sk+"_idx", 0); set_ss(sk+"_revealed", False)
                set_ss(sk+"_chosen", None); st.rerun()
        with col_b:
            if st.button("Q1: THE SYSTEM ▶", key=sk+"_next"):
                set_ss("current_step", "q1"); st.rerun()
        return

    rule = guide[idx]
    col  = stride_color(rule["letter"])

    # Progress strip
    prog_html = '<div style="display:flex;gap:6px;margin-bottom:16px;align-items:center">'
    for i, r in enumerate(guide):
        c = stride_color(r["letter"])
        done = i in passed
        active = i == idx
        bg = f"{c}22" if active else ("#66bb6a18" if done else "var(--raised)")
        bc = c if active else ("#66bb6a" if done else "var(--border)")
        prog_html += f'<div style="width:32px;height:32px;border-radius:5px;display:flex;align-items:center;justify-content:center;font-family:JetBrains Mono,monospace;font-size:14px;font-weight:900;background:{bg};border:2px solid {bc};color:{"#66bb6a" if done and not active else c if active else "var(--muted)"}">{"✓" if done and not active else r["letter"]}</div>'
    prog_html += f'<div style="margin-left:auto;font-size:10px;color:var(--muted);font-family:JetBrains Mono,monospace">{idx+1}/6 · {len(passed)} passed</div></div>'
    st.markdown(prog_html, unsafe_allow_html=True)

    # Letter header
    st.markdown(f"""<div style='display:flex;gap:16px;align-items:flex-start;padding:16px 18px;
        background:var(--card);border-radius:8px;border:1px solid {col}33;border-left:4px solid {col};margin-bottom:14px'>
        <div style='width:52px;height:52px;border-radius:7px;background:{col}18;border:2px solid {col};
            display:flex;align-items:center;justify-content:center;font-family:JetBrains Mono,monospace;
            font-size:32px;color:{col};font-weight:900;flex-shrink:0'>{rule["letter"]}</div>
        <div>
            <div style='font-family:JetBrains Mono,monospace;font-size:22px;color:{col};
                letter-spacing:1px;margin-bottom:3px'>{rule["name"].upper()}</div>
            <div style='font-size:14px;color:var(--sub);font-style:italic;margin-bottom:6px'>
                {rule.get("oneLiner","")}</div>
            <div style='display:inline-flex;padding:3px 10px;background:{col}12;border-radius:4px;
                font-size:11px;color:{col};font-family:JetBrains Mono,monospace;font-weight:600'>
                Zone rule: {str(rule.get("dfdRule",""))[:60]}
            </div>
        </div>
    </div>""", unsafe_allow_html=True)

    # Scenario
    scenario = rule.get("scenario") or rule.get("context") or rule.get("technical","")
    if scenario:
        st.markdown(f"""<div style='padding:16px 18px;background:{col}06;border-radius:8px;
            border:1px solid {col}22;border-left:4px solid {col};margin-bottom:14px'>
            <div style='font-size:9px;font-weight:700;color:{col};font-family:JetBrains Mono,monospace;
                text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px'>
                {ws["name"]} — Real Scenario</div>
            <p style='font-size:13.5px;color:var(--text);line-height:1.85;margin:0 0 10px'>{scenario[:600]}</p>
        </div>""", unsafe_allow_html=True)

    # Knowledge check
    quiz = rule.get("quiz", {})
    if quiz:
        st.markdown("**Knowledge check**")
        st.markdown(quiz.get("q",""))
        opts = quiz.get("opts", [])
        correct_idx = quiz.get("correct", 0)
        if not revealed:
            for i, opt in enumerate(opts):
                if st.button(f"{chr(65+i)}. {opt}", key=sk+f"_opt{i}", use_container_width=True):
                    set_ss(sk+"_chosen", i)
                    set_ss(sk+"_revealed", True)
                    if i == correct_idx:
                        new_passed = ss(sk+"_passed", set()) | {idx}
                        set_ss(sk+"_passed", new_passed)
                    st.rerun()
        else:
            for i, opt in enumerate(opts):
                if i == correct_idx:
                    st.success(f"✓ {opt}")
                elif i == chosen:
                    st.error(f"✗ {opt}")
                else:
                    st.markdown(f"&nbsp;&nbsp;{chr(65+i)}. {opt}")
            is_correct = chosen == correct_idx
            if is_correct:
                alert(f"✓ Correct! {quiz.get('why','')}", "success")
            else:
                alert(f"✗ Correct answer: **{opts[correct_idx]}**<br><br>{quiz.get('why','')}", "warn")

    # Navigation
    nav_c1, nav_c2 = st.columns(2)
    with nav_c1:
        if st.button("← PREV", key=sk+"_prev", disabled=(idx<=0)):
            set_ss(sk+"_idx", max(0, idx-1))
            set_ss(sk+"_revealed", False); set_ss(sk+"_chosen", None); st.rerun()
    with nav_c2:
        if revealed:
            lbl = f"NEXT: {guide[idx+1]['name']} ▶" if idx < 5 else "SEE RESULTS ▶"
            if st.button(lbl, key=sk+"_next_letter"):
                set_ss(sk+"_idx", idx+1)
                set_ss(sk+"_revealed", False); set_ss(sk+"_chosen", None); st.rerun()
        else:
            st.caption("Answer the question to continue")


def render_step_q1(ws):
    sk = f"ws{ws['id']}_q1"
    phase = ss(sk+"_phase", "explore")  # explore | quiz
    revealed_comps = ss(sk+"_revealed", set())
    selected = ss(sk+"_selected", None)
    quiz_chosen = ss(sk+"_qchosen", None)
    quiz_revealed = ss(sk+"_qrev", False)

    comps = ws.get("components", [])
    assets = ws.get("assets", [])
    assumptions = ws.get("assumptions", [])

    if phase == "quiz":
        st.markdown("## SYSTEM COMPREHENSION CHECK")
        alert("Before finding threats, confirm you understand what you're protecting.", "info")
        # Highest risk component
        best = max(comps, key=lambda c: c.get("score", 0)) if comps else {"name":"Unknown"}
        quiz_opts = [c["name"] for c in comps[:4]]
        correct_idx = quiz_opts.index(best["name"]) if best["name"] in quiz_opts else 0

        st.markdown(f"In **{ws['name']}**, which component represents the **highest-value target** for an attacker — the component whose compromise would have the greatest impact?")
        if not quiz_revealed:
            for i, opt in enumerate(quiz_opts):
                if st.button(f"{chr(65+i)}. {opt}", key=sk+f"_qopt{i}", use_container_width=True):
                    set_ss(sk+"_qchosen", i)
                    set_ss(sk+"_qrev", True); st.rerun()
        else:
            for i, opt in enumerate(quiz_opts):
                if i == correct_idx: st.success(f"✓ {opt}")
                elif i == quiz_chosen: st.error(f"✗ {opt}")
                else: st.markdown(f"&nbsp;&nbsp;{chr(65+i)}. {opt}")
            zcol = zone_color(best.get("zone",""))
            if quiz_chosen == correct_idx:
                alert(f"✓ Correct! <strong>{best['name']}</strong> sits in the {best.get('zone','')} zone and stores/processes the most sensitive data.", "success")
            else:
                alert(f"✗ Correct answer: <strong>{best['name']}</strong> — it sits in the {best.get('zone','')} zone (score {best.get('score',0)}). Highest zone score = highest-value target.", "warn")

        c1, c2 = st.columns(2)
        with c1:
            if st.button("← BACK TO SYSTEM", key=sk+"_back"):
                set_ss(sk+"_phase","explore"); st.rerun()
        with c2:
            if quiz_revealed and st.button("Q2: ZONE LABELS ▶", key=sk+"_next"):
                set_ss("current_step","q2zones"); st.rerun()
        return

    st.markdown("## WHAT ARE WE WORKING ON?")
    st.caption(f"Click each component to discover its role — {len(revealed_comps)}/{min(len(comps),4)} explored")

    col_l, col_r = st.columns([1,1])
    with col_l:
        st.markdown("**System Components — click to explore**")
        for comp in comps:
            zcol = zone_color(comp.get("zone",""))
            is_sel = selected == comp["name"]
            is_seen = comp["name"] in revealed_comps
            border = f"1.5px solid {zcol}" if is_sel or is_seen else "1px solid var(--border)"
            bg = f"rgba({','.join(str(int(zcol[i:i+2],16)) for i in (1,3,5))},0.12)" if is_sel else \
                 "var(--card)" if is_seen else "var(--raised)"
            if st.button(
                f"{'✓ ' if is_seen else '→ '}{comp['name']} [{comp.get('zone','').split()[0]}]",
                key=sk+f"_comp_{comp['name']}", use_container_width=True
            ):
                new_rev = revealed_comps | {comp["name"]}
                set_ss(sk+"_revealed", new_rev)
                set_ss(sk+"_selected", comp["name"]); st.rerun()

    with col_r:
        sel_comp = next((c for c in comps if c["name"]==selected), None)
        if sel_comp:
            zcol = zone_color(sel_comp.get("zone",""))
            zone = sel_comp.get("zone","")
            score = sel_comp.get("score", 0)
            if zone.startswith("Not") or score == 0:
                trust_msg = "Never trusted. All inputs validated. Every request potentially hostile."
            elif score >= 7:
                trust_msg = "Highest-value target. Compromise = full data breach."
            elif score >= 5:
                trust_msg = "Privileged component. Strict access controls required."
            else:
                trust_msg = "Standard trust. Parameterised queries and output encoding required."
            st.markdown(f"""<div style='padding:16px;background:var(--card);border-radius:8px;
                border:1.5px solid {zcol}'>
                <div style='display:flex;gap:10px;align-items:center;margin-bottom:12px'>
                    <div style='width:10px;height:10px;border-radius:5px;background:{zcol};flex-shrink:0'></div>
                    <div style='font-weight:700;color:var(--text);font-size:14px'>{sel_comp["name"]}</div>
                    {tag(zone, zcol)}
                </div>
                <p style='font-size:12.5px;color:var(--sub);line-height:1.7;margin-bottom:10px'>{sel_comp.get("desc","")}</p>
                <div style='padding:8px 10px;background:{zcol}10;border-radius:5px;border:1px solid {zcol}22'>
                    <div style='font-size:9px;font-weight:700;color:{zcol};font-family:JetBrains Mono,monospace;
                        text-transform:uppercase;letter-spacing:1.5px;margin-bottom:3px'>Trust implication</div>
                    <div style='font-size:11.5px;color:var(--sub);line-height:1.6'>{trust_msg}</div>
                </div>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown("""<div style='padding:40px;text-align:center;background:var(--raised);
                border-radius:8px;border:1px dashed var(--border)'>
                <div style='font-size:12px;color:var(--muted);font-family:JetBrains Mono,monospace'>
                    ← Click a component to see its role, trust zone, and threat implications
                </div>
            </div>""", unsafe_allow_html=True)

        if assets:
            st.markdown("**Key Assets**")
            for a in assets[:3]:
                col_s = "#ef5350" if a.get("sensitivity")=="Critical" else "#ffa726" if a.get("sensitivity")=="High" else "#5c6bc0"
                st.markdown(f"""<div style='display:flex;gap:8px;padding:5px 0;
                    border-bottom:1px solid var(--border)44'>
                    <div style='width:6px;height:6px;border-radius:3px;background:{col_s};
                        flex-shrink:0;margin-top:5px'></div>
                    <div>
                        <div style='font-size:11.5px;font-weight:700;color:var(--text)'>{a["name"]}</div>
                        <div style='font-size:10px;color:var(--muted);font-family:JetBrains Mono,monospace'>{a.get("sensitivity","")}</div>
                    </div>
                </div>""", unsafe_allow_html=True)

    if assumptions:
        st.markdown("**Key Assumptions** *(these become threats if wrong)*")
        cols_a = st.columns(2)
        for i, a in enumerate(assumptions[:4]):
            with cols_a[i%2]:
                st.markdown(f"⚡ {a}")

    can_proceed = len(revealed_comps) >= min(len(comps), 4)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("← STRIDE 101", key=sk+"_back"):
            set_ss("current_step","s101"); st.rerun()
    with c2:
        if can_proceed:
            if st.button("CHECK UNDERSTANDING ▶", key=sk+"_quiz"):
                set_ss(sk+"_phase","quiz"); st.rerun()
        else:
            st.caption(f"Explore {min(len(comps),4)-len(revealed_comps)} more components to continue")


def render_step_q2zones(ws):
    sk = f"ws{ws['id']}_q2zones"
    comps = ws.get("components",[])
    idx = ss(sk+"_idx", 0)
    revealed = ss(sk+"_revealed", False)
    chosen = ss(sk+"_chosen", None)
    correct_count = ss(sk+"_correct", 0)

    if idx >= len(comps):
        st.markdown("## ZONE LABELLING — Complete")
        st.success(f"✓ {correct_count}/{len(comps)} components correctly labelled")
        alert("Every zone boundary creates threat entry points. In Q2 you'll identify which STRIDE categories apply at each boundary.", "success")
        if st.button("STUDY ARCHITECTURE ▶", key=sk+"_next"):
            set_ss("current_step","q2arch"); st.rerun()
        return

    comp = comps[idx]
    st.markdown("## ZONE LABELLING")
    st.caption(f"Component {idx+1} of {len(comps)} · {correct_count} correct so far")

    # Progress bar
    st.progress(idx / len(comps))

    # Component card
    st.markdown(f"""<div style='padding:20px;background:var(--card);border-radius:8px;
        border:1px solid var(--borderHi);margin-bottom:16px;text-align:center'>
        <div style='font-size:10px;font-weight:700;color:var(--muted);font-family:JetBrains Mono,monospace;
            text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px'>
            Which trust zone does this component belong to?</div>
        <div style='font-family:JetBrains Mono,monospace;font-size:28px;color:var(--text);
            letter-spacing:1px;margin-bottom:8px'>{comp["name"]}</div>
        <div style='font-size:13px;color:var(--sub)'>{comp.get("desc","")}</div>
    </div>""", unsafe_allow_html=True)

    zones = [
        ("Not in Control (Z0)", "#ef5350", "External — internet, end users, third parties"),
        ("Minimal Trust (Z1)",  "#ffa726", "Authenticated entry point — gateway, CDN"),
        ("Standard (Z3)",       "#5c6bc0", "Application servers, business logic"),
        ("Elevated (Z5)",       "#ab47bc", "Queues, caches, processing services"),
        ("Critical (Z7/Z9)",    "#ef5350", "Databases, key stores, audit logs"),
    ]
    score = comp.get("score", 3)
    correct_zone = (0 if score==0 else 1 if score==1 else 2 if score==3 else 3 if score==5 else 4)

    if not revealed:
        for i,(zlabel,zcol,zhint) in enumerate(zones):
            if st.button(f"{zlabel} — {zhint}", key=sk+f"_zone{i}", use_container_width=True):
                set_ss(sk+"_chosen", i)
                set_ss(sk+"_revealed", True)
                if i == correct_zone:
                    set_ss(sk+"_correct", correct_count+1)
                st.rerun()
    else:
        for i,(zlabel,zcol,zhint) in enumerate(zones):
            if i == correct_zone: st.success(f"✓ {zlabel} — {zhint}")
            elif i == chosen: st.error(f"✗ {zlabel} — {zhint}")
            else: st.markdown(f"&nbsp;&nbsp;{zlabel}")

        if chosen == correct_zone:
            alert(f"✓ Correct! <strong>{comp['name']}</strong> belongs to <strong>{comp.get('zone','')}</strong>. {('As a Critical-zone component, every data flow entering it is an Information Disclosure risk.' if score>=7 else 'As a Z0 component, it is never trusted — all its inputs must be validated before processing.' if score==0 else 'Trust zone determines which STRIDE categories apply.')}", "success")
        else:
            alert(f"✗ Correct zone: <strong>{comp.get('zone','')}</strong>. Score {score} = {'external/untrusted' if score==0 else 'entry point' if score==1 else 'application layer' if score==3 else 'elevated' if score==5 else 'critical data'}.", "warn")

        c1,c2 = st.columns(2)
        with c1:
            if st.button("← THE SYSTEM", key=sk+"_back"):
                set_ss("current_step","q1"); st.rerun()
        with c2:
            label = "STUDY ARCHITECTURE ▶" if idx >= len(comps)-1 else "NEXT COMPONENT ▶"
            if st.button(label, key=sk+"_next"):
                set_ss(sk+"_idx", idx+1)
                set_ss(sk+"_revealed", False)
                set_ss(sk+"_chosen", None); st.rerun()


def render_step_q2arch(ws):
    sk = f"ws{ws['id']}_q2arch"
    view = ss(sk+"_view", "diagram")
    seen = ss(sk+"_seen", {"diagram"})
    sel_comp = ss(sk+"_sel", None)

    st.markdown("## STUDY THE ARCHITECTURE")
    st.caption("Understand what to protect before finding what can go wrong")

    view_cols = st.columns(3)
    views = [("diagram","Architecture Diagram"),("components","Component × STRIDE"),("rationale","Design Decisions")]
    for i,(v,l) in enumerate(views):
        with view_cols[i]:
            done_mark = "✓ " if (v in seen and v!=view) else ""
            if st.button(f"{done_mark}{l}", key=sk+f"_view_{v}", use_container_width=True):
                new_seen = seen | {v}
                set_ss(sk+"_seen", new_seen)
                set_ss(sk+"_view", v); st.rerun()

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    if view == "diagram":
        render_architecture(ws, key=sk)
        alert("Study the data flows. Every arrow crossing a zone boundary is a potential threat entry point. In Find Threats you'll classify exactly which STRIDE categories apply.", "info")

    elif view == "components":
        comps = ws.get("components", [])
        col_l, col_r = st.columns([1,2])
        with col_l:
            st.markdown("**Click a component**")
            for comp in comps:
                zcol = zone_color(comp.get("zone",""))
                score = comp.get("score",3)
                letters = []
                if score==0: letters = ["S","D"]
                elif score==1: letters = ["S","T","D"]
                elif score==3: letters = ["S","T","R","I","D"]
                elif score>=5: letters = ["S","T","R","I","D","E"]
                first_col = stride_color(letters[0]) if letters else "#aaa"
                if st.button(f"{comp['name']}", key=sk+f"_c_{comp['name']}", use_container_width=True):
                    set_ss(sk+"_sel", comp["name"]); st.rerun()
        with col_r:
            sc = next((c for c in comps if c["name"]==sel_comp), None)
            if sc:
                zcol = zone_color(sc.get("zone",""))
                score = sc.get("score",3)
                letters_map = {0:["S","D"],1:["S","T","D"],3:["S","T","R","I","D"],5:["S","T","R","I","D","E"],7:["S","T","R","I","D","E"]}
                letters = letters_map.get(score, ["S","T"])
                if score >= 5: letters = ["S","T","R","I","D","E"]
                why_map = {
                    "S":"Reachable from untrusted source — identity can be forged",
                    "T":"Data flows rise into this zone — can be modified in transit",
                    "R":"Both S and T apply — actions can be disputed",
                    "I":"Data flows descend from this zone — sensitive data exposed",
                    "D":"External source can reach shared resources — availability at risk",
                    "E":"Adjacent to lower-trust zone — privilege escalation possible",
                }
                full_map = {"S":"Spoofing","T":"Tampering","R":"Repudiation","I":"Information Disclosure","D":"Denial of Service","E":"Elevation of Privilege"}
                st.markdown(f"**{sc['name']}** — {tag(sc.get('zone',''), zcol)}", unsafe_allow_html=True)
                st.markdown("**STRIDE categories that apply — and why:**")
                for l in letters:
                    col_s = stride_color(l)
                    st.markdown(f"""<div style='display:flex;gap:10px;padding:8px 0;
                        border-bottom:1px solid var(--border)44'>
                        <div style='width:24px;height:24px;border-radius:4px;background:{col_s}20;
                            border:1px solid {col_s};display:flex;align-items:center;justify-content:center;
                            font-family:JetBrains Mono,monospace;font-size:13px;font-weight:900;
                            color:{col_s};flex-shrink:0'>{l}</div>
                        <div>
                            <div style='font-size:12px;font-weight:700;color:var(--text)'>{full_map[l]}</div>
                            <div style='font-size:11px;color:var(--sub);font-family:JetBrains Mono,monospace'>{why_map[l]}</div>
                        </div>
                    </div>""", unsafe_allow_html=True)
            else:
                st.info("Select a component to see which STRIDE categories apply and why")

    else:
        ctx = ws.get("orgContext",{})
        if ctx.get("background"):
            st.markdown(f"""<div style='padding:16px;background:var(--card);border-radius:8px;
                border:1px solid var(--border);margin-bottom:10px'>
                <div style='font-size:9px;font-weight:700;color:var(--muted);font-family:JetBrains Mono,monospace;
                    text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px'>Context</div>
                <p style='font-size:13px;color:var(--sub);line-height:1.75;margin:0'>{ctx["background"]}</p>
            </div>""", unsafe_allow_html=True)
        for d in (ctx.get("key_decisions") or []):
            st.markdown(f"▸ {d}")

    can_proceed = len(seen) >= 2
    c1, c2 = st.columns(2)
    with c1:
        if st.button("← ZONE LABELS", key=sk+"_back"):
            set_ss("current_step","q2zones"); st.rerun()
    with c2:
        if can_proceed:
            if st.button("FIND THREATS ▶", key=sk+"_next"):
                set_ss("current_step","q2stride"); st.rerun()
        else:
            st.caption("Review all 3 views to continue")


def render_step_q2stride(ws):
    sk = f"ws{ws['id']}_q2stride"
    phase = ss(sk+"_phase", "discover")
    threat_idx = ss(sk+"_tidx", 0)
    answers = ss(sk+"_answers", [])
    analyzed_ids = {a["id"] for a in answers}
    remaining = [t for t in ws["threats"] if t["id"] not in analyzed_ids]
    threat = remaining[threat_idx] if threat_idx < len(remaining) else ws["threats"][0]

    sc = stride_color(threat.get("stride","S"))

    # Header
    st.markdown("## FIND THREATS")
    # Progress pills
    pill_html = '<div style="display:flex;gap:4px;margin-bottom:14px">'
    for t in ws["threats"]:
        done = t["id"] in analyzed_ids or (phase=="reveal" and t["id"]==threat["id"])
        col2 = STRIDE_COLORS.get(t.get("stride","S")[:1], "#aaa")
        pill_html += f'<div style="width:10px;height:10px;border-radius:5px;background:{col2 if done else "var(--border)"};border:1px solid {col2 if done else "var(--border)"}"></div>'
    pill_html += "</div>"
    st.markdown(pill_html, unsafe_allow_html=True)

    # Phase tabs display
    phases_labels = [("discover","① Discover","Click the architecture"),
                     ("label","② Classify","STRIDE + likelihood + impact"),
                     ("reveal","③ Reveal","Attack path + mitigation")]
    phase_html = '<div style="display:flex;gap:2px;margin-bottom:14px;background:var(--raised);border-radius:7px;padding:3px">'
    for p,l,sub in phases_labels:
        pidx = ["discover","label","reveal"].index(p)
        cidx = ["discover","label","reveal"].index(phase)
        active = p==phase; done = pidx<cidx
        phase_html += f'<div style="flex:1;padding:7px 10px;border-radius:5px;background:{"rgba(0,229,255,0.13)" if active else "transparent"};opacity:{0.4 if pidx>cidx else 1}"><div style="font-size:10px;font-weight:700;font-family:JetBrains Mono,monospace;color:{"#00e5ff" if active else "#66bb6a" if done else "var(--muted)"}">{"✓ " if done else ""}{l}</div><div style="font-size:9px;color:var(--muted);font-family:JetBrains Mono,monospace">{sub}</div></div>'
    phase_html += "</div>"
    st.markdown(phase_html, unsafe_allow_html=True)

    # Architecture canvas with controls
    hot_nodes = set(); hot_flows = set()
    sim_mode_val = ss(sk+"_simmode", "attack")
    if phase == "reveal":
        hot_nodes = set(threat.get("nodes",[]))
        hot_flows = set(threat.get("flows",[]))

    arch_header = st.columns([3,1,1])
    with arch_header[0]:
        st.caption(f"🏛 {ws['name']} — Architecture")
    if phase == "reveal":
        with arch_header[1]:
            if st.button("▶ ATTACK", key=sk+"_atk"):
                set_ss(sk+"_simmode","attack"); st.rerun()
        with arch_header[2]:
            if st.button("✓ MITIGATED", key=sk+"_mit"):
                set_ss(sk+"_simmode","mitigated"); st.rerun()

    render_architecture(ws, hot_nodes=hot_nodes, hot_flows=hot_flows,
                        sim_mode=sim_mode_val, key=sk+"_"+phase)

    # ── DISCOVER phase ───────────────────────────────────────────────────────
    if phase == "discover":
        reveal_set = ss(sk+"_revealed_nodes", set()) | ss(sk+"_revealed_flows", set())
        all_disc = set(threat.get("nodes",[])) | set(threat.get("flows",[]))
        disc_count = len(reveal_set & all_disc)
        can_label = disc_count >= max(1, len(all_disc)//2)

        # Interactive component selector
        st.markdown("**Click components/flows that you think are involved in threats:**")
        comp_cols = st.columns(min(len(ws["components"]), 4))
        for i, comp in enumerate(ws["components"][:8]):
            with comp_cols[i % min(len(ws["components"]),4)]:
                zcol = zone_color(comp.get("zone",""))
                in_threat = comp["name"] in threat.get("nodes",[])
                is_rev = comp["name"] in ss(sk+"_revealed_nodes", set())
                btn_style = "btn-success" if is_rev else ""
                if st.button(f"{'✓ ' if is_rev else ''}{comp['name']}", key=sk+f"_dc_{comp['name']}",
                             use_container_width=True):
                    nr = ss(sk+"_revealed_nodes", set()) | {comp["name"]}
                    set_ss(sk+"_revealed_nodes", nr)
                    if in_threat:
                        set_ss(sk+"_hint", f"{comp['name']} carries a **{threat.get('stride','')}** threat: {threat.get('source','')} can {threat.get('action','')} via {str(threat.get('method',''))[:80]}...")
                    st.rerun()

        hint = ss(sk+"_hint")
        if hint:
            alert(hint, "info", "Potential threat found")
        else:
            st.info("Click components above — threats will surface here")

        c1,c2 = st.columns(2)
        with c1:
            if st.button("← ARCHITECTURE", key=sk+"_back"):
                set_ss("current_step","q2arch"); st.rerun()
        with c2:
            if can_label or disc_count>=1:
                if st.button("CLASSIFY THIS THREAT ▶", key=sk+"_tolabel"):
                    set_ss(sk+"_phase","label"); st.rerun()
            else:
                st.caption(f"Click {max(1,len(all_disc)//2)-disc_count} more elements to unlock classification")

    # ── LABEL phase ──────────────────────────────────────────────────────────
    elif phase == "label":
        st.markdown(f"**Classify: {threat['id']}** — {threat.get('source','')} → {threat.get('asset','')[:60]}")
        stride_val = ss(sk+"_stride","")
        likelihood = ss(sk+"_like","Medium")
        impact = ss(sk+"_imp","Medium")

        c1,c2,c3 = st.columns(3)
        with c1:
            st.markdown("**STRIDE Category**")
            for s in ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"]:
                col_s = stride_color(s)
                selected_s = stride_val == s
                if st.button(f"{s[0]} {s}", key=sk+f"_str_{s}", use_container_width=True):
                    set_ss(sk+"_stride", s); st.rerun()
        with c2:
            st.markdown("**Likelihood**")
            for l in ["Low","Medium","High"]:
                if st.button(l, key=sk+f"_lik_{l}", use_container_width=True):
                    set_ss(sk+"_like", l); st.rerun()
            st.caption(f"Selected: {likelihood}")
        with c3:
            st.markdown("**Impact**")
            for im in ["Low","Medium","High","Critical"]:
                if st.button(im, key=sk+f"_imp_{im}", use_container_width=True):
                    set_ss(sk+"_imp", im); st.rerun()
            st.caption(f"Selected: {impact}")

        if stride_val:
            st.success(f"Selected: **{stride_val}** | Likelihood: **{likelihood}** | Impact: **{impact}**")

        defend = st.text_area("Defend your decision (min. 20 words):",
            value=ss(sk+"_defend",""),
            placeholder="Why this STRIDE category? Which component is the primary target? What makes this exploitable?",
            key=sk+"_def_inp")
        set_ss(sk+"_defend", defend)
        word_count = len(defend.split()) if defend else 0
        st.caption(f"{word_count}/20 words")

        c1,c2 = st.columns(2)
        with c1:
            if st.button("← BACK", key=sk+"_lback"):
                set_ss(sk+"_phase","discover"); st.rerun()
        with c2:
            ready = stride_val and word_count >= 20
            if st.button("REVEAL ANSWER ▶", key=sk+"_submit", disabled=not ready):
                stride_ok = stride_val == threat.get("stride","")
                like_ok   = likelihood == threat.get("likelihood","")
                imp_ok    = impact == threat.get("impact_rating","")
                pts = (3 if stride_ok else 0) + (1 if like_ok else 0) + (1 if imp_ok else 0)
                entry = {
                    "id": threat["id"], "score": pts, "maxScore": 7,
                    "stride": stride_val, "likelihood": likelihood, "impact": impact,
                    "threat": threat,
                    "feedback": [
                        {"ok":stride_ok, "msg":"✓ STRIDE correct" if stride_ok else f"✗ STRIDE: correct is \"{threat.get('stride','')}\""},
                        {"ok":like_ok,   "msg":"✓ Likelihood correct" if like_ok else f"✗ Likelihood: correct is \"{threat.get('likelihood','')}\""},
                        {"ok":imp_ok,    "msg":"✓ Impact correct" if imp_ok else f"✗ Impact: correct is \"{threat.get('impact_rating','')}\""},
                    ]
                }
                set_ss(sk+"_answers", answers + [entry])
                set_ss(sk+"_phase","reveal")
                set_ss(sk+"_simmode","attack"); st.rerun()

    # ── REVEAL phase ─────────────────────────────────────────────────────────
    else:
        entry = next((a for a in ss(sk+"_answers",[]) if a["id"]==threat["id"]), None)
        if entry:
            c1,c2 = st.columns(2)
            with c1:
                st.markdown("**Your answers:**")
                for f in entry.get("feedback",[]):
                    if f["ok"]: st.success(f["msg"])
                    else: st.error(f["msg"])
            with c2:
                st.markdown("**Correct answers:**")
                sc_col = stride_color(threat.get("stride","S"))
                st.markdown(f"STRIDE: **{threat.get('stride','')}** | Likelihood: **{threat.get('likelihood','')}** | Impact: **{threat.get('impact_rating','')}**")

        # Threat explanation
        st.markdown(f"""<div style='padding:12px 14px;background:{sc}08;border-radius:7px;
            border:1px solid {sc}22;border-left:4px solid {sc};margin:12px 0'>
            <div style='font-size:10px;font-weight:700;color:{sc};font-family:JetBrains Mono,monospace;
                text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px'>
                What actually happens — {threat["id"]}</div>
            <p style='font-size:13px;color:var(--text);line-height:1.75;margin:0 0 8px'>
                {threat.get("composed","")}</p>
            <div style='font-size:11px;color:var(--muted);font-family:JetBrains Mono,monospace;font-style:italic'>
                Real world: {str(threat.get("real_world",""))[:120]}</div>
        </div>""", unsafe_allow_html=True)

        # Mitigation quiz
        ctrl_correct = (threat.get("controls_correct") or [""])[0]
        ctrl_wrong   = (threat.get("controls_wrong") or [])[:2]
        ctrl_opts    = [ctrl_correct] + ctrl_wrong
        import random; random.shuffle(ctrl_opts)
        correct_ctrl_idx = ctrl_opts.index(ctrl_correct) if ctrl_correct in ctrl_opts else 0
        qrev = ss(sk+"_qrev_mit", False)
        qcho = ss(sk+"_qcho_mit", None)

        st.markdown("**Which control blocks this attack?**")
        st.caption("(Switch ATTACK/MITIGATED above to see it animate on the diagram)")
        if not qrev:
            for i,ctrl in enumerate(ctrl_opts):
                if ctrl and st.button(f"{chr(65+i)}. {ctrl[:80]}", key=sk+f"_ctrl{i}", use_container_width=True):
                    set_ss(sk+"_qcho_mit", i)
                    set_ss(sk+"_qrev_mit", True); st.rerun()
        else:
            for i,ctrl in enumerate(ctrl_opts):
                if not ctrl: continue
                if i==correct_ctrl_idx: st.success(f"✓ {ctrl[:80]}")
                elif i==qcho: st.error(f"✗ {ctrl[:80]}")
                else: st.markdown(f"&nbsp;&nbsp;{chr(65+i)}. {ctrl[:80]}")
            if qcho==correct_ctrl_idx:
                alert(f"✓ Correct! Switch to MITIGATED above to see this control block the attack on the architecture diagram.", "success")
            else:
                alert(f"✗ Correct: **{ctrl_correct[:80]}**<br><br>{threat.get('explanation','')[:200]}", "warn")

        c1,c2 = st.columns(2)
        with c1:
            st.caption(f"Threat {threat_idx+1}/{len(remaining) or len(ws['threats'])}")
        with c2:
            btn_label = "NEXT THREAT ▶" if threat_idx < len(remaining)-1 else "ATTACK PATHS ▶"
            if st.button(btn_label, key=sk+"_nextth"):
                if threat_idx < len(remaining)-1:
                    set_ss(sk+"_tidx", threat_idx+1)
                    set_ss(sk+"_phase","discover")
                    set_ss(sk+"_revealed_nodes",set())
                    set_ss(sk+"_revealed_flows",set())
                    set_ss(sk+"_hint",None)
                    set_ss(sk+"_stride","")
                    set_ss(sk+"_like","Medium")
                    set_ss(sk+"_imp","Medium")
                    set_ss(sk+"_defend","")
                    set_ss(sk+"_qrev_mit",False)
                    set_ss(sk+"_qcho_mit",None)
                    set_ss(sk+"_simmode","attack"); st.rerun()
                else:
                    set_ss("current_step","q2tree"); st.rerun()


def render_step_q2tree(ws):
    sk = f"ws{ws['id']}_q2tree"
    mode = ss(sk+"_mode","sim")
    path_idx = ss(sk+"_pathidx",0)
    sim_phase = ss(sk+"_simphase","idle")  # idle|running|done|mitigated
    rt_sequence = ss(sk+"_rtseq",[])
    rt_submitted = ss(sk+"_rtsub",False)
    rt_result = ss(sk+"_rtres",None)

    paths = ws.get("attackTree",{}).get("paths",[])
    path  = paths[path_idx] if path_idx < len(paths) else (paths[0] if paths else None)

    st.markdown("## ATTACK PATHS")
    st.caption(f"How STRIDE weaknesses chain into a complete breach of {ws['name']}")

    # Mode + path selector
    mode_c, path_c = st.columns([1,2])
    with mode_c:
        new_mode = st.radio("Mode",["Attack Simulator","Red Team ⚔"],
                            index=0 if mode=="sim" else 1,
                            horizontal=True, label_visibility="collapsed")
        if (new_mode=="Attack Simulator") != (mode=="sim"):
            set_ss(sk+"_mode","sim" if new_mode=="Attack Simulator" else "redteam")
            set_ss(sk+"_simphase","idle")
            set_ss(sk+"_rtseq",[])
            set_ss(sk+"_rtsub",False)
            set_ss(sk+"_rtres",None); st.rerun()
    with path_c:
        if paths:
            path_labels = [p.get("label","Path") for p in paths]
            new_path = st.selectbox("Attack path",path_labels,index=path_idx,
                                    label_visibility="collapsed")
            new_idx = path_labels.index(new_path)
            if new_idx != path_idx:
                set_ss(sk+"_pathidx",new_idx)
                set_ss(sk+"_simphase","idle"); st.rerun()

    if not path:
        st.warning("No attack paths defined for this workshop.")
        return

    # Two-column layout: architecture LEFT, tree RIGHT
    arch_col, tree_col = st.columns([1,1])

    # Compute hot nodes/flows based on sim_phase
    hot_nodes = set(); hot_flows = set()
    sim_mode_val = "mitigated" if sim_phase == "mitigated" else "attack"
    if sim_phase in ("done","mitigated","running"):
        steps = path.get("steps",[])
        active_steps = steps if sim_phase in ("done","mitigated") else steps[:ss(sk+"_active",0)+1]
        for step in active_steps:
            t = next((t for t in ws["threats"] if t["id"]==step.get("strideId","")), None)
            if t:
                hot_nodes |= set(t.get("nodes",[]))
                hot_flows |= set(t.get("flows",[]))

    with arch_col:
        border_col = "#66bb6a" if sim_phase=="mitigated" else "#ef5350" if sim_phase in ("done","running") else "var(--border)"
        st.markdown(f"""<div style='border:1px solid {border_col};border-radius:8px;overflow:hidden;
            padding-bottom:0;transition:border-color .4s'>
            <div style='padding:6px 12px;background:var(--raised);display:flex;gap:8px;align-items:center'>
                <span style='font-size:9px;font-weight:700;color:var(--muted);font-family:JetBrains Mono,monospace;text-transform:uppercase;letter-spacing:1.5px'>Architecture</span>
                {('<span style="font-size:9px;color:#ef5350;font-family:JetBrains Mono,monospace;font-weight:700;margin-left:auto">✗ BREACH</span>' if sim_phase=="done" else '<span style="font-size:9px;color:#66bb6a;font-family:JetBrains Mono,monospace;font-weight:700;margin-left:auto">✓ PROTECTED</span>' if sim_phase=="mitigated" else "")}
            </div>
        </div>""", unsafe_allow_html=True)
        render_architecture(ws, hot_nodes=hot_nodes, hot_flows=hot_flows,
                            sim_mode=sim_mode_val, height=340, key=sk+"_tree")

    with tree_col:
        steps = path.get("steps",[])
        active_step = ss(sk+"_active",-1)
        st.markdown(f"""<div style='background:var(--card);border-radius:8px;border:1px solid var(--border);
            padding:12px;margin-bottom:0'>
            <div style='text-align:center;margin-bottom:10px'>
                <div style='display:inline-block;padding:7px 14px;border-radius:6px;
                    background:#ef535018;border:2px solid #ef5350;
                    font-family:JetBrains Mono,monospace;font-size:11px;font-weight:700;color:#ef5350'>
                    ☠ GOAL: {ws.get("attackTree",{}).get("goal","")[:50]}
                </div>
            </div>
            <div style='text-align:center;margin-bottom:8px;font-size:9px;color:var(--muted);
                font-family:JetBrains Mono,monospace;background:var(--raised);
                padding:2px 8px;border-radius:3px;display:inline-block'>
                {path.get("gateType","")} gate
            </div>
        </div>""", unsafe_allow_html=True)
        for i, step in enumerate(steps):
            is_active = sim_phase in ("running","done") and i <= active_step
            is_done   = sim_phase in ("done","mitigated")
            has_mit   = any(m.get("step")==step["id"] for m in path.get("mitigations",[]))
            is_blocked = sim_phase == "mitigated" and has_mit
            sc2 = stride_color(step.get("strideType","S")[:1])
            bg = "#66bb6a18" if is_blocked else "#ef535018" if is_active else "var(--raised)"
            bc = "#66bb6a" if is_blocked else "#ef5350" if is_active else "var(--border)"
            rt_pos = rt_sequence.index(step["id"]) if step["id"] in rt_sequence else -1

            mit_badge = ""
            if is_blocked:
                m = next((m for m in path.get("mitigations",[]) if m.get("step")==step["id"]), None)
                if m: mit_badge = f'<div style="margin-top:4px;padding:3px 7px;background:var(--greenD);border-radius:4px;font-size:10px;color:#66bb6a;font-family:JetBrains Mono,monospace;font-weight:700">⊘ {m.get("control","")[:50]}</div>'

            rt_badge = ""
            if mode == "redteam" and rt_pos >= 0:
                rt_col = "#66bb6a" if (rt_submitted and rt_pos==i) else "#ef5350" if rt_submitted else "#00e5ff"
                rt_badge = f'<span style="font-size:9px;color:{rt_col};font-family:JetBrains Mono,monospace;font-weight:700">#{rt_pos+1}{"✓" if rt_submitted and rt_pos==i else "✗" if rt_submitted else ""}</span>'

            clickable = "cursor:pointer" if mode=="redteam" and not rt_submitted else ""
            onclick_key = sk+f"_rtstep{i}"

            st.markdown(f"""<div style='padding:9px 11px;border-radius:6px;margin-bottom:5px;
                background:{bg};border:1.5px solid {bc};transition:all .3s;{clickable}'>
                <div style='display:flex;gap:8px;align-items:center;margin-bottom:3px'>
                    <div style='width:22px;height:22px;border-radius:4px;background:{sc2}20;
                        border:1px solid {sc2};display:flex;align-items:center;justify-content:center;
                        font-family:JetBrains Mono,monospace;font-size:11px;font-weight:900;
                        color:{sc2};flex-shrink:0'>{step.get("strideType","?")[:1]}</div>
                    <div style='font-weight:700;font-size:12px;color:{"#66bb6a" if is_blocked else "#ef5350" if is_active else "var(--text)"};flex:1'>{step.get("label","")}</div>
                    {"⚡" if is_active and not is_blocked else ""}
                    {"⊘ BLOCKED" if is_blocked else ""}
                    {rt_badge}
                </div>
                <div style='font-size:10px;color:var(--sub);line-height:1.5'>{str(step.get("detail",""))[:70]}</div>
                <div style='font-size:9px;color:var(--muted);font-family:JetBrains Mono,monospace;margin-top:2px'>↳ {step.get("component","")} · {step.get("strideType","")}</div>
                {mit_badge}
            </div>""", unsafe_allow_html=True)
            if mode=="redteam" and not rt_submitted:
                if st.button(f"Add step {i+1}", key=onclick_key, use_container_width=True):
                    if step["id"] not in rt_sequence:
                        set_ss(sk+"_rtseq", rt_sequence+[step["id"]]); st.rerun()

    # Controls
    if mode == "sim":
        gate_msg = "AND gate — blocking ANY single step stops this path." if path.get("gateType")=="AND" else "OR gate — you must block EVERY branch."
        alert(gate_msg, "info")
        btn_c1, btn_c2, btn_c3 = st.columns(3)
        with btn_c1:
            if sim_phase=="idle":
                if st.button("▶ SIMULATE ATTACK", key=sk+"_runatk", use_container_width=True):
                    # Simulate step by step (in Streamlit we step through on button press)
                    set_ss(sk+"_simphase","running")
                    set_ss(sk+"_active", len(steps)-1)
                    set_ss(sk+"_simphase","done"); st.rerun()
            else:
                if st.button("↺ RESET", key=sk+"_reset", use_container_width=True):
                    set_ss(sk+"_simphase","idle"); set_ss(sk+"_active",-1); st.rerun()
        with btn_c2:
            if sim_phase in ("done","mitigated"):
                if st.button("✓ SHOW MITIGATED", key=sk+"_runmit", use_container_width=True):
                    set_ss(sk+"_simphase","mitigated")
                    set_ss(sk+"_active",len(steps)-1); st.rerun()
        if sim_phase=="done":
            alert(f"✗ BREACH — Attacker reached: {ws.get('attackTree',{}).get('goal','')[:60]}", "error")
        elif sim_phase=="mitigated":
            mits = path.get("mitigations",[])
            mit_text = " | ".join(f"⊘ {m.get('control','')[:40]}" for m in mits)
            alert(f"✓ ATTACK BLOCKED — {mit_text}", "success")

    else:
        # Red team mode
        alert(f"You are the attacker. Add steps above in the order you'd execute them to reach: **{ws.get('attackTree',{}).get('goal','')[:50]}**", "warn", "Red Team Challenge")
        st.markdown(f"**Your sequence:** {' → '.join(rt_sequence) if rt_sequence else '(click steps above to build)'}")
        rt_c1, rt_c2 = st.columns(2)
        with rt_c1:
            if not rt_submitted and len(rt_sequence)==len(steps):
                if st.button("⚔ LAUNCH ATTACK", key=sk+"_rtlaunch", use_container_width=True):
                    correct = [s["id"] for s in steps]
                    score_rt = sum(1 for i,(a,b) in enumerate(zip(rt_sequence,correct)) if a==b)
                    pct = round(score_rt/len(correct)*100)
                    set_ss(sk+"_rtsub",True)
                    set_ss(sk+"_rtres",{"score":score_rt,"total":len(correct),"pct":pct,"correct":correct})
                    set_ss(sk+"_simphase","done")
                    set_ss(sk+"_active",len(steps)-1); st.rerun()
        with rt_c2:
            if rt_sequence or rt_submitted:
                if st.button("↺ RESET", key=sk+"_rtreset", use_container_width=True):
                    set_ss(sk+"_rtseq",[]); set_ss(sk+"_rtsub",False)
                    set_ss(sk+"_rtres",None); set_ss(sk+"_simphase","idle"); st.rerun()
        if rt_result:
            pct=rt_result["pct"]
            if pct==100: alert(f"✓ {pct}% — Perfect sequence! You understand how this attack chains together.", "success")
            else: alert(f"✗ {pct}% — {rt_result['score']}/{rt_result['total']} correct. Right order: {' → '.join(rt_result['correct'])}", "warn")

    nav_c1, nav_c2 = st.columns(2)
    with nav_c1:
        if st.button("← FIND THREATS", key=sk+"_back"):
            set_ss("current_step","q2stride"); st.rerun()
    with nav_c2:
        if st.button("Q3: MITIGATIONS ▶", key=sk+"_next"):
            set_ss("current_step","q3"); st.rerun()


def render_step_q3(ws):
    sk = f"ws{ws['id']}_q3"
    sel_id = ss(sk+"_sel", ws["threats"][0]["id"] if ws["threats"] else "")
    overrides = ss(sk+"_overrides", {t["id"]:"Mitigate" for t in ws["threats"]})
    sim_mode_val = ss(sk+"_simmode","attack")
    quiz_chosen = ss(sk+"_qcho", None)
    quiz_revealed = ss(sk+"_qrev", False)

    threat = next((t for t in ws["threats"] if t["id"]==sel_id), ws["threats"][0])
    sc = stride_color(threat.get("stride","S"))

    st.markdown("## WHAT ARE WE DOING ABOUT IT?")
    st.caption("Select a threat — simulate the attack — choose the right mitigation")

    # Two-column: threat list LEFT, detail RIGHT
    list_col, detail_col = st.columns([1,2])

    with list_col:
        st.markdown("**Threats**")
        strat_colors = {"Mitigate":"#66bb6a","Eliminate":"#5c6bc0","Transfer":"#ffa726","Accept":"var(--muted)"}
        for t in ws["threats"]:
            tc = STRIDE_COLORS.get(t.get("stride","S")[:1],"#aaa")
            strat = overrides.get(t["id"],"Mitigate")
            active = t["id"]==sel_id
            if st.button(
                f"{'▸ ' if active else ''}{t['id']} [{t.get('stride','')[:1]}]",
                key=sk+f"_tsel_{t['id']}", use_container_width=True
            ):
                set_ss(sk+"_sel", t["id"])
                set_ss(sk+"_qcho",None); set_ss(sk+"_qrev",False)
                set_ss(sk+"_simmode","attack"); st.rerun()
            st.caption(f"Strategy: {strat}")

    with detail_col:
        # Architecture with hot threat
        arch_c1, arch_c2 = st.columns(2)
        with arch_c1:
            if st.button("▶ ATTACK", key=sk+"_atk"):
                set_ss(sk+"_simmode","attack"); st.rerun()
        with arch_c2:
            if st.button("✓ MITIGATED", key=sk+"_mit"):
                set_ss(sk+"_simmode","mitigated"); st.rerun()
        render_architecture(ws,
            hot_nodes=set(threat.get("nodes",[])),
            hot_flows=set(threat.get("flows",[])),
            sim_mode=sim_mode_val, height=280, key=sk)

        # Threat header
        st.markdown(f"""<div style='padding:12px 14px;background:var(--card);border-radius:7px;
            border:1px solid {sc}33;border-left:4px solid {sc};margin-bottom:10px'>
            <div style='display:flex;gap:8px;align-items:center;margin-bottom:5px'>
                {tag(threat.get("stride",""), sc)}
                <strong style='color:var(--text)'>{threat.get("id","")}</strong>
                <span style='font-size:11px;color:var(--muted);font-family:JetBrains Mono,monospace;margin-left:auto'>
                    {threat.get("likelihood","")} likelihood · {threat.get("impact_rating","")} impact</span>
            </div>
            <p style='font-size:13px;color:var(--sub);line-height:1.75;margin:0'>
                {str(threat.get("composed",""))[:200]}</p>
        </div>""", unsafe_allow_html=True)

        # Mitigation quiz
        ctrl_correct = (threat.get("controls_correct") or [""])[0]
        ctrl_wrong   = (threat.get("controls_wrong") or [])[:2]
        ctrl_opts    = [ctrl_correct] + ctrl_wrong
        import random; random.shuffle(ctrl_opts)
        correct_ctrl_idx = ctrl_opts.index(ctrl_correct) if ctrl_correct in ctrl_opts else 0

        st.markdown("**Which control blocks this attack? Click MITIGATED above to see it animate.**")
        if not quiz_revealed:
            for i,ctrl in enumerate(ctrl_opts):
                if ctrl and st.button(f"{chr(65+i)}. {ctrl[:70]}", key=sk+f"_ctrl{i}", use_container_width=True):
                    set_ss(sk+"_qcho",i); set_ss(sk+"_qrev",True); st.rerun()
        else:
            for i,ctrl in enumerate(ctrl_opts):
                if not ctrl: continue
                if i==correct_ctrl_idx: st.success(f"✓ {ctrl[:70]}")
                elif i==quiz_chosen: st.error(f"✗ {ctrl[:70]}")
                else: st.markdown(f"&nbsp;&nbsp;{chr(65+i)}. {ctrl[:70]}")
            if quiz_chosen==correct_ctrl_idx:
                alert(f"✓ Correct! {threat.get('explanation','')[:200]}", "success")
            else:
                alert(f"✗ Correct: **{ctrl_correct[:70]}**<br><br>{threat.get('explanation','')[:200]}", "warn")

        # Strategy selector
        strat_c = st.columns(4)
        for i, strat in enumerate(["Mitigate","Eliminate","Transfer","Accept"]):
            with strat_c[i]:
                if st.button(strat, key=sk+f"_strat_{strat}_{sel_id}", use_container_width=True):
                    new_ov = dict(overrides)
                    new_ov[sel_id] = strat
                    set_ss(sk+"_overrides", new_ov); st.rerun()
        sc2 = {"Mitigate":"#66bb6a","Eliminate":"#5c6bc0","Transfer":"#ffa726","Accept":"var(--muted)"}
        st.caption(f"Strategy for {sel_id}: **{overrides.get(sel_id,'Mitigate')}**")

    nav_c1, nav_c2 = st.columns(2)
    with nav_c1:
        if st.button("← ATTACK PATHS", key=sk+"_back"):
            set_ss("current_step","q2tree"); st.rerun()
    with nav_c2:
        if st.button("Q4: VALIDATE ▶", key=sk+"_next"):
            set_ss("current_step","q4"); st.rerun()


def render_step_q4(ws):
    sk = f"ws{ws['id']}_q4"
    answers = ss(f"ws{ws['id']}_q2stride_answers", [])
    total_score = sum(a.get("score",0) for a in answers)
    max_score = len(ws["threats"]) * 7
    pct = round(total_score/max_score*100) if max_score else 0

    st.markdown("## DID WE DO A GOOD ENOUGH JOB?")
    m1,m2,m3 = st.columns(3)
    with m1: st.metric("Score", f"{total_score}/{max_score}")
    with m2: st.metric("Accuracy", f"{pct}%")
    with m3:
        grade = "A+" if pct>=90 else "A" if pct>=80 else "B" if pct>=70 else "C"
        st.metric("Grade", grade)

    st.progress(pct/100)

    # Coverage check
    checklist = ws.get("q4_validation",{}).get("checklist",[])
    if checklist:
        st.markdown("**Validation Checklist**")
        for item in checklist:
            done_q = ss(sk+f"_chk_{item[:20]}", False)
            if st.checkbox(item[:100], value=done_q, key=sk+f"_chkbox_{item[:20]}"):
                set_ss(sk+f"_chk_{item[:20]}", True)

    # Coverage matrix
    stride_cats = ["S","T","R","I","D","E"]
    stride_found = set(a.get("stride","")[:1] for a in answers)
    st.markdown("**STRIDE Coverage**")
    cov_cols = st.columns(6)
    for i,letter in enumerate(stride_cats):
        with cov_cols[i]:
            covered = letter in stride_found
            col2 = stride_color(letter)
            st.markdown(f"""<div style='text-align:center;padding:10px;background:{col2 if covered else "var(--raised)"}22;
                border-radius:6px;border:1.5px solid {col2 if covered else "var(--border)"}'>
                <div style='font-family:JetBrains Mono,monospace;font-size:20px;font-weight:900;
                    color:{col2 if covered else "var(--muted)"}'>{letter}</div>
                <div style='font-size:9px;color:{"#66bb6a" if covered else "var(--muted)"}'>
                    {"✓" if covered else "—"}</div>
            </div>""", unsafe_allow_html=True)

    # Known gaps
    gaps = ws.get("q4_validation",{}).get("known_gaps",[])
    if gaps:
        st.markdown("**Known Gaps**")
        for g in gaps:
            st.markdown(f"⚠ **{g.get('gap','')}** — Owner: {g.get('owner','')} · Review: {g.get('reviewDate','')}")

    nav_c1, nav_c2 = st.columns(2)
    with nav_c1:
        if st.button("← MITIGATIONS", key=sk+"_back"):
            set_ss("current_step","q3"); st.rerun()
    with nav_c2:
        if st.button("🏆 GET CERTIFICATE ▶", key=sk+"_next"):
            set_ss("current_step","cert"); st.rerun()


def render_step_cert(ws):
    sk = f"ws{ws['id']}_cert"
    answers = ss(f"ws{ws['id']}_q2stride_answers", [])
    total_score = sum(a.get("score",0) for a in answers)
    max_score = len(ws["threats"]) * 7
    pct = round(total_score/max_score*100) if max_score else 0
    grade = "A+" if pct>=90 else "A" if pct>=80 else "B" if pct>=70 else "C"
    user = ss("tm_user",{})

    grade_col = "#66bb6a" if grade.startswith("A") else "#ffa726" if grade=="B" else "#ef5350"

    st.markdown(f"""<div style='text-align:center;padding:32px;background:var(--card);
        border-radius:12px;border:2px solid {grade_col}44;margin-bottom:24px'>
        <div style='font-size:10px;font-weight:700;color:var(--muted);font-family:JetBrains Mono,monospace;
            text-transform:uppercase;letter-spacing:3px;margin-bottom:12px'>
            Certificate of Completion</div>
        <div style='font-family:JetBrains Mono,monospace;font-size:52px;color:{grade_col};
            font-weight:900;margin-bottom:8px'>{grade}</div>
        <div style='font-size:18px;color:var(--text);font-weight:700;margin-bottom:4px'>
            {user.get("name","Student")}</div>
        <div style='font-size:14px;color:var(--sub);margin-bottom:16px'>
            has completed <strong style='color:var(--text)'>{ws["name"]}</strong></div>
        {tag(ws.get("level","FOUNDATION"), "#00e5ff")}
        <div style='font-size:13px;color:var(--muted);margin-top:12px'>
            Score: {total_score}/{max_score} ({pct}%) · Threats analysed: {len(answers)}/6
        </div>
    </div>""", unsafe_allow_html=True)

    # Skills validated
    st.markdown("**Skills Validated**")
    base_skills = [
        "Shostack 4-Question Framework end-to-end",
        "Asset classification and assumption documentation",
        "C4-style system decomposition",
        "Trust zone scoring and boundary identification",
        "STRIDE threat derivation",
        "Threat Grammar: precise actionable statements",
        "Attack path simulation — AND/OR gate analysis",
        "Mitigation strategy selection and gap validation",
    ]
    level_skills = {
        "INTERMEDIATE": ["MAESTRO AI threat framework","LLM prompt injection attack chains","EU AI Act compliance logging"],
        "ADVANCED":     ["Multi-tenant isolation architecture","Kafka ACL and event stream security","SOC 2 CC7.2 audit trail requirements"],
        "EXPERT":       ["FDA SaMD post-market surveillance","Adversarial ML attack classification","Safety-critical AI Repudiation controls"],
    }
    all_skills = base_skills + level_skills.get(ws.get("level",""), [])
    skill_cols = st.columns(2)
    for i, skill in enumerate(all_skills):
        with skill_cols[i % 2]:
            st.markdown(f"✓ {skill}")

    # Threat model summary table
    st.markdown("**Your Threat Model — Summary**")
    if answers:
        import pandas as pd
        rows = []
        for a in answers:
            t = a.get("threat", {})
            rows.append({
                "ID": t.get("id",""),
                "STRIDE": t.get("stride",""),
                "Likelihood": t.get("likelihood",""),
                "Impact": t.get("impact_rating",""),
                "Strategy": "Mitigate",
                "Score": f"{a.get('score',0)}/7",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

        # Export
        import io
        df = pd.DataFrame(rows)
        csv = df.to_csv(index=False)
        st.download_button(
            "⬇ EXPORT THREAT MODEL (CSV)",
            data=csv,
            file_name=f"{ws['name'].replace(' ','_')}_threat_model.csv",
            mime="text/csv",
        )

    # Mark completed
    completed = ss("tm_completed", set())
    completed.add(ws["id"])
    set_ss("tm_completed", completed)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("RESTART WORKSHOP ↺", key=sk+"_restart"):
            for key in list(st.session_state.keys()):
                if key.startswith(f"ws{ws['id']}_"):
                    del st.session_state[key]
            set_ss("current_step","why"); st.rerun()
    with c2:
        if st.button("BACK TO HOME ▶", key=sk+"_home"):
            set_ss("current_ws", None); st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# SIDEBAR — Glossary + Cheat Sheet
# ═══════════════════════════════════════════════════════════════════════════

def render_sidebar():
    with st.sidebar:
        st.markdown("## Quick Reference")
        tabs = st.tabs(["Glossary","STRIDE Rules","Zone Map","4Q Framework"])
        with tabs[0]:
            search = st.text_input("Search", placeholder="Search terms...", key="gloss_search")
            cat_filter = st.selectbox("Category",
                ["All"] + list(dict.fromkeys(g["cat"] for g in GLOSSARY)),
                key="gloss_cat")
            for g in GLOSSARY:
                if (cat_filter=="All" or g["cat"]==cat_filter) and \
                   (not search or search.lower() in g["term"].lower() or search.lower() in g["def"].lower()):
                    with st.expander(g["term"]):
                        st.caption(g["cat"])
                        st.write(g["def"])

        with tabs[1]:
            for rule in STRIDE_GUIDE:
                col_s = stride_color(rule["letter"])
                with st.expander(f"{rule['letter']} — {rule['name']}"):
                    st.markdown(f"*{rule.get('oneLiner','')}*")
                    st.markdown(f"**Zone rule:** {rule.get('dfdRule','')[:80]}")
                    st.markdown(f"**Defence:** {rule.get('defence','')[:100]}")

        with tabs[2]:
            for zone, col in ZONE_COLORS.items():
                st.markdown(f'<span style="color:{col};font-weight:700">{zone}</span>', unsafe_allow_html=True)
                st.caption(f"Score: {'0' if 'Not' in zone else '1' if 'Minimal' in zone else '3' if 'Standard' in zone else '5' if 'Elevated' in zone else '7+'}")

        with tabs[3]:
            for q, lbl, col in [("Q1","What are we working on?","#00e5ff"),
                                  ("Q2","What can go wrong?","#5c6bc0"),
                                  ("Q3","What are we doing about it?","#ffa726"),
                                  ("Q4","Did we do a good enough job?","#66bb6a")]:
                st.markdown(f'<span style="color:{col};font-weight:700">{q}: {lbl}</span>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# WORKSHOP VIEW
# ═══════════════════════════════════════════════════════════════════════════

def render_workshop():
    ws_id = ss("current_ws")
    ws    = WS.get(str(ws_id))
    if not ws:
        st.error("Workshop not found.")
        return

    step = ss("current_step","why")

    # Back to home button
    hc1, hc2 = st.columns([3,1])
    with hc1:
        st.markdown(f"""<div style='font-family:JetBrains Mono,monospace;font-size:15px;
            color:var(--accent);letter-spacing:1.5px'>{ws["name"]}</div>""",
            unsafe_allow_html=True)
    with hc2:
        if st.button("← HOME", key="ws_home"):
            set_ss("current_ws", None); st.rerun()

    render_step_bar(ws_id, step)
    render_sidebar()

    # Route to step
    step_fns = {
        "why":      render_step_why,
        "s101":     render_step_s101,
        "q1":       render_step_q1,
        "q2zones":  render_step_q2zones,
        "q2arch":   render_step_q2arch,
        "q2stride": render_step_q2stride,
        "q2tree":   render_step_q2tree,
        "q3":       render_step_q3,
        "q4":       render_step_q4,
        "cert":     render_step_cert,
    }
    fn = step_fns.get(step)
    if fn:
        fn(ws)
    else:
        st.warning(f"Step '{step}' not found.")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    user = ss("tm_user")

    if not user:
        render_auth()
        return

    if ss("current_ws"):
        render_workshop()
    else:
        render_home()


if __name__ == "__main__":
    main()
