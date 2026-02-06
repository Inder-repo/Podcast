import streamlit as st
import base64
import json
import os
import pandas as pd
from graphviz import Digraph, ExecutableNotFound
from datetime import datetime

# Streamlit app configuration
st.set_page_config(
    page_title="STRIDE Threat Modeling - Progressive Workshops",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Workshop unlock codes  
WORKSHOP_CODES = {
    "1": None,  # Always unlocked
    "2": "MICRO2025",
    "3": "TENANT2025",
    "4": "HEALTH2025"
}

# OWASP and Standards Mappings
OWASP_MITIGATIONS = {
    "SQL Injection": {
        "mitigations": [
            "Use parameterized queries/prepared statements",
            "Use ORM frameworks (Sequelize, TypeORM, Hibernate)",
            "Input validation with allowlisting",
            "Least privilege database accounts",
            "Deploy Web Application Firewall (WAF)"
        ],
        "controls": [
            "Parameterized queries",
            "ORM with query builder",
            "Input validation library",
            "Database user permissions (SELECT only)",
            "AWS WAF with OWASP Core Rule Set"
        ],
        "compliance": [
            "OWASP Top 10 A03:2021 - Injection",
            "OWASP ASVS V5.3.4",
            "PCI-DSS 6.5.1",
            "CWE-89"
        ]
    },
    "Cross-Site Scripting (XSS)": {
        "mitigations": [
            "Implement Content Security Policy (CSP)",
            "Context-aware output encoding",
            "Input sanitization with DOMPurify",
            "Use HttpOnly and Secure flags on cookies",
            "Framework built-in protections"
        ],
        "controls": [
            "CSP headers: default-src 'self'",
            "DOMPurify library",
            "Output encoding based on context",
            "HTTPOnly cookies"
        ],
        "compliance": [
            "OWASP Top 10 A03:2021",
            "OWASP ASVS V5.3.3",
            "PCI-DSS 6.5.7"
        ]
    },
    "Broken Authentication": {
        "mitigations": [
            "Implement Multi-Factor Authentication (MFA)",
            "Strong password policies (12+ chars)",
            "Account lockout after failed attempts",
            "Session timeout and regeneration",
            "Secure session management"
        ],
        "controls": [
            "TOTP-based MFA",
            "Password strength validator",
            "Account lockout: 5 attempts",
            "Session timeout: 30 minutes"
        ],
        "compliance": [
            "OWASP Top 10 A07:2021",
            "OWASP ASVS V2.1.1",
            "PCI-DSS 8.2.3"
        ]
    },
    "Sensitive Data Exposure": {
        "mitigations": [
            "Encrypt data at rest (AES-256)",
            "Encrypt data in transit (TLS 1.3)",
            "Key management (AWS KMS)",
            "Data classification procedures",
            "Data masking"
        ],
        "controls": [
            "AES-256 encryption",
            "TLS 1.3",
            "AWS KMS",
            "Data classification labels"
        ],
        "compliance": [
            "OWASP Top 10 A02:2021",
            "GDPR Article 32",
            "HIPAA 164.312(a)(2)(iv)",
            "PCI-DSS 3.4"
        ]
    },
    "Broken Access Control": {
        "mitigations": [
            "Implement RBAC",
            "Deny by default",
            "Validate permissions per request",
            "Object-level authorization",
            "Disable directory listing"
        ],
        "controls": [
            "RBAC middleware",
            "Principle of least privilege",
            "Resource ownership checks"
        ],
        "compliance": [
            "OWASP Top 10 A01:2021",
            "OWASP ASVS V4.1.1",
            "PCI-DSS 7.1"
        ]
    },
    "Insufficient Logging": {
        "mitigations": [
            "Log authentication events",
            "Log sensitive data access",
            "Centralized log management",
            "Log integrity protection",
            "Real-time alerting"
        ],
        "controls": [
            "Structured logging",
            "Write-once storage",
            "SIEM integration",
            "Automated alerts"
        ],
        "compliance": [
            "OWASP Top 10 A09:2021",
            "PCI-DSS 10",
            "HIPAA 164.312(b)"
        ]
    }
}

# STRIDE categories
STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege"
]

# Threat types by STRIDE
THREAT_TYPES_BY_STRIDE = {
    "Spoofing": ["Credential Theft", "Session Hijacking", "Man-in-the-Middle", "Token Theft"],
    "Tampering": ["SQL Injection", "Cross-Site Scripting (XSS)", "Configuration Tampering", "Firmware Tampering"],
    "Repudiation": ["Insufficient Logging", "Log Tampering", "Missing Digital Signatures"],
    "Information Disclosure": ["Unencrypted Data", "Verbose Errors", "Broken Access Control", "Database Backup Exposure"],
    "Denial of Service": ["DDoS Attack", "Resource Exhaustion", "Connection Pool Exhaustion"],
    "Elevation of Privilege": ["Broken Access Control", "Privilege Escalation", "Command Injection", "Mass Assignment"]
}

# CSS
st.markdown("""
<style>
    .threat-critical {
        background-color: #ffcccc;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #cc0000;
        margin: 5px 0;
    }
    .threat-high {
        background-color: #ffdddd;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #ff6666;
        margin: 5px 0;
    }
    .threat-medium {
        background-color: #fff4cc;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #ff9900;
        margin: 5px 0;
    }
    .threat-low {
        background-color: #ccffcc;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #00cc00;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)

# Session state
def init_session_state():
    defaults = {
        'selected_workshop': None,
        'completed_workshops': set(),
        'unlocked_workshops': set(["1"]),
        'current_step': 1,
        'threats': [],
        'diagram_generated': None
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# Workshops
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: E-Commerce",
        "scenario": {
            "title": "TechMart Store",
            "description": "E-commerce platform",
            "components": [
                {"name": "Customer", "type": "external"},
                {"name": "Web Frontend", "type": "process"},
                {"name": "API Backend", "type": "process"},
                {"name": "Database", "type": "datastore"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls"},
                {"source": "API Backend", "destination": "Database", "data": "SQL"}
            ]
        },
        "target_threats": 15
    },
    "2": {
        "name": "Workshop 2: Mobile Banking",
        "scenario": {
            "title": "CloudBank",
            "description": "Banking app",
            "components": [
                {"name": "Mobile App", "type": "external"},
                {"name": "API Gateway", "type": "process"},
                {"name": "Database", "type": "datastore"}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS"},
                {"source": "API Gateway", "destination": "Database", "data": "Data"}
            ]
        },
        "target_threats": 25
    },
    "3": {
        "name": "Workshop 3: SaaS Analytics",
        "scenario": {
            "title": "DataInsight",
            "description": "Analytics platform",
            "components": [
                {"name": "Web Portal", "type": "external"},
                {"name": "API", "type": "process"},
                {"name": "Data Lake", "type": "datastore"}
            ],
            "data_flows": [
                {"source": "Web Portal", "destination": "API", "data": "Queries"},
                {"source": "API", "destination": "Data Lake", "data": "Data"}
            ]
        },
        "target_threats": 30
    },
    "4": {
        "name": "Workshop 4: AI Healthcare",
        "scenario": {
            "title": "HealthAI",
            "description": "AI platform",
            "components": [
                {"name": "AI Agent", "type": "process"},
                {"name": "LLM API", "type": "external"},
                {"name": "Patient DB", "type": "datastore"}
            ],
            "data_flows": [
                {"source": "AI Agent", "destination": "LLM API", "data": "Prompts"},
                {"source": "AI Agent", "destination": "Patient DB", "data": "PHI"}
            ]
        },
        "target_threats": 40
    }
}

def calculate_risk_score(likelihood, impact):
    vals = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    score = vals.get(likelihood, 2) * vals.get(impact, 2)
    if score >= 9:
        return "Critical", score
    elif score >= 6:
        return "High", score
    elif score >= 3:
        return "Medium", score
    return "Low", score

def generate_dfd(workshop_config):
    try:
        dot = Digraph(format="png")
        dot.attr(rankdir="TB")
        
        for comp in workshop_config["scenario"]["components"]:
            shape = "oval" if comp["type"] == "external" else "cylinder" if comp["type"] == "datastore" else "box"
            dot.node(comp["name"], shape=shape)
        
        for flow in workshop_config["scenario"]["data_flows"]:
            dot.edge(flow["source"], flow["destination"], flow["data"])
        
        path = dot.render("dfd", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except:
        return None

# SIDEBAR
with st.sidebar:
    st.title("🔒 STRIDE Workshops")
    
    for ws_id, ws in WORKSHOPS.items():
        unlocked = ws_id in st.session_state.unlocked_workshops
        completed = ws_id in st.session_state.completed_workshops
        
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"Workshop {ws_id}", key=f"ws_{ws_id}", disabled=not unlocked):
                st.session_state.selected_workshop = ws_id
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.rerun()
        
        with col2:
            st.markdown("✅" if completed else ("🔒" if not unlocked else ""))
        
        if not unlocked and ws_id != "1":
            with st.expander("Unlock"):
                code = st.text_input("Code", key=f"code_{ws_id}", type="password")
                if st.button("Unlock", key=f"btn_{ws_id}"):
                    if code == WORKSHOP_CODES[ws_id]:
                        st.session_state.unlocked_workshops.add(ws_id)
                        st.success("Unlocked!")
                        st.rerun()
                    else:
                        st.error("Invalid code")
    
    st.markdown("---")
    with st.expander("STRIDE"):
        st.markdown("**S** - Spoofing\n**T** - Tampering\n**R** - Repudiation\n**I** - Info Disclosure\n**D** - Denial of Service\n**E** - Elevation of Privilege")

# MAIN
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Workshops")
    st.markdown("Select a workshop from the sidebar.\n\n**Unlock Codes:**\n- Workshop 2: `MICRO2025`\n- Workshop 3: `TENANT2025`\n- Workshop 4: `HEALTH2025`")
    st.stop()

current = WORKSHOPS[st.session_state.selected_workshop]
st.title(current["name"])

# Progress
steps = ["Scope", "Decompose", "Threats", "Assess", "Complete"]
cols = st.columns(len(steps))
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
    st.write(f"**{current['scenario']['title']}** - {current['scenario']['description']}")
    
    st.subheader("Components")
    for comp in current["scenario"]["components"]:
        st.write(f"• {comp['name']} ({comp['type']})")
    
    if st.button("Next ➡️", type="primary"):
        st.session_state.current_step = 2
        st.rerun()

# STEP 2
elif st.session_state.current_step == 2:
    st.header("Step 2: Decompose")
    
    diagram = generate_dfd(current)
    if diagram:
        st.image(f"data:image/png;base64,{diagram}")
        st.session_state.diagram_generated = diagram
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 1
            st.rerun()
    with col2:
        if st.button("Next ➡️", type="primary"):
            st.session_state.current_step = 3
            st.rerun()

# STEP 3
elif st.session_state.current_step == 3:
    st.header("Step 3: Identify Threats")
    st.info(f"Target: {current['target_threats']} threats")
    
    with st.form("threat_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            stride = st.selectbox("STRIDE *", STRIDE_CATEGORIES)
            threat_type = st.selectbox("Threat Type *", THREAT_TYPES_BY_STRIDE.get(stride, []))
            
            components = [c["name"] for c in current["scenario"]["components"]]
            flows = [f"{f['source']} → {f['destination']}" for f in current["scenario"]["data_flows"]]
            affected = st.selectbox("Component *", components + flows)
            
            likelihood = st.select_slider("Likelihood *", options=["Low", "Medium", "High", "Critical"])
            impact = st.select_slider("Impact *", options=["Low", "Medium", "High", "Critical"])
        
        with col2:
            owasp = OWASP_MITIGATIONS.get(threat_type, {})
            if owasp:
                st.markdown("**💡 OWASP Recommendations**")
                for m in owasp.get("mitigations", [])[:3]:
                    st.caption(f"• {m}")
        
        description = st.text_area("Description *", height=100)
        
        if owasp:
            mitigations = st.multiselect("Mitigations", owasp.get("mitigations", []))
            custom_mit = st.text_input("Custom Mitigation")
            final_mit = "; ".join(mitigations + ([custom_mit] if custom_mit else []))
            
            controls = st.multiselect("Controls", owasp.get("controls", []))
            custom_ctrl = st.text_input("Custom Control")
            final_ctrl = ", ".join(controls + ([custom_ctrl] if custom_ctrl else []))
            
            compliance = st.multiselect("Compliance", owasp.get("compliance", []))
            custom_comp = st.text_input("Custom Compliance")
            final_comp = ", ".join(compliance + ([custom_comp] if custom_comp else []))
        else:
            final_mit = st.text_area("Mitigation *")
            final_ctrl = st.text_input("Controls")
            final_comp = st.text_input("Compliance")
        
        if st.form_submit_button("Add Threat", type="primary"):
            if description and final_mit:
                risk_priority, risk_score = calculate_risk_score(likelihood, impact)
                
                threat = {
                    "id": f"T-{len(st.session_state.threats) + 1:03d}",
                    "stride_category": stride,
                    "threat_type": threat_type,
                    "affected_component": affected,
                    "description": description,
                    "likelihood": likelihood,
                    "impact": impact,
                    "risk_priority": risk_priority,
                    "risk_score": risk_score,
                    "mitigation": final_mit,
                    "controls": final_ctrl,
                    "compliance_mapping": final_comp
                }
                
                st.session_state.threats.append(threat)
                st.success(f"✅ Added {threat['id']}")
                st.rerun()
            else:
                st.error("Fill required fields (*)")
    
    st.markdown("---")
    st.subheader(f"Threats ({len(st.session_state.threats)}/{current['target_threats']})")
    
    for threat in st.session_state.threats:
        risk_class = f"threat-{threat['risk_priority'].lower()}"
        st.markdown(f"""
        <div class="{risk_class}">
            <strong>{threat['id']}</strong> - {threat['threat_type']} 
            <span style="float: right;">{threat['risk_priority']}</span><br>
            <strong>Description:</strong> {threat['description']}<br>
            <strong>Mitigation:</strong> {threat['mitigation']}<br>
            <strong>Controls:</strong> {threat['controls']}<br>
            <strong>Compliance:</strong> {threat['compliance_mapping']}
        </div>
        """, unsafe_allow_html=True)
    
    st.progress(min(len(st.session_state.threats) / current['target_threats'], 1.0))
    
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 2
            st.rerun()
    with col2:
        if st.button("Next ➡️", type="primary"):
            if st.session_state.threats:
                st.session_state.current_step = 4
                st.rerun()
            else:
                st.error("Add at least one threat")

# STEP 4
elif st.session_state.current_step == 4:
    st.header("Step 4: Assess & Mitigate")
    
    if not st.session_state.threats:
        st.warning("No threats")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            st.rerun()
        st.stop()
    
    st.subheader("Risk Distribution")
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in st.session_state.threats:
        risk_counts[t.get("risk_priority", "Low")] += 1
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Critical", risk_counts["Critical"])
    col2.metric("High", risk_counts["High"])
    col3.metric("Medium", risk_counts["Medium"])
    col4.metric("Low", risk_counts["Low"])
    
    st.subheader("Prioritized Threats")
    sorted_threats = sorted(st.session_state.threats, key=lambda x: x.get("risk_score", 0), reverse=True)
    
    df = pd.DataFrame([{
        "ID": t["id"],
        "Type": t.get("threat_type", ""),
        "Component": t["affected_component"],
        "Risk": t["risk_priority"],
        "Mitigation": t["mitigation"][:50] + "..."
    } for t in sorted_threats])
    
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    st.subheader("STRIDE Distribution")
    stride_counts = {}
    for t in st.session_state.threats:
        cat = t["stride_category"]
        stride_counts[cat] = stride_counts.get(cat, 0) + 1
    
    st.bar_chart(pd.DataFrame([{"STRIDE": k, "Count": v} for k, v in stride_counts.items()]).set_index("STRIDE"))
    
    st.markdown("---")
    csv = df.to_csv(index=False)
    st.download_button("📥 CSV", csv, f"threats_{st.session_state.selected_workshop}.csv", "text/csv")
    
    if st.session_state.diagram_generated:
        img = base64.b64decode(st.session_state.diagram_generated)
        st.download_button("📥 DFD", img, "dfd.png", "image/png")
    
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            st.rerun()
    with col2:
        if st.button("Complete ➡️", type="primary"):
            st.session_state.current_step = 5
            st.rerun()

# STEP 5
elif st.session_state.current_step == 5:
    st.header("🎉 Complete!")
    
    st.success(f"Completed {current['name']}!\n\n✅ {len(st.session_state.threats)} threats identified")
    
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total", len(st.session_state.threats))
    col2.metric("Critical", len([t for t in st.session_state.threats if t.get("risk_priority") == "Critical"]))
    col3.metric("High", len([t for t in st.session_state.threats if t.get("risk_priority") == "High"]))
    
    if st.button("🏠 Home"):
        st.session_state.selected_workshop = None
        st.session_state.current_step = 1
        st.rerun()

st.markdown("---")
st.caption("STRIDE Threat Modeling | OWASP Aligned")
