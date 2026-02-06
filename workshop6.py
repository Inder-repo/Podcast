"""
STRIDE Threat Modeling - COMPLETE FIXED VERSION
All 4 Workshops | No Nested Expanders | Full Implementation
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

# UNLOCK CODES
WORKSHOP_CODES = {"1": None, "2": "MICRO2025", "3": "TENANT2025", "4": "HEALTH2025"}

st.markdown("""<style>
.stButton>button{width:100%;border-radius:4px;font-weight:500}
.threat-critical{background-color:#B71C1C;color:white;padding:12px;border-radius:4px;border-left:5px solid #D32F2F;margin:8px 0}
.threat-high{background-color:#FFE5E5;padding:12px;border-radius:4px;border-left:5px solid #F96167;margin:8px 0}
.threat-medium{background-color:#FFF9E5;padding:12px;border-radius:4px;border-left:5px solid #FFC107;margin:8px 0}
.threat-low{background-color:#E8F5E9;padding:12px;border-radius:4px;border-left:5px solid #2C5F2D;margin:8px 0}
.score-excellent{background-color:#4CAF50;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
.score-good{background-color:#8BC34A;color:white;padding:16px;border-radius:8px;text-align:center;font-size:1.2em;font-weight:bold}
.badge-completed{background-color:#2C5F2D;color:white;padding:4px 12px;border-radius:12px;font-size:0.85em;font-weight:600}
.badge-locked{background-color:#757575;color:white;padding:4px 12px;border-radius:12px;font-size:0.85em;font-weight:600}
.info-box{background-color:#E3F2FD;padding:16px;border-radius:4px;border-left:4px solid #1976D2;margin:12px 0}
</style>""", unsafe_allow_html=True)

def init_session_state():
    defaults = {
        'selected_workshop': None, 'completed_workshops': set(), 'unlocked_workshops': set(['1']), 
        'current_step': 1, 'threats': [], 'user_answers': [], 'total_score': 0, 'max_score': 0, 
        'diagram_generated': None, 'show_unlock_form': {}, 'show_learning': {}
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# ALL WORKSHOP THREATS
PREDEFINED_THREATS = {
    "1": [
        {"id": "T-001", "stride": "Spoofing", "component": "Web Frontend → API Backend",
         "threat": "Session hijacking via XSS", "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["HttpOnly cookies", "CSP headers", "Input sanitization"],
         "incorrect_mitigations": ["Increase password complexity", "Add rate limiting"],
         "explanation": "XSS allows stealing session cookies. HttpOnly prevents JavaScript access to cookies.",
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.7", "points": 10},
        
        {"id": "T-002", "stride": "Tampering", "component": "API Backend → Database",
         "threat": "SQL injection in search queries", "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Parameterized queries", "Use ORM", "Input validation"],
         "incorrect_mitigations": ["Encrypt database", "Add logging"],
         "explanation": "SQL injection exploits unsanitized input. Parameterized queries prevent code execution.",
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1", "points": 10},
    ],
    "2": [
        {"id": "T-101", "stride": "Information Disclosure", "component": "Mobile App → API Gateway",
         "threat": "BOLA - accessing other users' accounts", "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Object-level authorization", "Verify resource ownership", "JWT validation"],
         "incorrect_mitigations": ["Add encryption", "Use HTTPS"],
         "explanation": "BOLA allows accessing resources without ownership check. Must validate user owns resource.",
         "compliance": "OWASP API Security Top 10 - API1", "points": 10},
        
        {"id": "T-102", "stride": "Tampering", "component": "Payment Service",
         "threat": "Vulnerable container image with CVEs", "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["ECR image scanning", "Regular updates", "Minimal base images"],
         "incorrect_mitigations": ["Add firewall", "Enable logging"],
         "explanation": "Container images can contain vulnerabilities. Scan on push and update regularly.",
         "compliance": "CIS Docker Benchmark", "points": 10},
    ],
    "3": [
        {"id": "T-201", "stride": "Information Disclosure", "component": "Query Service → Data Warehouse",
         "threat": "Row-level security bypass allows cross-tenant data access", "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["RLS enforcement", "Query rewriting", "Tenant context validation"],
         "incorrect_mitigations": ["Add encryption", "Use VPN"],
         "explanation": "Multi-tenant systems must enforce RLS. Tenant A should never see Tenant B data.",
         "compliance": "SOC 2 CC6.1", "points": 10},
        
        {"id": "T-202", "stride": "Tampering", "component": "API Gateway → Query Service",
         "threat": "Data pipeline poisoning via malicious messages", "likelihood": "Low", "impact": "High",
         "correct_mitigations": ["Message schema validation", "Producer authentication", "Input sanitization"],
         "incorrect_mitigations": ["Add monitoring", "Increase storage"],
         "explanation": "Data pipelines process untrusted data. Validate schema and sanitize inputs.",
         "compliance": "ISO 27001 A.14.2.5", "points": 10},
    ],
    "4": [
        {"id": "T-301", "stride": "Tampering", "component": "AI Agent → LLM API",
         "threat": "Prompt injection manipulates AI behavior", "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Input sanitization", "Prompt templates", "Output validation"],
         "incorrect_mitigations": ["Add encryption", "Use HTTPS"],
         "explanation": "Prompt injection tricks AI into harmful actions. Sanitize inputs and validate outputs.",
         "compliance": "NIST AI Risk Management Framework", "points": 10},
        
        {"id": "T-302", "stride": "Information Disclosure", "component": "Vector DB",
         "threat": "RAG poisoning with malicious medical content", "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Content signing", "Source verification", "Regular audits"],
         "incorrect_mitigations": ["Add rate limiting", "Enable logging"],
         "explanation": "Vector databases can be poisoned with false medical info. Verify sources and sign content.",
         "compliance": "FDA AI/ML Guidance", "points": 10},
    ]
}

# ALL 4 WORKSHOPS
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: E-Commerce Platform",
        "level": "Foundation", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "TechMart Online Store",
            "description": "E-commerce platform selling electronics",
            "components": [
                {"name": "Customer", "type": "external_entity"},
                {"name": "Web Frontend", "type": "process"},
                {"name": "API Backend", "type": "process"},
                {"name": "Database", "type": "datastore"},
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls"},
                {"source": "API Backend", "destination": "Database", "data": "SQL"},
            ]
        }
    },
    "2": {
        "name": "Workshop 2: Mobile Banking",
        "level": "Intermediate", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "CloudBank Mobile App",
            "description": "Microservices banking platform",
            "components": [
                {"name": "Mobile App", "type": "external_entity"},
                {"name": "API Gateway", "type": "process"},
                {"name": "Payment Service", "type": "process"},
                {"name": "Transaction DB", "type": "datastore"},
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS"},
                {"source": "API Gateway", "destination": "Payment Service", "data": "Payments"},
                {"source": "Payment Service", "destination": "Transaction DB", "data": "Data"},
            ]
        }
    },
    "3": {
        "name": "Workshop 3: SaaS Analytics",
        "level": "Advanced", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "DataInsight Platform",
            "description": "Multi-tenant SaaS analytics",
            "components": [
                {"name": "Web Portal", "type": "external_entity"},
                {"name": "API Gateway", "type": "process"},
                {"name": "Query Service", "type": "process"},
                {"name": "Data Warehouse", "type": "datastore"},
            ],
            "data_flows": [
                {"source": "Web Portal", "destination": "API Gateway", "data": "Queries"},
                {"source": "API Gateway", "destination": "Query Service", "data": "SQL"},
                {"source": "Query Service", "destination": "Data Warehouse", "data": "Data"},
            ]
        }
    },
    "4": {
        "name": "Workshop 4: AI Healthcare",
        "level": "Expert", "duration": "2 hours", "target_threats": 2,
        "scenario": {
            "title": "HealthAI Platform",
            "description": "AI-powered healthcare diagnostics",
            "components": [
                {"name": "Clinician Portal", "type": "external_entity"},
                {"name": "AI Agent", "type": "process"},
                {"name": "LLM API", "type": "external_entity"},
                {"name": "Vector DB", "type": "datastore"},
            ],
            "data_flows": [
                {"source": "Clinician Portal", "destination": "AI Agent", "data": "Queries"},
                {"source": "AI Agent", "destination": "LLM API", "data": "Prompts"},
                {"source": "AI Agent", "destination": "Vector DB", "data": "Embeddings"},
            ]
        }
    }
}

def generate_dfd(workshop_config):
    try:
        dot = Digraph(format="png")
        dot.attr(rankdir="LR", size="10,6")
        
        for comp in workshop_config["scenario"]["components"]:
            shape = "oval" if comp["type"] == "external_entity" else "cylinder" if comp["type"] == "datastore" else "box"
            dot.node(comp["name"], shape=shape, style="filled", fillcolor="lightblue")
        
        for flow in workshop_config["scenario"]["data_flows"]:
            dot.edge(flow["source"], flow["destination"], flow["data"])
        
        path = dot.render("dfd", format="png", cleanup=True)
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
    
    if len(correct_selected) >= 2:
        score += 4
        feedback.append(f"✓ Good mitigations ({len(correct_selected)} correct)")
    elif len(correct_selected) >= 1:
        score += 2
        feedback.append(f"⚠ Partial ({len(correct_selected)} correct)")
    
    return max(0, score), max_score, feedback

# SIDEBAR
with st.sidebar:
    st.title("🔒 STRIDE Lab")
    st.markdown("### Workshops")
    
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
            
            # FIXED: Not inside expander anymore
            if st.session_state.show_unlock_form.get(unlock_key, False):
                code = st.text_input("Code", type="password", key=f"code_{ws_id}")
                if st.button("Submit", key=f"submit_{ws_id}"):
                    if code == WORKSHOP_CODES.get(ws_id):
                        st.session_state.unlocked_workshops.add(ws_id)
                        st.session_state.show_unlock_form[unlock_key] = False
                        st.success("Unlocked!")
                        st.rerun()
                    else:
                        st.error("Invalid code")
        
        st.caption(ws["name"])

# MAIN
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling")
    st.markdown("Select a workshop from the sidebar.")
    st.markdown("**Unlock codes:** Workshop 2: `MICRO2025`, Workshop 3: `TENANT2025`, Workshop 4: `HEALTH2025`")
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
    st.markdown(f"**Description:** {current['scenario']['description']}")
    
    st.subheader("Components")
    for comp in current["scenario"]["components"]:
        st.markdown(f"- {comp['name']} ({comp['type']})")
    
    if st.button("Next ➡️", type="primary"):
        st.session_state.current_step = 2
        st.rerun()

# STEP 2
elif st.session_state.current_step == 2:
    st.header("Step 2: Decompose")
    
    diagram = generate_dfd(current)
    if diagram:
        st.image(f"data:image/png;base64,{diagram}")
    
    st.subheader("Data Flows")
    for flow in current["scenario"]["data_flows"]:
        st.markdown(f"- {flow['source']} → {flow['destination']}: {flow['data']}")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 1
            st.rerun()
    with col2:
        if st.button("Next ➡️", type="primary"):
            st.session_state.current_step = 3
            st.rerun()

# STEP 3 - FIXED: NO NESTED EXPANDERS
elif st.session_state.current_step == 3:
    st.header("Step 3: Identify Threats")
    st.info(f"Goal: Analyze {current['target_threats']} threats")
    
    with st.form("threat_form"):
        st.subheader("Select Threat")
        
        threat_options = {f"{t['id']}: {t['threat']}": t for t in workshop_threats}
        
        if not threat_options:
            st.error("No threats available")
            st.stop()
        
        selected_key = st.selectbox("Threat scenario:", list(threat_options.keys()))
        selected_predefined = threat_options[selected_key]
        
        col1, col2 = st.columns(2)
        
        with col1:
            all_components = [c["name"] for c in current["scenario"]["components"]]
            all_flows = [f"{f['source']} → {f['destination']}" for f in current["scenario"]["data_flows"]]
            
            user_component = st.selectbox("Affected component:", all_components + all_flows)
            user_stride = st.selectbox("STRIDE:", ["Spoofing", "Tampering", "Repudiation", 
                                                    "Information Disclosure", "Denial of Service", 
                                                    "Elevation of Privilege"])
            user_likelihood = st.select_slider("Likelihood:", ["Low", "Medium", "High", "Critical"])
            user_impact = st.select_slider("Impact:", ["Low", "Medium", "High", "Critical"])
        
        with col2:
            st.caption("Select mitigations:")
            all_mits = selected_predefined["correct_mitigations"] + selected_predefined.get("incorrect_mitigations", [])
            random.shuffle(all_mits)
            user_mitigations = st.multiselect("Security controls:", all_mits)
        
        submitted = st.form_submit_button("Submit Answer", type="primary")
        
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
                "score": score,
                "max_score": max_score,
                "feedback": feedback,
                "predefined_threat": selected_predefined
            })
            
            st.session_state.threats.append(user_answer)
            st.rerun()
    
    # Display answers - FIXED: Using buttons instead of nested expanders
    if st.session_state.user_answers:
        st.markdown("---")
        st.subheader(f"Answers ({len(st.session_state.user_answers)}/{current['target_threats']})")
        
        for idx, answer in enumerate(st.session_state.user_answers):
            score_pct = (answer["score"] / answer["max_score"]) * 100
            emoji = "✅" if score_pct >= 80 else "⚠️" if score_pct >= 50 else "❌"
            
            # Main answer card
            st.markdown(f"**{emoji} Answer {idx + 1}: {answer['matched_threat_id']} ({score_pct:.0f}%)**")
            
            # Toggle learning content with button (NOT nested expander)
            learning_key = f"show_learning_{idx}"
            if learning_key not in st.session_state.show_learning:
                st.session_state.show_learning[learning_key] = False
            
            if st.button(f"{'Hide' if st.session_state.show_learning.get(learning_key) else 'Show'} Details", 
                        key=f"toggle_{idx}"):
                st.session_state.show_learning[learning_key] = not st.session_state.show_learning.get(learning_key, False)
                st.rerun()
            
            # Show details if toggled (NOT in expander)
            if st.session_state.show_learning.get(learning_key, False):
                st.markdown(f"""
                **Your Analysis:**
                - Component: {answer['component']}
                - STRIDE: {answer['stride']}
                - Risk: {answer['likelihood']} × {answer['impact']}
                """)
                
                st.markdown("**Feedback:**")
                for fb in answer["feedback"]:
                    if "✓" in fb:
                        st.success(fb)
                    elif "✗" in fb:
                        st.error(fb)
                    else:
                        st.warning(fb)
                
                predefined = answer.get("predefined_threat")
                if predefined:
                    st.info(f"**Explanation:** {predefined['explanation']}")
                    st.caption(f"**Compliance:** {predefined['compliance']}")
                
                st.markdown("---")
    
    progress = len(st.session_state.user_answers) / current['target_threats']
    st.progress(min(progress, 1.0))
    
    if len(st.session_state.user_answers) >= current['target_threats']:
        st.success("Target reached!")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back"):
            st.session_state.current_step = 2
            st.rerun()
    with col2:
        if st.button("Next ➡️", type="primary"):
            if st.session_state.user_answers:
                st.session_state.current_step = 4
                st.rerun()
            else:
                st.error("Complete at least one threat")

# STEP 4
elif st.session_state.current_step == 4:
    st.header("Step 4: Assessment")
    
    if not st.session_state.user_answers:
        st.warning("No answers")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            st.rerun()
        st.stop()
    
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percentage", f"{final_score_pct:.1f}%")
    col3.metric("Grade", "A" if final_score_pct >= 90 else "B" if final_score_pct >= 80 else "C")
    
    st.subheader("Results")
    results_df = pd.DataFrame([{
        "Threat": a["matched_threat_id"],
        "Component": a["component"],
        "Score": f"{a['score']}/{a['max_score']}",
        "Percent": f"{(a['score']/a['max_score']*100):.0f}%"
    } for a in st.session_state.user_answers])
    
    st.dataframe(results_df, hide_index=True)
    
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
    
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    if final_score_pct >= 90:
        st.balloons()
        st.success(f"Excellent! Score: {final_score_pct:.1f}%")
    else:
        st.info(f"Completed! Score: {final_score_pct:.1f}%")
    
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
    
    next_ws = str(int(st.session_state.selected_workshop) + 1)
    
    if next_ws in WORKSHOPS:
        st.info(f"Ready for Workshop {next_ws}?")
        
        if next_ws in st.session_state.unlocked_workshops:
            if st.button(f"Start Workshop {next_ws} ➡️", type="primary"):
                st.session_state.selected_workshop = next_ws
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                st.rerun()
    
    if st.button("🏠 Home"):
        st.session_state.selected_workshop = None
        st.session_state.current_step = 1
        st.rerun()

st.caption("STRIDE Threat Modeling Learning Lab")
