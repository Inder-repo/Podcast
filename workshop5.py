"""
Enhanced STRIDE Threat Modeling Application
AWS Threat Composer Methodology with Progressive Labs
Version 2.0 - Production Ready
"""

import streamlit as st
import base64
import json
import os
import pandas as pd
from graphviz import Digraph, ExecutableNotFound
from datetime import datetime
from io import BytesIO

# =============================================================================
# CONFIGURATION
# =============================================================================

st.set_page_config(
    page_title="STRIDE Threat Modeling - AWS Methodology",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Workshop unlock codes (NOT displayed in UI)
# Keep these for your reference:
# Workshop 2: MICRO2025
# Workshop 3: TENANT2025  
# Workshop 4: HEALTH2025
WORKSHOP_CODES = {
    "1": None,  # Always unlocked
    "2": "MICRO2025",
    "3": "TENANT2025",
    "4": "HEALTH2025"
}

# =============================================================================
# CUSTOM CSS
# =============================================================================

st.markdown("""
<style>
    /* Global styles */
    .stButton>button {
        width: 100%;
        border-radius: 4px;
        font-weight: 500;
    }
    
    /* Risk level cards */
    .threat-critical {
        background-color: #B71C1C;
        color: white;
        padding: 12px;
        border-radius: 4px;
        border-left: 5px solid #D32F2F;
        margin: 8px 0;
    }
    
    .threat-high {
        background-color: #FFE5E5;
        padding: 12px;
        border-radius: 4px;
        border-left: 5px solid #F96167;
        margin: 8px 0;
    }
    
    .threat-medium {
        background-color: #FFF9E5;
        padding: 12px;
        border-radius: 4px;
        border-left: 5px solid #FFC107;
        margin: 8px 0;
    }
    
    .threat-low {
        background-color: #E8F5E9;
        padding: 12px;
        border-radius: 4px;
        border-left: 5px solid #2C5F2D;
        margin: 8px 0;
    }
    
    /* Workshop cards */
    .workshop-card {
        padding: 20px;
        border-radius: 8px;
        border: 2px solid #E0E0E0;
        margin: 12px 0;
        background-color: white;
        transition: all 0.3s;
    }
    
    .workshop-card:hover {
        border-color: #028090;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    
    /* Status badges */
    .badge-completed {
        background-color: #2C5F2D;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: 600;
    }
    
    .badge-locked {
        background-color: #757575;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: 600;
    }
    
    .badge-available {
        background-color: #028090;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: 600;
    }
    
    /* Info boxes */
    .info-box {
        background-color: #E3F2FD;
        padding: 16px;
        border-radius: 4px;
        border-left: 4px solid #1976D2;
        margin: 12px 0;
    }
    
    .warning-box {
        background-color: #FFF3E0;
        padding: 16px;
        border-radius: 4px;
        border-left: 4px solid #F57C00;
        margin: 12px 0;
    }
    
    .success-box {
        background-color: #E8F5E9;
        padding: 16px;
        border-radius: 4px;
        border-left: 4px solid #388E3C;
        margin: 12px 0;
    }
    
    /* Component cards */
    .component-card {
        background-color: #F5F5F5;
        padding: 12px;
        border-radius: 4px;
        border-left: 3px solid #028090;
        margin: 8px 0;
    }
    
    /* STRIDE tags */
    .stride-tag {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.85em;
        font-weight: 600;
        margin: 4px;
        color: white;
    }
    
    .stride-s { background-color: #E53935; }
    .stride-t { background-color: #FB8C00; }
    .stride-r { background-color: #FDD835; color: #333; }
    .stride-i { background-color: #43A047; }
    .stride-d { background-color: #1E88E5; }
    .stride-e { background-color: #8E24AA; }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================

def init_session_state():
    """Initialize all session state variables"""
    defaults = {
        'selected_workshop': None,
        'completed_workshops': set(),
        'unlocked_workshops': set(['1']),  # Workshop 1 always unlocked
        'current_step': 1,
        'threats': [],
        'diagram_generated': None,
        'show_unlock_form': {}
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# =============================================================================
# WORKSHOP CONFIGURATIONS
# =============================================================================

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
            "business_context": "Series A startup, 50K monthly users, $2M annual revenue",
            "assets": [
                "Customer PII (names, addresses, emails)",
                "Payment card data (via Stripe - not stored)",
                "User credentials",
                "Order history",
                "Product inventory"
            ],
            "objectives": [
                "Confidentiality: Protect customer PII",
                "Integrity: Ensure order accuracy",
                "Availability: 99.5% uptime"
            ],
            "compliance": ["PCI-DSS Level 4", "GDPR", "CCPA"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users browsing and purchasing"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA hosted on CloudFront/S3"},
                {"name": "API Backend", "type": "process", "description": "Node.js/Express REST API on ECS"},
                {"name": "Database", "type": "datastore", "description": "Amazon RDS PostgreSQL"},
                {"name": "Stripe", "type": "external_entity", "description": "Payment processing"},
                {"name": "S3 Storage", "type": "datastore", "description": "Product images"},
                {"name": "SendGrid", "type": "external_entity", "description": "Email notifications"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP requests, credentials", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls, user data", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database", "data": "SQL queries, user data", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payment tokens", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "S3 Storage", "data": "Image files", "protocol": "S3 API"},
                {"source": "API Backend", "destination": "SendGrid", "data": "Email content", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Internet Boundary", "description": "Untrusted users → Trusted infrastructure", "components": ["Customer", "Web Frontend"]},
                {"name": "Application Tier", "description": "Frontend → Backend", "components": ["Web Frontend", "API Backend"]},
                {"name": "Data Tier", "description": "Application → Storage", "components": ["API Backend", "Database", "S3 Storage"]},
                {"name": "External Services", "description": "Internal → Third parties", "components": ["API Backend", "Stripe", "SendGrid"]}
            ]
        }
    },
    
    "2": {
        "name": "Workshop 2: Mobile Banking",
        "level": "Intermediate",
        "duration": "2 hours",
        "complexity": "Microservices architecture",
        "target_threats": 25,
        "unlock_requirement": "1",
        "scenario": {
            "title": "CloudBank Mobile Banking",
            "description": "Modern cloud-native banking platform with mobile-first approach",
            "business_context": "Regional bank, 500K customers, $50B assets",
            "assets": [
                "Customer financial data",
                "Transaction history",
                "PII including SSN",
                "OAuth tokens",
                "API keys"
            ],
            "objectives": [
                "Confidentiality: Protect financial data",
                "Integrity: Prevent unauthorized transfers",
                "Availability: 99.95% uptime",
                "Non-repudiation: Complete audit trail"
            ],
            "compliance": ["PCI-DSS", "SOC 2", "GLBA", "Banking regulations"],
            "components": [
                {"name": "Mobile App", "type": "external_entity", "description": "iOS/Android native apps"},
                {"name": "API Gateway", "type": "process", "description": "AWS API Gateway with throttling"},
                {"name": "User Service", "type": "process", "description": "Authentication & profiles (ECS)"},
                {"name": "Account Service", "type": "process", "description": "Balance & transactions (Lambda)"},
                {"name": "Payment Service", "type": "process", "description": "Transfers & bill pay (ECS)"},
                {"name": "Notification Service", "type": "process", "description": "Push/email/SMS (Lambda)"},
                {"name": "Message Queue", "type": "datastore", "description": "Amazon SQS"},
                {"name": "User DB", "type": "datastore", "description": "DynamoDB"},
                {"name": "Transaction DB", "type": "datastore", "description": "Aurora PostgreSQL"},
                {"name": "Cache", "type": "datastore", "description": "ElastiCache Redis"},
                {"name": "Plaid", "type": "external_entity", "description": "Bank account linking"},
                {"name": "Twilio", "type": "external_entity", "description": "SMS service"}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS requests, JWT", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "User Service", "data": "Auth requests", "protocol": "HTTP/2"},
                {"source": "API Gateway", "destination": "Account Service", "data": "Account queries", "protocol": "HTTP/2"},
                {"source": "API Gateway", "destination": "Payment Service", "data": "Payment instructions", "protocol": "HTTP/2"},
                {"source": "Payment Service", "destination": "Transaction DB", "data": "Transaction records", "protocol": "PostgreSQL"},
                {"source": "Payment Service", "destination": "Message Queue", "data": "Event messages", "protocol": "SQS"},
                {"source": "Message Queue", "destination": "Notification Service", "data": "Notification events", "protocol": "SQS"},
                {"source": "User Service", "destination": "User DB", "data": "User data", "protocol": "DynamoDB"},
                {"source": "Account Service", "destination": "Cache", "data": "Cached balances", "protocol": "Redis"},
                {"source": "Account Service", "destination": "Plaid", "data": "Account links", "protocol": "HTTPS"},
                {"source": "Notification Service", "destination": "Twilio", "data": "SMS messages", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Client Boundary", "description": "Mobile → Cloud", "components": ["Mobile App", "API Gateway"]},
                {"name": "Service Mesh", "description": "Microservices inter-communication", "components": ["User Service", "Account Service", "Payment Service", "Notification Service"]},
                {"name": "Data Layer", "description": "Services → Datastores", "components": ["User DB", "Transaction DB", "Cache", "Message Queue"]},
                {"name": "External Integrations", "description": "Platform → Third parties", "components": ["Plaid", "Twilio"]}
            ]
        }
    },
    
    "3": {
        "name": "Workshop 3: Multi-Tenant SaaS",
        "level": "Advanced",
        "duration": "2 hours",
        "complexity": "Cloud-native with data pipeline",
        "target_threats": 30,
        "unlock_requirement": "2",
        "scenario": {
            "title": "DataInsight Analytics Platform",
            "description": "Multi-tenant SaaS for business intelligence",
            "business_context": "B2B SaaS, 500 enterprise customers, 10TB daily",
            "assets": [
                "Customer business data",
                "Tenant metadata",
                "Data pipeline logic",
                "API keys and OAuth tokens",
                "Aggregated analytics"
            ],
            "objectives": [
                "Confidentiality: Complete tenant isolation",
                "Integrity: Accurate analytics",
                "Availability: 99.99% SLA",
                "Privacy: Data residency compliance"
            ],
            "compliance": ["SOC 2 Type II", "ISO 27001", "GDPR", "CCPA"],
            "components": [
                {"name": "Web Dashboard", "type": "external_entity", "description": "React SPA"},
                {"name": "API Gateway", "type": "process", "description": "Kong Gateway"},
                {"name": "Auth Service", "type": "process", "description": "Multi-tenant SSO"},
                {"name": "Ingestion Service", "type": "process", "description": "Data ingestion API"},
                {"name": "Kafka", "type": "datastore", "description": "Amazon MSK streaming"},
                {"name": "Spark Processing", "type": "process", "description": "EMR data transformation"},
                {"name": "Data Lake", "type": "datastore", "description": "S3 raw data"},
                {"name": "Data Warehouse", "type": "datastore", "description": "Redshift with RLS"},
                {"name": "Query Service", "type": "process", "description": "Analytics queries"},
                {"name": "Tenant DB", "type": "datastore", "description": "PostgreSQL with RLS"},
                {"name": "Salesforce", "type": "external_entity", "description": "CRM integration"}
            ],
            "data_flows": [
                {"source": "Web Dashboard", "destination": "API Gateway", "data": "Authenticated requests", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "Auth Service", "data": "JWT validation", "protocol": "HTTP/2"},
                {"source": "Salesforce", "destination": "Ingestion Service", "data": "CRM data", "protocol": "HTTPS"},
                {"source": "Ingestion Service", "destination": "Kafka", "data": "Event streams", "protocol": "Kafka"},
                {"source": "Kafka", "destination": "Spark Processing", "data": "Raw events", "protocol": "Kafka"},
                {"source": "Spark Processing", "destination": "Data Lake", "data": "Processed data", "protocol": "S3"},
                {"source": "Data Lake", "destination": "Data Warehouse", "data": "ETL loads", "protocol": "Redshift"},
                {"source": "Query Service", "destination": "Data Warehouse", "data": "SQL queries", "protocol": "Redshift"},
                {"source": "Query Service", "destination": "Tenant DB", "data": "Metadata", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Tenant A Isolation", "description": "Logical boundary for Tenant A", "components": []},
                {"name": "Tenant B Isolation", "description": "Logical boundary for Tenant B", "components": []},
                {"name": "Pipeline Ingestion", "description": "External → Processing", "components": ["Salesforce", "Ingestion Service", "Kafka"]},
                {"name": "Pipeline Storage", "description": "Processing → Data Lake/Warehouse", "components": ["Spark Processing", "Data Lake", "Data Warehouse"]}
            ]
        }
    },
    
    "4": {
        "name": "Workshop 4: Healthcare IoT",
        "level": "Expert",
        "duration": "2 hours",
        "complexity": "IoT + Legacy + Safety-critical",
        "target_threats": 40,
        "unlock_requirement": "3",
        "scenario": {
            "title": "HealthMonitor Connected Care",
            "description": "Remote patient monitoring with medical IoT devices",
            "business_context": "FDA-registered device, 10K patients, life-critical",
            "assets": [
                "Protected Health Information (PHI)",
                "Real-time vital signs (safety-critical)",
                "Device calibration data",
                "Clinical decision algorithms",
                "Prescription data"
            ],
            "objectives": [
                "Safety: Device data integrity (HIGHEST PRIORITY)",
                "Privacy: Protect PHI per HIPAA",
                "Availability: 99.99% for alerts",
                "Integrity: Prevent Rx tampering",
                "Auditability: Complete audit trail"
            ],
            "compliance": ["HIPAA", "HITECH", "FDA 21 CFR Part 11", "GDPR"],
            "components": [
                {"name": "Glucose Monitor", "type": "external_entity", "description": "CGM IoT device"},
                {"name": "BP Monitor", "type": "external_entity", "description": "Blood pressure cuff"},
                {"name": "IoT Gateway", "type": "process", "description": "Edge device in home"},
                {"name": "Device Mgmt", "type": "process", "description": "Firmware & config"},
                {"name": "Mobile App", "type": "external_entity", "description": "Patient app"},
                {"name": "Web Portal", "type": "external_entity", "description": "Clinician portal"},
                {"name": "API Gateway", "type": "process", "description": "AWS API Gateway"},
                {"name": "Device Data Svc", "type": "process", "description": "Telemetry ingestion"},
                {"name": "Alert Service", "type": "process", "description": "SAFETY-CRITICAL alerts"},
                {"name": "CDS Service", "type": "process", "description": "Clinical Decision Support"},
                {"name": "Prescription Svc", "type": "process", "description": "E-prescribing"},
                {"name": "Kinesis", "type": "datastore", "description": "Real-time streaming"},
                {"name": "Patient DB", "type": "datastore", "description": "Aurora (HIPAA)"},
                {"name": "Telemetry DB", "type": "datastore", "description": "TimescaleDB"},
                {"name": "FHIR Server", "type": "process", "description": "HL7 FHIR API"},
                {"name": "HL7 Interface", "type": "process", "description": "HL7 v2 integration"},
                {"name": "Legacy EHR", "type": "external_entity", "description": "On-prem EHR"},
                {"name": "Pharmacy", "type": "external_entity", "description": "E-prescribing"},
                {"name": "Emergency 911", "type": "external_entity", "description": "911 integration"}
            ],
            "data_flows": [
                {"source": "Glucose Monitor", "destination": "IoT Gateway", "data": "Glucose readings", "protocol": "BLE"},
                {"source": "BP Monitor", "destination": "IoT Gateway", "data": "BP readings", "protocol": "BLE"},
                {"source": "IoT Gateway", "destination": "Device Data Svc", "data": "Vital signs", "protocol": "MQTT/TLS"},
                {"source": "Device Data Svc", "destination": "Kinesis", "data": "Telemetry stream", "protocol": "Kinesis"},
                {"source": "Kinesis", "destination": "Alert Service", "data": "Vitals monitoring", "protocol": "Kinesis"},
                {"source": "Kinesis", "destination": "Telemetry DB", "data": "Historical storage", "protocol": "PostgreSQL"},
                {"source": "Alert Service", "destination": "Web Portal", "data": "Critical alerts", "protocol": "WebSocket"},
                {"source": "Alert Service", "destination": "Emergency 911", "data": "Emergency alerts", "protocol": "HTTPS"},
                {"source": "Device Data Svc", "destination": "CDS Service", "data": "Vitals analysis", "protocol": "HTTP/2"},
                {"source": "CDS Service", "destination": "Prescription Svc", "data": "Rx recommendations", "protocol": "HTTP/2"},
                {"source": "Prescription Svc", "destination": "Pharmacy", "data": "E-prescriptions", "protocol": "HTTPS"},
                {"source": "FHIR Server", "destination": "HL7 Interface", "data": "FHIR → HL7", "protocol": "HTTP"},
                {"source": "HL7 Interface", "destination": "Legacy EHR", "data": "HL7 v2 messages", "protocol": "MLLP"},
                {"source": "Mobile App", "destination": "API Gateway", "data": "Patient queries", "protocol": "HTTPS"},
                {"source": "Web Portal", "destination": "API Gateway", "data": "Clinician queries", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "Patient DB", "data": "PHI queries", "protocol": "PostgreSQL"},
                {"source": "Device Mgmt", "destination": "IoT Gateway", "data": "Firmware updates", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Patient Home", "description": "Physical access risk", "components": ["Glucose Monitor", "BP Monitor", "IoT Gateway"]},
                {"name": "Patient WiFi", "description": "Untrusted network", "components": ["IoT Gateway", "Device Data Svc"]},
                {"name": "Cloud Platform", "description": "Trusted AWS", "components": ["Device Data Svc", "Alert Service", "CDS Service"]},
                {"name": "Safety-Critical", "description": "Alert path", "components": ["Alert Service", "Web Portal", "Emergency 911"]},
                {"name": "Legacy Integration", "description": "Cloud ↔ On-prem", "components": ["HL7 Interface", "Legacy EHR"]},
                {"name": "External Healthcare", "description": "Platform ↔ External", "components": ["Pharmacy", "Emergency 911"]}
            ]
        }
    }
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def is_workshop_unlocked(workshop_id):
    """Check if workshop is unlocked"""
    return workshop_id in st.session_state.unlocked_workshops

def calculate_risk_score(likelihood, impact):
    """Calculate risk level and score"""
    risk_values = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    score = risk_values.get(likelihood, 2) * risk_values.get(impact, 2)
    
    if score >= 9:
        return "Critical", score
    elif score >= 6:
        return "High", score
    elif score >= 3:
        return "Medium", score
    else:
        return "Low", score

def generate_dfd(workshop_config, threats=[]):
    """Generate Data Flow Diagram using Graphviz"""
    try:
        dot = Digraph(comment="Data Flow Diagram", format="png")
        dot.attr(rankdir="TB", size="12,10", fontname="Arial", bgcolor="white", splines="polyline")
        dot.attr("node", fontname="Arial", fontsize="11")
        dot.attr("edge", fontname="Arial", fontsize="9")

        # Style definitions
        styles = {
            "external_entity": {"shape": "oval", "style": "filled", "fillcolor": "lightcoral", "color": "red", "penwidth": "2"},
            "process": {"shape": "box", "style": "filled,rounded", "fillcolor": "lightblue", "color": "blue", "penwidth": "2"},
            "datastore": {"shape": "cylinder", "style": "filled", "fillcolor": "lightgreen", "color": "green", "penwidth": "2"}
        }

        # Collect threat information
        node_threats = {}
        edge_threats = {}
        for threat in threats:
            affected = threat.get("affected_component", "")
            threat_id = threat.get("id", "")
            
            if "→" in affected:
                edge_threats.setdefault(affected, []).append(threat_id)
            else:
                node_threats.setdefault(affected, []).append(threat_id)

        # Add nodes
        components = workshop_config["scenario"]["components"]
        for comp in components:
            name = comp["name"]
            comp_type = comp["type"]
            desc = comp["description"]
            
            threat_label = node_threats.get(name, [])
            threat_str = f"\\nThreats: {', '.join(threat_label)}" if threat_label else ""
            
            label = f"{name}\\n{desc}{threat_str}"
            style = styles.get(comp_type, styles["process"])
            
            # Highlight if threats exist
            if threat_label:
                style = style.copy()
                style["fillcolor"] = "#ffcccc"
            
            dot.node(name, label, **style)

        # Add edges
        flows = workshop_config["scenario"]["data_flows"]
        for flow in flows:
            source = flow["source"]
            dest = flow["destination"]
            data = flow["data"]
            
            edge_key = f"{source} → {dest}"
            threat_label = edge_threats.get(edge_key, [])
            threat_str = f"\\nThreats: {', '.join(threat_label)}" if threat_label else ""
            
            label = f"{data}{threat_str}"
            color = "red" if threat_label else "black"
            penwidth = "2.5" if threat_label else "1.5"
            
            dot.edge(source, dest, label=label, color=color, penwidth=penwidth)

        # Add trust boundaries as subgraphs
        for idx, boundary in enumerate(workshop_config["scenario"]["trust_boundaries"]):
            with dot.subgraph(name=f"cluster_{idx}") as c:
                c.attr(label=boundary["name"], style="dashed", color="purple", 
                       fontsize="12", penwidth="2", bgcolor="#f0f0ff")
                
                for comp_name in boundary.get("components", []):
                    c.node(comp_name)

        # Render diagram
        diagram_path = dot.render("workshop_diagram", format="png", cleanup=True)
        with open(diagram_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    
    except ExecutableNotFound:
        st.error("⚠️ Graphviz not installed. Diagram generation unavailable.")
        return None
    except Exception as e:
        st.error(f"Diagram generation failed: {str(e)}")
        return None

def get_stride_guidance(element_type, stride_category):
    """Provide context-specific STRIDE guidance"""
    guidance_db = {
        ("external_entity", "Spoofing"): {
            "question": "Can this external entity be impersonated?",
            "examples": ["Stolen credentials", "Session hijacking", "Man-in-the-middle"],
            "controls": ["MFA", "Certificate pinning", "Mutual TLS"]
        },
        ("process", "Tampering"): {
            "question": "Can data/code be maliciously modified?",
            "examples": ["Memory corruption", "Config tampering", "Code injection"],
            "controls": ["Input validation", "Integrity checks", "Code signing"]
        },
        ("datastore", "Information Disclosure"): {
            "question": "Can sensitive data be exposed?",
            "examples": ["Unencrypted storage", "Excessive permissions", "SQL injection"],
            "controls": ["Encryption at rest", "Access controls", "Data masking"]
        },
        ("data_flow", "Denial of Service"): {
            "question": "Can this flow be disrupted?",
            "examples": ["Flooding", "Resource exhaustion", "Protocol exploits"],
            "controls": ["Rate limiting", "Load balancing", "Input size limits"]
        }
    }
    
    return guidance_db.get((element_type, stride_category), {
        "question": f"How might {stride_category} affect this {element_type}?",
        "examples": ["Consider attack scenarios"],
        "controls": ["Apply defense in depth"]
    })

def save_progress():
    """Save progress to file"""
    try:
        progress = {
            "completed_workshops": list(st.session_state.completed_workshops),
            "unlocked_workshops": list(st.session_state.unlocked_workshops),
            "selected_workshop": st.session_state.selected_workshop,
            "current_step": st.session_state.current_step,
            "threats": st.session_state.threats
        }
        with open("/tmp/threat_model_progress.json", "w") as f:
            json.dump(progress, f)
    except Exception as e:
        st.warning(f"Could not save progress: {e}")

def load_progress():
    """Load progress from file"""
    try:
        if os.path.exists("/tmp/threat_model_progress.json"):
            with open("/tmp/threat_model_progress.json", "r") as f:
                progress = json.load(f)
                st.session_state.completed_workshops = set(progress.get("completed_workshops", []))
                st.session_state.unlocked_workshops = set(progress.get("unlocked_workshops", ["1"]))
                st.session_state.selected_workshop = progress.get("selected_workshop")
                st.session_state.current_step = progress.get("current_step", 1)
                st.session_state.threats = progress.get("threats", [])
    except Exception as e:
        pass  # Silently fail on first run

load_progress()

def export_threat_report(workshop_config, threats):
    """Generate exportable threat report"""
    df = pd.DataFrame(threats)
    
    col_order = ["id", "stride_category", "affected_component", "description", 
                 "likelihood", "impact", "risk_priority", "risk_score",
                 "mitigation", "controls", "compliance_mapping"]
    
    df = df[[col for col in col_order if col in df.columns]]
    
    summary = f"""# THREAT MODEL REPORT
Workshop: {workshop_config['name']}
Scenario: {workshop_config['scenario']['title']}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## SUMMARY
Total Threats: {len(threats)}
Critical: {len([t for t in threats if t.get('risk_priority') == 'Critical'])}
High: {len([t for t in threats if t.get('risk_priority') == 'High'])}
Medium: {len([t for t in threats if t.get('risk_priority') == 'Medium'])}
Low: {len([t for t in threats if t.get('risk_priority') == 'Low'])}

## COMPLIANCE
{', '.join(workshop_config['scenario']['compliance'])}

## THREATS DETAIL
"""
    
    csv_data = df.to_csv(index=False)
    return summary + "\n" + csv_data

# =============================================================================
# SIDEBAR
# =============================================================================

with st.sidebar:
    st.title("🔒 STRIDE Workshops")
    st.markdown("### Progressive Training")
    
    st.markdown("---")
    
    st.markdown("### Select Workshop")
    
    for ws_id, ws_config in WORKSHOPS.items():
        unlocked = is_workshop_unlocked(ws_id)
        completed = ws_id in st.session_state.completed_workshops
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if st.button(
                f"Workshop {ws_id}",
                key=f"select_ws_{ws_id}",
                disabled=not unlocked,
                use_container_width=True
            ):
                st.session_state.selected_workshop = ws_id
                st.session_state.current_step = 1
                st.session_state.threats = []
                save_progress()
                st.rerun()
        
        with col2:
            if completed:
                st.markdown('<span class="badge-completed">✓</span>', unsafe_allow_html=True)
            elif not unlocked:
                st.markdown('<span class="badge-locked">🔒</span>', unsafe_allow_html=True)
        
        # Show unlock form if workshop is locked
        if not unlocked and ws_id != "1":
            unlock_key = f"unlock_{ws_id}"
            if unlock_key not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[unlock_key] = False
            
            if st.button(f"🔓 Unlock", key=f"show_unlock_{ws_id}", use_container_width=True):
                st.session_state.show_unlock_form[unlock_key] = not st.session_state.show_unlock_form[unlock_key]
                st.rerun()
            
            if st.session_state.show_unlock_form[unlock_key]:
                with st.form(f"unlock_form_{ws_id}"):
                    code = st.text_input("Enter unlock code", type="password", key=f"code_{ws_id}")
                    submitted = st.form_submit_button("Submit")
                    
                    if submitted:
                        if code == WORKSHOP_CODES.get(ws_id):
                            st.session_state.unlocked_workshops.add(ws_id)
                            st.session_state.show_unlock_form[unlock_key] = False
                            save_progress()
                            st.success("✅ Unlocked!")
                            st.rerun()
                        else:
                            st.error("❌ Invalid code")
        
        with st.expander(f"ℹ️ Details"):
            st.caption(f"**Level:** {ws_config['level']}")
            st.caption(f"**Duration:** {ws_config['duration']}")
            st.caption(f"**Target:** {ws_config['target_threats']} threats")
            st.caption(f"**Type:** {ws_config['complexity']}")
            if ws_config['unlock_requirement']:
                st.caption(f"**Requires:** Workshop {ws_config['unlock_requirement']}")
    
    st.markdown("---")
    
    st.markdown("### Your Progress")
    progress_pct = (len(st.session_state.completed_workshops) / len(WORKSHOPS)) * 100
    st.progress(progress_pct / 100)
    st.caption(f"{len(st.session_state.completed_workshops)}/{len(WORKSHOPS)} completed")
    
    st.markdown("---")
    
    with st.expander("📚 STRIDE Reference"):
        st.markdown("""
        **S** - Spoofing: Identity impersonation  
        **T** - Tampering: Data/code modification  
        **R** - Repudiation: Denying actions  
        **I** - Information Disclosure: Data exposure  
        **D** - Denial of Service: Availability attacks  
        **E** - Elevation of Privilege: Unauthorized access
        """)
    
    if st.button("🔄 Reset Progress", type="secondary"):
        if st.button("⚠️ Confirm Reset"):
            st.session_state.completed_workshops = set()
            st.session_state.unlocked_workshops = set(['1'])
            st.session_state.selected_workshop = None
            st.session_state.threats = []
            save_progress()
            st.rerun()

# =============================================================================
# MAIN CONTENT
# =============================================================================

# Welcome screen
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling Workshops")
    st.markdown("### AWS Methodology - Progressive Training")
    
    st.markdown("""
    <div class="info-box">
    <strong>Welcome!</strong> These hands-on workshops teach systematic threat modeling 
    using the STRIDE framework and AWS Threat Composer methodology.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 📊 Learning Path")
    
    cols = st.columns(4)
    for idx, (ws_id, ws_config) in enumerate(WORKSHOPS.items()):
        with cols[idx]:
            unlocked = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            
            if completed:
                badge = "✅ Completed"
                badge_color = "#2C5F2D"
            elif unlocked:
                badge = "🔓 Available"
                badge_color = "#028090"
            else:
                badge = "🔒 Locked"
                badge_color = "#757575"
            
            st.markdown(f"""
            <div class="workshop-card" style="border-color: {badge_color};">
                <h4>Lab {ws_id}</h4>
                <p><strong>{ws_config['scenario']['title']}</strong></p>
                <p style="font-size: 0.9em; color: #666;">{ws_config['level']}</p>
                <p style="font-size: 0.8em; color: #999;">⏱️ {ws_config['duration']}</p>
                <span style="background-color: {badge_color}; color: white; padding: 5px 10px; border-radius: 12px; font-size: 0.8em;">
                    {badge}
                </span>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    st.markdown("""
    ### 🎯 What You'll Learn
    
    - **STRIDE Framework**: Master systematic threat identification
    - **Data Flow Diagrams**: Visualize architecture for security analysis
    - **Risk Assessment**: Prioritize threats by likelihood × impact
    - **AWS Best Practices**: Apply Well-Architected security principles
    - **Compliance Mapping**: Align with PCI-DSS, HIPAA, SOC 2, etc.
    
    ### 📘 How to Use
    
    1. **Select Workshop 1** from sidebar to begin
    2. **Complete each step** in the guided workflow
    3. **Identify threats** using STRIDE methodology
    4. **Assess risk** and plan mitigations
    5. **Export documentation** for your records
    6. **Unlock next workshop** by completing current one
    
    Start with Workshop 1 to build your foundation!
    """)
    
    st.stop()

# =============================================================================
# WORKSHOP CONTENT
# =============================================================================

current_workshop = WORKSHOPS[st.session_state.selected_workshop]

# Header
st.title(current_workshop["name"])
level_colors = {"Foundation": "🟢", "Intermediate": "🟡", "Advanced": "🟠", "Expert": "🔴"}
st.markdown(f"{level_colors[current_workshop['level']]} **{current_workshop['level']}** | {current_workshop['scenario']['title']}")
st.caption(current_workshop['scenario']['description'])

# Progress indicator
st.markdown("### Progress")
step_labels = ["1️⃣ Scope", "2️⃣ Decompose", "3️⃣ Threats", "4️⃣ Assess", "5️⃣ Complete"]
progress_cols = st.columns(len(step_labels))

for idx, label in enumerate(step_labels):
    with progress_cols[idx]:
        if idx + 1 < st.session_state.current_step:
            st.markdown(f"✅ {label}")
        elif idx + 1 == st.session_state.current_step:
            st.markdown(f"**▶️ {label}**")
        else:
            st.markdown(f"⭕ {label}")

st.markdown("---")

# =============================================================================
# STEP 1: SCOPE
# =============================================================================

if st.session_state.current_step == 1:
    st.header("Step 1: Define Scope & Security Objectives")
    
    scenario = current_workshop["scenario"]
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📋 Application Information")
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
        st.markdown(f"""
        <div class="success-box">
        <strong>Workshop Objectives</strong><br><br>
        📊 Identify {current_workshop['target_threats']} threats<br>
        ⏱️ Complete in {current_workshop['duration']}<br>
        📈 {current_workshop['level']} difficulty
        </div>
        """, unsafe_allow_html=True)
        
        if current_workshop['level'] == "Foundation":
            st.info("**Foundation**: Core STRIDE concepts")
        elif current_workshop['level'] == "Intermediate":
            st.warning("**Intermediate**: Microservices & API security")
        elif current_workshop['level'] == "Advanced":
            st.warning("**Advanced**: Multi-tenant isolation")
        else:
            st.error("**Expert**: Safety-critical systems")
    
    st.markdown("---")
    
    # System Components with enhanced visualization
    st.subheader("🏗️ System Architecture")
    
    # Generate mini diagram preview
    with st.spinner("Generating architecture preview..."):
        diagram_b64 = generate_dfd(current_workshop, [])
    
    if diagram_b64:
        st.image(f"data:image/png;base64,{diagram_b64}", 
                 caption="Architecture Overview",
                 use_column_width=True)
    
    # Component details
    st.markdown("### Component Details")
    comp_cols = st.columns(3)
    for idx, comp in enumerate(scenario["components"]):
        with comp_cols[idx % 3]:
            icon = "👤" if comp["type"] == "external_entity" else "⚙️" if comp["type"] == "process" else "💾"
            st.markdown(f"""
            <div class="component-card">
                <strong>{icon} {comp['name']}</strong><br>
                <small>{comp['description']}</small>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    if st.button("Next: Decompose System ➡️", type="primary", use_container_width=True):
        st.session_state.current_step = 2
        save_progress()
        st.rerun()

# =============================================================================
# STEP 2: DECOMPOSE
# =============================================================================

elif st.session_state.current_step == 2:
    st.header("Step 2: Decompose the Application")
    
    scenario = current_workshop["scenario"]
    
    st.markdown("""
    <div class="info-box">
    <strong>Data Flow Diagrams (DFDs)</strong> visualize how data moves through your system.
    Understanding these flows helps identify where threats can occur.
    </div>
    """, unsafe_allow_html=True)
    
    # Generate DFD
    st.subheader("📊 Data Flow Diagram")
    
    with st.spinner("Generating diagram..."):
        diagram_b64 = generate_dfd(current_workshop, st.session_state.threats)
    
    if diagram_b64:
        st.image(f"data:image/png;base64,{diagram_b64}",
                 caption="Data Flow Diagram with Trust Boundaries",
                 use_column_width=True)
        st.session_state.diagram_generated = diagram_b64
    else:
        st.warning("Diagram generation unavailable. Review flows below.")
    
    # Data Flows Table
    st.subheader("📝 Data Flows")
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
    
    # Trust Boundaries
    st.subheader("🔒 Trust Boundaries")
    
    st.markdown("""
    Trust boundaries mark where data crosses between zones with different security levels.
    These are **critical** areas for threat analysis!
    """)
    
    for boundary in scenario["trust_boundaries"]:
        with st.expander(f"🔐 {boundary['name']}", expanded=False):
            st.markdown(f"**Description:** {boundary['description']}")
            if boundary.get("components"):
                st.markdown(f"**Components:** {', '.join(boundary['components'])}")
    
    # Analysis guidance
    with st.expander("💡 Analysis Guidance"):
        if current_workshop['level'] == "Foundation":
            st.markdown("""
            **Foundation Focus:**
            - Identify DFD element types (External Entity, Process, Data Store, Flow)
            - Mark where data crosses trust boundaries
            - Note flows with sensitive data (PII, credentials)
            
            **Key Question:** Where does untrusted data enter?
            """)
        elif current_workshop['level'] == "Intermediate":
            st.markdown("""
            **Microservices Focus:**
            - Service-to-service authentication
            - Container-specific threats
            - API security (OWASP API Top 10)
            - Message queue security
            
            **Key Question:** How is trust established between services?
            """)
        elif current_workshop['level'] == "Advanced":
            st.markdown("""
            **Multi-Tenant Focus:**
            - Tenant isolation boundaries
            - Data pipeline stages
            - Cross-tenant attack vectors
            - Shared resource security
            
            **Key Question:** How can Tenant A access Tenant B's data?
            """)
        else:
            st.markdown("""
            **Safety-Critical Focus:**
            - Mark safety-critical paths (alerts, dosing)
            - IoT device vulnerabilities
            - Legacy integration constraints
            - Attack impact on patient safety
            
            **Key Question:** What failures could cause physical harm?
            """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back", use_container_width=True):
            st.session_state.current_step = 1
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Identify Threats ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()

# =============================================================================
# STEP 3: IDENTIFY THREATS
# =============================================================================

elif st.session_state.current_step == 3:
    st.header("Step 3: Identify Threats Using STRIDE")
    
    scenario = current_workshop["scenario"]
    
    st.info(f"""
    **Target:** Identify at least **{current_workshop['target_threats']} threats** using STRIDE methodology.
    
    For each threat, document: STRIDE category, affected component, description, likelihood, impact, and mitigation.
    """)
    
    # Threat entry form
    with st.form("threat_entry_form"):
        st.subheader("➕ Add New Threat")
        
        col1, col2 = st.columns(2)
        
        with col1:
            stride_category = st.selectbox(
                "STRIDE Category",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"],
                help="Primary threat category"
            )
            
            all_elements = [comp["name"] for comp in scenario["components"]]
            all_flows = [f"{f['source']} → {f['destination']}" for f in scenario["data_flows"]]
            affected_component = st.selectbox(
                "Affected Component/Flow",
                all_elements + all_flows,
                help="DFD element affected by this threat"
            )
            
            likelihood = st.select_slider(
                "Likelihood",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
            
            impact = st.select_slider(
                "Impact",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
        
        with col2:
            element_type = "data_flow" if "→" in affected_component else next(
                (comp["type"] for comp in scenario["components"] if comp["name"] == affected_component),
                "process"
            )
            guidance = get_stride_guidance(element_type, stride_category)
            
            st.markdown(f"**💡 {guidance['question']}**")
            st.markdown("**Examples:**")
            for ex in guidance["examples"]:
                st.caption(f"• {ex}")
            st.markdown("**Typical Controls:**")
            for ctrl in guidance["controls"]:
                st.caption(f"• {ctrl}")
        
        threat_description = st.text_area(
            "Threat Description",
            placeholder="Describe the threat scenario and attack vector...",
            height=100,
            help="Be specific about how the attack could occur"
        )
        
        mitigation = st.text_area(
            "Proposed Mitigation",
            placeholder="Describe security controls...",
            height=80
        )
        
        controls = st.text_input(
            "Specific Controls",
            placeholder="e.g., MFA, AES-256, rate limiting"
        )
        
        compliance_mapping = st.text_input(
            "Compliance Mapping",
            placeholder=f"e.g., {scenario['compliance'][0]} requirement"
        )
        
        submitted = st.form_submit_button("Add Threat", type="primary", use_container_width=True)
        
        if submitted:
            if threat_description and mitigation:
                risk_priority, risk_score = calculate_risk_score(likelihood, impact)
                threat_id = f"T-{len(st.session_state.threats) + 1:03d}"
                
                new_threat = {
                    "id": threat_id,
                    "stride_category": stride_category,
                    "affected_component": affected_component,
                    "description": threat_description,
                    "likelihood": likelihood,
                    "impact": impact,
                    "risk_priority": risk_priority,
                    "risk_score": risk_score,
                    "mitigation": mitigation,
                    "controls": controls,
                    "compliance_mapping": compliance_mapping
                }
                
                st.session_state.threats.append(new_threat)
                save_progress()
                st.success(f"✅ Added {threat_id}: {stride_category}")
                st.rerun()
            else:
                st.error("Please provide description and mitigation")
    
    # Display threats
    st.markdown("---")
    st.subheader(f"Identified Threats ({len(st.session_state.threats)}/{current_workshop['target_threats']})")
    
    if st.session_state.threats:
        stride_groups = {}
        for threat in st.session_state.threats:
            cat = threat["stride_category"]
            if cat not in stride_groups:
                stride_groups[cat] = []
            stride_groups[cat].append(threat)
        
        for category in ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                         "Denial of Service", "Elevation of Privilege"]:
            if category in stride_groups:
                with st.expander(f"**{category}** ({len(stride_groups[category])} threats)", expanded=True):
                    for threat in stride_groups[category]:
                        priority_class = f"threat-{threat['risk_priority'].lower()}"
                        
                        st.markdown(f"""
                        <div class="{priority_class}">
                            <strong>{threat['id']}</strong> - {threat['affected_component']}
                            <span style="float: right; font-weight: bold;">{threat['risk_priority']} Risk</span>
                            <br>{threat['description']}
                            <br><br><strong>Mitigation:</strong> {threat['mitigation']}
                            <br><strong>Controls:</strong> {threat['controls']}
                            <br><strong>Compliance:</strong> {threat['compliance_mapping']}
                        </div>
                        """, unsafe_allow_html=True)
                        
                        if st.button(f"Delete {threat['id']}", key=f"del_{threat['id']}"):
                            st.session_state.threats = [t for t in st.session_state.threats if t['id'] != threat['id']]
                            save_progress()
                            st.rerun()
    else:
        st.info("No threats identified yet. Use the form above.")
    
    progress = len(st.session_state.threats) / current_workshop['target_threats']
    st.progress(min(progress, 1.0))
    
    if len(st.session_state.threats) >= current_workshop['target_threats']:
        st.success(f"✅ Great job! {len(st.session_state.threats)} threats identified.")
    else:
        remaining = current_workshop['target_threats'] - len(st.session_state.threats)
        st.warning(f"⚠️ {remaining} more threats needed.")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back", use_container_width=True):
            st.session_state.current_step = 2
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Assess ➡️", type="primary", use_container_width=True):
            if st.session_state.threats:
                st.session_state.current_step = 4
                save_progress()
                st.rerun()
            else:
                st.error("Add at least one threat")

# =============================================================================
# STEP 4: ASSESS
# =============================================================================

elif st.session_state.current_step == 4:
    st.header("Step 4: Risk Assessment & Mitigation")
    
    if not st.session_state.threats:
        st.warning("No threats. Go back to Step 3.")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
        st.stop()
    
    # Risk distribution
    st.subheader("📊 Risk Distribution")
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in st.session_state.threats:
        risk_counts[t.get("risk_priority", "Low")] += 1
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Critical", risk_counts["Critical"])
    col2.metric("High", risk_counts["High"])
    col3.metric("Medium", risk_counts["Medium"])
    col4.metric("Low", risk_counts["Low"])
    
    # Prioritized threats
    st.subheader("🎯 Prioritized Threats")
    sorted_threats = sorted(st.session_state.threats, key=lambda x: x.get("risk_score", 0), reverse=True)
    
    threat_df = pd.DataFrame([{
        "ID": t["id"],
        "STRIDE": t["stride_category"],
        "Component": t["affected_component"],
        "Risk": t["risk_priority"],
        "Mitigation": t["mitigation"][:50] + "..."
    } for t in sorted_threats])
    
    st.dataframe(threat_df, use_container_width=True, hide_index=True)
    
    # STRIDE distribution
    st.subheader("📈 STRIDE Distribution")
    stride_counts = {}
    for t in st.session_state.threats:
        cat = t["stride_category"]
        stride_counts[cat] = stride_counts.get(cat, 0) + 1
    
    stride_df = pd.DataFrame([{"STRIDE": k, "Count": v} for k, v in stride_counts.items()])
    st.bar_chart(stride_df.set_index("STRIDE"))
    
    # Export
    st.markdown("---")
    st.subheader("📥 Export Threat Model")
    
    report_data = export_threat_report(current_workshop, st.session_state.threats)
    
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 Download CSV Report",
            report_data,
            f"threat_model_{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.csv",
            "text/csv",
            use_container_width=True
        )
    
    with col2:
        if st.session_state.diagram_generated:
            img_data = base64.b64decode(st.session_state.diagram_generated)
            st.download_button(
                "📥 Download DFD",
                img_data,
                f"dfd_{st.session_state.selected_workshop}.png",
                "image/png",
                use_container_width=True
            )
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
    with col2:
        if st.button("Complete ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 5
            save_progress()
            st.rerun()

# =============================================================================
# STEP 5: COMPLETE
# =============================================================================

elif st.session_state.current_step == 5:
    st.header("🎉 Workshop Complete!")
    
    st.success(f"""
    Congratulations! You've completed {current_workshop['name']}
    
    **Achievements:**
    - ✅ Analyzed architecture
    - ✅ Created DFD
    - ✅ Identified {len(st.session_state.threats)} threats
    - ✅ Assessed risk
    - ✅ Generated documentation
    """)
    
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total", len(st.session_state.threats))
    col2.metric("Critical", len([t for t in st.session_state.threats if t.get("risk_priority") == "Critical"]))
    col3.metric("High", len([t for t in st.session_state.threats if t.get("risk_priority") == "High"]))
    col4.metric("Mapped", len([t for t in st.session_state.threats if t.get("compliance_mapping")]))
    
    st.markdown("---")
    st.subheader("Next Steps")
    
    next_workshop = str(int(st.session_state.selected_workshop) + 1)
    
    if next_workshop in WORKSHOPS:
        st.info(f"""
        **Ready for the next challenge?**
        
        Workshop {next_workshop}: {WORKSHOPS[next_workshop]['name']}
        
        Level: {WORKSHOPS[next_workshop]['level']} | {WORKSHOPS[next_workshop]['complexity']}
        """)
        
        if st.button(f"Start Workshop {next_workshop} ➡️", type="primary", use_container_width=True):
            st.session_state.selected_workshop = next_workshop
            st.session_state.current_step = 1
            st.session_state.threats = []
            save_progress()
            st.rerun()
    else:
        st.success("""
        🏆 **You've completed all workshops!**
        
        You're now proficient in STRIDE threat modeling across:
        - Basic web applications
        - Microservices architectures
        - Multi-tenant SaaS platforms
        - Safety-critical IoT systems
        
        Keep practicing on your own projects!
        """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review", use_container_width=True):
            st.session_state.current_step = 4
            save_progress()
            st.rerun()
    with col2:
        if st.button("🏠 Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            save_progress()
            st.rerun()

# Footer
st.markdown("---")
st.caption("STRIDE Threat Modeling | AWS Methodology | OWASP Aligned")
