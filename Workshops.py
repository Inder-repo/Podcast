import streamlit as st
import base64
import json
import re
import os
import pandas as pd
from graphviz import Digraph, ExecutableNotFound
from datetime import datetime
from io import BytesIO
import hashlib

# Streamlit app configuration
st.set_page_config(
    page_title="STRIDE Threat Modeling - Progressive Workshops",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .stButton>button {
        width: 100%;
    }
    .threat-high {
        background-color: #ffcccc;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #cc0000;
    }
    .threat-medium {
        background-color: #fff4cc;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #ff9900;
    }
    .threat-low {
        background-color: #ccffcc;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #00cc00;
    }
    .workshop-card {
        padding: 20px;
        border-radius: 10px;
        border: 2px solid #ddd;
        margin: 10px 0;
    }
    .success-badge {
        background-color: #28a745;
        color: white;
        padding: 5px 10px;
        border-radius: 15px;
        font-size: 0.9em;
    }
    .locked-badge {
        background-color: #6c757d;
        color: white;
        padding: 5px 10px;
        border-radius: 15px;
        font-size: 0.9em;
    }
</style>
""", unsafe_allow_html=True)

# Workshop Configurations
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: E-Commerce Platform (Foundation)",
        "duration": "2 hours",
        "complexity": "Basic 2-tier",
        "scenario": {
            "title": "TechMart Online Store",
            "description": "A startup e-commerce platform selling electronics",
            "assets": ["Customer PII", "Payment card data (via Stripe)", "User credentials", "Order history", "Product inventory"],
            "objectives": ["Confidentiality: Protect customer PII", "Integrity: Ensure order accuracy", "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS Level 4", "GDPR"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users browsing and purchasing"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA"},
                {"name": "API Backend", "type": "process", "description": "Node.js/Express REST API"},
                {"name": "Database", "type": "datastore", "description": "PostgreSQL"},
                {"name": "Stripe", "type": "external_entity", "description": "Payment processing"},
                {"name": "S3 Storage", "type": "datastore", "description": "Product images"},
                {"name": "SendGrid", "type": "external_entity", "description": "Email notifications"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP requests, credentials"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls, user data"},
                {"source": "API Backend", "destination": "Database", "data": "SQL queries, user data, orders"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payment tokens"},
                {"source": "API Backend", "destination": "S3 Storage", "data": "Image files"},
                {"source": "API Backend", "destination": "SendGrid", "data": "Email content"}
            ],
            "trust_boundaries": [
                {"name": "Internet Boundary", "description": "Customer → Web Frontend", "components": ["Customer", "Web Frontend"]},
                {"name": "Application Boundary", "description": "Frontend → Backend", "components": ["Web Frontend", "API Backend"]},
                {"name": "External Services", "description": "Backend → Third Parties", "components": ["API Backend", "Stripe", "S3 Storage", "SendGrid"]}
            ]
        },
        "threat_templates": [
            {
                "stride": "Spoofing",
                "element_type": "data_flow",
                "example": "Session hijacking via XSS allowing attacker to impersonate user",
                "mitigation_example": "HttpOnly cookies, Content Security Policy headers",
                "asvs": "V3.4.1 - Cookie-based session management"
            },
            {
                "stride": "Tampering",
                "element_type": "data_flow",
                "example": "SQL injection allowing modification of order data",
                "mitigation_example": "Parameterized queries, ORM usage",
                "asvs": "V5.3.4 - Database query parameterization"
            }
        ],
        "target_threats": 15,
        "unlock_requirement": None
    },
    "2": {
        "name": "Workshop 2: Mobile Banking Platform (Intermediate)",
        "duration": "2 hours",
        "complexity": "Microservices architecture",
        "scenario": {
            "title": "CloudBank Mobile Banking",
            "description": "Modern microservices-based banking platform",
            "assets": ["Customer financial data", "Transaction history", "PII including SSN", "OAuth tokens", "API keys"],
            "objectives": [
                "Confidentiality: Protect financial data",
                "Integrity: Prevent unauthorized transfers",
                "Availability: 99.95% uptime",
                "Non-repudiation: Audit trail"
            ],
            "compliance": ["PCI-DSS", "SOC 2", "GLBA", "State banking regulations"],
            "components": [
                {"name": "Mobile App", "type": "external_entity", "description": "iOS/Android banking app"},
                {"name": "API Gateway", "type": "process", "description": "AWS API Gateway"},
                {"name": "User Service", "type": "process", "description": "Authentication & profiles"},
                {"name": "Account Service", "type": "process", "description": "Balance & transactions"},
                {"name": "Payment Service", "type": "process", "description": "Transfers & bill pay"},
                {"name": "Notification Service", "type": "process", "description": "Push, email, SMS"},
                {"name": "Message Queue", "type": "datastore", "description": "AWS SQS"},
                {"name": "User DB", "type": "datastore", "description": "DynamoDB"},
                {"name": "Transaction DB", "type": "datastore", "description": "Aurora PostgreSQL"},
                {"name": "Cache", "type": "datastore", "description": "ElastiCache Redis"},
                {"name": "Plaid", "type": "external_entity", "description": "Bank account linking"},
                {"name": "Twilio", "type": "external_entity", "description": "SMS service"}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS requests, JWT tokens"},
                {"source": "API Gateway", "destination": "User Service", "data": "Auth requests"},
                {"source": "API Gateway", "destination": "Account Service", "data": "Account queries"},
                {"source": "API Gateway", "destination": "Payment Service", "data": "Payment instructions"},
                {"source": "Payment Service", "destination": "Transaction DB", "data": "Transaction records"},
                {"source": "Payment Service", "destination": "Message Queue", "data": "Event messages"},
                {"source": "Message Queue", "destination": "Notification Service", "data": "Notification events"},
                {"source": "User Service", "destination": "User DB", "data": "User data"},
                {"source": "Account Service", "destination": "Cache", "data": "Cached balances"},
                {"source": "Account Service", "destination": "Plaid", "data": "Account link requests"},
                {"source": "Notification Service", "destination": "Twilio", "data": "SMS messages"}
            ],
            "trust_boundaries": [
                {"name": "Client Boundary", "description": "Mobile → API Gateway", "components": ["Mobile App", "API Gateway"]},
                {"name": "Service Mesh", "description": "Microservices inter-communication", "components": ["User Service", "Account Service", "Payment Service", "Notification Service"]},
                {"name": "Data Layer", "description": "Services → Data stores", "components": ["User DB", "Transaction DB", "Cache", "Message Queue"]},
                {"name": "External Integrations", "description": "Platform → Third parties", "components": ["Plaid", "Twilio"]}
            ]
        },
        "threat_templates": [
            {
                "stride": "Information Disclosure",
                "element_type": "interaction",
                "example": "BOLA vulnerability allowing User A to access User B's account data",
                "mitigation_example": "Object-level authorization checks, resource-based permissions",
                "owasp_api": "API1:2023 Broken Object Level Authorization"
            },
            {
                "stride": "Tampering",
                "element_type": "container",
                "example": "Container image with vulnerable dependencies",
                "mitigation_example": "ECR image scanning, admission controllers, SBOM",
                "cis_docker": "4.1 - Ensure that a user for the container has been created"
            }
        ],
        "target_threats": 25,
        "unlock_requirement": "1"
    },
    "3": {
        "name": "Workshop 3: Multi-Tenant SaaS Analytics (Advanced)",
        "duration": "2 hours",
        "complexity": "Cloud-native with data pipeline",
        "scenario": {
            "title": "DataInsight Analytics Platform",
            "description": "Multi-tenant SaaS for business intelligence",
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
                {"name": "Web Frontend", "type": "external_entity", "description": "React dashboard"},
                {"name": "API Gateway", "type": "process", "description": "Kong Gateway"},
                {"name": "Auth Service", "type": "process", "description": "Multi-tenant SSO"},
                {"name": "Ingestion Service", "type": "process", "description": "Data ingestion API"},
                {"name": "Kafka", "type": "datastore", "description": "Event streaming"},
                {"name": "Spark", "type": "process", "description": "Data processing"},
                {"name": "Data Lake", "type": "datastore", "description": "S3 raw data"},
                {"name": "Data Warehouse", "type": "datastore", "description": "Redshift"},
                {"name": "Query Service", "type": "process", "description": "Analytics queries"},
                {"name": "Tenant DB", "type": "datastore", "description": "PostgreSQL with RLS"},
                {"name": "Salesforce", "type": "external_entity", "description": "CRM integration"}
            ],
            "data_flows": [
                {"source": "Web Frontend", "destination": "API Gateway", "data": "Authenticated requests"},
                {"source": "API Gateway", "destination": "Auth Service", "data": "JWT validation"},
                {"source": "Salesforce", "destination": "Ingestion Service", "data": "CRM data"},
                {"source": "Ingestion Service", "destination": "Kafka", "data": "Event streams"},
                {"source": "Kafka", "destination": "Spark", "data": "Raw events"},
                {"source": "Spark", "destination": "Data Lake", "data": "Processed data"},
                {"source": "Data Lake", "destination": "Data Warehouse", "data": "ETL loads"},
                {"source": "Query Service", "destination": "Data Warehouse", "data": "SQL queries"},
                {"source": "Query Service", "destination": "Tenant DB", "data": "Metadata queries"}
            ],
            "trust_boundaries": [
                {"name": "Tenant A Isolation", "description": "Logical boundary for Tenant A data", "components": []},
                {"name": "Tenant B Isolation", "description": "Logical boundary for Tenant B data", "components": []},
                {"name": "Pipeline Ingestion", "description": "External data → Processing", "components": ["Salesforce", "Ingestion Service", "Kafka"]},
                {"name": "Pipeline Processing", "description": "Processing → Storage", "components": ["Spark", "Data Lake", "Data Warehouse"]},
                {"name": "Pipeline Query", "description": "Application → Analytics", "components": ["Query Service", "Data Warehouse"]}
            ]
        },
        "threat_templates": [
            {
                "stride": "Information Disclosure",
                "element_type": "multi_tenant",
                "example": "Row-level security bypass allows Tenant A to query Tenant B data",
                "mitigation_example": "RLS enforcement, query rewriting, integration tests with cross-tenant attempts",
                "soc2": "CC6.1 - Logical access controls"
            },
            {
                "stride": "Tampering",
                "element_type": "data_pipeline",
                "example": "Malicious Spark UDF allows code execution and data corruption",
                "mitigation_example": "UDF sandboxing, code review, static analysis",
                "iso27001": "A.14.2.5 - Secure system engineering principles"
            }
        ],
        "target_threats": 30,
        "unlock_requirement": "2"
    },
    "4": {
        "name": "Workshop 4: Healthcare IoT Platform (Expert)",
        "duration": "2 hours",
        "complexity": "IoT + Legacy + Safety-critical",
        "scenario": {
            "title": "HealthMonitor Connected Care",
            "description": "Remote patient monitoring with medical IoT devices",
            "assets": [
                "Protected Health Information (PHI)",
                "Device calibration data (safety-critical)",
                "Clinical decision algorithms",
                "Prescription data",
                "Real-time vital signs"
            ],
            "objectives": [
                "Safety: Ensure device data integrity for clinical decisions",
                "Privacy: Protect PHI per HIPAA",
                "Availability: 99.99% for critical alerts",
                "Integrity: Prevent prescription modifications",
                "Auditability: Complete audit trail"
            ],
            "compliance": ["HIPAA", "HITECH", "FDA 21 CFR Part 11", "GDPR (EU patients)"],
            "components": [
                {"name": "Glucose Monitor", "type": "external_entity", "description": "CGM IoT device"},
                {"name": "Blood Pressure Monitor", "type": "external_entity", "description": "BP IoT device"},
                {"name": "IoT Gateway", "type": "process", "description": "Edge device in patient home"},
                {"name": "Device Management", "type": "process", "description": "Firmware & config"},
                {"name": "Mobile App", "type": "external_entity", "description": "Patient app"},
                {"name": "Web Portal", "type": "external_entity", "description": "Clinician portal"},
                {"name": "API Gateway", "type": "process", "description": "AWS API Gateway"},
                {"name": "Device Data Service", "type": "process", "description": "Telemetry ingestion"},
                {"name": "Alert Service", "type": "process", "description": "Critical value alerts (SAFETY-CRITICAL)"},
                {"name": "CDS Service", "type": "process", "description": "Clinical Decision Support"},
                {"name": "Prescription Service", "type": "process", "description": "E-prescribing"},
                {"name": "Kinesis", "type": "datastore", "description": "Real-time streaming"},
                {"name": "Patient DB", "type": "datastore", "description": "Aurora (HIPAA-compliant)"},
                {"name": "Telemetry DB", "type": "datastore", "description": "TimescaleDB"},
                {"name": "FHIR Server", "type": "process", "description": "FHIR API"},
                {"name": "HL7 Interface", "type": "process", "description": "HL7 v2 integration"},
                {"name": "Legacy EHR", "type": "external_entity", "description": "On-premises EHR (HL7 v2)"},
                {"name": "Pharmacy System", "type": "external_entity", "description": "E-prescribing"},
                {"name": "Emergency Services", "type": "external_entity", "description": "911 integration"}
            ],
            "data_flows": [
                {"source": "Glucose Monitor", "destination": "IoT Gateway", "data": "Glucose readings (BLE)"},
                {"source": "Blood Pressure Monitor", "destination": "IoT Gateway", "data": "BP readings (BLE)"},
                {"source": "IoT Gateway", "destination": "Device Data Service", "data": "Vital signs (MQTT over TLS)"},
                {"source": "Device Data Service", "destination": "Kinesis", "data": "Real-time telemetry stream"},
                {"source": "Kinesis", "destination": "Alert Service", "data": "Vital signs for monitoring"},
                {"source": "Kinesis", "destination": "Telemetry DB", "data": "Historical storage"},
                {"source": "Alert Service", "destination": "Web Portal", "data": "Critical alerts to clinician"},
                {"source": "Alert Service", "destination": "Emergency Services", "data": "Emergency alerts"},
                {"source": "Device Data Service", "destination": "CDS Service", "data": "Vitals for analysis"},
                {"source": "CDS Service", "destination": "Prescription Service", "data": "Treatment recommendations"},
                {"source": "Prescription Service", "destination": "Pharmacy System", "data": "E-prescriptions"},
                {"source": "FHIR Server", "destination": "HL7 Interface", "data": "Patient data (FHIR → HL7)"},
                {"source": "HL7 Interface", "destination": "Legacy EHR", "data": "ADT messages (HL7 v2)"},
                {"source": "Mobile App", "destination": "API Gateway", "data": "Patient queries"},
                {"source": "Web Portal", "destination": "API Gateway", "data": "Clinician queries"},
                {"source": "API Gateway", "destination": "Patient DB", "data": "PHI queries"},
                {"source": "Device Management", "destination": "IoT Gateway", "data": "Firmware updates"}
            ],
            "trust_boundaries": [
                {"name": "Patient Home", "description": "IoT devices → Gateway (physical access risk)", "components": ["Glucose Monitor", "Blood Pressure Monitor", "IoT Gateway"]},
                {"name": "Patient WiFi", "description": "Gateway → Cloud (untrusted network)", "components": ["IoT Gateway", "Device Data Service"]},
                {"name": "Cloud Platform", "description": "Trusted AWS environment", "components": ["Device Data Service", "Alert Service", "CDS Service", "API Gateway"]},
                {"name": "Safety-Critical Path", "description": "Alert generation and delivery", "components": ["Alert Service", "Web Portal", "Emergency Services"]},
                {"name": "Legacy Integration", "description": "Cloud → On-premises EHR (limited security)", "components": ["HL7 Interface", "Legacy EHR"]},
                {"name": "External Healthcare", "description": "Platform → External systems", "components": ["Pharmacy System", "Emergency Services"]}
            ]
        },
        "threat_templates": [
            {
                "stride": "Tampering",
                "element_type": "iot_device",
                "example": "Device firmware tampering leads to false glucose readings causing incorrect insulin dosage",
                "mitigation_example": "Secure boot, firmware signing with PKI, TPM for key storage",
                "safety_impact": "CRITICAL - Patient harm/death",
                "fda": "Premarket Cybersecurity Guidance - Secure boot",
                "hipaa": "N/A (Safety threat)"
            },
            {
                "stride": "Denial of Service",
                "element_type": "safety_critical",
                "example": "Alert suppression attack prevents critical value notification to clinician",
                "mitigation_example": "Redundant alert channels (app + SMS + pager), watchdog timers, fail-safe defaults",
                "safety_impact": "CRITICAL - Missed alert could result in patient death",
                "fda": "Risk management per ISO 14971",
                "hipaa": "164.308(a)(7) - Contingency plan"
            },
            {
                "stride": "Tampering",
                "element_type": "legacy",
                "example": "HL7 message injection creates fake patient record leading to wrong-patient treatment",
                "mitigation_example": "Message validation, network isolation, VPN, application-level integrity checks",
                "safety_impact": "CRITICAL - Wrong patient, wrong treatment",
                "constraint": "Legacy EHR doesn't support modern authentication",
                "hipaa": "164.312(e)(1) - Transmission security"
            }
        ],
        "target_threats": 40,
        "unlock_requirement": "3"
    }
}

# Initialize session state
def init_session_state():
    if 'selected_workshop' not in st.session_state:
        st.session_state.selected_workshop = None
    if 'completed_workshops' not in st.session_state:
        st.session_state.completed_workshops = set()
    if 'current_step' not in st.session_state:
        st.session_state.current_step = 1
    if 'threats' not in st.session_state:
        st.session_state.threats = []
    if 'custom_components' not in st.session_state:
        st.session_state.custom_components = []
    if 'custom_flows' not in st.session_state:
        st.session_state.custom_flows = []
    if 'diagram_generated' not in st.session_state:
        st.session_state.diagram_generated = None
    if 'show_help' not in st.session_state:
        st.session_state.show_help = {}

init_session_state()

# Session persistence
SESSION_FILE = "threat_model_progress.json"

def save_progress():
    """Save user progress across workshops"""
    progress = {
        "completed_workshops": list(st.session_state.completed_workshops),
        "selected_workshop": st.session_state.selected_workshop,
        "current_step": st.session_state.current_step,
        "threats": st.session_state.threats
    }
    with open(SESSION_FILE, "w") as f:
        json.dump(progress, f)

def load_progress():
    """Load user progress"""
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, "r") as f:
            progress = json.load(f)
            st.session_state.completed_workshops = set(progress.get("completed_workshops", []))
            st.session_state.selected_workshop = progress.get("selected_workshop")
            st.session_state.current_step = progress.get("current_step", 1)
            st.session_state.threats = progress.get("threats", [])

load_progress()

def is_workshop_unlocked(workshop_id):
    """Check if a workshop is unlocked based on prerequisites"""
    unlock_req = WORKSHOPS[workshop_id].get("unlock_requirement")
    if unlock_req is None:
        return True
    return unlock_req in st.session_state.completed_workshops

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
            threat_type = threat.get("stride_category", "")
            
            if "→" in affected:
                edge_threats.setdefault(affected, []).append(f"{threat_id}")
            else:
                node_threats.setdefault(affected, []).append(f"{threat_id}")

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
                
                # Add components to boundary if specified
                for comp_name in boundary.get("components", []):
                    c.node(comp_name)

        # Render diagram
        diagram_path = dot.render("workshop_diagram", format="png", cleanup=True)
        with open(diagram_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    
    except ExecutableNotFound:
        st.error("Graphviz not installed. Please install Graphviz to generate diagrams.")
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
            "controls": ["Strong authentication (MFA)", "Certificate pinning", "Mutual TLS"]
        },
        ("process", "Tampering"): {
            "question": "Can data or code in this process be maliciously modified?",
            "examples": ["Memory corruption", "Configuration tampering", "Code injection"],
            "controls": ["Input validation", "Integrity checks", "Code signing"]
        },
        ("datastore", "Information Disclosure"): {
            "question": "Can sensitive data be exposed from this data store?",
            "examples": ["Unencrypted storage", "Excessive permissions", "SQL injection"],
            "controls": ["Encryption at rest", "Access controls", "Data masking"]
        },
        ("data_flow", "Denial of Service"): {
            "question": "Can this data flow be disrupted or overwhelmed?",
            "examples": ["Flooding attacks", "Resource exhaustion", "Protocol exploits"],
            "controls": ["Rate limiting", "Load balancing", "Input size limits"]
        }
    }
    
    return guidance_db.get((element_type, stride_category), {
        "question": f"How might {stride_category} affect this {element_type}?",
        "examples": ["Consider attack scenarios"],
        "controls": ["Apply defense in depth"]
    })

def calculate_risk_score(likelihood, impact):
    """Calculate risk score and priority"""
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

def export_threat_report(workshop_config, threats):
    """Generate exportable threat report"""
    # Create DataFrame
    df = pd.DataFrame(threats)
    
    # Reorder columns
    col_order = ["id", "stride_category", "affected_component", "description", 
                 "likelihood", "impact", "risk_priority", "risk_score",
                 "mitigation", "controls", "compliance_mapping", "status"]
    
    df = df[[col for col in col_order if col in df.columns]]
    
    # Add summary statistics
    summary = f"""
# THREAT MODEL REPORT
Workshop: {workshop_config['name']}
Scenario: {workshop_config['scenario']['title']}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## SUMMARY
Total Threats Identified: {len(threats)}
Critical: {len([t for t in threats if t.get('risk_priority') == 'Critical'])}
High: {len([t for t in threats if t.get('risk_priority') == 'High'])}
Medium: {len([t for t in threats if t.get('risk_priority') == 'Medium'])}
Low: {len([t for t in threats if t.get('risk_priority') == 'Low'])}

## COMPLIANCE
{', '.join(workshop_config['scenario']['compliance'])}

## THREATS DETAIL
"""
    
    csv_data = df.to_csv(index=False)
    return summary + "\\n" + csv_data

# ============================================================================
# SIDEBAR - Workshop Selection
# ============================================================================
with st.sidebar:
    st.title("🔒 STRIDE Workshops")
    st.markdown("### Progressive Threat Modeling Training")
    
    st.markdown("---")
    
    # Workshop selection
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
                st.rerun()
        
        with col2:
            if completed:
                st.markdown('<span class="success-badge">✓</span>', unsafe_allow_html=True)
            elif not unlocked:
                st.markdown('<span class="locked-badge">🔒</span>', unsafe_allow_html=True)
        
        with st.expander(f"ℹ️ {ws_config['complexity']}", expanded=False):
            st.markdown(f"**Duration:** {ws_config['duration']}")
            st.markdown(f"**Target:** {ws_config['target_threats']} threats")
            if ws_config['unlock_requirement']:
                st.markdown(f"**Requires:** Workshop {ws_config['unlock_requirement']}")
    
    st.markdown("---")
    
    # Progress summary
    st.markdown("### Your Progress")
    progress_pct = (len(st.session_state.completed_workshops) / len(WORKSHOPS)) * 100
    st.progress(progress_pct / 100)
    st.markdown(f"{len(st.session_state.completed_workshops)}/{len(WORKSHOPS)} workshops completed")
    
    st.markdown("---")
    
    # Quick reference
    with st.expander("📚 STRIDE Quick Reference"):
        st.markdown("""
        **S - Spoofing**: Impersonation
        **T - Tampering**: Modification
        **R - Repudiation**: Deny actions
        **I - Information Disclosure**: Data exposure
        **D - Denial of Service**: Availability
        **E - Elevation of Privilege**: Unauthorized access
        """)
    
    # Reset progress
    if st.button("🔄 Reset All Progress", type="secondary"):
        st.session_state.completed_workshops = set()
        st.session_state.selected_workshop = None
        st.session_state.threats = []
        save_progress()
        st.rerun()

# ============================================================================
# MAIN CONTENT
# ============================================================================

# Welcome screen if no workshop selected
if not st.session_state.selected_workshop:
    st.title("🎓 Progressive STRIDE Threat Modeling Workshops")
    
    st.markdown("""
    Welcome to the comprehensive threat modeling training program. These workshops will guide you 
    through increasingly complex systems, teaching you to identify and mitigate security threats 
    using the STRIDE methodology.
    
    ### Learning Path
    """)
    
    cols = st.columns(4)
    for idx, (ws_id, ws_config) in enumerate(WORKSHOPS.items()):
        with cols[idx]:
            unlocked = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            
            card_class = "workshop-card"
            if completed:
                badge = "✅ Completed"
                badge_color = "#28a745"
            elif unlocked:
                badge = "🔓 Available"
                badge_color = "#007bff"
            else:
                badge = "🔒 Locked"
                badge_color = "#6c757d"
            
            st.markdown(f"""
            <div class="{card_class}" style="border-color: {badge_color};">
                <h4>Workshop {ws_id}</h4>
                <p><strong>{ws_config['scenario']['title']}</strong></p>
                <p style="font-size: 0.9em;">{ws_config['complexity']}</p>
                <p style="font-size: 0.8em; color: #666;">{ws_config['duration']}</p>
                <span style="background-color: {badge_color}; color: white; padding: 5px 10px; border-radius: 15px; font-size: 0.8em;">
                    {badge}
                </span>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    st.markdown("""
    ### How to Use This Tool
    
    1. **Select a Workshop** from the sidebar
    2. **Define Scope** - Understand the system and security objectives
    3. **Decompose Architecture** - Explore the Data Flow Diagram
    4. **Identify Threats** - Apply STRIDE methodology systematically
    5. **Assess Risk** - Prioritize threats by likelihood and impact
    6. **Plan Mitigations** - Map controls to compliance frameworks
    7. **Export Report** - Generate audit-ready documentation
    
    Start with Workshop 1 to build your foundation!
    """)
    
    st.stop()

# ============================================================================
# WORKSHOP CONTENT
# ============================================================================

current_workshop = WORKSHOPS[st.session_state.selected_workshop]

# Workshop header
st.title(current_workshop["name"])
st.markdown(f"**{current_workshop['scenario']['title']}** - {current_workshop['scenario']['description']}")

# Progress indicator
step_labels = ["Define Scope", "Decompose System", "Identify Threats", "Assess & Mitigate", "Complete"]
progress_cols = st.columns(len(step_labels))
for idx, label in enumerate(step_labels):
    with progress_cols[idx]:
        if idx + 1 < st.session_state.current_step:
            st.markdown(f"✅ **{label}**")
        elif idx + 1 == st.session_state.current_step:
            st.markdown(f"▶️ **{label}**")
        else:
            st.markdown(f"⭕ {label}")

st.markdown("---")

# ============================================================================
# STEP 1: Define Scope and Objectives
# ============================================================================
if st.session_state.current_step == 1:
    st.header("Step 1: Define Scope and Objectives")
    
    scenario = current_workshop["scenario"]
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("System Overview")
        st.markdown(f"**Description:** {scenario['description']}")
        
        st.markdown("### Critical Assets")
        for asset in scenario["assets"]:
            st.markdown(f"- {asset}")
        
        st.markdown("### Security Objectives")
        for obj in scenario["objectives"]:
            st.markdown(f"- {obj}")
        
        st.markdown("### Compliance Requirements")
        for comp in scenario["compliance"]:
            st.markdown(f"- {comp}")
    
    with col2:
        st.info("""
        **Workshop Objectives:**
        
        📊 Create Data Flow Diagrams
        
        🎯 Identify {target} threats
        
        ⚖️ Assess risk levels
        
        🛡️ Plan mitigations
        
        📄 Generate documentation
        """.format(target=current_workshop["target_threats"]))
        
        # Workshop-specific guidance
        if st.session_state.selected_workshop == "1":
            st.success("**Foundation Workshop**: Focus on basic STRIDE-per-Element analysis")
        elif st.session_state.selected_workshop == "2":
            st.warning("**Intermediate**: Analyze microservices interactions and API security")
        elif st.session_state.selected_workshop == "3":
            st.warning("**Advanced**: Master multi-tenant isolation and data pipeline threats")
        elif st.session_state.selected_workshop == "4":
            st.error("**Expert**: Safety-critical systems, IoT, and legacy integration")
    
    st.markdown("---")
    
    # Architecture components preview
    st.subheader("System Components")
    comp_cols = st.columns(3)
    components = scenario["components"]
    for idx, comp in enumerate(components):
        with comp_cols[idx % 3]:
            icon = "👤" if comp["type"] == "external_entity" else "⚙️" if comp["type"] == "process" else "💾"
            st.markdown(f"{icon} **{comp['name']}**")
            st.caption(comp['description'])
    
    st.markdown("---")
    
    if st.button("Next: Decompose System ➡️", type="primary", use_container_width=True):
        st.session_state.current_step = 2
        st.rerun()

# ============================================================================
# STEP 2: Decompose the System (View DFD)
# ============================================================================
elif st.session_state.current_step == 2:
    st.header("Step 2: Decompose the Application")
    
    scenario = current_workshop["scenario"]
    
    # Generate and display DFD
    st.subheader("Data Flow Diagram")
    
    with st.spinner("Generating diagram..."):
        diagram_b64 = generate_dfd(current_workshop, st.session_state.threats)
    
    if diagram_b64:
        st.image(f"data:image/png;base64,{diagram_b64}", 
                 caption="Data Flow Diagram with Trust Boundaries",
                 use_column_width=True)
        st.session_state.diagram_generated = diagram_b64
    else:
        st.warning("Diagram generation failed. Review components and flows below.")
    
    # Data flows table
    st.subheader("Data Flows")
    flows_data = []
    for flow in scenario["data_flows"]:
        flows_data.append({
            "Source": flow["source"],
            "→": "→",
            "Destination": flow["destination"],
            "Data": flow["data"]
        })
    st.dataframe(pd.DataFrame(flows_data), use_container_width=True, hide_index=True)
    
    # Trust boundaries
    st.subheader("Trust Boundaries")
    for boundary in scenario["trust_boundaries"]:
        with st.expander(f"🔒 {boundary['name']}", expanded=False):
            st.markdown(f"**Description:** {boundary['description']}")
            if boundary.get("components"):
                st.markdown(f"**Components:** {', '.join(boundary['components'])}")
    
    # Workshop-specific guidance
    with st.expander("💡 Analysis Guidance"):
        if st.session_state.selected_workshop == "1":
            st.markdown("""
            **Foundation Focus:**
            - Identify each DFD element type (External Entity, Process, Data Store, Data Flow)
            - Mark where data crosses trust boundaries
            - Note which data flows contain sensitive information (PII, credentials)
            
            **Key Question:** Where does untrusted data enter the system?
            """)
        elif st.session_state.selected_workshop == "2":
            st.markdown("""
            **Microservices Focus:**
            - Analyze service-to-service authentication
            - Identify container-specific threats
            - Consider API security (OWASP API Top 10)
            - Review message queue security
            
            **Key Question:** How is trust established between microservices?
            """)
        elif st.session_state.selected_workshop == "3":
            st.markdown("""
            **Multi-Tenant Focus:**
            - Identify tenant isolation boundaries
            - Trace data pipeline stages
            - Analyze cross-tenant attack vectors
            - Review shared resource security
            
            **Key Question:** How can Tenant A access Tenant B's data?
            """)
        elif st.session_state.selected_workshop == "4":
            st.markdown("""
            **Safety-Critical Focus:**
            - Mark safety-critical data paths (alerts, dosing)
            - Identify IoT device vulnerabilities
            - Review legacy integration constraints
            - Consider attack impact on patient safety
            
            **Key Question:** What security failures could harm patients?
            """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Scope", use_container_width=True):
            st.session_state.current_step = 1
            st.rerun()
    with col2:
        if st.button("Next: Identify Threats ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 3
            st.rerun()

# ============================================================================
# STEP 3: Identify Threats (STRIDE Analysis)
# ============================================================================
elif st.session_state.current_step == 3:
    st.header("Step 3: Identify Threats Using STRIDE")
    
    scenario = current_workshop["scenario"]
    
    # Instructions
    st.info(f"""
    **Target:** Identify at least **{current_workshop['target_threats']} threats** using STRIDE methodology.
    
    For each threat, document:
    - STRIDE category
    - Affected component
    - Description and attack scenario
    - Likelihood and Impact
    - Proposed mitigation
    """)
    
    # Threat entry form
    with st.form("threat_entry_form"):
        st.subheader("Add New Threat")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # STRIDE category
            stride_category = st.selectbox(
                "STRIDE Category",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", 
                 "Denial of Service", "Elevation of Privilege"],
                help="Select the primary threat category"
            )
            
            # Affected component
            all_elements = [comp["name"] for comp in scenario["components"]]
            all_flows = [f"{f['source']} → {f['destination']}" for f in scenario["data_flows"]]
            affected_component = st.selectbox(
                "Affected Component/Flow",
                all_elements + all_flows,
                help="Select the DFD element affected by this threat"
            )
            
            # Likelihood
            likelihood = st.select_slider(
                "Likelihood",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
            
            # Impact
            impact = st.select_slider(
                "Impact",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
        
        with col2:
            # Get context-sensitive guidance
            element_type = "data_flow" if "→" in affected_component else next(
                (comp["type"] for comp in scenario["components"] if comp["name"] == affected_component),
                "process"
            )
            guidance = get_stride_guidance(element_type, stride_category)
            
            st.markdown(f"**💡 Guidance: {guidance['question']}**")
            st.markdown("**Examples:**")
            for ex in guidance["examples"]:
                st.markdown(f"- {ex}")
            st.markdown("**Typical Controls:**")
            for ctrl in guidance["controls"]:
                st.markdown(f"- {ctrl}")
        
        # Threat description
        threat_description = st.text_area(
            "Threat Description",
            placeholder="Describe the threat scenario and attack vector...",
            height=100,
            help="Be specific about how the attack could occur"
        )
        
        # Mitigation
        mitigation = st.text_area(
            "Proposed Mitigation",
            placeholder="Describe security controls to address this threat...",
            height=80
        )
        
        # Specific controls
        controls = st.text_input(
            "Specific Controls",
            placeholder="e.g., MFA, AES-256 encryption, rate limiting",
            help="List specific technical controls"
        )
        
        # Compliance mapping
        compliance_frameworks = scenario["compliance"]
        compliance_mapping = st.text_input(
            "Compliance Mapping",
            placeholder=f"e.g., {compliance_frameworks[0] if compliance_frameworks else 'OWASP ASVS'} requirement",
            help="Map to relevant compliance requirements"
        )
        
        # Workshop-specific fields
        if st.session_state.selected_workshop == "4":
            safety_impact = st.select_slider(
                "Safety Impact (Healthcare)",
                options=["None", "Low", "Medium", "High", "Critical - Patient Harm"],
                value="None",
                help="Impact on patient safety"
            )
        
        # Submit button
        submitted = st.form_submit_button("Add Threat", type="primary", use_container_width=True)
        
        if submitted:
            if threat_description and mitigation:
                # Calculate risk
                risk_priority, risk_score = calculate_risk_score(likelihood, impact)
                
                # Generate threat ID
                threat_id = f"T-{len(st.session_state.threats) + 1:03d}"
                
                # Create threat object
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
                    "compliance_mapping": compliance_mapping,
                    "status": "Open"
                }
                
                # Add workshop-specific fields
                if st.session_state.selected_workshop == "4":
                    new_threat["safety_impact"] = safety_impact
                
                st.session_state.threats.append(new_threat)
                save_progress()
                st.success(f"✅ Added threat {threat_id}: {stride_category}")
                st.rerun()
            else:
                st.error("Please provide both threat description and mitigation")
    
    # Display existing threats
    st.markdown("---")
    st.subheader(f"Identified Threats ({len(st.session_state.threats)}/{current_workshop['target_threats']})")
    
    if st.session_state.threats:
        # Group by STRIDE category
        stride_groups = {}
        for threat in st.session_state.threats:
            cat = threat["stride_category"]
            if cat not in stride_groups:
                stride_groups[cat] = []
            stride_groups[cat].append(threat)
        
        # Display by category
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
                            <br>
                            {threat['description']}
                            <br><br>
                            <strong>Mitigation:</strong> {threat['mitigation']}
                            <br>
                            <strong>Controls:</strong> {threat['controls']}
                            <br>
                            <strong>Compliance:</strong> {threat['compliance_mapping']}
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Delete button
                        if st.button(f"Delete {threat['id']}", key=f"del_{threat['id']}"):
                            st.session_state.threats = [t for t in st.session_state.threats if t['id'] != threat['id']]
                            save_progress()
                            st.rerun()
    else:
        st.info("No threats identified yet. Use the form above to add threats.")
    
    # Progress check
    progress = len(st.session_state.threats) / current_workshop['target_threats']
    st.progress(min(progress, 1.0))
    
    if len(st.session_state.threats) >= current_workshop['target_threats']:
        st.success(f"✅ Great job! You've identified {len(st.session_state.threats)} threats. Ready to assess and mitigate.")
    else:
        remaining = current_workshop['target_threats'] - len(st.session_state.threats)
        st.warning(f"⚠️ {remaining} more threats needed to meet the workshop target.")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to DFD", use_container_width=True):
            st.session_state.current_step = 2
            st.rerun()
    with col2:
        if st.button("Next: Assess & Mitigate ➡️", type="primary", use_container_width=True):
            if len(st.session_state.threats) > 0:
                st.session_state.current_step = 4
                st.rerun()
            else:
                st.error("Please identify at least one threat before proceeding")

# ============================================================================
# STEP 4: Assess Risk and Plan Mitigations
# ============================================================================
elif st.session_state.current_step == 4:
    st.header("Step 4: Risk Assessment and Mitigation Planning")
    
    if not st.session_state.threats:
        st.warning("No threats to assess. Go back to Step 3 to identify threats.")
        if st.button("⬅️ Back to Threat Identification"):
            st.session_state.current_step = 3
            st.rerun()
        st.stop()
    
    # Risk matrix visualization
    st.subheader("Risk Matrix")
    
    risk_matrix_data = {"Critical": [0, 0, 0, 0], "High": [0, 0, 0, 0], 
                        "Medium": [0, 0, 0, 0], "Low": [0, 0, 0, 0]}
    likelihood_order = ["Low", "Medium", "High", "Critical"]
    
    for threat in st.session_state.threats:
        lik = threat.get("likelihood", "Medium")
        imp = threat.get("impact", "Medium")
        if lik in likelihood_order and imp in likelihood_order:
            risk_matrix_data[imp][likelihood_order.index(lik)] += 1
    
    matrix_df = pd.DataFrame(risk_matrix_data, index=likelihood_order)
    matrix_df.index.name = "Likelihood →"
    matrix_df.columns.name = "↓ Impact"
    
    st.dataframe(matrix_df, use_container_width=True)
    
    # Threat prioritization
    st.subheader("Prioritized Threats")
    
    # Sort threats by risk score
    sorted_threats = sorted(st.session_state.threats, 
                           key=lambda x: x.get("risk_score", 0), 
                           reverse=True)
    
    # Create DataFrame for display
    threat_df = pd.DataFrame([
        {
            "ID": t["id"],
            "STRIDE": t["stride_category"],
            "Component": t["affected_component"],
            "Description": t["description"][:60] + "..." if len(t["description"]) > 60 else t["description"],
            "Likelihood": t["likelihood"],
            "Impact": t["impact"],
            "Risk": t["risk_priority"],
            "Mitigation": t["mitigation"][:50] + "..." if len(t.get("mitigation", "")) > 50 else t.get("mitigation", "")
        }
        for t in sorted_threats
    ])
    
    # Style the dataframe
    def highlight_risk(row):
        if row["Risk"] == "Critical":
            return ["background-color: #cc0000; color: white"] * len(row)
        elif row["Risk"] == "High":
            return ["background-color: #ffcccc"] * len(row)
        elif row["Risk"] == "Medium":
            return ["background-color: #fff4cc"] * len(row)
        else:
            return ["background-color: #ccffcc"] * len(row)
    
    styled_df = threat_df.style.apply(highlight_risk, axis=1)
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
    
    # Summary statistics
    st.subheader("Threat Summary by STRIDE")
    
    stride_counts = {}
    for threat in st.session_state.threats:
        cat = threat["stride_category"]
        stride_counts[cat] = stride_counts.get(cat, 0) + 1
    
    stride_df = pd.DataFrame([
        {"STRIDE Category": cat, "Count": count}
        for cat, count in stride_counts.items()
    ])
    st.bar_chart(stride_df.set_index("STRIDE Category"))
    
    # Mitigation roadmap
    st.subheader("Mitigation Roadmap")
    
    critical_threats = [t for t in sorted_threats if t.get("risk_priority") == "Critical"]
    high_threats = [t for t in sorted_threats if t.get("risk_priority") == "High"]
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Immediate Action (Critical)")
        if critical_threats:
            for threat in critical_threats:
                st.markdown(f"""
                **{threat['id']}**: {threat['stride_category']}
                - Component: {threat['affected_component']}
                - Mitigation: {threat['mitigation']}
                - Controls: {threat['controls']}
                """)
        else:
            st.success("No critical threats identified")
    
    with col2:
        st.markdown("### Current Sprint/Release (High)")
        if high_threats:
            for threat in high_threats[:5]:  # Top 5
                st.markdown(f"""
                **{threat['id']}**: {threat['stride_category']}
                - Component: {threat['affected_component']}
                - Mitigation: {threat['mitigation']}
                """)
        else:
            st.success("No high-priority threats identified")
    
    # Export report
    st.markdown("---")
    st.subheader("Export Threat Model Report")
    
    report_data = export_threat_report(current_workshop, st.session_state.threats)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.download_button(
            label="📥 Download CSV Report",
            data=report_data,
            file_name=f"threat_model_workshop_{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    with col2:
        if st.session_state.diagram_generated:
            img_data = base64.b64decode(st.session_state.diagram_generated)
            st.download_button(
                label="📥 Download DFD Image",
                data=img_data,
                file_name=f"dfd_workshop_{st.session_state.selected_workshop}.png",
                mime="image/png",
                use_container_width=True
            )
    
    with col3:
        # Generate PDF would require reportlab
        st.button(
            label="📄 Generate PDF (Coming Soon)",
            disabled=True,
            use_container_width=True
        )
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Threats", use_container_width=True):
            st.session_state.current_step = 3
            st.rerun()
    with col2:
        if st.button("Complete Workshop ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 5
            st.rerun()

# ============================================================================
# STEP 5: Workshop Complete
# ============================================================================
elif st.session_state.current_step == 5:
    st.header("🎉 Workshop Complete!")
    
    st.success(f"""
    Congratulations! You've completed {current_workshop['name']}
    
    **Achievements:**
    - ✅ Analyzed system architecture
    - ✅ Created Data Flow Diagram
    - ✅ Identified {len(st.session_state.threats)} threats
    - ✅ Assessed risk and prioritized mitigations
    - ✅ Generated documentation
    """)
    
    # Mark workshop as completed
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()
    
    # Final statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Threats", len(st.session_state.threats))
    with col2:
        critical_count = len([t for t in st.session_state.threats if t.get("risk_priority") == "Critical"])
        st.metric("Critical Risks", critical_count)
    with col3:
        high_count = len([t for t in st.session_state.threats if t.get("risk_priority") == "High"])
        st.metric("High Risks", high_count)
    with col4:
        compliance_mapped = len([t for t in st.session_state.threats if t.get("compliance_mapping")])
        st.metric("Compliance Mapped", compliance_mapped)
    
    # Next steps
    st.markdown("---")
    st.subheader("Next Steps")
    
    next_workshop = str(int(st.session_state.selected_workshop) + 1)
    
    if next_workshop in WORKSHOPS:
        st.info(f"""
        **Ready for the next challenge?**
        
        Unlock Workshop {next_workshop}: {WORKSHOPS[next_workshop]['name']}
        
        This workshop introduces: {WORKSHOPS[next_workshop]['complexity']}
        """)
        
        if st.button(f"Start Workshop {next_workshop} ➡️", type="primary", use_container_width=True):
            st.session_state.selected_workshop = next_workshop
            st.session_state.current_step = 1
            st.session_state.threats = []
            st.rerun()
    else:
        st.success("""
        🏆 **You've completed all workshops!**
        
        You are now proficient in STRIDE threat modeling across various architectures:
        - Basic web applications
        - Microservices and containers
        - Multi-tenant SaaS platforms
        - Safety-critical IoT systems
        
        Continue practicing on your own projects and remember:
        **Threat modeling is a continuous process, not a one-time activity!**
        """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review Threats", use_container_width=True):
            st.session_state.current_step = 4
            st.rerun()
    with col2:
        if st.button("🏠 Return to Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            st.rerun()

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; font-size: 0.9em;">
    <p>STRIDE Threat Modeling Progressive Workshops | Aligned with OWASP, AWS Security, and Industry Best Practices</p>
    <p>Based on <a href="https://catalog.workshops.aws/threatmodel/" target="_blank">AWS Threat Modeling Workshop</a></p>
</div>
""", unsafe_allow_html=True)
