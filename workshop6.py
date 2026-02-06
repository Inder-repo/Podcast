"""
Enhanced STRIDE Threat Modeling Application v3.0
AWS Threat Composer Methodology with Learning Validation
Features: High-level vs Detailed Architecture, Threat Validation, Scoring System
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
    page_title="STRIDE Threat Modeling - Learning Edition",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Workshop unlock codes (NOT displayed in UI)
WORKSHOP_CODES = {
    "1": None,
    "2": "MICRO2025",
    "3": "TENANT2025",
    "4": "HEALTH2025"
}

# =============================================================================
# CUSTOM CSS
# =============================================================================

st.markdown("""
<style>
    .stButton>button { width: 100%; border-radius: 4px; font-weight: 500; }
    
    /* Risk levels */
    .threat-critical { background-color: #B71C1C; color: white; padding: 12px; border-radius: 4px; border-left: 5px solid #D32F2F; margin: 8px 0; }
    .threat-high { background-color: #FFE5E5; padding: 12px; border-radius: 4px; border-left: 5px solid #F96167; margin: 8px 0; }
    .threat-medium { background-color: #FFF9E5; padding: 12px; border-radius: 4px; border-left: 5px solid #FFC107; margin: 8px 0; }
    .threat-low { background-color: #E8F5E9; padding: 12px; border-radius: 4px; border-left: 5px solid #2C5F2D; margin: 8px 0; }
    
    /* Validation feedback */
    .correct-answer { background-color: #C8E6C9; padding: 12px; border-radius: 4px; border-left: 5px solid #4CAF50; margin: 8px 0; }
    .incorrect-answer { background-color: #FFCDD2; padding: 12px; border-radius: 4px; border-left: 5px solid #F44336; margin: 8px 0; }
    .partial-answer { background-color: #FFF9C4; padding: 12px; border-radius: 4px; border-left: 5px solid #FFC107; margin: 8px 0; }
    
    /* Score display */
    .score-excellent { background-color: #4CAF50; color: white; padding: 16px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; }
    .score-good { background-color: #8BC34A; color: white; padding: 16px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; }
    .score-fair { background-color: #FFC107; color: white; padding: 16px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; }
    .score-poor { background-color: #FF5722; color: white; padding: 16px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; }
    
    /* Badges */
    .badge-completed { background-color: #2C5F2D; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
    .badge-locked { background-color: #757575; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
    .badge-available { background-color: #028090; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
    
    /* Info boxes */
    .info-box { background-color: #E3F2FD; padding: 16px; border-radius: 4px; border-left: 4px solid #1976D2; margin: 12px 0; }
    .warning-box { background-color: #FFF3E0; padding: 16px; border-radius: 4px; border-left: 4px solid #F57C00; margin: 12px 0; }
    .success-box { background-color: #E8F5E9; padding: 16px; border-radius: 4px; border-left: 4px solid #388E3C; margin: 12px 0; }
    
    /* Component cards */
    .component-card { background-color: #F5F5F5; padding: 12px; border-radius: 4px; border-left: 3px solid #028090; margin: 8px 0; }
    
    /* Workshop cards */
    .workshop-card { padding: 20px; border-radius: 8px; border: 2px solid #E0E0E0; margin: 12px 0; background-color: white; transition: all 0.3s; }
    .workshop-card:hover { border-color: #028090; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# SESSION STATE
# =============================================================================

def init_session_state():
    defaults = {
        'selected_workshop': None,
        'completed_workshops': set(),
        'unlocked_workshops': set(['1']),
        'current_step': 1,
        'threats': [],
        'user_answers': [],
        'total_score': 0,
        'max_score': 0,
        'diagram_generated': None,
        'show_unlock_form': {},
        'show_feedback': {}
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# =============================================================================
# PRE-DEFINED THREATS DATABASE WITH SCORING
# =============================================================================

PREDEFINED_THREATS = {
    "1": [  # Workshop 1: E-Commerce
        {
            "id": "T-001",
            "stride": "Spoofing",
            "component": "Web Frontend → API Backend",
            "threat": "Session hijacking via XSS allowing attacker to impersonate legitimate user",
            "likelihood": "Medium",
            "impact": "High",
            "correct_mitigations": [
                "HttpOnly and Secure flags on cookies",
                "Content Security Policy (CSP) headers",
                "Input sanitization with DOMPurify",
                "XSS prevention through output encoding"
            ],
            "incorrect_mitigations": [
                "Increase password complexity",  # Wrong - doesn't prevent XSS
                "Add rate limiting",  # Wrong - doesn't prevent XSS
                "Enable 2FA"  # Wrong - session already hijacked
            ],
            "explanation": "XSS attacks allow stealing session cookies. HttpOnly prevents JavaScript access to cookies, CSP restricts script sources, and input sanitization prevents malicious script injection.",
            "compliance": "OWASP Top 10 A03:2021 (Injection), OWASP ASVS V5.3.3",
            "points": 10
        },
        {
            "id": "T-002",
            "stride": "Tampering",
            "component": "API Backend → Database",
            "threat": "SQL injection allowing modification of product prices or customer data",
            "likelihood": "Medium",
            "impact": "Critical",
            "correct_mitigations": [
                "Parameterized queries / Prepared statements",
                "Use ORM (Sequelize, TypeORM)",
                "Input validation with allowlisting",
                "Least privilege database user"
            ],
            "incorrect_mitigations": [
                "Encrypt database connections",  # Wrong - doesn't prevent SQL injection
                "Add logging",  # Wrong - doesn't prevent, only detects
                "Use strong passwords"  # Wrong - doesn't prevent SQL injection
            ],
            "explanation": "SQL injection exploits unsanitized user input. Parameterized queries separate data from SQL commands, preventing injection attacks.",
            "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1, CWE-89",
            "points": 10
        },
        {
            "id": "T-003",
            "stride": "Information Disclosure",
            "component": "Database",
            "threat": "Unencrypted customer PII in database exposed through backup theft or breach",
            "likelihood": "Low",
            "impact": "Critical",
            "correct_mitigations": [
                "Encryption at rest (AES-256)",
                "AWS RDS encryption enabled",
                "Encrypt database backups",
                "Key management with AWS KMS"
            ],
            "incorrect_mitigations": [
                "Add firewall rules",  # Wrong - doesn't encrypt data
                "Increase password strength",  # Wrong - data still unencrypted
                "Add monitoring"  # Wrong - doesn't prevent exposure
            ],
            "explanation": "Unencrypted data at rest can be exposed if storage media is stolen or accessed. Encryption ensures data remains protected even if physical security fails.",
            "compliance": "GDPR Article 32, PCI-DSS 3.4, HIPAA 164.312(a)(2)(iv)",
            "points": 10
        },
        {
            "id": "T-004",
            "stride": "Denial of Service",
            "component": "API Backend",
            "threat": "API flooding attack exhausting server resources and causing service unavailability",
            "likelihood": "High",
            "impact": "Medium",
            "correct_mitigations": [
                "Rate limiting per user/IP",
                "AWS WAF with rate-based rules",
                "Auto-scaling for ECS tasks",
                "DDoS protection with AWS Shield"
            ],
            "incorrect_mitigations": [
                "Add more memory",  # Wrong - doesn't prevent flood
                "Enable logging",  # Wrong - doesn't prevent DoS
                "Use encryption"  # Wrong - unrelated to DoS
            ],
            "explanation": "DoS attacks overwhelm resources. Rate limiting restricts requests per user, auto-scaling adds capacity dynamically, and WAF filters malicious traffic.",
            "compliance": "OWASP Top 10 A05:2021 (Security Misconfiguration)",
            "points": 10
        },
        {
            "id": "T-005",
            "stride": "Elevation of Privilege",
            "component": "API Backend",
            "threat": "Broken access control allowing regular user to access admin endpoints",
            "likelihood": "Medium",
            "impact": "High",
            "correct_mitigations": [
                "Role-Based Access Control (RBAC)",
                "Validate permissions on every request",
                "Principle of least privilege",
                "Deny by default"
            ],
            "incorrect_mitigations": [
                "Encrypt API traffic",  # Wrong - doesn't prevent authorization bypass
                "Add logging",  # Wrong - doesn't prevent access
                "Use strong authentication"  # Wrong - already authenticated, issue is authorization
            ],
            "explanation": "Authentication confirms identity, but authorization determines access rights. RBAC ensures users only access resources appropriate for their role.",
            "compliance": "OWASP Top 10 A01:2021 (Broken Access Control), PCI-DSS 7.1",
            "points": 10
        },
        {
            "id": "T-006",
            "stride": "Repudiation",
            "component": "API Backend",
            "threat": "Insufficient logging allows attackers to cover tracks or users to deny actions",
            "likelihood": "Medium",
            "impact": "Medium",
            "correct_mitigations": [
                "Comprehensive audit logging",
                "Log authentication events",
                "Log all data modifications",
                "Centralized logging (CloudWatch)",
                "Write-once log storage"
            ],
            "incorrect_mitigations": [
                "Add encryption",  # Wrong - doesn't provide audit trail
                "Enable 2FA",  # Wrong - doesn't log actions
                "Use firewalls"  # Wrong - doesn't log application events
            ],
            "explanation": "Non-repudiation requires proof of actions. Comprehensive audit logs create an immutable record of who did what and when.",
            "compliance": "PCI-DSS 10, SOC 2 CC7.2, HIPAA 164.312(b)",
            "points": 10
        },
        {
            "id": "T-007",
            "stride": "Tampering",
            "component": "Customer → Web Frontend",
            "threat": "Man-in-the-middle attack intercepting and modifying data in transit",
            "likelihood": "Low",
            "impact": "High",
            "correct_mitigations": [
                "TLS 1.3 for all connections",
                "HSTS headers",
                "Certificate pinning in mobile apps",
                "Enforce HTTPS with redirects"
            ],
            "incorrect_mitigations": [
                "Add database encryption",  # Wrong - doesn't protect transit
                "Enable logging",  # Wrong - doesn't prevent MITM
                "Use strong passwords"  # Wrong - doesn't prevent MITM
            ],
            "explanation": "MITM attacks intercept unencrypted communications. TLS encrypts data in transit, and HSTS prevents protocol downgrade attacks.",
            "compliance": "PCI-DSS 4.1, OWASP ASVS V9.1.1",
            "points": 10
        },
        {
            "id": "T-008",
            "stride": "Information Disclosure",
            "component": "API Backend",
            "threat": "Verbose error messages exposing stack traces and internal paths to attackers",
            "likelihood": "High",
            "impact": "Low",
            "correct_mitigations": [
                "Generic error messages for users",
                "Log detailed errors server-side only",
                "Disable debug mode in production",
                "Custom error pages"
            ],
            "incorrect_mitigations": [
                "Encrypt the error messages",  # Wrong - still exposed
                "Add authentication",  # Wrong - errors shown before auth
                "Use rate limiting"  # Wrong - doesn't hide errors
            ],
            "explanation": "Detailed errors reveal system internals to attackers. Production systems should show generic errors to users while logging details server-side.",
            "compliance": "OWASP Top 10 A05:2021, CWE-209",
            "points": 10
        },
        {
            "id": "T-009",
            "stride": "Spoofing",
            "component": "Customer",
            "threat": "Weak password policy allowing brute force attacks to compromise accounts",
            "likelihood": "High",
            "impact": "Medium",
            "correct_mitigations": [
                "Strong password requirements (12+ chars, complexity)",
                "Multi-Factor Authentication (MFA)",
                "Account lockout after failed attempts",
                "CAPTCHA on login",
                "Password breach detection"
            ],
            "incorrect_mitigations": [
                "Encrypt passwords in database",  # Correct but insufficient alone
                "Add logging",  # Wrong - doesn't prevent brute force
                "Use HTTPS"  # Wrong - doesn't prevent weak passwords
            ],
            "explanation": "Weak passwords are easily guessed. Strong password policies combined with MFA and account lockout make brute force attacks impractical.",
            "compliance": "OWASP ASVS V2.1.1, PCI-DSS 8.2.3, NIST 800-63B",
            "points": 10
        },
        {
            "id": "T-010",
            "stride": "Elevation of Privilege",
            "component": "API Backend → S3 Storage",
            "threat": "Misconfigured S3 bucket allows public access to upload malicious files or access private images",
            "likelihood": "Medium",
            "impact": "High",
            "correct_mitigations": [
                "S3 Block Public Access enabled",
                "Bucket policies with least privilege",
                "IAM roles for API access (not keys)",
                "S3 access logging enabled",
                "Regular access audits"
            ],
            "incorrect_mitigations": [
                "Encrypt S3 objects",  # Wrong - doesn't prevent public access
                "Add CloudWatch",  # Wrong - doesn't prevent misconfiguration
                "Use strong passwords"  # Wrong - S3 uses IAM, not passwords
            ],
            "explanation": "Misconfigured S3 buckets are a common vulnerability. Block Public Access prevents accidental exposure, and IAM roles provide granular access control.",
            "compliance": "AWS Well-Architected Security Pillar, CIS AWS Foundations",
            "points": 10
        },
        {
            "id": "T-011",
            "stride": "Tampering",
            "component": "Web Frontend",
            "threat": "DOM-based XSS through client-side JavaScript manipulation of user input",
            "likelihood": "Medium",
            "impact": "Medium",
            "correct_mitigations": [
                "Use React's built-in XSS protection",
                "Avoid dangerouslySetInnerHTML",
                "DOMPurify for sanitization when needed",
                "Content Security Policy",
                "Validate all user inputs"
            ],
            "incorrect_mitigations": [
                "Add server-side validation only",  # Wrong - DOM XSS is client-side
                "Use HTTPS",  # Wrong - doesn't prevent XSS
                "Enable database encryption"  # Wrong - unrelated to DOM XSS
            ],
            "explanation": "DOM-based XSS occurs in the browser. React escapes output by default, but developers must avoid unsafe patterns like dangerouslySetInnerHTML.",
            "compliance": "OWASP Top 10 A03:2021, CWE-79",
            "points": 10
        },
        {
            "id": "T-012",
            "stride": "Information Disclosure",
            "component": "API Backend → Stripe",
            "threat": "API keys hardcoded in frontend code exposing Stripe credentials",
            "likelihood": "High",
            "impact": "Critical",
            "correct_mitigations": [
                "Use Stripe publishable keys in frontend",
                "Store secret keys in AWS Secrets Manager",
                "Never commit keys to version control",
                "Rotate keys regularly",
                "Use environment variables"
            ],
            "incorrect_mitigations": [
                "Encrypt the keys in code",  # Wrong - still exposed in bundle
                "Obfuscate JavaScript",  # Wrong - still recoverable
                "Add rate limiting"  # Wrong - keys already exposed
            ],
            "explanation": "Frontend code is visible to users. Use publishable keys for client-side and keep secret keys server-side in secure secret stores.",
            "compliance": "PCI-DSS 6.5.3, OWASP Top 10 A05:2021",
            "points": 10
        },
        {
            "id": "T-013",
            "stride": "Denial of Service",
            "component": "Database",
            "threat": "Expensive database queries without pagination causing resource exhaustion",
            "likelihood": "Medium",
            "impact": "Medium",
            "correct_mitigations": [
                "Implement pagination (limit/offset)",
                "Query timeouts",
                "Database connection pooling",
                "Index frequently queried fields",
                "Query complexity analysis"
            ],
            "incorrect_mitigations": [
                "Add more database storage",  # Wrong - doesn't limit queries
                "Enable encryption",  # Wrong - unrelated to query performance
                "Add logging"  # Wrong - doesn't prevent expensive queries
            ],
            "explanation": "Unbounded queries can exhaust memory and CPU. Pagination limits result sets, and timeouts prevent long-running queries.",
            "compliance": "OWASP API Security Top 10 API4:2023",
            "points": 10
        },
        {
            "id": "T-014",
            "stride": "Spoofing",
            "component": "API Backend → SendGrid",
            "threat": "Email spoofing allowing attackers to send phishing emails appearing from legitimate domain",
            "likelihood": "Medium",
            "impact": "Medium",
            "correct_mitigations": [
                "SPF records configured",
                "DKIM signing enabled",
                "DMARC policy enforced",
                "Verify SendGrid API key security",
                "Monitor email sending patterns"
            ],
            "incorrect_mitigations": [
                "Encrypt email content",  # Wrong - doesn't prevent spoofing
                "Add rate limiting",  # Wrong - doesn't prevent spoofing
                "Use strong passwords"  # Wrong - doesn't prevent domain spoofing
            ],
            "explanation": "Email authentication (SPF, DKIM, DMARC) proves emails originate from authorized servers, preventing domain spoofing.",
            "compliance": "Anti-Phishing Best Practices, DMARC RFC 7489",
            "points": 10
        },
        {
            "id": "T-015",
            "stride": "Tampering",
            "component": "API Backend",
            "threat": "Mass assignment vulnerability allowing users to modify unintended fields",
            "likelihood": "Medium",
            "impact": "High",
            "correct_mitigations": [
                "Explicitly define allowed fields",
                "Use DTO (Data Transfer Objects)",
                "Validate input against schema",
                "Blacklist sensitive fields",
                "Use ORM's field protection"
            ],
            "incorrect_mitigations": [
                "Encrypt the request",  # Wrong - doesn't prevent mass assignment
                "Add authentication",  # Wrong - user is authenticated, issue is field access
                "Enable logging"  # Wrong - doesn't prevent the attack
            ],
            "explanation": "Mass assignment occurs when APIs blindly accept all input fields. Explicitly defining allowed fields prevents users from modifying protected attributes.",
            "compliance": "OWASP API Top 10 API6:2023 (Mass Assignment), CWE-915",
            "points": 10
        }
    ],
    
    "2": [  # Workshop 2: Mobile Banking - Add 25 threats
        {
            "id": "T-016",
            "stride": "Information Disclosure",
            "component": "Account Service",
            "threat": "Broken Object Level Authorization (BOLA) allowing User A to access User B's account data by manipulating account IDs",
            "likelihood": "High",
            "impact": "Critical",
            "correct_mitigations": [
                "Object-level authorization checks",
                "Validate user owns requested resource",
                "Use indirect object references (UUIDs)",
                "Implement resource-based permissions",
                "Check ownership in every query"
            ],
            "incorrect_mitigations": [
                "Add authentication",  # Wrong - user is authenticated
                "Encrypt the account ID",  # Wrong - still accessible if user guesses
                "Add rate limiting"  # Wrong - doesn't prevent BOLA
            ],
            "explanation": "BOLA occurs when APIs fail to verify resource ownership. Every request must verify the authenticated user has permission to access the specific resource.",
            "compliance": "OWASP API Top 10 API1:2023 (BOLA), CWE-639",
            "points": 10
        },
        {
            "id": "T-017",
            "stride": "Tampering",
            "component": "Payment Service",
            "threat": "Insufficient validation allows modifying transaction amount after approval",
            "likelihood": "Medium",
            "impact": "Critical",
            "correct_mitigations": [
                "Cryptographic signing of transaction data",
                "Server-side amount validation",
                "Transaction state machine",
                "Immutable audit log",
                "Multi-step verification"
            ],
            "incorrect_mitigations": [
                "Add logging",  # Wrong - doesn't prevent tampering
                "Encrypt in transit",  # Wrong - tampering happens server-side
                "Use HTTPS"  # Wrong - doesn't validate business logic
            ],
            "explanation": "Financial transactions require integrity protection. Cryptographic signatures and server-side validation prevent amount manipulation.",
            "compliance": "PCI-DSS, SOC 2, Banking regulations",
            "points": 10
        }
        # Add more threats for Workshop 2...
    ],
    
    # Add threats for Workshops 3 and 4...
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def generate_high_level_architecture(workshop_config):
    """Generate simple high-level architecture diagram"""
    try:
        dot = Digraph(comment="High-Level Architecture", format="png")
        dot.attr(rankdir="LR", size="10,6", fontname="Arial", bgcolor="white")
        dot.attr("node", fontname="Arial", fontsize="14", shape="box", style="rounded,filled")
        dot.attr("edge", fontname="Arial", fontsize="11")
        
        # Simplified grouping
        scenario = workshop_config["scenario"]
        
        # Group components by type for high-level view
        external = [c for c in scenario["components"] if c["type"] == "external_entity"]
        processes = [c for c in scenario["components"] if c["type"] == "process"]
        datastores = [c for c in scenario["components"] if c["type"] == "datastore"]
        
        # Create high-level nodes
        if external:
            dot.node("Users", "Users/Clients", fillcolor="lightcoral")
        
        dot.node("Application", f"{scenario['title']}\nApplication Layer", fillcolor="lightblue")
        
        if datastores:
            dot.node("Data", "Data Layer\n(Databases & Storage)", fillcolor="lightgreen")
        
        # Simple connections
        if external:
            dot.edge("Users", "Application", "HTTPS")
        if datastores:
            dot.edge("Application", "Data", "Queries")
        
        # External services
        ext_services = [c["name"] for c in external if "Stripe" in c["name"] or "Twilio" in c["name"] 
                       or "SendGrid" in c["name"] or "Plaid" in c["name"] or "Salesforce" in c["name"]]
        if ext_services:
            dot.node("External", "External Services\n" + "\n".join(ext_services[:3]), fillcolor="lightyellow")
            dot.edge("Application", "External", "API")
        
        diagram_path = dot.render("high_level_arch", format="png", cleanup=True)
        with open(diagram_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except:
        return None

def generate_detailed_dfd(workshop_config, threats=[]):
    """Generate detailed Data Flow Diagram with trust boundaries"""
    try:
        dot = Digraph(comment="Detailed DFD", format="png")
        dot.attr(rankdir="TB", size="14,12", fontname="Arial", bgcolor="white", splines="polyline")
        dot.attr("node", fontname="Arial", fontsize="10")
        dot.attr("edge", fontname="Arial", fontsize="8")

        styles = {
            "external_entity": {"shape": "oval", "style": "filled", "fillcolor": "lightcoral", "color": "red", "penwidth": "2"},
            "process": {"shape": "box", "style": "filled,rounded", "fillcolor": "lightblue", "color": "blue", "penwidth": "2"},
            "datastore": {"shape": "cylinder", "style": "filled", "fillcolor": "lightgreen", "color": "green", "penwidth": "2"}
        }

        # Collect identified threats
        identified_threat_ids = {t.get("matched_threat_id") for t in threats if t.get("matched_threat_id")}
        
        node_threats = {}
        edge_threats = {}
        for threat in threats:
            if threat.get("matched_threat_id"):
                affected = threat.get("component", "")
                threat_id = threat.get("matched_threat_id")
                
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
            threat_str = f"\\n✓ Threats: {', '.join(threat_label)}" if threat_label else ""
            
            label = f"{name}\\n{desc}{threat_str}"
            style = styles.get(comp_type, styles["process"]).copy()
            
            if threat_label:
                style["fillcolor"] = "#C8E6C9"  # Green for identified threats
            
            dot.node(name, label, **style)

        # Add edges
        flows = workshop_config["scenario"]["data_flows"]
        for flow in flows:
            source = flow["source"]
            dest = flow["destination"]
            data = flow["data"]
            protocol = flow.get("protocol", "")
            
            edge_key = f"{source} → {dest}"
            threat_label = edge_threats.get(edge_key, [])
            threat_str = f"\\n✓ {', '.join(threat_label)}" if threat_label else ""
            
            label = f"{data}\\n({protocol}){threat_str}"
            color = "#4CAF50" if threat_label else "black"
            penwidth = "3" if threat_label else "1.5"
            
            dot.edge(source, dest, label=label, color=color, penwidth=penwidth)

        # Add trust boundaries
        for idx, boundary in enumerate(workshop_config["scenario"]["trust_boundaries"]):
            with dot.subgraph(name=f"cluster_{idx}") as c:
                c.attr(label=f"🔒 {boundary['name']}", style="dashed", color="purple", 
                       fontsize="12", penwidth="2.5", bgcolor="#F3E5F5")
                
                for comp_name in boundary.get("components", []):
                    c.node(comp_name)

        diagram_path = dot.render("detailed_dfd", format="png", cleanup=True)
        with open(diagram_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception as e:
        st.error(f"Diagram error: {e}")
        return None

def calculate_threat_score(user_threat, predefined_threat):
    """Calculate score for user's threat identification"""
    score = 0
    max_score = predefined_threat["points"]
    feedback = []
    
    # Check if correct threat identified (component + threat type)
    if user_threat["component"] == predefined_threat["component"]:
        score += 2
        feedback.append("✓ Correct component identified")
    else:
        feedback.append(f"✗ Wrong component. Expected: {predefined_threat['component']}")
    
    # Check STRIDE category
    if user_threat["stride"] == predefined_threat["stride"]:
        score += 2
        feedback.append("✓ Correct STRIDE category")
    else:
        feedback.append(f"✗ Wrong STRIDE. Expected: {predefined_threat['stride']}")
    
    # Check risk assessment
    if user_threat["likelihood"] == predefined_threat["likelihood"]:
        score += 1
        feedback.append("✓ Correct likelihood assessment")
    else:
        feedback.append(f"✗ Likelihood should be: {predefined_threat['likelihood']}")
    
    if user_threat["impact"] == predefined_threat["impact"]:
        score += 1
        feedback.append("✓ Correct impact assessment")
    else:
        feedback.append(f"✗ Impact should be: {predefined_threat['impact']}")
    
    # Check mitigations (most important part)
    correct_mits = set(predefined_threat["correct_mitigations"])
    user_mits = set(user_threat.get("selected_mitigations", []))
    incorrect_mits = set(predefined_threat.get("incorrect_mitigations", []))
    
    correct_selected = user_mits & correct_mits
    incorrect_selected = user_mits & incorrect_mits
    
    # Score based on mitigation selection
    if len(correct_selected) >= 3:
        score += 4
        feedback.append(f"✓ Excellent mitigation selection: {', '.join(correct_selected)}")
    elif len(correct_selected) >= 2:
        score += 3
        feedback.append(f"✓ Good mitigation selection: {', '.join(correct_selected)}")
    elif len(correct_selected) >= 1:
        score += 2
        feedback.append(f"⚠ Partial mitigation selection: {', '.join(correct_selected)}")
    else:
        feedback.append("✗ No correct mitigations selected")
    
    if incorrect_selected:
        score -= len(incorrect_selected)
        feedback.append(f"✗ Incorrect mitigations selected: {', '.join(incorrect_selected)}")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    return score, max_score, feedback

def is_workshop_unlocked(workshop_id):
    return workshop_id in st.session_state.unlocked_workshops

def save_progress():
    try:
        progress = {
            "completed_workshops": list(st.session_state.completed_workshops),
            "unlocked_workshops": list(st.session_state.unlocked_workshops),
            "selected_workshop": st.session_state.selected_workshop,
            "current_step": st.session_state.current_step,
            "threats": st.session_state.threats,
            "user_answers": st.session_state.user_answers,
            "total_score": st.session_state.total_score,
            "max_score": st.session_state.max_score
        }
        with open("/tmp/threat_model_progress.json", "w") as f:
            json.dump(progress, f)
    except:
        pass

def load_progress():
    try:
        if os.path.exists("/tmp/threat_model_progress.json"):
            with open("/tmp/threat_model_progress.json", "r") as f:
                progress = json.load(f)
                st.session_state.completed_workshops = set(progress.get("completed_workshops", []))
                st.session_state.unlocked_workshops = set(progress.get("unlocked_workshops", ["1"]))
                st.session_state.selected_workshop = progress.get("selected_workshop")
                st.session_state.current_step = progress.get("current_step", 1)
                st.session_state.threats = progress.get("threats", [])
                st.session_state.user_answers = progress.get("user_answers", [])
                st.session_state.total_score = progress.get("total_score", 0)
                st.session_state.max_score = progress.get("max_score", 0)
    except:
        pass

load_progress()

# =============================================================================
# WORKSHOP CONFIGURATIONS (Simplified - keep from previous version)
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
            "description": "A startup e-commerce platform selling electronics",
            "business_context": "Series A startup, 50K monthly users, $2M revenue",
            "assets": ["Customer PII", "Payment data (via Stripe)", "User credentials", "Order history"],
            "objectives": ["Confidentiality: Protect PII", "Integrity: Order accuracy", "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS Level 4", "GDPR", "CCPA"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA on CloudFront/S3"},
                {"name": "API Backend", "type": "process", "description": "Node.js/Express on ECS"},
                {"name": "Database", "type": "datastore", "description": "RDS PostgreSQL"},
                {"name": "Stripe", "type": "external_entity", "description": "Payment processing"},
                {"name": "S3 Storage", "type": "datastore", "description": "Product images"},
                {"name": "SendGrid", "type": "external_entity", "description": "Email service"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP requests", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database", "data": "SQL queries", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payment tokens", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "S3 Storage", "data": "Images", "protocol": "S3 API"},
                {"source": "API Backend", "destination": "SendGrid", "data": "Emails", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Internet Boundary", "description": "Untrusted → Trusted", "components": ["Customer", "Web Frontend"]},
                {"name": "Application Tier", "description": "Frontend → Backend", "components": ["Web Frontend", "API Backend"]},
                {"name": "Data Tier", "description": "App → Storage", "components": ["API Backend", "Database", "S3 Storage"]},
                {"name": "External Services", "description": "Internal → Third-party", "components": ["API Backend", "Stripe", "SendGrid"]}
            ]
        }
    }
    # Add other workshops...
}

# =============================================================================
# SIDEBAR
# =============================================================================

with st.sidebar:
    st.title("🔒 STRIDE Learning Lab")
    st.markdown("### Progressive Training with Scoring")
    
    st.markdown("---")
    
    # Display current score if in a workshop
    if st.session_state.selected_workshop and st.session_state.max_score > 0:
        score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
        st.markdown(f"### 📊 Current Score")
        st.progress(score_pct / 100)
        st.markdown(f"**{st.session_state.total_score} / {st.session_state.max_score}** points ({score_pct:.1f}%)")
        
        if score_pct >= 90:
            st.success("🏆 Excellent!")
        elif score_pct >= 75:
            st.info("👍 Good job!")
        elif score_pct >= 60:
            st.warning("📚 Keep learning!")
        else:
            st.error("💪 Review materials!")
        
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
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                save_progress()
                st.rerun()
        
        with col2:
            if completed:
                st.markdown('<span class="badge-completed">✓</span>', unsafe_allow_html=True)
            elif not unlocked:
                st.markdown('<span class="badge-locked">🔒</span>', unsafe_allow_html=True)
        
        if not unlocked and ws_id != "1":
            unlock_key = f"unlock_{ws_id}"
            if unlock_key not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[unlock_key] = False
            
            if st.button(f"🔓 Unlock", key=f"show_unlock_{ws_id}", use_container_width=True):
                st.session_state.show_unlock_form[unlock_key] = not st.session_state.show_unlock_form[unlock_key]
                st.rerun()
            
            if st.session_state.show_unlock_form[unlock_key]:
                with st.form(f"unlock_form_{ws_id}"):
                    code = st.text_input("Enter code", type="password", key=f"code_{ws_id}")
                    if st.form_submit_button("Submit"):
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
            st.caption(f"**Threats:** {ws_config['target_threats']}")
    
    st.markdown("---")
    
    st.markdown("### Your Progress")
    progress_pct = (len(st.session_state.completed_workshops) / len(WORKSHOPS)) * 100
    st.progress(progress_pct / 100)
    st.caption(f"{len(st.session_state.completed_workshops)}/{len(WORKSHOPS)} completed")
    
    st.markdown("---")
    
    with st.expander("📚 STRIDE Reference"):
        st.markdown("""
        **S** - Spoofing: Identity impersonation  
        **T** - Tampering: Data modification  
        **R** - Repudiation: Denying actions  
        **I** - Info Disclosure: Data exposure  
        **D** - Denial of Service: Availability  
        **E** - Elevation of Privilege: Unauthorized access
        """)

# =============================================================================
# MAIN CONTENT
# =============================================================================

if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling Learning Lab")
    st.markdown("### Learn by Doing with Instant Feedback")
    
    st.markdown("""
    <div class="info-box">
    <strong>Interactive Learning!</strong> This enhanced workshop teaches threat modeling through 
    hands-on practice with immediate feedback and scoring. Learn what makes a good threat 
    identification and why certain mitigations work better than others.
    </div>
    """, unsafe_allow_html=True)
    
    cols = st.columns(4)
    for idx, (ws_id, ws_config) in enumerate(WORKSHOPS.items()):
        with cols[idx]:
            unlocked = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            
            badge = "✅ Completed" if completed else "🔓 Available" if unlocked else "🔒 Locked"
            badge_color = "#2C5F2D" if completed else "#028090" if unlocked else "#757575"
            
            st.markdown(f"""
            <div class="workshop-card" style="border-color: {badge_color};">
                <h4>Lab {ws_id}</h4>
                <p><strong>{ws_config['scenario']['title']}</strong></p>
                <p style="font-size: 0.9em; color: #666;">{ws_config['level']}</p>
                <span style="background-color: {badge_color}; color: white; padding: 5px 10px; border-radius: 12px; font-size: 0.8em;">
                    {badge}
                </span>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    st.markdown("""
    ### 🎯 What's New in Learning Edition
    
    - **✅ Instant Validation**: Get immediate feedback on your threat identifications
    - **📊 Scoring System**: Earn points for correct answers, understand why
    - **🎓 Learn from Mistakes**: See why certain mitigations work and others don't
    - **📈 Track Progress**: Monitor your learning journey with scores
    - **🔍 Detailed vs High-Level**: Understand architecture at different abstraction levels
    
    ### 📘 How It Works
    
    1. **Learn the Architecture**: Start with high-level, then detailed views
    2. **Identify Threats**: Select from predefined threat scenarios
    3. **Choose Mitigations**: Pick appropriate security controls
    4. **Get Feedback**: Instant scoring with explanations
    5. **Improve**: Learn from feedback and try again
    
    Start with Workshop 1 to begin learning!
    """)
    
    st.stop()

# =============================================================================
# WORKSHOP CONTENT
# =============================================================================

current_workshop = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

st.title(current_workshop["name"])
level_colors = {"Foundation": "🟢", "Intermediate": "🟡", "Advanced": "🟠", "Expert": "🔴"}
st.markdown(f"{level_colors[current_workshop['level']]} **{current_workshop['level']}** | {current_workshop['scenario']['title']}")

# Progress
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
# STEP 1: SCOPE (High-Level Architecture)
# =============================================================================

if st.session_state.current_step == 1:
    st.header("Step 1: Define Scope & System Overview")
    
    scenario = current_workshop["scenario"]
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📋 Application Information")
        st.markdown(f"**Context:** {scenario['business_context']}")
        
        st.markdown("### 🎯 Security Objectives")
        for obj in scenario["objectives"]:
            st.markdown(f"- {obj}")
        
        st.markdown("### 💎 Critical Assets")
        for asset in scenario["assets"]:
            st.markdown(f"- {asset}")
        
        st.markdown("### 📜 Compliance")
        for comp in scenario["compliance"]:
            st.markdown(f"- {comp}")
    
    with col2:
        st.markdown(f"""
        <div class="success-box">
        <strong>Workshop Goals</strong><br><br>
        📊 Identify {current_workshop['target_threats']} threats<br>
        ⏱️ {current_workshop['duration']}<br>
        📈 {current_workshop['level']} level<br>
        🎯 Score 90%+ for mastery!
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # HIGH-LEVEL ARCHITECTURE
    st.subheader("🏗️ High-Level System Architecture")
    
    st.markdown("""
    <div class="info-box">
    <strong>Understanding at Different Levels</strong><br>
    This high-level view shows the major components and their relationships. 
    In the next step, you'll see the detailed decomposition with all data flows and trust boundaries.
    </div>
    """, unsafe_allow_html=True)
    
    with st.spinner("Generating high-level architecture..."):
        high_level_diagram = generate_high_level_architecture(current_workshop)
    
    if high_level_diagram:
        st.image(f"data:image/png;base64,{high_level_diagram}",
                 caption="High-Level Architecture - Major Components",
                 use_column_width=True)
    
    # Component summary
    st.markdown("### Component Summary")
    comp_types = {"external_entity": [], "process": [], "datastore": []}
    for comp in scenario["components"]:
        comp_types[comp["type"]].append(comp["name"])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**External Entities**")
        for name in comp_types["external_entity"]:
            st.caption(f"👤 {name}")
    with col2:
        st.markdown("**Processes**")
        for name in comp_types["process"]:
            st.caption(f"⚙️ {name}")
    with col3:
        st.markdown("**Data Stores**")
        for name in comp_types["datastore"]:
            st.caption(f"💾 {name}")
    
    st.markdown("---")
    
    if st.button("Next: Decompose System ➡️", type="primary", use_container_width=True):
        st.session_state.current_step = 2
        save_progress()
        st.rerun()

# =============================================================================
# STEP 2: DECOMPOSE (Detailed Architecture with Trust Boundaries)
# =============================================================================

elif st.session_state.current_step == 2:
    st.header("Step 2: Detailed Application Decomposition")
    
    scenario = current_workshop["scenario"]
    
    st.markdown("""
    <div class="info-box">
    <strong>Detailed Data Flow Diagram (DFD)</strong><br>
    This detailed view shows all components, data flows, protocols, and trust boundaries. 
    Trust boundaries (purple dashed boxes) mark where data crosses security zones - these are 
    critical areas for threat analysis!
    </div>
    """, unsafe_allow_html=True)
    
    # DETAILED DFD with Trust Boundaries
    st.subheader("📊 Detailed Data Flow Diagram")
    
    with st.spinner("Generating detailed DFD with trust boundaries..."):
        detailed_diagram = generate_detailed_dfd(current_workshop, st.session_state.threats)
    
    if detailed_diagram:
        st.image(f"data:image/png;base64,{detailed_diagram}",
                 caption="Detailed DFD with Trust Boundaries and Data Flows",
                 use_column_width=True)
        st.session_state.diagram_generated = detailed_diagram
    
    # Data Flows Table
    st.subheader("📝 Data Flows with Protocols")
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
    Trust boundaries are where data crosses between security zones. **Focus your threat analysis here!**
    """)
    
    for boundary in scenario["trust_boundaries"]:
        with st.expander(f"🔐 {boundary['name']}", expanded=False):
            st.markdown(f"**Description:** {boundary['description']}")
            if boundary.get("components"):
                st.markdown(f"**Components:** {', '.join(boundary['components'])}")
            
            st.markdown("**Why this matters:** Data crossing this boundary needs authentication, "
                       "authorization, encryption, and validation.")
    
    # Analysis guidance
    with st.expander("💡 Threat Analysis Guidance"):
        st.markdown("""
        **How to use this diagram for threat modeling:**
        
        1. **Focus on trust boundaries** - These are where most threats occur
        2. **Examine each data flow** - What data? What protocol? Is it encrypted?
        3. **Apply STRIDE to each element** - Systematically check all threat categories
        4. **Consider the attacker's perspective** - What would you attack?
        
        **Key questions to ask:**
        - Where does untrusted data enter the system?
        - Which components handle sensitive data?
        - Are authentication and authorization verified at each boundary?
        - What happens if a component is compromised?
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
# STEP 3: IDENTIFY THREATS (With Validation and Scoring)
# =============================================================================

elif st.session_state.current_step == 3:
    st.header("Step 3: Identify Threats (Learning Mode)")
    
    st.markdown(f"""
    <div class="info-box">
    <strong>How This Works:</strong><br>
    1. Select a threat scenario from the list<br>
    2. Choose the affected component<br>
    3. Assess likelihood and impact<br>
    4. Select appropriate mitigations<br>
    5. Get instant feedback and score!<br><br>
    <strong>Goal:</strong> Identify {current_workshop['target_threats']} threats with 90%+ accuracy
    </div>
    """, unsafe_allow_html=True)
    
    # Threat selection form
    with st.form("threat_selection_form"):
        st.subheader("➕ Select Threat to Analyze")
        
        # Build threat options (show ID and brief description)
        threat_options = {
            f"{t['id']}: {t['threat'][:80]}...": t 
            for t in workshop_threats
        }
        
        selected_threat_key = st.selectbox(
            "Choose a threat scenario to analyze:",
            list(threat_options.keys()),
            help="Select a potential threat to this system"
        )
        
        selected_predefined = threat_options[selected_threat_key]
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Your Analysis")
            
            # Component selection
            all_components = [comp["name"] for comp in current_workshop["scenario"]["components"]]
            all_flows = [f"{f['source']} → {f['destination']}" 
                        for f in current_workshop["scenario"]["data_flows"]]
            
            user_component = st.selectbox(
                "Which component/flow is affected?",
                all_components + all_flows,
                help="Select the system element this threat targets"
            )
            
            # STRIDE category
            user_stride = st.selectbox(
                "STRIDE Category",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"]
            )
            
            # Risk assessment
            user_likelihood = st.select_slider(
                "Likelihood",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
            
            user_impact = st.select_slider(
                "Impact",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
        
        with col2:
            st.markdown("### Select Mitigations")
            
            st.caption("Choose all controls that would effectively mitigate this threat:")
            
            # Combine correct and incorrect mitigations
            all_possible_mitigations = (
                selected_predefined["correct_mitigations"] + 
                selected_predefined.get("incorrect_mitigations", [])
            )
            
            # Shuffle to avoid pattern recognition
            import random
            random.shuffle(all_possible_mitigations)
            
            user_mitigations = st.multiselect(
                "Mitigation Controls",
                all_possible_mitigations,
                help="Select all appropriate security controls"
            )
        
        st.markdown("---")
        
        submitted = st.form_submit_button("✅ Submit Answer & Get Score", 
                                          type="primary", 
                                          use_container_width=True)
        
        if submitted:
            # Create user answer object
            user_answer = {
                "component": user_component,
                "stride": user_stride,
                "likelihood": user_likelihood,
                "impact": user_impact,
                "selected_mitigations": user_mitigations,
                "matched_threat_id": selected_predefined["id"]
            }
            
            # Calculate score
            score, max_score, feedback = calculate_threat_score(user_answer, selected_predefined)
            
            # Update totals
            st.session_state.total_score += score
            st.session_state.max_score += max_score
            
            # Save answer
            st.session_state.user_answers.append({
                **user_answer,
                "score": score,
                "max_score": max_score,
                "feedback": feedback
            })
            
            # Add to threats list
            st.session_state.threats.append(user_answer)
            
            save_progress()
            st.rerun()
    
    # Display previous answers with feedback
    if st.session_state.user_answers:
        st.markdown("---")
        st.subheader(f"📊 Your Answers ({len(st.session_state.user_answers)}/{current_workshop['target_threats']})")
        
        for idx, answer in enumerate(st.session_state.user_answers):
            score_pct = (answer["score"] / answer["max_score"]) * 100
            
            if score_pct >= 80:
                feedback_class = "correct-answer"
                emoji = "✅"
            elif score_pct >= 50:
                feedback_class = "partial-answer"
                emoji = "⚠️"
            else:
                feedback_class = "incorrect-answer"
                emoji = "❌"
            
            with st.expander(f"{emoji} Answer {idx + 1}: {answer['matched_threat_id']} - Score: {answer['score']}/{answer['max_score']} ({score_pct:.0f}%)"):
                st.markdown(f"""
                <div class="{feedback_class}">
                    <strong>Your Analysis:</strong><br>
                    Component: {answer['component']}<br>
                    STRIDE: {answer['stride']}<br>
                    Risk: {answer['likelihood']} likelihood, {answer['impact']} impact<br>
                    Mitigations: {', '.join(answer.get('selected_mitigations', []))}
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("**Feedback:**")
                for fb in answer["feedback"]:
                    if "✓" in fb:
                        st.success(fb)
                    elif "✗" in fb:
                        st.error(fb)
                    else:
                        st.warning(fb)
                
                # Show explanation from predefined threat
                predefined = next((t for t in workshop_threats if t["id"] == answer["matched_threat_id"]), None)
                if predefined:
                    with st.expander("📚 Learn More"):
                        st.markdown(f"**Why this matters:**\n\n{predefined['explanation']}")
                        st.markdown(f"**Compliance:** {predefined.get('compliance', 'N/A')}")
    
    # Progress
    progress = len(st.session_state.user_answers) / current_workshop['target_threats']
    st.progress(min(progress, 1.0))
    
    if len(st.session_state.user_answers) >= current_workshop['target_threats']:
        final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
        
        if final_score_pct >= 90:
            score_class = "score-excellent"
            message = "🏆 Excellent! You've mastered this workshop!"
        elif final_score_pct >= 75:
            score_class = "score-good"
            message = "👍 Good job! You understand the concepts well."
        elif final_score_pct >= 60:
            score_class = "score-fair"
            message = "📚 Fair! Review the feedback to improve."
        else:
            score_class = "score-poor"
            message = "💪 Keep learning! Review materials and try again."
        
        st.markdown(f"""
        <div class="{score_class}">
            {message}<br>
            Final Score: {st.session_state.total_score} / {st.session_state.max_score} ({final_score_pct:.1f}%)
        </div>
        """, unsafe_allow_html=True)
    else:
        remaining = current_workshop['target_threats'] - len(st.session_state.user_answers)
        current_score_pct = (st.session_state.total_score / st.session_state.max_score * 100) if st.session_state.max_score > 0 else 0
        st.info(f"⚠️ {remaining} more threats needed. Current score: {current_score_pct:.1f}%")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back", use_container_width=True):
            st.session_state.current_step = 2
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Review ➡️", type="primary", use_container_width=True):
            if st.session_state.user_answers:
                st.session_state.current_step = 4
                save_progress()
                st.rerun()
            else:
                st.error("Complete at least one threat analysis")

# =============================================================================
# STEP 4: ASSESS & REVIEW
# =============================================================================

elif st.session_state.current_step == 4:
    st.header("Step 4: Review & Assessment")
    
    if not st.session_state.user_answers:
        st.warning("No answers to review")
        if st.button("⬅️ Back"):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
        st.stop()
    
    # Final score
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percentage", f"{final_score_pct:.1f}%")
    col3.metric("Threats Analyzed", len(st.session_state.user_answers))
    col4.metric("Grade", 
                "A" if final_score_pct >= 90 else "B" if final_score_pct >= 80 else 
                "C" if final_score_pct >= 70 else "D" if final_score_pct >= 60 else "F")
    
    # Performance breakdown
    st.subheader("📊 Performance Breakdown")
    
    correct_count = sum(1 for a in st.session_state.user_answers if (a["score"] / a["max_score"]) >= 0.8)
    partial_count = sum(1 for a in st.session_state.user_answers if 0.5 <= (a["score"] / a["max_score"]) < 0.8)
    incorrect_count = sum(1 for a in st.session_state.user_answers if (a["score"] / a["max_score"]) < 0.5)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Excellent (80%+)", correct_count, delta_color="normal")
    col2.metric("Partial (50-79%)", partial_count, delta_color="normal")
    col3.metric("Needs Review (<50%)", incorrect_count, delta_color="inverse")
    
    # Learning recommendations
    st.subheader("📚 Learning Recommendations")
    
    if final_score_pct < 70:
        st.warning("""
        **Areas to Review:**
        - Review STRIDE categories and what each means
        - Study the relationship between threats and appropriate mitigations
        - Understand why certain controls work and others don't
        - Practice identifying components correctly
        """)
    elif final_score_pct < 90:
        st.info("""
        **To Improve:**
        - Fine-tune your risk assessment (likelihood vs impact)
        - Study the nuances of different mitigation strategies
        - Review feedback on partial answers
        """)
    else:
        st.success("""
        **Excellent Work!**
        - You've demonstrated strong understanding of STRIDE methodology
        - Your threat identification skills are excellent
        - You understand appropriate mitigations
        - Ready for the next workshop!
        """)
    
    # Export
    st.markdown("---")
    st.subheader("📥 Export Results")
    
    results_data = pd.DataFrame([{
        "Threat_ID": a["matched_threat_id"],
        "Component": a["component"],
        "STRIDE": a["stride"],
        "Score": f"{a['score']}/{a['max_score']}",
        "Percentage": f"{(a['score']/a['max_score']*100):.1f}%"
    } for a in st.session_state.user_answers])
    
    csv_data = results_data.to_csv(index=False)
    
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 Download Results CSV",
            csv_data,
            f"threat_learning_results_{st.session_state.selected_workshop}.csv",
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
    
    final_score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    if final_score_pct >= 90:
        st.balloons()
        st.success(f"""
        🏆 **Outstanding Performance!**
        
        You've completed {current_workshop['name']} with a score of **{final_score_pct:.1f}%**!
        
        You've demonstrated excellent understanding of:
        - ✅ STRIDE threat categories
        - ✅ Appropriate risk assessment
        - ✅ Effective mitigation strategies
        - ✅ System architecture analysis
        """)
    elif final_score_pct >= 70:
        st.info(f"""
        👍 **Good Job!**
        
        You've completed {current_workshop['name']} with a score of **{final_score_pct:.1f}%**
        
        You understand the core concepts. Review the feedback to improve further.
        """)
    else:
        st.warning(f"""
        📚 **Workshop Completed - Keep Learning!**
        
        Score: **{final_score_pct:.1f}%**
        
        Consider reviewing the materials and trying again to improve your understanding.
        """)
    
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()
    
    st.markdown("---")
    st.subheader("Next Steps")
    
    next_workshop = str(int(st.session_state.selected_workshop) + 1)
    
    if next_workshop in WORKSHOPS:
        st.info(f"""
        **Ready for the next challenge?**
        
        Workshop {next_workshop}: {WORKSHOPS[next_workshop]['name']}
        Level: {WORKSHOPS[next_workshop]['level']}
        """)
        
        if st.button(f"Start Workshop {next_workshop} ➡️", type="primary", use_container_width=True):
            st.session_state.selected_workshop = next_workshop
            st.session_state.current_step = 1
            st.session_state.threats = []
            st.session_state.user_answers = []
            st.session_state.total_score = 0
            st.session_state.max_score = 0
            save_progress()
            st.rerun()
    else:
        st.success("""
        🏆 **All Workshops Completed!**
        
        Congratulations on completing the STRIDE Threat Modeling Learning Path!
        """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review Scores", use_container_width=True):
            st.session_state.current_step = 4
            save_progress()
            st.rerun()
    with col2:
        if st.button("🏠 Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            save_progress()
            st.rerun()

st.markdown("---")
st.caption("STRIDE Threat Modeling Learning Lab | Interactive Learning with Instant Feedback")
