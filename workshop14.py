"""
STRIDE Threat Modeling - ENTERPRISE EDITION
Enhanced with professional scope documentation, advanced diagrams, and enterprise-grade reporting
All 4 Workshops | Enterprise Scope | Professional UI | Enhanced PDFs
"""

import streamlit as st
import base64
import json
import os
import pandas as pd
from graphviz import Digraph
from datetime import datetime
import random
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image as RLImage, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from io import BytesIO

# Hide Streamlit elements for cleaner UI
st.set_page_config(
    page_title="STRIDE Threat Modeling Enterprise Lab", 
    page_icon="🔒", 
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "STRIDE Threat Modeling Enterprise Lab - Professional Security Training Platform"
    }
)

# Hide Streamlit branding and menu
hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# UNLOCK CODES - STORED HERE FOR REFERENCE ONLY, NEVER DISPLAYED IN UI
WORKSHOP_CODES = {"1": None, "2": "MICRO2025", "3": "TENANT2025", "4": "HEALTH2025"}

# ENHANCED CSS WITH PROFESSIONAL STYLING
st.markdown("""<style>
.stButton>button{width:100%;border-radius:8px;font-weight:600;transition:all 0.3s ease;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.stButton>button:hover{transform:translateY(-2px);box-shadow:0 4px 8px rgba(0,0,0,0.15)}

/* Enterprise Card Components */
.enterprise-card{
    background:linear-gradient(135deg,#EFF6FF 0%,white 100%);
    border-left:5px solid #2563EB;
    border-radius:12px;
    padding:24px;
    margin:16px 0;
    box-shadow:0 4px 12px rgba(0,0,0,0.1);
    transition:all 0.3s ease;
}
.enterprise-card:hover{box-shadow:0 8px 24px rgba(0,0,0,0.15);transform:translateY(-2px)}
.enterprise-card-green{background:linear-gradient(135deg,#F0FDF4 0%,white 100%);border-left-color:#10B981}
.enterprise-card-red{background:linear-gradient(135deg,#FEF2F2 0%,white 100%);border-left-color:#EF4444}
.enterprise-card-purple{background:linear-gradient(135deg,#F5F3FF 0%,white 100%);border-left-color:#7C3AED}
.enterprise-card-orange{background:linear-gradient(135deg,#FFF7ED 0%,white 100%);border-left-color:#F97316}

/* Threat Severity Cards */
.threat-critical{background:linear-gradient(135deg,#7F1D1D 0%,#B71C1C 100%);color:white;padding:16px;border-radius:8px;border-left:5px solid #450A0A;margin:12px 0;box-shadow:0 4px 8px rgba(127,29,29,0.3)}
.threat-high{background:linear-gradient(135deg,#FFE5E5 0%,#FFCDD2 100%);padding:16px;border-radius:8px;border-left:5px solid #F96167;margin:12px 0;box-shadow:0 2px 6px rgba(249,97,103,0.2)}
.threat-medium{background:linear-gradient(135deg,#FFF9E5 0%,#FFF9C4 100%);padding:16px;border-radius:8px;border-left:5px solid#FFC107;margin:12px 0;box-shadow:0 2px 6px rgba(255,193,7,0.2)}
.threat-low{background:linear-gradient(135deg,#E8F5E9 0%,#C8E6C9 100%);padding:16px;border-radius:8px;border-left:5px solid #2C5F2D;margin:12px 0;box-shadow:0 2px 6px rgba(44,95,45,0.2)}

/* Assessment Feedback */
.correct-answer{background:linear-gradient(135deg,#C8E6C9 0%,#A5D6A7 100%);padding:16px;border-radius:8px;border-left:5px solid #4CAF50;margin:12px 0;box-shadow:0 2px 6px rgba(76,175,80,0.3)}
.incorrect-answer{background:linear-gradient(135deg,#FFCDD2 0%,#EF9A9A 100%);padding:16px;border-radius:8px;border-left:5px solid #F44336;margin:12px 0;box-shadow:0 2px 6px rgba(244,67,54,0.3)}
.partial-answer{background:linear-gradient(135deg,#FFF9C4 0%,#FFF59D 100%);padding:16px;border-radius:8px;border-left:5px solid #FFC107;margin:12px 0;box-shadow:0 2px 6px rgba(255,193,7,0.3)}

/* Score Display */
.score-excellent{background:linear-gradient(135deg,#4CAF50 0%,#66BB6A 100%);color:white;padding:24px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:bold;box-shadow:0 4px 12px rgba(76,175,80,0.4)}
.score-good{background:linear-gradient(135deg,#8BC34A 0%,#9CCC65 100%);color:white;padding:24px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:bold;box-shadow:0 4px 12px rgba(139,195,74,0.4)}
.score-fair{background:linear-gradient(135deg,#FFC107 0%,#FFCA28 100%);color:white;padding:24px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:bold;box-shadow:0 4px 12px rgba(255,193,7,0.4)}
.score-poor{background:linear-gradient(135deg,#FF5722 0%,#FF7043 100%);color:white;padding:24px;border-radius:12px;text-align:center;font-size:1.3em;font-weight:bold;box-shadow:0 4px 12px rgba(255,87,34,0.4)}

/* Badges */
.badge-completed{background:linear-gradient(135deg,#2C5F2D 0%,#388E3C 100%);color:white;padding:6px 16px;border-radius:20px;font-size:0.85em;font-weight:700;box-shadow:0 2px 4px rgba(44,95,45,0.3)}
.badge-locked{background:linear-gradient(135deg,#757575 0%,#9E9E9E 100%);color:white;padding:6px 16px;border-radius:20px;font-size:0.85em;font-weight:700;box-shadow:0 2px 4px rgba(117,117,117,0.3)}

/* Info Boxes */
.info-box{background:linear-gradient(135deg,#E3F2FD 0%,#BBDEFB 100%);padding:20px;border-radius:8px;border-left:4px solid #1976D2;margin:16px 0;box-shadow:0 2px 6px rgba(25,118,210,0.2)}
.success-box{background:linear-gradient(135deg,#E8F5E9 0%,#C8E6C9 100%);padding:20px;border-radius:8px;border-left:4px solid #388E3C;margin:16px 0;box-shadow:0 2px 6px rgba(56,142,60,0.2)}
.warning-box{background:linear-gradient(135deg,#FFF3E0 0%,#FFE0B2 100%);padding:20px;border-radius:8px;border-left:4px solid #F57C00;margin:16px 0;box-shadow:0 2px 6px rgba(245,124,0,0.2)}
.learning-box{background:linear-gradient(135deg,#E8EAF6 0%,#C5CAE9 100%);padding:20px;border-radius:8px;border-left:4px solid #3F51B5;margin:16px 0;box-shadow:0 2px 6px rgba(63,81,181,0.2)}

/* Component Cards */
.component-card{background:linear-gradient(135deg,#F5F5F5 0%,#EEEEEE 100%);padding:16px;border-radius:8px;border-left:3px solid #028090;margin:10px 0;box-shadow:0 2px 4px rgba(2,128,144,0.2);transition:all 0.3s ease}
.component-card:hover{transform:translateX(4px);box-shadow:0 4px 8px rgba(2,128,144,0.3)}

.mitigation-card{background:linear-gradient(135deg,#FFFDE7 0%,#FFF9C4 100%);padding:16px;border-radius:8px;border-left:4px solid #F9A825;margin:10px 0;box-shadow:0 2px 4px rgba(249,168,37,0.2)}

/* Metrics Dashboard */
.metric-card{
    background:white;
    border:2px solid #E5E7EB;
    border-radius:12px;
    padding:20px;
    text-align:center;
    box-shadow:0 2px 6px rgba(0,0,0,0.1);
    transition:all 0.3s ease;
}
.metric-card:hover{
    transform:translateY(-4px);
    box-shadow:0 6px 16px rgba(0,0,0,0.15);
    border-color:#3B82F6;
}
.metric-icon{font-size:40px;margin-bottom:12px}
.metric-value{font-size:32px;font-weight:bold;margin:8px 0}
.metric-label{font-size:13px;color:#6B7280;text-transform:uppercase;letter-spacing:0.5px}

/* Progress Stepper */
.step-active{color:#3B82F6;font-weight:700;font-size:1.1em}
.step-complete{color:#10B981;font-weight:600}
.step-pending{color:#9CA3AF;font-weight:400}

/* Collapsible Sections */
details{
    background:white;
    border:1px solid #E5E7EB;
    border-radius:10px;
    padding:18px;
    margin:14px 0;
    box-shadow:0 2px 6px rgba(0,0,0,0.05);
    transition:all 0.3s ease;
}
details:hover{box-shadow:0 4px 12px rgba(0,0,0,0.1)}
details summary{
    font-weight:700;
    color:#1F2937;
    cursor:pointer;
    list-style:none;
    display:flex;
    align-items:center;
    transition:color 0.3s ease;
}
details summary:hover{color:#3B82F6}
details[open] summary{color:#3B82F6;margin-bottom:16px;padding-bottom:16px;border-bottom:2px solid #E5E7EB}

/* Summary Box for Scope */
.summary-box{
    background:linear-gradient(135deg,#FEF3C7 0%,#FDE68A 100%);
    border:2px solid #F59E0B;
    border-radius:10px;
    padding:20px;
    margin:16px 0;
    box-shadow:0 4px 10px rgba(245,158,11,0.2);
}
.summary-box h4{color:#92400E;margin-top:0}

/* Typography Enhancements */
h1{font-weight:800;letter-spacing:-0.5px}
h2{font-weight:700;letter-spacing:-0.3px;color:#1F2937}
h3{font-weight:600;color:#374151}
.section-header{
    font-size:1.4em;
    font-weight:700;
    color:#1F2937;
    margin:24px 0 16px 0;
    padding-bottom:8px;
    border-bottom:3px solid #3B82F6;
}
</style>""", unsafe_allow_html=True)

def init_session_state():
    defaults = {
        'selected_workshop': None, 'completed_workshops': set(), 'unlocked_workshops': set(['1']), 
        'current_step': 1, 'threats': [], 'user_answers': [], 'total_score': 0, 'max_score': 0, 
        'diagram_generated': None, 'detailed_diagram_generated': None, 'show_unlock_form': {}
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# ============================================================================
# ENTERPRISE SCOPE DOCUMENTATION - COMPREHENSIVE FOR ALL WORKSHOPS
# ============================================================================

ENTERPRISE_SCOPE = {
    "1": {  # Workshop 1: E-Commerce
        "executive_summary": {
            "business_context": """
            TechMart is a Series A e-commerce startup operating in the competitive consumer 
            electronics market. With 50,000 monthly active users and $2M in annual recurring 
            revenue, the platform represents critical revenue-generating infrastructure. 
            The system processes approximately 5,000 transactions monthly with an average 
            order value of $350.
            """,
            "strategic_importance": """
            As the primary revenue channel, the e-commerce platform's security directly impacts:
            • Customer trust and brand reputation
            • Regulatory compliance (PCI-DSS, GDPR, CCPA)
            • Revenue continuity and growth trajectory
            • Competitive positioning in crowded market
            """,
            "risk_tolerance": "MEDIUM - Some risk acceptable for rapid feature deployment, but no tolerance for payment data breaches or extended outages"
        },
        "system_classification": {
            "confidentiality": "CONFIDENTIAL - Contains customer PII and payment card data",
            "integrity": "HIGH - Order accuracy critical for customer satisfaction and financial accuracy",
            "availability": "MEDIUM-HIGH - 99.5% uptime SLA, 4-hour maximum acceptable downtime",
            "criticality": "TIER 2 - Revenue-critical but not life-safety critical"
        },
        "stakeholders": {
            "business_owner": "CTO / VP Engineering",
            "system_owner": "Engineering Manager - Platform Team",
            "security_sme": "Security Architect / AppSec Lead",
            "compliance_officer": "Legal/Compliance Manager",
            "additional": ["Customer Support Manager", "DevOps Lead"]
        },
        "regulatory_framework": {
            "pci_dss": {
                "level": "Level 4 (< 1M transactions annually)",
                "requirements": [
                    "Requirement 1: Install and maintain firewall configuration",
                    "Requirement 3: Protect stored cardholder data",
                    "Requirement 4: Encrypt transmission of cardholder data",
                    "Requirement 6: Develop secure systems (SDL, patch management)",
                    "Requirement 8: Identify and authenticate access",
                    "Requirement 10: Track and monitor all access"
                ],
                "assessment_type": "Self-Assessment Questionnaire (SAQ A-EP)",
                "next_assessment": "Annual - Q2 2026"
            },
            "gdpr": {
                "data_types": ["Personal data (names, emails, addresses)", "Behavioral data (browsing history)"],
                "lawful_basis": "Contract performance & Legitimate interest",
                "data_retention": "7 years for transaction records, 2 years for marketing data",
                "dpo_required": "No (< 250 employees)",
                "key_controls": ["Data encryption", "Access logging", "Data breach procedures"]
            },
            "ccpa": {
                "threshold_met": "Yes (revenue > $25M expected in 2026)",
                "consumer_rights": ["Right to know", "Right to delete", "Right to opt-out"],
                "notice_requirements": "Privacy policy + collection notices",
                "data_sales": "Not applicable - no data selling"
            }
        },
        "architecture_overview": {
            "deployment_model": "Public Cloud (AWS)",
            "region": "us-east-1 (primary), us-west-2 (DR)",
            "technology_stack": {
                "frontend": "React 18.2, TypeScript, CloudFront + S3",
                "backend": "Node.js 18 LTS, Express 4.18, ECS Fargate",
                "database": "RDS PostgreSQL 14.7, Multi-AZ",
                "cache": "ElastiCache Redis 7.0",
                "cdn": "CloudFront with WAF",
                "monitoring": "CloudWatch, DataDog APM"
            },
            "integration_points": [
                "Stripe Payment Gateway (PCI SAQ A-EP compliance)",
                "SendGrid Email Service (transactional emails)",
                "AWS S3 (product images, user uploads)",
                "Segment (analytics and customer data platform)"
            ],
            "network_zones": {
                "dmz": "CloudFront, ALB, WAF",
                "app_tier": "ECS Fargate tasks (private subnets)",
                "data_tier": "RDS, ElastiCache (isolated subnets, no internet access)",
                "admin": "Bastion host with MFA for emergency access"
            },
            "authentication": {
                "customer": "Email + password with optional Google OAuth2, planned MFA rollout Q3 2026",
                "admin": "SSO via Okta with mandatory MFA, certificate-based for SSH"
            }
        },
        "asset_inventory": {
            "crown_jewels": [
                {
                    "asset": "Payment Card Data (via Stripe)",
                    "sensitivity": "CRITICAL",
                    "impact_if_compromised": "Regulatory fines (PCI-DSS), immediate business shutdown risk",
                    "protection": "Never stored - tokenized via Stripe, PCI SAQ A-EP scope"
                },
                {
                    "asset": "Customer Authentication Credentials",
                    "sensitivity": "CRITICAL",
                    "impact_if_compromised": "Account takeovers, fraudulent orders, brand damage",
                    "protection": "bcrypt hashing (cost factor 12), rate limiting, account lockout"
                }
            ],
            "high_value": [
                {
                    "asset": "Customer PII Database",
                    "sensitivity": "HIGH",
                    "data_types": "Names, emails, shipping addresses, phone numbers",
                    "volume": "~50,000 customer records",
                    "protection": "AES-256 encryption at rest, TLS 1.3 in transit, access logging"
                },
                {
                    "asset": "Order History & Transaction Records",
                    "sensitivity": "HIGH",
                    "retention": "7 years (financial record keeping)",
                    "protection": "Encrypted backups, immutable audit logs"
                }
            ],
            "medium_value": [
                {
                    "asset": "Shopping Cart & Session Data",
                    "sensitivity": "MEDIUM",
                    "storage": "Redis with 30-day TTL",
                    "protection": "Encrypted session cookies (HttpOnly, Secure, SameSite)"
                }
            ]
        },
        "security_objectives_extended": {
            "confidentiality": [
                "Protect customer PII from unauthorized access",
                "Prevent payment data exposure (via Stripe tokenization)",
                "Secure session tokens and authentication credentials",
                "Encrypt sensitive data at rest and in transit"
            ],
            "integrity": [
                "Prevent unauthorized modification of product prices",
                "Ensure order accuracy and data consistency",
                "Protect against SQL injection and XSS attacks",
                "Maintain audit trail for all data changes"
            ],
            "availability": [
                "Maintain 99.5% uptime SLA",
                "Prevent DDoS attacks on public endpoints",
                "Ensure database scalability during peak loads",
                "Implement auto-scaling for traffic spikes"
            ],
            "authenticity": [
                "Verify user identity with strong authentication",
                "Implement MFA for high-risk transactions",
                "Validate all API requests with tokens"
            ],
            "non_repudiation": [
                "Comprehensive audit logging of all transactions",
                "Immutable transaction records",
                "Cryptographic signing of critical operations"
            ],
            "authorization": [
                "Role-based access control (RBAC) for admin functions",
                "Principle of least privilege for all access",
                "API endpoint authorization on every request"
            ]
        },
        "threat_landscape": {
            "known_threat_actors": [
                "E-commerce credential stuffing botnets",
                "Magecart-style JavaScript skimmers",
                "SQL injection automated scanners",
                "DDoS extortion groups"
            ],
            "attack_vectors": [
                "Credential stuffing with leaked password databases",
                "XSS injection in search and comment fields",
                "API enumeration and BOLA attacks",
                "Brute force attacks on admin panels"
            ],
            "vulnerability_history": [
                "E-commerce platforms commonly targeted for payment skimming",
                "40% of web applications vulnerable to XSS (OWASP)",
                "API security issues in 90% of applications (Salt Security)"
            ],
            "threat_intelligence": [
                "OWASP Top 10 2021",
                "OWASP API Security Top 10",
                "PCI-DSS vulnerability scanning requirements",
                "CVE database for framework vulnerabilities"
            ]
        },
        "assumptions_constraints": {
            "security_assumptions": [
                "AWS infrastructure security is managed by AWS",
                "Stripe handles PCI-DSS compliance for payment processing",
                "Third-party SaaS providers (SendGrid, Segment) are secure",
                "DNS and domain registrar are properly secured"
            ],
            "architectural_constraints": [
                "Must use serverless ECS Fargate (no EC2 management)",
                "PostgreSQL chosen for ACID compliance",
                "React SPA architecture for modern UX",
                "CloudFront CDN for global performance"
            ],
            "resource_constraints": [
                "Security budget: $50K annually",
                "Team size: 8 engineers (1 security-focused)",
                "Timeline: 6-month development cycle",
                "Compliance deadline: Q2 2026"
            ],
            "organizational_constraints": [
                "Board requires SOC 2 Type II within 18 months",
                "Sales requires 99.5% uptime in contracts",
                "Marketing wants rapid feature deployment"
            ]
        },
        "success_criteria": {
            "coverage_metrics": "100% of components with identified threats",
            "depth_metrics": "Minimum 3 threats per critical component",
            "mitigation_metrics": "90% of high/critical threats with defined mitigations",
            "quality_metrics": "Risk assessment validated by security architect"
        }
    },
    "2": {  # Workshop 2: Microservices Banking
        "executive_summary": {
            "business_context": """
            CloudBank is a regional financial institution serving 500,000 retail and business customers
            with $12B in deposits. The mobile banking platform processes 2M transactions daily with
            zero tolerance for data breaches or financial fraud. API-first architecture enables
            third-party integrations while maintaining strict security controls.
            """,
            "strategic_importance": """
            Mobile banking platform is mission-critical for:
            • Customer account access and fund transfers
            • Regulatory compliance (GLBA, SOC 2, PCI-DSS)
            • Third-party fintech integrations (Plaid, etc.)
            • Competitive advantage in digital banking
            """,
            "risk_tolerance": "ZERO TOLERANCE - Financial services require highest security standards"
        },
        "system_classification": {
            "confidentiality": "RESTRICTED - Financial data, PII, transaction history",
            "integrity": "CRITICAL - Financial accuracy is non-negotiable",
            "availability": "CRITICAL - 99.95% uptime SLA, <5 minute RTO",
            "criticality": "TIER 1 - Business-critical financial infrastructure"
        },
        "regulatory_framework": {
            "glba": {
                "safeguards_rule": "Implement comprehensive information security program",
                "privacy_rule": "Annual privacy notices to customers",
                "pretexting": "Protection against social engineering"
            },
            "soc2": {
                "type": "SOC 2 Type II (annual audit)",
                "trust_criteria": ["Security", "Availability", "Confidentiality"],
                "controls": "AICPA TSC framework"
            },
            "pci_dss": {
                "level": "Level 2 (1-6M transactions annually)",
                "scope": "Card-on-file, payment processing",
                "qsa_required": "Yes - Qualified Security Assessor"
            }
        },
        "threat_landscape": {
            "known_threat_actors": [
                "APT38 (Lazarus Group) - North Korean state-sponsored targeting banks",
                "FIN7 - Financial cybercrime syndicate",
                "Scattered Spider - Social engineering experts",
                "Insider threats - Privileged access abuse"
            ],
            "attack_vectors": [
                "Business Email Compromise (BEC) targeting employees",
                "BOLA vulnerabilities in banking APIs",
                "Service mesh lateral movement",
                "JWT token theft from mobile devices"
            ]
        }
    },
    "3": {  # Workshop 3: Multi-Tenant SaaS
        "executive_summary": {
            "business_context": """
            DataInsight is a B2B analytics SaaS platform serving 500 enterprise customers including
            Fortune 500 companies. Platform processes 10TB of customer data daily across shared
            infrastructure. Tenant isolation is THE critical security requirement - a single
            cross-tenant breach would destroy business viability.
            """,
            "strategic_importance": """
            Multi-tenant architecture enables:
            • Cost-effective scaling to thousands of customers
            • Enterprise-grade analytics for mid-market pricing
            • However: Tenant isolation failure = complete business failure
            • SOC 2 Type II required by all enterprise customers
            """,
            "risk_tolerance": "ZERO TOLERANCE for tenant isolation breaches - business-ending event"
        },
        "system_classification": {
            "confidentiality": "RESTRICTED - Customer business intelligence, proprietary data",
            "integrity": "HIGH - Analytics accuracy impacts customer decisions",
            "availability": "HIGH - 99.99% SLA for enterprise tier",
            "criticality": "TIER 1 - Tenant isolation is existential requirement"
        },
        "regulatory_framework": {
            "soc2": {
                "type": "SOC 2 Type II (mandatory for enterprise sales)",
                "focus": "Tenant isolation controls (CC6.1)",
                "auditor": "Big 4 accounting firm"
            },
            "gdpr": {
                "role": "Data Processor for EU customers",
                "dpa_required": "Data Processing Agreements with each customer",
                "tenant_isolation": "GDPR requires data separation"
            },
            "iso27001": {
                "status": "Pursuing certification",
                "focus": "Information security management system"
            }
        },
        "threat_landscape": {
            "known_threat_actors": [
                "Corporate espionage - Competitor intelligence gathering",
                "Insider threats - Privileged user accessing tenant data",
                "Supply chain attacks - Compromised dependencies"
            ],
            "attack_vectors": [
                "SQL injection to bypass tenant filters",
                "JWT token manipulation to change tenant_id",
                "Shared Kafka topics without ACLs",
                "Database missing Row-Level Security (RLS)"
            ]
        },
        "architecture_overview": {
            "deployment_model": "Multi-tenant SaaS on AWS",
            "tenant_isolation_model": "Logical isolation with shared infrastructure",
            "database_strategy": "Shared schema with tenant_id column + RLS policies"
        }
    },
    "4": {  # Workshop 4: IoT Healthcare
        "executive_summary": {
            "business_context": """
            HealthMonitor provides FDA-registered continuous glucose monitoring (CGM) devices
            serving 10,000 diabetic patients. System is LIFE-CRITICAL - device malfunctions or
            alert failures can result in patient death. HIPAA compliance mandatory. System must
            prevent: 1) Patient harm via device tampering, 2) PHI breaches, 3) Alert suppression.
            """,
            "strategic_importance": """
            Medical IoT platform with unique requirements:
            • FDA 21 CFR Part 11 compliance (software as medical device)
            • HIPAA Security & Privacy Rules (PHI protection)
            • Safety-critical system - patient lives depend on alerts
            • HL7 integration with legacy hospital EHR systems
            """,
            "risk_tolerance": "ZERO TOLERANCE for patient safety risks - regulatory and ethical imperative"
        },
        "system_classification": {
            "confidentiality": "RESTRICTED - Protected Health Information (PHI)",
            "integrity": "SAFETY-CRITICAL - Data accuracy impacts patient treatment",
            "availability": "SAFETY-CRITICAL - 99.99% uptime, <30 second alert delivery",
            "criticality": "TIER 0 - Life-safety critical system"
        },
        "regulatory_framework": {
            "hipaa": {
                "covered_entity": "Healthcare provider",
                "privacy_rule": "PHI access controls, minimum necessary",
                "security_rule": "Administrative, physical, technical safeguards",
                "breach_notification": "<60 days for breaches affecting 500+ individuals"
            },
            "fda": {
                "classification": "Class II medical device (510(k) clearance)",
                "regulations": "21 CFR Part 11 (electronic records/signatures)",
                "cybersecurity": "FDA Cybersecurity Guidance 2023",
                "post_market": "Mandatory adverse event reporting"
            },
            "hitech": {
                "breach_penalties": "$100-$50,000 per violation, $1.5M annual max",
                "encryption_requirement": "PHI encryption at rest and in transit"
            }
        },
        "threat_landscape": {
            "known_threat_actors": [
                "Nation-state APTs targeting healthcare (APT41)",
                "Ransomware groups (BlackCat, LockBit)",
                "Medical device hackers (research/proof-of-concept)",
                "Insider threats - Healthcare workers accessing PHI"
            ],
            "attack_vectors": [
                "Firmware tampering on patient devices",
                "Replay attacks on vital signs data",
                "Alert flooding to suppress critical notifications",
                "HL7 v2 message injection (no authentication)",
                "Bluetooth MITM attacks on CGM devices"
            ]
        },
        "architecture_overview": {
            "deployment_model": "Hybrid - Edge devices + Cloud + On-prem EHR",
            "safety_critical_path": "CGM → Gateway → Cloud → Alert Service → Clinician Portal",
            "legacy_integration": "HL7 v2 over MLLP to hospital EHR systems"
        },
        "asset_inventory": {
            "crown_jewels": [
                {
                    "asset": "Patient Vital Signs (Real-time Glucose)",
                    "sensitivity": "SAFETY-CRITICAL + PHI",
                    "impact_if_compromised": "Patient death from missed alerts, HIPAA breach",
                    "protection": "End-to-end encryption, replay protection, redundant alert channels"
                },
                {
                    "asset": "Device Firmware",
                    "sensitivity": "SAFETY-CRITICAL",
                    "impact_if_compromised": "Malicious firmware could harm patients",
                    "protection": "Secure boot, firmware signing, TPM attestation"
                }
            ]
        },
        "success_criteria": {
            "safety_metrics": "Zero patient harm events due to security failures",
            "availability_metrics": "99.99% alert delivery success rate",
            "compliance_metrics": "Zero HIPAA violations, FDA audit compliance"
        }
    }
}


# ============================================================================
# COMPLETE THREAT DATABASE - ALL THREATS FOR ALL WORKSHOPS
# ============================================================================

PREDEFINED_THREATS = {
    "1": [
        {"id": "T-001", "stride": "Spoofing", "component": "Web Frontend → API Backend",
         "threat": "Session hijacking via XSS allowing attacker to impersonate legitimate user",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["HttpOnly and Secure flags on cookies", "Content Security Policy (CSP) headers", 
                                 "Input sanitization with DOMPurify", "XSS prevention through output encoding"],
         "incorrect_mitigations": ["Increase password complexity", "Add rate limiting", "Enable 2FA"],
         "explanation": "XSS attacks allow stealing session cookies. HttpOnly prevents JavaScript from accessing cookies, CSP restricts allowed script sources, and input sanitization prevents malicious script injection.",
         "compliance": "OWASP Top 10 A03:2021 (Injection), OWASP ASVS V5.3.3, PCI-DSS 6.5.7",
         "points": 10,
         "why_this_risk": "Medium likelihood because XSS is common (found in 40% of apps). High impact because session hijacking gives full account access.",
         "why_these_controls": "HttpOnly blocks cookie theft via JavaScript. CSP prevents unauthorized scripts from running. DOMPurify sanitizes user input before rendering.",
         "real_world": "British Airways fined £20M for breach involving XSS (2019). Magecart attacks use XSS to steal payment data."},
        
        {"id": "T-002", "stride": "Tampering", "component": "API Backend → Database",
         "threat": "SQL injection allowing modification of product prices or customer data",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Parameterized queries/Prepared statements", "Use ORM (Sequelize, TypeORM)", 
                                 "Input validation with allowlisting", "Least privilege database user"],
         "incorrect_mitigations": ["Encrypt database connections", "Add logging", "Use strong passwords"],
         "explanation": "SQL injection exploits unsanitized user input in SQL queries. Parameterized queries separate SQL code from data, preventing injection.",
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1, CWE-89",
         "points": 10,
         "why_this_risk": "Medium likelihood - still found in 25% of applications. Critical impact - can modify/delete ALL data including prices and customer records.",
         "why_these_controls": "Parameterized queries treat user input as data only, never as executable SQL. ORMs abstract SQL generation safely.",
         "real_world": "Target breach (2013) started with SQL injection. 40M credit cards stolen, $18M settlement."},
        
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
         "real_world": "Equifax breach exposed 147M people. Encryption would have limited damage. €50M GDPR fine."},
        
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
         "real_world": "GitHub survived 1.35 Tbps DDoS (2018) using auto-scaling and traffic filtering. Dyn DNS attack took down Twitter, Netflix (2016)."},
        
        {"id": "T-005", "stride": "Elevation of Privilege", "component": "API Backend",
         "threat": "Broken access control allowing regular user to access admin endpoints",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Role-Based Access Control (RBAC)", "Validate permissions on every request", 
                                 "Principle of least privilege", "Deny by default access policy"],
         "incorrect_mitigations": ["Encrypt API traffic", "Add logging", "Use strong authentication"],
         "explanation": "Authentication confirms identity, but authorization determines access rights. RBAC ensures users only access resources appropriate for their role.",
         "compliance": "OWASP Top 10 A01:2021 (Broken Access Control), PCI-DSS 7.1, NIST 800-53 AC-2",
         "points": 10,
         "why_this_risk": "Medium likelihood - common developer oversight. High impact - admin access = full system control, data modification.",
         "why_these_controls": "Check authorization on EVERY request, not just authentication. Deny by default means explicitly grant each permission.",
         "real_world": "Instagram API bug (2020) let users access admin endpoints. Peloton API allowed accessing any user's data (2021)."}
    ],
    "2": [
        {"id": "T-101", "stride": "Information Disclosure", "component": "API Gateway → Payment Service",
         "threat": "BOLA (Broken Object Level Authorization) - accessing other users' data",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Object-level authorization on every API call", "Resource ownership checks", "Use UUIDs not sequential IDs", "Validate user owns resource"],
         "incorrect_mitigations": ["Add authentication", "Encrypt account ID", "Add rate limiting"],
         "explanation": "BOLA = broken object authorization. API returns data based only on object ID without verifying ownership. Must verify user owns the specific resource being accessed.",
         "compliance": "OWASP API Security Top 10 - API1:2023",
         "points": 10,
         "why_this_risk": "High likelihood - trivial to exploit in banking apps. Critical impact - access to all customer financial data.",
         "why_these_controls": "Validate ownership on EVERY API call. Database query must include: WHERE id=? AND user_id=current_user",
         "real_world": "Peloton API (2021): Any user could access any other user's data by changing user ID."}
    ],
    "3": [
        {"id": "T-201", "stride": "Information Disclosure", "component": "Query Service → Data Warehouse",
         "threat": "Cross-Tenant Data Access - SQL missing tenant filter",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Row-Level Security (RLS) in PostgreSQL/Redshift", "Tenant context validation on every request", "WHERE tenant_id = :tenant_id in ALL queries", "Database-level enforcement"],
         "incorrect_mitigations": ["Application-level filtering only", "Trust tenant_id from request", "No RLS policies"],
         "explanation": "SQL query doesn't include tenant filter. Attacker from Tenant A crafts API request that returns Tenant B's data.",
         "compliance": "SOC 2 CC6.1 (Logical Access), ISO 27001 A.9.4.1",
         "points": 10,
         "why_this_risk": "High/critical - THE multi-tenant SaaS vulnerability. One query returns data from ALL tenants.",
         "why_these_controls": "PostgreSQL RLS policies enforce tenant_id filter on ALL queries automatically at database level.",
         "real_world": "GitHub Gist (2020): Cross-tenant data leak. Complete business failure if exposed."}
    ],
    "4": [
        {"id": "T-301", "stride": "Tampering", "component": "Glucose Monitor → IoT Gateway",
         "threat": "Device Tampering - firmware modification or physical access",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Secure boot with signature verification", "Firmware signing with manufacturer key", "TPM (Trusted Platform Module)", "Physical tamper detection sensors"],
         "incorrect_mitigations": ["No firmware verification", "Unsigned firmware allowed", "No tamper seals"],
         "explanation": "Attacker gains physical access to glucose monitor. Reflashes firmware to report false readings. Patient doesn't get alerts for dangerously high glucose.",
         "compliance": "FDA 21 CFR Part 11, IEC 62304 (medical device software)",
         "points": 10,
         "why_this_risk": "Medium/CRITICAL - needs physical access but LIFE-THREATENING. Patient could die from missed alerts.",
         "why_these_controls": "Secure boot verifies firmware signature before boot. Only signed firmware will execute.",
         "real_world": "Medtronic insulin pump recall: Unencrypted RF allowed unauthorized dosing."}
    ]
}


# ============================================================================
# WORKSHOP CONFIGURATIONS WITH ENTERPRISE SCOPE INTEGRATION
# ============================================================================

WORKSHOPS = {
    "1": {
        "name": "Workshop 1: Web Application (2-Tier)",
        "architecture_type": "2-Tier Web Application",
        "level": "Foundation",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": None,
        "scenario": {
            "title": "TechMart E-Commerce Store",
            "description": "React frontend + Node.js API + PostgreSQL database",
            "business_context": "Series A startup, 50K monthly users, $2M revenue",
            "assets": ["Customer PII", "Payment data", "User credentials", "Order history"],
            "objectives": ["Confidentiality: Protect customer PII", "Integrity: Order accuracy", "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS Level 4", "GDPR", "CCPA"],
            "components": [
                {"name": "Customer", "type": "external_entity", "description": "End users"},
                {"name": "Web Frontend", "type": "process", "description": "React SPA"},
                {"name": "API Backend", "type": "process", "description": "Node.js/Express"},
                {"name": "Database", "type": "datastore", "description": "PostgreSQL"},
                {"name": "Stripe", "type": "external_entity", "description": "Payments"}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend", "data": "HTTP", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend", "data": "API calls", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database", "data": "SQL", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe", "data": "Payments", "protocol": "HTTPS"}
            ],
            "trust_boundaries": [
                {"name": "Internet", "description": "Untrusted → Trusted", "components": ["Customer", "Web Frontend"]},
                {"name": "Application", "description": "Frontend → Backend", "components": ["Web Frontend", "API Backend"]},
                {"name": "Data", "description": "App → Storage", "components": ["API Backend", "Database"]}
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
        "scenario": {
            "title": "CloudBank Mobile Banking",
            "description": "API Gateway + Multiple Services + Message Queues",
            "business_context": "Regional bank, 500K customers",
            "assets": ["Financial data", "Transactions", "PII", "OAuth tokens"],
            "objectives": ["Confidentiality", "Integrity", "Availability: 99.95%"],
            "compliance": ["PCI-DSS", "SOC 2", "GLBA"],
            "components": [
                {"name": "Mobile App", "type": "external_entity", "description": "iOS/Android"},
                {"name": "API Gateway", "type": "process", "description": "AWS API Gateway"},
                {"name": "User Service", "type": "process", "description": "Auth (ECS)"},
                {"name": "Payment Service", "type": "process", "description": "Transfers (ECS)"},
                {"name": "User DB", "type": "datastore", "description": "DynamoDB"},
                {"name": "Transaction DB", "type": "datastore", "description": "Aurora"}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway", "data": "HTTPS", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "User Service", "data": "Auth", "protocol": "HTTP/2"},
                {"source": "API Gateway", "destination": "Payment Service", "data": "Payments", "protocol": "HTTP/2"}
            ],
            "trust_boundaries": [
                {"name": "Client", "description": "Mobile → Cloud", "components": ["Mobile App", "API Gateway"]},
                {"name": "Service Mesh", "description": "Microservices", "components": ["User Service", "Payment Service"]}
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
        "scenario": {
            "title": "DataInsight Analytics Platform",
            "description": "Shared infrastructure with logical tenant isolation",
            "business_context": "B2B SaaS, 500 enterprise customers",
            "assets": ["Business data", "Tenant metadata", "API keys"],
            "objectives": ["Tenant isolation", "Data integrity", "99.99% SLA"],
            "compliance": ["SOC 2 Type II", "ISO 27001", "GDPR"],
            "components": [
                {"name": "Web Dashboard", "type": "external_entity", "description": "React SPA"},
                {"name": "API Gateway", "type": "process", "description": "Kong"},
                {"name": "Query Service", "type": "process", "description": "Analytics"},
                {"name": "Data Warehouse", "type": "datastore", "description": "Redshift"}
            ],
            "data_flows": [
                {"source": "Web Dashboard", "destination": "API Gateway", "data": "Requests", "protocol": "HTTPS"},
                {"source": "Query Service", "destination": "Data Warehouse", "data": "SQL", "protocol": "Redshift"}
            ],
            "trust_boundaries": [
                {"name": "Tenant A", "description": "Tenant A isolation", "components": []},
                {"name": "Tenant B", "description": "Tenant B isolation", "components": []}
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
        "scenario": {
            "title": "HealthMonitor Connected Care",
            "description": "IoT Devices + Edge Gateway + Cloud + Legacy Integration",
            "business_context": "FDA-registered device, 10K patients",
            "assets": ["PHI", "Vital signs (safety-critical)", "Device calibration"],
            "objectives": ["Safety: Data integrity (HIGHEST)", "Privacy: PHI", "Availability: 99.99%"],
            "compliance": ["HIPAA", "FDA 21 CFR Part 11", "HITECH"],
            "components": [
                {"name": "Glucose Monitor", "type": "external_entity", "description": "CGM device"},
                {"name": "IoT Gateway", "type": "process", "description": "Edge device"},
                {"name": "Device Data Svc", "type": "process", "description": "Telemetry"},
                {"name": "Patient DB", "type": "datastore", "description": "Aurora"},
                {"name": "Web Portal", "type": "external_entity", "description": "Clinician portal"}
            ],
            "data_flows": [
                {"source": "Glucose Monitor", "destination": "IoT Gateway", "data": "Glucose", "protocol": "BLE"},
                {"source": "IoT Gateway", "destination": "Device Data Svc", "data": "Vitals", "protocol": "MQTT/TLS"},
                {"source": "Device Data Svc", "destination": "Patient DB", "data": "PHI", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Patient Home", "description": "Physical access", "components": ["Glucose Monitor", "IoT Gateway"]},
                {"name": "Cloud", "description": "Trusted AWS", "components": ["Device Data Svc"]}
            ]
        }
    }
}


# ============================================================================
# ENHANCED DIAGRAM GENERATION WITH PROFESSIONAL STYLING
# ============================================================================

def generate_high_level_architecture(workshop_config):
    """Generate enterprise-grade high-level architecture with gradients"""
    try:
        dot = Digraph(comment="High-Level Architecture", format="png")
        dot.attr(rankdir="LR", size="12,8", fontname="Helvetica", bgcolor="white", dpi="150")
        dot.attr("node", fontname="Helvetica-Bold", fontsize="16", shape="box", 
                style="rounded,filled", margin="0.3,0.2")
        dot.attr("edge", fontname="Helvetica", fontsize="12", penwidth="2.5", color="#6B7280")
        
        scenario = workshop_config["scenario"]
        
        # Professional gradient styling
        dot.node("Users", "Users/Clients", 
                fillcolor="#FEE2E2:#EF4444", gradientangle="90",
                color="#991B1B", penwidth="3")
        
        dot.node("Application", f"{scenario['title']}\\nApplication Layer", 
                fillcolor="#DBEAFE:#3B82F6", gradientangle="90",
                color="#1E40AF", penwidth="3")
        
        dot.node("Data", "Data Layer\\n(Databases & Storage)", 
                fillcolor="#D1FAE5:#10B981", gradientangle="90",
                color="#065F46", penwidth="3")
        
        # Check for external services
        ext_services = [c["name"] for c in scenario["components"] if c["type"] == "external_entity" 
                       and any(kw in c["name"] for kw in ["Stripe", "SendGrid", "Twilio", "Plaid"])]
        if ext_services:
            dot.node("External", f"External Services\\n{chr(10).join(ext_services[:3])}", 
                    fillcolor="#FEF3C7:#FCD34D", gradientangle="90",
                    color="#92400E", penwidth="3")
            dot.edge("Application", "External", "APIs", color="#F97316", penwidth="2.5")
        
        # Professional edges
        dot.edge("Users", "Application", "HTTPS", color="#3B82F6", penwidth="3", 
                arrowsize="1.3", style="bold")
        dot.edge("Application", "Data", "Queries", color="#10B981", penwidth="3",
                arrowsize="1.3", style="bold")
        
        path = dot.render("high_level_arch", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception as e:
        st.warning("⚠️ Unable to generate diagram. Please continue with the workshop.")
        return None

def generate_detailed_dfd(workshop_config, threats=[]):
    """Generate detailed DFD with professional enterprise styling"""
    try:
        dot = Digraph(comment="Detailed DFD", format="png")
        dot.attr(rankdir="TB", size="18,16", fontname="Helvetica", bgcolor="#FAFAFA", 
                splines="ortho", dpi="150")
        dot.attr("node", fontname="Helvetica", fontsize="11")
        dot.attr("edge", fontname="Helvetica", fontsize="9", penwidth="2.0")

        # Enterprise styles with gradients
        styles = {
            "external_entity": {
                "shape": "box", "style": "filled,rounded", 
                "fillcolor": "#FEE2E2:#EF4444", "gradientangle": "90",
                "color": "#991B1B", "penwidth": "3", "fontname": "Helvetica-Bold"
            },
            "process": {
                "shape": "box", "style": "filled,rounded",
                "fillcolor": "#DBEAFE:#3B82F6", "gradientangle": "90",
                "color": "#1E40AF", "penwidth": "3", "fontname": "Helvetica-Bold"
            },
            "datastore": {
                "shape": "cylinder", "style": "filled",
                "fillcolor": "#D1FAE5:#10B981", "gradientangle": "90",
                "color": "#065F46", "penwidth": "3", "fontname": "Helvetica-Bold"
            }
        }

        # Map threats
        node_threats = {}
        edge_threats = {}
        for threat in threats:
            threat_id = threat.get("matched_threat_id", threat.get("id", ""))
            affected = threat.get("component", "")
            
            if "→" in affected:
                edge_threats.setdefault(affected, []).append(threat_id)
            else:
                node_threats.setdefault(affected, []).append(threat_id)

        # Add nodes with threat highlighting
        for comp in workshop_config["scenario"]["components"]:
            name = comp["name"]
            threat_ids = node_threats.get(name, [])
            
            # Enhanced label with icon
            icon = "👤" if comp["type"] == "external_entity" else "⚙️" if comp["type"] == "process" else "💾"
            label = f"{icon} {name}\\n{comp['description']}"
            if threat_ids:
                label += f"\\n⚠️ Threats: {', '.join(threat_ids)}"
            
            style = styles.get(comp["type"], styles["process"]).copy()
            if threat_ids:
                # Highlight threatened components
                style["fillcolor"] = "#FFEDD5:#FB923C"
                style["color"] = "#EA580C"
                style["penwidth"] = "4"
            
            dot.node(name, label, **style)

        # Add edges with professional styling
        for flow in workshop_config["scenario"]["data_flows"]:
            edge_key = f"{flow['source']} → {flow['destination']}"
            threat_ids = edge_threats.get(edge_key, [])
            
            label = f"{flow['data']}\\n({flow['protocol']})"
            if threat_ids:
                label += f"\\n⚠️ {', '.join(threat_ids)}"
            
            if threat_ids:
                dot.edge(flow['source'], flow['destination'], label=label,
                        color="#EF4444", penwidth="4", style="bold,dashed",
                        arrowsize="1.5", fontcolor="#991B1B")
            else:
                dot.edge(flow['source'], flow['destination'], label=label,
                        color="#6B7280", penwidth="2.5", arrowsize="1.3")

        # Add trust boundaries with professional styling
        for idx, boundary in enumerate(workshop_config["scenario"]["trust_boundaries"]):
            with dot.subgraph(name=f"cluster_{idx}") as c:
                c.attr(label=f"🔒 {boundary['name']}\\n{boundary['description']}", 
                      style="dashed,bold", color="#7C3AED", fontsize="14",
                      penwidth="3.5", bgcolor="#F5F3FF:#FAFAFA",
                      gradientangle="90", fontname="Helvetica-Bold",
                      fontcolor="#5B21B6", margin="25")
                for comp_name in boundary.get("components", []):
                    if any(c["name"] == comp_name for c in workshop_config["scenario"]["components"]):
                        c.node(comp_name)

        path = dot.render("detailed_dfd", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception as e:
        st.warning("⚠️ Unable to generate detailed diagram. Continuing with text-based analysis.")
        return None


# ============================================================================
# ENTERPRISE PDF GENERATION WITH PROFESSIONAL LAYOUTS
# ============================================================================

def create_enterprise_pdf_styles():
    """Create professional PDF styles"""
    styles = getSampleStyleSheet()
    
    # Enterprise title style
    styles.add(ParagraphStyle(
        'EnterpriseTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=colors.HexColor('#1E40AF'),
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        leading=34
    ))
    
    # Section heading
    styles.add(ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=18,
        textColor=colors.HexColor('#028090'),
        spaceAfter=14,
        spaceBefore=16,
        fontName='Helvetica-Bold',
        borderPadding=8,
        leftIndent=0
    ))
    
    # Subsection
    styles.add(ParagraphStyle(
        'SubSection',
        parent=styles['Heading3'],
        fontSize=14,
        textColor=colors.HexColor('#2C5F2D'),
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    ))
    
    return styles

def generate_enterprise_cover_page(story, workshop_config, styles):
    """Generate professional cover page with branding"""
    story.append(Spacer(1, 1*inch))
    
    # Main title
    story.append(Paragraph("THREAT MODEL ASSESSMENT REPORT", styles['EnterpriseTitle']))
    
    # Decorative line
    story.append(HRFlowable(
        width="80%",
        thickness=4,
        color=colors.HexColor('#3B82F6'),
        spaceBefore=16,
        spaceAfter=16,
        hAlign='CENTER'
    ))
    
    # System name
    story.append(Paragraph(workshop_config['scenario']['title'], styles['Heading2']))
    story.append(Spacer(1, 0.3*inch))
    
    # Classification banner
    classification_data = [[
        Paragraph('<para align="center"><b>CLASSIFICATION: INTERNAL USE</b></para>', 
                 styles['Normal'])
    ]]
    
    classification_table = Table(classification_data, colWidths=[6*inch])
    classification_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FEF3C7')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#92400E')),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOX', (0, 0), (-1, -1), 3, colors.HexColor('#F59E0B')),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    story.append(classification_table)
    story.append(Spacer(1, 0.5*inch))
    
    # Metadata table
    metadata = [
        ['Report Type:', 'Comprehensive Threat Assessment'],
        ['Workshop:', workshop_config['name']],
        ['Architecture:', workshop_config.get('architecture_type', 'N/A')],
        ['Security Level:', workshop_config['level']],
        ['Date Generated:', datetime.now().strftime('%B %d, %Y')],
        ['Version:', '1.0']
    ]
    
    meta_table = Table(metadata, colWidths=[2.5*inch, 3.5*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E3F2FD')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#D1D5DB')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    story.append(meta_table)

def generate_complete_threat_model_pdf(workshop_config, workshop_id):
    """Generate comprehensive enterprise-grade PDF"""
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, 
                              topMargin=0.75*inch, bottomMargin=0.75*inch,
                              leftMargin=0.75*inch, rightMargin=0.75*inch)
        story = []
        styles = create_enterprise_pdf_styles()
        
        # Generate cover page
        generate_enterprise_cover_page(story, workshop_config, styles)
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['SectionHeading']))
        
        scope = ENTERPRISE_SCOPE.get(workshop_id, {})
        exec_summary = scope.get('executive_summary', {})
        
        if exec_summary:
            story.append(Paragraph("<b>Business Context</b>", styles['SubSection']))
            story.append(Paragraph(exec_summary.get('business_context', ''), styles['Normal']))
            story.append(Spacer(1, 0.15*inch))
            
            story.append(Paragraph("<b>Strategic Importance</b>", styles['SubSection']))
            story.append(Paragraph(exec_summary.get('strategic_importance', ''), styles['Normal']))
            story.append(Spacer(1, 0.15*inch))
            
            story.append(Paragraph("<b>Risk Tolerance</b>", styles['SubSection']))
            story.append(Paragraph(exec_summary.get('risk_tolerance', ''), styles['Normal']))
        
        story.append(PageBreak())
        
        # System Classification
        story.append(Paragraph("System Classification", styles['SectionHeading']))
        
        classification = scope.get('system_classification', {})
        if classification:
            class_data = [
                ['Attribute', 'Classification'],
                ['Confidentiality', classification.get('confidentiality', 'N/A')],
                ['Integrity', classification.get('integrity', 'N/A')],
                ['Availability', classification.get('availability', 'N/A')],
                ['Criticality', classification.get('criticality', 'N/A')]
            ]
            
            class_table = Table(class_data, colWidths=[2.5*inch, 4*inch])
            class_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#028090')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#D1D5DB')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), 
                 [colors.white, colors.HexColor('#F9FAFB')])
            ]))
            
            story.append(class_table)
        
        story.append(PageBreak())
        
        # Architecture Overview
        story.append(Paragraph("Architecture Overview", styles['SectionHeading']))
        
        scenario = workshop_config['scenario']
        story.append(Paragraph(f"<b>Description:</b> {scenario['description']}", styles['Normal']))
        story.append(Paragraph(f"<b>Business Context:</b> {scenario['business_context']}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("<b>Components:</b>", styles['Normal']))
        for comp in scenario['components']:
            story.append(Paragraph(f"• {comp['name']} ({comp['type']}): {comp['description']}", 
                                 styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("<b>Trust Boundaries:</b>", styles['Normal']))
        for boundary in scenario['trust_boundaries']:
            story.append(Paragraph(f"• {boundary['name']}: {boundary['description']}", 
                                 styles['Normal']))
        
        story.append(PageBreak())
        
        # Security Objectives
        story.append(Paragraph("Security Objectives", styles['SectionHeading']))
        for obj in scenario['objectives']:
            story.append(Paragraph(f"• {obj}", styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("<b>Critical Assets:</b>", styles['Normal']))
        for asset in scenario['assets']:
            story.append(Paragraph(f"• {asset}", styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("<b>Compliance Requirements:</b>", styles['Normal']))
        for comp in scenario['compliance']:
            story.append(Paragraph(f"• {comp}", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
        
    except Exception as e:
        st.warning("⚠️ Unable to generate PDF report at this time. Please try downloading CSV results instead.")
        return None


# ============================================================================
# UTILITY FUNCTIONS AND UI COMPONENTS
# ============================================================================

def enterprise_card(title, content, icon="📊", color="blue"):
    """Professional card component"""
    color_classes = {
        'blue': 'enterprise-card',
        'green': 'enterprise-card enterprise-card-green',
        'red': 'enterprise-card enterprise-card-red',
        'purple': 'enterprise-card enterprise-card-purple',
        'orange': 'enterprise-card enterprise-card-orange'
    }
    
    return f"""
    <div class="{color_classes.get(color, 'enterprise-card')}">
        <div style="display: flex; align-items: center; margin-bottom: 16px;">
            <span style="font-size: 32px; margin-right: 14px;">{icon}</span>
            <h3 style="margin: 0; font-size: 20px; font-weight: 700;">{title}</h3>
        </div>
        <div style="color: #374151; line-height: 1.7; font-size: 15px;">
            {content}
        </div>
    </div>
    """

def enterprise_metrics_row(metrics_list):
    """Display professional metrics dashboard"""
    cols = st.columns(len(metrics_list))
    
    for idx, metric in enumerate(metrics_list):
        with cols[idx]:
            st.markdown(f"""
            <div class="metric-card" style="border-color: {metric.get('color', '#E5E7EB')};">
                <div class="metric-icon">{metric['icon']}</div>
                <div class="metric-value" style="color: {metric.get('color', '#1F2937')};">
                    {metric['value']}
                </div>
                <div class="metric-label">{metric['label']}</div>
            </div>
            """, unsafe_allow_html=True)

def calculate_threat_score(user_threat, predefined_threat):
    """Calculate score with detailed feedback"""
    score, max_score, feedback = 0, predefined_threat["points"], []
    
    # Component check (2 points)
    if user_threat["component"] == predefined_threat["component"]:
        score += 2
        feedback.append("✓ Correct component identified")
    else:
        feedback.append(f"✗ Wrong component. Expected: {predefined_threat['component']}")
    
    # STRIDE category (2 points)
    if user_threat["stride"] == predefined_threat["stride"]:
        score += 2
        feedback.append("✓ Correct STRIDE category")
    else:
        feedback.append(f"✗ Wrong STRIDE. Expected: {predefined_threat['stride']}")
    
    # Risk assessment (2 points)
    if user_threat["likelihood"] == predefined_threat["likelihood"]:
        score += 1
        feedback.append("✓ Correct likelihood")
    else:
        feedback.append(f"✗ Likelihood should be: {predefined_threat['likelihood']}")
    
    if user_threat["impact"] == predefined_threat["impact"]:
        score += 1
        feedback.append("✓ Correct impact")
    else:
        feedback.append(f"✗ Impact should be: {predefined_threat['impact']}")
    
    # Mitigations (4 points)
    correct_mits = set(predefined_threat["correct_mitigations"])
    user_mits = set(user_threat.get("selected_mitigations", []))
    incorrect_mits = set(predefined_threat.get("incorrect_mitigations", []))
    
    correct_selected = user_mits & correct_mits
    incorrect_selected = user_mits & incorrect_mits
    
    if len(correct_selected) >= 3:
        score += 4
        feedback.append(f"✓ Excellent mitigation selection ({len(correct_selected)} correct)")
    elif len(correct_selected) >= 2:
        score += 3
        feedback.append(f"✓ Good mitigation selection ({len(correct_selected)} correct)")
    elif len(correct_selected) >= 1:
        score += 2
        feedback.append(f"⚠ Partial mitigation selection ({len(correct_selected)} correct)")
    else:
        feedback.append("✗ No correct mitigations selected")
    
    if incorrect_selected:
        score -= len(incorrect_selected)
        feedback.append(f"✗ Incorrect mitigations penalty: {', '.join(incorrect_selected)}")
    
    return max(0, score), max_score, feedback

def is_workshop_unlocked(ws_id):
    return ws_id in st.session_state.unlocked_workshops

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
    except:
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
    except:
        pass

load_progress()


# ============================================================================
# MAIN APPLICATION - SIDEBAR AND HOME SCREEN
# ============================================================================

# SIDEBAR
with st.sidebar:
    st.title("🔒 STRIDE Enterprise Lab")
    st.markdown("### Professional Threat Modeling")
    st.markdown("---")
    
    # Current score display
    if st.session_state.selected_workshop and st.session_state.max_score > 0:
        score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
        
        st.markdown("### 📊 Current Score")
        st.progress(score_pct / 100)
        st.markdown(f"**{st.session_state.total_score}/{st.session_state.max_score}** ({score_pct:.1f}%)")
        
        if score_pct >= 90:
            st.success("🏆 Excellent!")
        elif score_pct >= 75:
            st.info("👍 Good!")
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
            if st.button(f"Workshop {ws_id}", key=f"ws_{ws_id}", 
                        disabled=not unlocked, use_container_width=True):
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
        
        # Unlock form
        if not unlocked and ws_id != "1":
            unlock_key = f"unlock_{ws_id}"
            if unlock_key not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[unlock_key] = False
            
            if st.button(f"🔓 Unlock", key=f"unlock_btn_{ws_id}", use_container_width=True):
                st.session_state.show_unlock_form[unlock_key] = not st.session_state.show_unlock_form[unlock_key]
                st.rerun()
            
            if st.session_state.show_unlock_form[unlock_key]:
                with st.form(f"unlock_form_{ws_id}"):
                    st.caption("Enter unlock code")
                    code = st.text_input("Code", type="password", key=f"code_{ws_id}")
                    if st.form_submit_button("Submit"):
                        if code == WORKSHOP_CODES.get(ws_id):
                            st.session_state.unlocked_workshops.add(ws_id)
                            st.session_state.show_unlock_form[unlock_key] = False
                            save_progress()
                            st.success("✅ Unlocked!")
                            st.rerun()
                        else:
                            st.error("❌ Invalid code")
        
        with st.expander("ℹ️ Details"):
            st.caption(f"**Level:** {ws_config['level']}")
            st.caption(f"**Duration:** {ws_config['duration']}")
            st.caption(f"**Architecture:** {ws_config.get('architecture_type', 'N/A')}")
    
    st.markdown("---")
    
    with st.expander("📚 STRIDE Reference"):
        st.markdown("""
        **S** - Spoofing  
        **T** - Tampering  
        **R** - Repudiation  
        **I** - Information Disclosure  
        **D** - Denial of Service  
        **E** - Elevation of Privilege
        """)

# MAIN CONTENT - HOME SCREEN
if not st.session_state.selected_workshop:
    st.title("🎓 STRIDE Threat Modeling Enterprise Lab")
    st.markdown("### Professional Security Assessment Platform")
    
    st.markdown(enterprise_card(
        "Welcome to Enterprise Threat Modeling",
        """This interactive platform teaches systematic threat modeling using the STRIDE framework
        with enterprise-grade documentation, professional diagrams, and comprehensive reporting.
        <br><br>
        <strong>Key Features:</strong>
        <ul>
        <li>Comprehensive scope documentation with regulatory frameworks</li>
        <li>Professional architecture diagrams with gradients and styling</li>
        <li>Real-time scoring and instant feedback</li>
        <li>Enterprise-grade PDF reports with cover pages</li>
        <li>Progressive learning path across 4 workshops</li>
        </ul>
        """,
        "🎯",
        "blue"
    ), unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Metrics dashboard
    enterprise_metrics_row([
        {"icon": "🎯", "value": "4", "label": "Workshops", "color": "#3B82F6"},
        {"icon": "🔒", "value": "15+", "label": "Threat Scenarios", "color": "#10B981"},
        {"icon": "📊", "value": "100%", "label": "Coverage", "color": "#F97316"},
        {"icon": "🏆", "value": "90%", "label": "Mastery Goal", "color": "#7C3AED"}
    ])
    
    st.markdown("---")
    st.markdown('<h2 class="section-header">Progressive Workshop Path</h2>', unsafe_allow_html=True)
    
    cols = st.columns(4)
    for idx, (ws_id, ws) in enumerate(WORKSHOPS.items()):
        with cols[idx]:
            unlocked = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            
            badge_text = "✅ Completed" if completed else "🔓 Available" if unlocked else "🔒 Locked"
            card_color = "green" if completed else "blue" if unlocked else "red"
            
            st.markdown(enterprise_card(
                f"Workshop {ws_id}",
                f"""
                <strong>{ws['scenario']['title']}</strong><br>
                <em>{ws['level']}</em><br><br>
                {ws['architecture_type']}<br>
                {ws['target_threats']} threats<br><br>
                <span class="badge-{'completed' if completed else 'locked' if not unlocked else 'available'}">
                {badge_text}</span>
                """,
                "📚" if ws_id == "1" else "🏢" if ws_id == "2" else "☁️" if ws_id == "3" else "🏥",
                card_color
            ), unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown('<h2 class="section-header">How It Works</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(enterprise_card(
            "Learning Path",
            """
            1. <strong>Enterprise Scope</strong> - Understand business context and regulations<br>
            2. <strong>Architecture Decomposition</strong> - Analyze with professional DFDs<br>
            3. <strong>STRIDE Application</strong> - Learn systematic threat identification<br>
            4. <strong>Threat Assessment</strong> - Identify and mitigate threats<br>
            5. <strong>Scoring & Feedback</strong> - Get instant evaluation<br>
            6. <strong>Enterprise Reporting</strong> - Generate professional PDFs
            """,
            "📖",
            "purple"
        ), unsafe_allow_html=True)
    
    with col2:
        st.markdown(enterprise_card(
            "What You'll Master",
            """
            <ul style="margin: 0; padding-left: 20px;">
            <li>STRIDE threat methodology</li>
            <li>Architecture security analysis</li>
            <li>Risk assessment (Likelihood × Impact)</li>
            <li>Mitigation strategy selection</li>
            <li>Compliance mapping (PCI-DSS, GDPR, HIPAA)</li>
            <li>Professional documentation</li>
            </ul>
            """,
            "🎓",
            "orange"
        ), unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### Ready to Begin?")
    st.info("👈 Select **Workshop 1** from the sidebar to start your threat modeling journey!")
    
    st.stop()


# ============================================================================
# WORKSHOP STEPS - ENHANCED WITH ENTERPRISE FEATURES
# ============================================================================

current_workshop = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

st.title(current_workshop["name"])
st.markdown(f"**{current_workshop['level']}** | {current_workshop['scenario']['title']}")

# Professional progress stepper
progress_cols = st.columns(5)
steps = ["1️⃣ Scope", "2️⃣ Decompose", "3️⃣ Threats", "4️⃣ Assess", "5️⃣ Complete"]
step_values = [1, 2, 3, 4, 5]

for idx, (step, step_val) in enumerate(zip(steps, step_values)):
    with progress_cols[idx]:
        if st.session_state.current_step > step_val:
            st.markdown(f'<span class="step-complete">{step}</span>', unsafe_allow_html=True)
        elif st.session_state.current_step == step_val:
            st.markdown(f'<span class="step-active">{step}</span>', unsafe_allow_html=True)
        else:
            st.markdown(f'<span class="step-pending">{step}</span>', unsafe_allow_html=True)

st.markdown("---")

# STEP 1: ENTERPRISE SCOPE WITH HIGH-LEVEL ARCHITECTURE
if st.session_state.current_step == 1:
    st.markdown('<h2 class="section-header">Step 1: Enterprise Scope & Security Objectives</h2>', 
                unsafe_allow_html=True)
    
    scenario = current_workshop["scenario"]
    scope = ENTERPRISE_SCOPE.get(st.session_state.selected_workshop, {})
    
    # Executive Summary Card
    exec_summary = scope.get('executive_summary', {})
    if exec_summary:
        st.markdown(enterprise_card(
            "Executive Summary",
            f"""
            <strong>Business Context:</strong><br>
            {exec_summary.get('business_context', 'N/A')}<br><br>
            <strong>Strategic Importance:</strong><br>
            {exec_summary.get('strategic_importance', 'N/A')}<br><br>
            <strong>Risk Tolerance:</strong> {exec_summary.get('risk_tolerance', 'N/A')}
            """,
            "📋",
            "blue"
        ), unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Application Overview
        st.markdown(enterprise_card(
            "Application Overview",
            f"""
            <strong>Description:</strong> {scenario['description']}<br>
            <strong>Business Context:</strong> {scenario['business_context']}
            """,
            "🎯",
            "green"
        ), unsafe_allow_html=True)
        
        # Security Objectives
        objectives_html = "<br>".join([f"• {obj}" for obj in scenario["objectives"]])
        st.markdown(enterprise_card(
            "Security Objectives",
            objectives_html,
            "🎯",
            "purple"
        ), unsafe_allow_html=True)
    
    with col2:
        # System Classification
        classification = scope.get('system_classification', {})
        if classification:
            st.markdown(enterprise_card(
                "System Classification",
                f"""
                <strong>Confidentiality:</strong> {classification.get('confidentiality', 'N/A')}<br><br>
                <strong>Integrity:</strong> {classification.get('integrity', 'N/A')}<br><br>
                <strong>Availability:</strong> {classification.get('availability', 'N/A')}<br><br>
                <strong>Criticality:</strong> {classification.get('criticality', 'N/A')}
                """,
                "🔐",
                "orange"
            ), unsafe_allow_html=True)
    
    # Critical Assets & Compliance
    col3, col4 = st.columns(2)
    
    with col3:
        assets_html = "<br>".join([f"• {asset}" for asset in scenario["assets"]])
        st.markdown(enterprise_card(
            "Critical Assets",
            assets_html,
            "💎",
            "blue"
        ), unsafe_allow_html=True)
    
    with col4:
        compliance_html = "<br>".join([f"• {comp}" for comp in scenario["compliance"]])
        st.markdown(enterprise_card(
            "Compliance Requirements",
            compliance_html,
            "📜",
            "green"
        ), unsafe_allow_html=True)
    
    st.markdown("---")
    
    # HIGH-LEVEL ARCHITECTURE
    st.markdown('<h3 class="section-header">High-Level System Architecture</h3>', 
                unsafe_allow_html=True)
    
    with st.spinner("Generating enterprise architecture diagram..."):
        high_level = generate_high_level_architecture(current_workshop)
    
    if high_level:
        st.image(f"data:image/png;base64,{high_level}",
                 caption="High-Level Enterprise Architecture",
                 use_column_width=True)
    
    # Component Summary
    st.markdown("### 📦 Component Summary")
    comp_types = {"external_entity": [], "process": [], "datastore": []}
    for comp in scenario["components"]:
        comp_types[comp["type"]].append(comp)
    
    comp_col1, comp_col2, comp_col3 = st.columns(3)
    
    with comp_col1:
        st.markdown("**👤 External Entities**")
        for comp in comp_types["external_entity"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br><small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    
    with comp_col2:
        st.markdown("**⚙️ Processes**")
        for comp in comp_types["process"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br><small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    
    with comp_col3:
        st.markdown("**💾 Data Stores**")
        for comp in comp_types["datastore"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br><small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    
    st.markdown("---")
    
    if st.button("Next: Decompose System ➡️", type="primary", use_container_width=True):
        st.session_state.current_step = 2
        save_progress()
        st.rerun()

# STEP 2: DETAILED DECOMPOSITION
elif st.session_state.current_step == 2:
    st.markdown('<h2 class="section-header">Step 2: Detailed Architecture Decomposition</h2>',
                unsafe_allow_html=True)
    
    scenario = current_workshop["scenario"]
    
    st.markdown(enterprise_card(
        "Professional Data Flow Diagram",
        """This detailed DFD shows all components, data flows, protocols, and trust boundaries.
        Trust boundaries (purple dashed boxes) mark critical security zones where threats concentrate.""",
        "🗺️",
        "purple"
    ), unsafe_allow_html=True)
    
    # GENERATE DETAILED DFD
    with st.spinner("Generating enterprise DFD with trust boundaries..."):
        detailed_dfd = generate_detailed_dfd(current_workshop, st.session_state.threats)
    
    if detailed_dfd:
        st.image(f"data:image/png;base64,{detailed_dfd}",
                 caption="Enterprise Data Flow Diagram with Trust Boundaries",
                 use_column_width=True)
        st.session_state.detailed_diagram_generated = detailed_dfd
    
    # Data Flows Table
    st.markdown("### 📝 Data Flows")
    flows_df = pd.DataFrame([
        {
            "Source": f["source"],
            "→": "→",
            "Destination": f["destination"],
            "Data": f["data"],
            "Protocol": f.get("protocol", "N/A")
        }
        for f in scenario["data_flows"]
    ])
    st.dataframe(flows_df, use_container_width=True, hide_index=True)
    
    # Trust Boundaries
    st.markdown("### 🔒 Trust Boundaries - Critical Analysis Points")
    for boundary in scenario["trust_boundaries"]:
        with st.expander(f"🔐 {boundary['name']}: {boundary['description']}", expanded=False):
            st.info(f"**Why critical:** Data crossing this boundary requires authentication, "
                   f"authorization, encryption, and validation checks.")
            if boundary.get("components"):
                st.markdown(f"**Components:** {', '.join(boundary['components'])}")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back to Scope", use_container_width=True):
            st.session_state.current_step = 1
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Identify Threats ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()


# STEP 3: IDENTIFY THREATS
elif st.session_state.current_step == 3:
    st.markdown('<h2 class="section-header">Step 3: Identify Threats Using STRIDE</h2>',
                unsafe_allow_html=True)
    
    st.markdown(enterprise_card(
        "Threat Identification Process",
        f"""1. Select a threat scenario from the predefined list<br>
        2. Identify affected component/flow<br>
        3. Assess likelihood and impact<br>
        4. Select appropriate mitigations<br>
        5. Get instant scored feedback!<br><br>
        <strong>Goal:</strong> Analyze {current_workshop['target_threats']} threats with 90%+ accuracy""",
        "🎯",
        "blue"
    ), unsafe_allow_html=True)
    
    # Threat Selection Form
    with st.form("threat_form"):
        st.subheader("➕ Select Threat to Analyze")
        
        threat_options = {
            f"{t['id']}: {t['threat'][:70]}...": t 
            for t in workshop_threats
        }
        
        selected_key = st.selectbox("Choose threat:", list(threat_options.keys()))
        selected_predefined = threat_options[selected_key]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Your Analysis")
            
            all_components = [c["name"] for c in current_workshop["scenario"]["components"]]
            all_flows = [f"{f['source']} → {f['destination']}" 
                        for f in current_workshop["scenario"]["data_flows"]]
            
            user_component = st.selectbox("Component/Flow:", all_components + all_flows)
            user_stride = st.selectbox("STRIDE Category:",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"])
            user_likelihood = st.select_slider("Likelihood:",
                options=["Low", "Medium", "High", "Critical"], value="Medium")
            user_impact = st.select_slider("Impact:",
                options=["Low", "Medium", "High", "Critical"], value="Medium")
        
        with col2:
            st.markdown("### Select Mitigations")
            all_mits = (selected_predefined["correct_mitigations"] + 
                       selected_predefined.get("incorrect_mitigations", []))
            random.shuffle(all_mits)
            user_mitigations = st.multiselect("Controls:", all_mits)
        
        submitted = st.form_submit_button("✅ Submit & Get Score", 
                                          type="primary", use_container_width=True)
        
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
            save_progress()
            st.rerun()
    
    # Display Previous Answers
    if st.session_state.user_answers:
        st.markdown("---")
        st.markdown(f"### 📊 Your Answers ({len(st.session_state.user_answers)}/{current_workshop['target_threats']})")
        
        for idx, answer in enumerate(st.session_state.user_answers):
            score_pct = (answer["score"] / answer["max_score"]) * 100
            
            feedback_class = "correct-answer" if score_pct >= 80 else "partial-answer" if score_pct >= 50 else "incorrect-answer"
            emoji = "✅" if score_pct >= 80 else "⚠️" if score_pct >= 50 else "❌"
            
            with st.expander(f"{emoji} Answer {idx + 1}: {answer['matched_threat_id']} ({score_pct:.0f}%)"):
                st.markdown(f'<div class="{feedback_class}">'
                          f'<strong>Component:</strong> {answer["component"]}<br>'
                          f'<strong>STRIDE:</strong> {answer["stride"]}<br>'
                          f'<strong>Risk:</strong> {answer["likelihood"]} × {answer["impact"]}<br>'
                          f'</div>', unsafe_allow_html=True)
                
                for fb in answer["feedback"]:
                    if "✓" in fb:
                        st.success(fb)
                    elif "✗" in fb:
                        st.error(fb)
                    else:
                        st.warning(fb)
    
    # Progress
    progress = len(st.session_state.user_answers) / current_workshop['target_threats']
    st.progress(min(progress, 1.0))
    
    if len(st.session_state.user_answers) >= current_workshop['target_threats']:
        score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
        score_class = "score-excellent" if score_pct >= 90 else "score-good" if score_pct >= 75 else "score-fair"
        st.markdown(f'<div class="{score_class}">Ready to proceed!<br>Score: {score_pct:.1f}%</div>',
                   unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back", use_container_width=True):
            st.session_state.current_step = 2
            save_progress()
            st.rerun()
    with col2:
        if st.button("Next: Assessment ➡️", type="primary", use_container_width=True):
            if st.session_state.user_answers:
                st.session_state.current_step = 4
                save_progress()
                st.rerun()

# STEP 4: ASSESSMENT
elif st.session_state.current_step == 4:
    st.markdown('<h2 class="section-header">Step 4: Assessment & Results</h2>',
                unsafe_allow_html=True)
    
    score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    # Metrics Dashboard
    enterprise_metrics_row([
        {"icon": "📝", "value": f"{st.session_state.total_score}/{st.session_state.max_score}", 
         "label": "Total Score", "color": "#3B82F6"},
        {"icon": "📊", "value": f"{score_pct:.1f}%", "label": "Percentage", 
         "color": "#10B981" if score_pct >= 75 else "#F97316"},
        {"icon": "🎯", "value": len(st.session_state.user_answers), "label": "Threats Analyzed", 
         "color": "#7C3AED"},
        {"icon": "🏆", "value": "A" if score_pct >= 90 else "B" if score_pct >= 80 else "C", 
         "label": "Grade", "color": "#F59E0B"}
    ])
    
    st.markdown("---")
    
    # Threat-Mapped Diagram
    st.markdown("### 🗺️ Threat-Mapped Architecture")
    with st.spinner("Generating threat map..."):
        threat_mapped = generate_detailed_dfd(current_workshop, st.session_state.threats)
    
    if threat_mapped:
        st.image(f"data:image/png;base64,{threat_mapped}",
                 caption="Architecture with Identified Threats",
                 use_column_width=True)
    
    # Export Options
    st.markdown("---")
    st.markdown("### 📥 Export Professional Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        results_df = pd.DataFrame([{
            "Threat_ID": a["matched_threat_id"],
            "Component": a["component"],
            "STRIDE": a["stride"],
            "Score": f"{a['score']}/{a['max_score']}"
        } for a in st.session_state.user_answers])
        
        csv_data = results_df.to_csv(index=False)
        st.download_button("📥 Download CSV", csv_data,
            f"results_ws{st.session_state.selected_workshop}.csv",
            "text/csv", use_container_width=True)
    
    with col2:
        with st.spinner("Generating enterprise PDF..."):
            pdf_data = generate_complete_threat_model_pdf(
                current_workshop, st.session_state.selected_workshop)
        
        if pdf_data:
            st.download_button("📄 Enterprise PDF Report", pdf_data,
                f"threat_model_ws{st.session_state.selected_workshop}.pdf",
                "application/pdf", use_container_width=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬅️ Back", use_container_width=True):
            st.session_state.current_step = 3
            save_progress()
            st.rerun()
    with col2:
        if st.button("Complete Workshop ➡️", type="primary", use_container_width=True):
            st.session_state.current_step = 5
            save_progress()
            st.rerun()

# STEP 5: COMPLETE
elif st.session_state.current_step == 5:
    score_pct = (st.session_state.total_score / st.session_state.max_score) * 100
    
    if score_pct >= 90:
        st.balloons()
    
    score_class = "score-excellent" if score_pct >= 90 else "score-good"
    st.markdown(f'''<div class="{score_class}">
        🏆 Workshop Complete!<br>
        Final Score: {score_pct:.1f}%
    </div>''', unsafe_allow_html=True)
    
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()
    
    # Next steps
    next_ws = str(int(st.session_state.selected_workshop) + 1)
    if next_ws in WORKSHOPS:
        st.info(f"**Next:** Workshop {next_ws} - {WORKSHOPS[next_ws]['name']}")
        
        if is_workshop_unlocked(next_ws):
            if st.button(f"Start Workshop {next_ws} ➡️", type="primary", use_container_width=True):
                st.session_state.selected_workshop = next_ws
                st.session_state.current_step = 1
                st.session_state.threats = []
                st.session_state.user_answers = []
                st.session_state.total_score = 0
                st.session_state.max_score = 0
                save_progress()
                st.rerun()
    else:
        st.success("🏆 All workshops completed!")
    
    st.markdown("---")
    
    if st.button("🏠 Return Home", use_container_width=True):
        st.session_state.selected_workshop = None
        st.session_state.current_step = 1
        save_progress()
        st.rerun()

st.markdown("---")
st.caption("STRIDE Threat Modeling Enterprise Lab | Professional Security Assessment Platform")
