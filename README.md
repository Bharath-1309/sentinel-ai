@'
# SentinelAI

## AI-Powered SOC Investigation & Incident Response Platform

SentinelAI is an enterprise-inspired Security Operations Center (SOC) platform that combines security event ingestion, detection engineering, alert correlation, threat hunting, UEBA, threat intelligence, case management, AI-assisted investigation, and SOAR into a unified platform.

The project demonstrates practical cybersecurity engineering concepts used in modern SOC environments.

---

## Architecture

```text
                    Security Events
                          |
                          v
                +-------------------+
                |  Data Ingestion   |
                | Linux / Windows / |
                | Network Events    |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Event Normalizer  |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Detection Engine  |
                | Detection-as-Code |
                +---------+---------+
                          |
              +-----------+-----------+
              |                       |
              v                       v
       +-------------+         +-------------+
       | Correlation |         |    UEBA     |
       |   Engine    |         | Behavioral  |
       +------+------+         +------+------+
              |                       |
              +-----------+-----------+
                          |
                          v
                +-------------------+
                | Incident Engine   |
                | Risk + MITRE      |
                +---------+---------+
                          |
              +-----------+-----------+
              |                       |
              v                       v
       +-------------+         +-------------+
       | Threat Intel|         |   Hunting   |
       | IOC Engine  |         | Query Engine|
       +------+------+         +------+------+
              |                       |
              +-----------+-----------+
                          |
                          v
                +-------------------+
                | Case Management   |
                +---------+---------+
                          |
                          v
                +-------------------+
                | AI SOC Agent      |
                | Investigation     |
                +---------+---------+
                          |
                          v
                +-------------------+
                | SOAR Engine       |
                | Playbooks         |
                +---------+---------+
                          |
                          v
                +-------------------+
                | SOC Dashboard     |
                | FastAPI + Streamlit|
                +-------------------+
Core Capabilities
Security Event Ingestion

Supports a unified event model for:

Linux authentication logs
Windows security/authentication events
Network security events
Multiple ingestion adapters
Detection Engineering

Detection-as-Code architecture with detection rules for:

SSH brute force
SSH password spraying
Suspicious root login
Windows authentication attacks
Credential dumping indicators
Network reconnaissance/scanning
Phishing-related activity
Alert Correlation

Correlates related security events into higher-confidence attack scenarios.

Examples include:

Reconnaissance → Credential Attack
Credential Attack → Successful Login
Credential Attack + Credential Dumping

Correlation considers source IP, temporal ordering, relevant alerts, and severity.

UEBA

User and Entity Behavior Analytics establishes historical behavioral baselines and identifies deviations such as:

Abnormally high failed-login volume
New source IPs
New hosts
Unusual authentication activity
Threat Hunting

Structured hunting queries support:

AND / OR conditions
Equality and inequality operators
String matching
Numeric comparisons
Time ranges
Sorting
Result limits
Threat Intelligence & IOC Management

Supported IOC types:

IP
Domain
URL
Hash

Capabilities include:

IOC validation
IOC storage
IOC lookup
IOC enrichment
Threat-intelligence aggregation
Confidence scoring
Provider evidence

AbuseIPDB integration is included for IP reputation enrichment.

MITRE ATT&CK

Security detections can be mapped to MITRE ATT&CK techniques.

Examples:

Detection	Technique
Brute Force	T1110
Password Spraying	T1110.003
Incident & Case Management

Cases support:

Incident-to-case conversion
Severity
Status
Assignment
Analyst notes
Evidence
IOC references
MITRE information
AI investigation results

Case statuses:

OPEN
INVESTIGATING
CONTAINED
RESOLVED
CLOSED
AI SOC Investigation

The AI SOC agent analyzes structured incident and case context and assists with:

Incident analysis
Investigation observations
Risk context
Findings
Security recommendations

External AI failures are handled gracefully, and automated tests use mocked AI responses.

SOAR

SentinelAI includes a safe SOAR engine with predefined response playbooks.

Credential Compromise Response
Investigate source
Review authentication logs
Reset credentials
Collect endpoint evidence
Preserve security logs
Reconnaissance Response
Investigate source
Review network activity
Check exploitation attempts
Preserve security logs
Generic Security Response
Investigate source
Review related logs
Identify affected systems
Preserve security logs
Monitor activity

SOAR actions are intentionally simulated. The project does not directly modify production endpoints, credentials, firewalls, or other external infrastructure.

SOC Workflow
Security Event
      |
      v
Normalization
      |
      v
Detection
      |
      v
Correlation / UEBA
      |
      v
Risk Assessment
      |
      v
Threat Intelligence
      |
      v
Incident
      |
      v
Case
      |
      v
AI Investigation
      |
      v
SOAR Playbook
      |
      v
Auditable Response
Dashboard

The Streamlit SOC dashboard provides:

SOC overview
Risk distribution
Security analysis
Phishing analysis
Incident management
Case management
AI investigation
SOAR response
SOAR execution history
Configured playbooks

The dashboard communicates with the FastAPI backend.

REST API

SentinelAI uses FastAPI for its backend.

Start the API:

uvicorn api:app --reload

API:

http://127.0.0.1:8000

Swagger documentation:

http://127.0.0.1:8000/docs

Major API areas include:

/analyze
/incidents
/phishing/analyze
/hunting/search
/ioc/enrich
/ioc
/cases
/cases/{case_id}/investigate
/cases/{case_id}/respond
/soar/playbooks
/soar/executions
Technology Stack
Area	Technologies
Language	Python
Backend	FastAPI
Dashboard	Streamlit
Database	SQLite
AI	Gemini API
Threat Intelligence	AbuseIPDB
Security Analytics	Detection-as-Code, Correlation, UEBA
Threat Framework	MITRE ATT&CK
Testing	pytest
Dependency Security	pip-audit
Version Control	Git / GitHub
Project Structure
sentinel-ai/
│
├── analyzer/
│   ├── case_management/
│   ├── correlation/
│   ├── detections/
│   ├── hunting/
│   ├── ingestion/
│   ├── soar/
│   ├── ueba/
│   ├── ai_agent.py
│   ├── database.py
│   ├── detection_engine.py
│   ├── incident_manager.py
│   ├── ioc_engine.py
│   ├── ioc_store.py
│   ├── ioc_validator.py
│   ├── log_analyzer.py
│   ├── mitre_mapper.py
│   ├── response_engine.py
│   ├── risk_engine.py
│   ├── threat_intel.py
│   └── threat_intel_providers.py
│
├── dashboard/
│   └── app.py
│
├── knowledge/
│
├── logs/
│   └── auth.log
│
├── tests/
│
├── api.py
├── api_models.py
├── requirements.txt
├── .gitignore
└── README.md
Installation

Clone the repository:

git clone https://github.com/Bharath-1309/sentinel-ai.git
cd sentinel-ai

Create a virtual environment:

python -m venv .venv

Activate it on Windows PowerShell:

.venv\Scripts\Activate.ps1

Install dependencies:

python -m pip install -r requirements.txt
Configuration

Create a .env file in the project root.

Example:

FAILED_ATTEMPT_THRESHOLD=3
ALERT_WINDOW_MINUTES=5
ABUSEIPDB_API_KEY=your_abuseipdb_key
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=your_configured_model

Never commit API keys or .env files to GitHub.

The repository already excludes .env through .gitignore.

Some functionality can be tested without external API access because external responses are mocked in the automated test suite.

Running SentinelAI
Start the API
uvicorn api:app --reload
Start the Dashboard

Open another terminal:

.venv\Scripts\Activate.ps1
streamlit run dashboard/app.py

The Streamlit terminal will display the local dashboard URL.

Testing

Run the complete test suite:

python -m pytest -q tests

Current verified result:

270 passed
1 warning

The test suite covers:

API behavior
Log ingestion
Detection engines
Correlation
Threat hunting
UEBA
IOC validation and storage
Threat intelligence
Incident management
Case management
AI investigation
SOAR
Security hardening
Security Verification

Dependency vulnerabilities are checked with:

python -m pip_audit

Current verified result:

No known vulnerabilities found

Dependency consistency:

python -m pip check

Current verified result:

No broken requirements found.

Security-hardening tests include handling of:

SQL-injection-style input
Command-injection-style input
Path-traversal-style input
Invalid JSON
Attacker-controlled response values
Unknown API routes
Security Design Principles

SentinelAI follows several defensive engineering principles:

Treat attacker-controlled input as data.
Validate structured API input.
Avoid executing user-controlled commands.
Keep credentials outside source control.
Separate detection from response.
Maintain auditable investigation records.
Simulate potentially disruptive SOAR actions.
Test security-sensitive inputs.
Audit project dependencies.
Limitations

SentinelAI is a portfolio-scale SOC platform and is not intended to replace a production enterprise SIEM/SOAR deployment.

Current limitations include:

SQLite-based local persistence
Local development deployment
Simulated SOAR actions
External AI dependency for AI-assisted investigation
Threat intelligence depends on configured providers
No production-scale distributed event streaming
No enterprise identity/RBAC implementation
Future Improvements

Potential future extensions include:

Additional detection rules
Additional threat-intelligence providers
Production event streaming
Enterprise authentication and RBAC
Distributed storage
Containerized deployment
CI/CD security testing
Additional endpoint telemetry
Production observability
Project Goal

SentinelAI demonstrates how modern SOC capabilities can be combined into a single security platform:

Security Monitoring
        +
Detection Engineering
        +
Threat Hunting
        +
UEBA
        +
Threat Intelligence
        +
Incident & Case Management
        +
AI-Assisted Investigation
        +
SOAR
        =
Unified SOC Platform

The project focuses on practical cybersecurity engineering, security analytics, incident response, automation, API development, AI-assisted investigation, and secure software design.