# SentinelAI

AI-Powered SOC Investigation & Incident Response Platform

SentinelAI is a cybersecurity platform that analyzes security logs, detects suspicious authentication activity, correlates security alerts into incidents, enriches events with threat intelligence, maps activity to MITRE ATT&CK, calculates risk, and uses AI to assist SOC investigations.

## Features

* SSH brute-force detection
* SSH password-spraying detection
* Suspicious root-login detection
* Security alert correlation
* Automated incident generation
* Risk scoring
* MITRE ATT&CK technique mapping
* AbuseIPDB threat-intelligence enrichment
* Gemini-powered AI incident investigation
* AI-generated investigation analysis and recommendations
* FastAPI REST API
* Automated testing with pytest

## Architecture

```text
Security Logs
      |
      v
Log Analyzer
      |
      v
Detection Engine
      |
      +----> MITRE ATT&CK Mapping
      |
      +----> Threat Intelligence
      |
      v
Correlation Engine
      |
      v
Risk Engine
      |
      v
Incident Manager
      |
      v
Gemini AI SOC Agent
      |
      v
Investigation & Recommendations
      |
      v
FastAPI
```

## Detection Capabilities

### SSH Brute Force

Detects repeated failed SSH authentication attempts from the same source IP within a configurable time window.

### SSH Password Spraying

Detects authentication attempts against multiple usernames from the same source IP.

### Potential Account Compromise

Correlates brute-force activity with a subsequent successful login and creates a critical incident.

### Coordinated SSH Attack

Correlates multiple credential-attack techniques originating from the same source IP.

### Suspicious Root Login

Identifies successful SSH authentication attempts involving the root account.

## AI SOC Investigation

SentinelAI uses the Gemini API to investigate generated security incidents.

The AI investigation provides:

* Incident analysis
* Risk context
* Investigation observations
* Practical SOC recommendations

Temporary Gemini API failures are handled with retry logic, and automated tests use mocked API responses so the test suite does not depend on external API availability.

## Threat Intelligence

SentinelAI integrates with AbuseIPDB to enrich source IP addresses with reputation information.

The enrichment includes:

* Abuse confidence score
* Malicious IP indication
* Threat description
* Intelligence source

API credentials are stored locally in environment variables and are not committed to the repository.

## MITRE ATT&CK

Detected credential attacks are mapped to MITRE ATT&CK techniques.

Current mappings include:

| Detection             | Technique                     | Tactic            |
| --------------------- | ----------------------------- | ----------------- |
| SSH Brute Force       | T1110 - Brute Force           | Credential Access |
| SSH Password Spraying | T1110.003 - Password Spraying | Credential Access |

## Risk Scoring

SentinelAI calculates an incident risk score based on factors including:

* Attack type
* Number of failed attempts
* Successful authentication
* Alert severity
* Threat-intelligence results

The resulting score is converted into:

* LOW
* MEDIUM
* HIGH
* CRITICAL

## REST API

SentinelAI provides a FastAPI interface for security analysis.

Start the API with:

```bash
uvicorn api:app --reload
```

Then open:

[http://127.0.0.1:8000](http://127.0.0.1:8000)

Interactive API documentation:

[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Project Structure

```text
sentinel-ai/
├── analyzer/
│   ├── __init__.py
│   ├── ai_agent.py
│   ├── correlation_engine.py
│   ├── detection_engine.py
│   ├── incident_manager.py
│   ├── log_analyzer.py
│   ├── mitre_mapper.py
│   ├── risk_engine.py
│   └── threat_intel.py
│
├── logs/
│   └── auth.log
│
├── tests/
│   ├── password_spray.log
│   ├── time_window.log
│   ├── test_ai_agent.py
│   ├── test_correlation_engine.py
│   ├── test_incident_manager.py
│   ├── test_log_analyzer.py
│   ├── test_mitre_mapper.py
│   ├── test_risk_engine.py
│   └── test_threat_intel.py
│
├── api.py
├── api_models.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Bharath-1309/sentinel-ai.git
cd sentinel-ai
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Environment Variables

Create a `.env` file in the project root:

```text
FAILED_ATTEMPT_THRESHOLD=3
ALERT_WINDOW_MINUTES=5
ABUSEIPDB_API_KEY=your_abuseipdb_key
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=gemini-3.8-flash
```

Never commit `.env` or API keys to GitHub.

## Testing

Run the complete test suite:

```bash
pytest -v
```

Current test status:

```text
21 passed
```

## Technologies

* Python
* FastAPI
* Gemini API
* AbuseIPDB API
* pytest
* MITRE ATT&CK
* REST API
* Git & GitHub

## Roadmap

Planned improvements include:

* Additional attack detections
* DDoS detection
* Phishing detection
* Web attack detection
* Malware-related detection
* Security knowledge RAG
* Automated SOC tool calling
* Incident report generation
* Web-based SOC dashboard
* Docker deployment
* Cloud deployment
* CI/CD pipeline
* Monitoring and observability
* AI security testing
* Prompt-injection defenses
* RAG poisoning defenses
* Tool-abuse protection
* Role-based access control

## Project Goal

The goal of SentinelAI is to demonstrate how security monitoring, detection engineering, threat intelligence, incident response, and AI-assisted investigation can be combined into a practical SOC platform.
