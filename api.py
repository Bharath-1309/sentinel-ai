from fastapi import FastAPI
from pydantic import BaseModel

from analyzer.log_analyzer import analyze_logs
from analyzer.phishing_detector import PhishingDetector
from api_models import AnalysisResponse


app = FastAPI(
    title="SentinelAI",
    description="AI-Powered SOC Investigation & Incident Response Platform",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "name": "SentinelAI",
        "status": "running"
    }


@app.get("/analyze", response_model=AnalysisResponse)
def analyze():

    result = analyze_logs()

    return {
        "alerts": [
            {
                "type": alert["type"],
                "timestamp": alert["timestamp"],
                "username": alert["username"],
                "ip": alert["ip"],
                "failed_attempts": alert["failed_attempts"],
                "successful_login": alert["successful_login"],
                "risk": alert["risk"],
                "mitre": alert["mitre"],
                "threat_intelligence": alert["threat_intelligence"]
            }
            for alert in result["alerts"]
        ],
        "incidents": [
            {
                "incident_id": incident["incident_id"],
                "type": incident["type"],
                "source_ip": incident["source_ip"],
                "risk": incident["risk"],
                "risk_score": incident["risk_score"],
                "status": incident["status"],
                "alert_count": incident["alert_count"],
                "start_time": incident["start_time"],
                "end_time": incident["end_time"],
                "mitre_techniques": incident["mitre_techniques"],
                "evidence": incident["evidence"],
                "ai_investigation": incident["ai_investigation"]
            }
            for incident in result["incidents"]
        ]
    }

class PhishingRequest(BaseModel):
    message: str


@app.post("/phishing/analyze")
def analyze_phishing(request: PhishingRequest):

    detector = PhishingDetector()

    return detector.analyze(request.message)