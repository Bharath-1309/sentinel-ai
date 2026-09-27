from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from analyzer.log_analyzer import analyze_logs
from analyzer.phishing_detector import PhishingDetector
from analyzer.database import get_incidents

from analyzer.hunting.adapter import security_events_to_hunting_data
from analyzer.hunting.engine import ThreatHuntingEngine
from analyzer.hunting.models import (
    HuntingQuery,
    HuntingQueryGroup,
    HuntingSearch,
    HuntingTimeRange,
)

from analyzer.ingestion.pipeline import LinuxIngestionPipeline

from api_models import (
    AnalysisResponse,
    HuntingSearchRequest,
)

from analyzer.ioc_engine import IOCEnrichmentEngine

from analyzer.case_management.manager import CaseManager
from analyzer.case_management.investigation import CaseInvestigationService

from analyzer.soar.engine import SOAREngine
from analyzer.soar.playbooks import list_playbooks


app = FastAPI(
    title="SentinelAI",
    description="AI-Powered SOC Investigation & Incident Response Platform",
    version="1.0.0"
)


ioc_engine = IOCEnrichmentEngine()
case_manager = CaseManager()
case_investigation_service = CaseInvestigationService()
soar_engine = SOAREngine()


# ============================================================
# IOC MODELS
# ============================================================

class IOCEnrichmentRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)


class IOCResponse(BaseModel):
    value: str
    ioc_type: str | None
    valid: bool
    enriched: bool
    result: dict | None = None


# ============================================================
# LOG ANALYSIS
# ============================================================

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
                "mitre": alert.get("mitre"),
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
                "ai_investigation": incident["ai_investigation"],
                "response_playbook": incident["response_playbook"]
            }
            for incident in result["incidents"]
        ]
    }


# ============================================================
# PHISHING ANALYSIS
# ============================================================

class PhishingRequest(BaseModel):
    message: str


@app.post("/phishing/analyze")
def analyze_phishing(request: PhishingRequest):
    detector = PhishingDetector()

    return detector.analyze(request.message)


# ============================================================
# INCIDENTS
# ============================================================

@app.get("/incidents")
def incidents():
    return {
        "incidents": get_incidents()
    }


@app.post("/incidents/{incident_id}/case")
def create_case_from_incident(incident_id: str):

    incidents = get_incidents()

    incident = next(
        (
            item
            for item in incidents
            if item.get("incident_id") == incident_id
        ),
        None,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    case = case_manager.create_case_from_incident(
        incident
    )

    return case.__dict__


# ============================================================
# THREAT HUNTING
# ============================================================

@app.post("/hunting/search")
def hunting_search(request: HuntingSearchRequest):

    pipeline = LinuxIngestionPipeline()

    events = pipeline.ingest("logs/auth.log")

    hunting_events = security_events_to_hunting_data(events)

    conditions = None

    if request.query is not None:

        conditions = HuntingQuery(
            field=request.query.field,
            operator=request.query.operator,
            value=request.query.value,
        )

    elif request.query_group is not None:

        conditions = HuntingQueryGroup(
            queries=[
                HuntingQuery(
                    field=query.field,
                    operator=query.operator,
                    value=query.value,
                )
                for query in request.query_group.queries
            ],
            logic=request.query_group.logic,
        )

    time_range = None

    if request.time_range is not None:

        time_range = HuntingTimeRange(
            start=request.time_range.start,
            end=request.time_range.end,
        )

    search = HuntingSearch(
        conditions=conditions,
        time_range=time_range,
        limit=request.limit,
        sort_by=request.sort_by,
        sort_order=request.sort_order,
    )

    results = ThreatHuntingEngine().search(
        hunting_events,
        search
    )

    return {
        "count": len(results),
        "results": results
    }


# ============================================================
# IOC / THREAT INTELLIGENCE
# ============================================================

@app.post("/ioc/enrich", response_model=IOCResponse)
def enrich_ioc(request: IOCEnrichmentRequest):
    return ioc_engine.enrich(request.value)


@app.get("/ioc")
def list_iocs():

    return {
        "count": len(ioc_engine.list_iocs()),
        "iocs": [
            {
                "value": ioc.value,
                "ioc_type": ioc.ioc_type
            }
            for ioc in ioc_engine.list_iocs()
        ],
    }


@app.get("/ioc/{value}")
def get_ioc(value: str):

    ioc = ioc_engine.get_ioc(value)

    if ioc is None:
        raise HTTPException(
            status_code=404,
            detail="IOC not found"
        )

    result = ioc_engine.get_result(value)

    result_data = None

    if result is not None:

        result_data = {
            "value": result.value,
            "ioc_type": result.ioc_type,
            "malicious": result.malicious,
            "confidence": result.confidence,
            "threat": result.threat,
            "source": result.source,
            "first_seen": result.first_seen,
            "last_seen": result.last_seen,
            "tags": result.tags,
            "provider_results": result.provider_results,
        }

    return {
        "value": ioc.value,
        "ioc_type": ioc.ioc_type,
        "result": result_data,
    }


@app.delete("/ioc/{value}")
def delete_ioc(value: str):

    removed = ioc_engine.remove_ioc(value)

    if not removed:
        raise HTTPException(
            status_code=404,
            detail="IOC not found"
        )

    return {
        "message": "IOC removed",
        "value": value
    }


# ============================================================
# CASE MANAGEMENT
# ============================================================

@app.get("/cases")
def list_cases():
    return {
        "cases": [
            case.__dict__
            for case in case_manager.list_cases()
        ]
    }


@app.get("/cases/{case_id}")
def get_case(case_id: str):

    case = case_manager.get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    return case.__dict__


# ============================================================
# AI CASE INVESTIGATION
# ============================================================

@app.post("/cases/{case_id}/investigate")
def investigate_case(case_id: str):

    case = case_manager.get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    investigation = case_investigation_service.investigate(case)

    case_manager.save_ai_investigation(
        case_id,
        investigation
    )

    return investigation


# ============================================================
# SOAR / SECURITY ORCHESTRATION
# ============================================================

@app.get("/soar/playbooks")
def get_soar_playbooks():
    """
    Return all configured SOAR playbooks.
    """

    playbooks = list_playbooks()

    return {
        "count": len(playbooks),
        "playbooks": [
            {
                "playbook_id": playbook.playbook_id,
                "name": playbook.name,
                "description": playbook.description,
                "incident_types": playbook.incident_types,
                "minimum_severity": playbook.minimum_severity,
                "actions": playbook.actions,
            }
            for playbook in playbooks
        ],
    }


@app.post("/cases/{case_id}/respond")
def respond_to_case(case_id: str):
    """
    Execute the appropriate SOAR response playbook for a case.

    Actions are simulated and recorded for audit purposes.
    No external endpoint, account, firewall, or credential system
    is modified.
    """

    case = case_manager.get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    execution = soar_engine.execute_playbook(case)

    return {
        "execution_id": execution.execution_id,
        "case_id": execution.case_id,
        "playbook_id": execution.playbook_id,
        "playbook_name": execution.playbook_name,
        "status": execution.status,
        "started_at": execution.started_at,
        "completed_at": execution.completed_at,
        "error": execution.error,
        "actions": [
            {
                "action_id": action.action_id,
                "action_type": action.action_type,
                "description": action.description,
                "target": action.target,
                "status": action.status,
                "result": action.result,
                "executed_at": action.executed_at,
            }
            for action in execution.actions
        ],
    }


@app.get("/soar/executions")
def list_soar_executions():
    """
    Return all SOAR executions held by the current application instance.
    """

    executions = soar_engine.list_executions()

    return {
        "count": len(executions),
        "executions": [
            {
                "execution_id": execution.execution_id,
                "case_id": execution.case_id,
                "playbook_id": execution.playbook_id,
                "playbook_name": execution.playbook_name,
                "status": execution.status,
                "started_at": execution.started_at,
                "completed_at": execution.completed_at,
                "error": execution.error,
                "actions": [
                    {
                        "action_id": action.action_id,
                        "action_type": action.action_type,
                        "description": action.description,
                        "target": action.target,
                        "status": action.status,
                        "result": action.result,
                        "executed_at": action.executed_at,
                    }
                    for action in execution.actions
                ],
            }
            for execution in executions
        ],
    }


@app.get("/soar/executions/{execution_id}")
def get_soar_execution(execution_id: str):

    execution = soar_engine.get_execution(
        execution_id
    )

    if execution is None:
        raise HTTPException(
            status_code=404,
            detail="SOAR execution not found"
        )

    return {
        "execution_id": execution.execution_id,
        "case_id": execution.case_id,
        "playbook_id": execution.playbook_id,
        "playbook_name": execution.playbook_name,
        "status": execution.status,
        "started_at": execution.started_at,
        "completed_at": execution.completed_at,
        "error": execution.error,
        "actions": [
            {
                "action_id": action.action_id,
                "action_type": action.action_type,
                "description": action.description,
                "target": action.target,
                "status": action.status,
                "result": action.result,
                "executed_at": action.executed_at,
            }
            for action in execution.actions
        ],
    }