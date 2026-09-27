import streamlit as st
import requests


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SentinelAI SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# API CONFIGURATION
# ============================================================

API_BASE_URL = "http://127.0.0.1:8000"

API_URL = f"{API_BASE_URL}/analyze"
INCIDENTS_API_URL = f"{API_BASE_URL}/incidents"
PHISHING_API_URL = f"{API_BASE_URL}/phishing/analyze"

CASES_API_URL = f"{API_BASE_URL}/cases"

SOAR_PLAYBOOKS_API_URL = (
    f"{API_BASE_URL}/soar/playbooks"
)

SOAR_EXECUTIONS_API_URL = (
    f"{API_BASE_URL}/soar/executions"
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_get(url, timeout=15):
    response = requests.get(
        url,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def safe_post(
    url,
    json_data=None,
    timeout=30,
):
    response = requests.post(
        url,
        json=json_data,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def display_mitre_techniques(techniques):
    if not techniques:
        st.info(
            "No MITRE ATT&CK techniques recorded."
        )
        return

    for technique in techniques:
        if not isinstance(technique, dict):
            st.write(str(technique))
            continue

        technique_id = technique.get(
            "technique_id",
            "Unknown",
        )

        technique_name = technique.get(
            "technique",
            "Unknown",
        )

        tactic = technique.get(
            "tactic",
            "Unknown",
        )

        st.markdown(
            f"**{technique_id} — {technique_name}**"
        )

        st.write(
            f"Tactic: {tactic}"
        )


def display_evidence(evidence):
    if not evidence:
        st.info(
            "No evidence recorded."
        )
        return

    for index, item in enumerate(
        evidence,
        start=1,
    ):
        with st.expander(
            f"Evidence {index}",
            expanded=True,
        ):
            if not isinstance(item, dict):
                st.code(str(item))
                continue

            item = {
                key: value
                for key, value in item.items()
                if key != "_legacy_alert_class"
            }

            evidence_type = item.get(
                "type",
                item.get(
                    "evidence_type",
                    "Unknown",
                ),
            )

            timestamp = item.get(
                "timestamp",
                item.get(
                    "created_at",
                    "Unknown",
                ),
            )

            username = item.get(
                "username"
            )

            source_ip = item.get(
                "ip",
                item.get(
                    "source_ip",
                    "Unknown",
                ),
            )

            failed_attempts = item.get(
                "failed_attempts",
                0,
            )

            successful_login = item.get(
                "successful_login",
                False,
            )

            risk = item.get(
                "risk",
                "UNKNOWN",
            )

            col1, col2, col3 = st.columns(3)

            col1.write(
                f"**Detection Type**\n\n"
                f"{evidence_type}"
            )

            col2.write(
                f"**Source IP**\n\n"
                f"{source_ip}"
            )

            col3.write(
                f"**Username**\n\n"
                f"{username if username else 'N/A'}"
            )

            col1, col2, col3 = st.columns(3)

            col1.write(
                f"**Timestamp**\n\n"
                f"{timestamp}"
            )

            col2.write(
                f"**Failed Attempts**\n\n"
                f"{failed_attempts}"
            )

            col3.write(
                f"**Successful Login**\n\n"
                f"{'YES' if successful_login else 'NO'}"
            )

            st.write(
                f"**Risk:** {risk}"
            )

            mitre = item.get(
                "mitre"
            )

            if mitre:
                st.markdown(
                    "#### MITRE ATT&CK"
                )

                st.write(
                    f"**"
                    f"{mitre.get('technique_id', 'Unknown')}"
                    f" — "
                    f"{mitre.get('technique', 'Unknown')}"
                    f"**"
                )

                st.write(
                    f"Tactic: "
                    f"{mitre.get('tactic', 'Unknown')}"
                )

            threat_intelligence = item.get(
                "threat_intelligence"
            )

            if threat_intelligence:
                st.markdown(
                    "#### Threat Intelligence"
                )

                ti_col1, ti_col2, ti_col3, ti_col4 = (
                    st.columns(4)
                )

                ti_col1.write(
                    f"**Source**\n\n"
                    f"{threat_intelligence.get('source', 'Unknown')}"
                )

                ti_col2.write(
                    f"**Malicious**\n\n"
                    f"{'YES' if threat_intelligence.get('malicious') else 'NO'}"
                )

                ti_col3.write(
                    f"**Confidence**\n\n"
                    f"{threat_intelligence.get('confidence', 0)}"
                )

                ti_col4.write(
                    f"**Threat**\n\n"
                    f"{threat_intelligence.get('threat') or 'None reported'}"
                )


def display_ai_investigation(ai):
    if not ai:
        st.info(
            "No AI investigation data recorded."
        )
        return

    ai_status = ai.get(
        "investigation_status",
        "UNKNOWN",
    )

    col1, col2 = st.columns([1, 3])

    col1.metric(
        "Investigation Status",
        ai_status,
    )

    col2.write(
        f"**Incident:** "
        f"{ai.get('incident_id', 'Unknown')}"
    )

    analysis = ai.get(
        "analysis"
    )

    if analysis:
        st.markdown(
            "#### Analyst Analysis"
        )

        if ai_status == "UNAVAILABLE":
            st.info(analysis)
        else:
            st.write(analysis)

    else:
        st.info(
            "No AI analysis available."
        )

    recommendations = ai.get(
        "recommendations",
        [],
    )

    if recommendations:
        st.markdown(
            "#### AI Recommendations"
        )

        for index, recommendation in enumerate(
            recommendations,
            start=1,
        ):
            st.write(
                f"**{index}.** {recommendation}"
            )

    elif ai_status == "UNAVAILABLE":
        st.caption(
            "AI recommendations are unavailable "
            "because the AI investigation did not complete."
        )


def display_response_playbook(playbook):
    if not playbook:
        st.info(
            "No response playbook recorded."
        )
        return

    col1, col2 = st.columns([1, 3])

    col1.metric(
        "Severity",
        playbook.get(
            "severity",
            "UNKNOWN",
        ),
    )

    col2.write(
        f"**Incident Type:** "
        f"{playbook.get('incident_type', 'Unknown')}"
    )

    actions = playbook.get(
        "actions",
        [],
    )

    if not actions:
        st.info(
            "No response actions recorded."
        )
        return

    st.markdown(
        "#### Response Checklist"
    )

    for index, action in enumerate(
        actions,
        start=1,
    ):
        st.checkbox(
            action,
            value=False,
            key=(
                f"response_action_"
                f"{index}_"
                f"{action}"
            ),
        )


def display_case_evidence(evidence):
    if not evidence:
        st.info(
            "No case evidence recorded."
        )
        return

    for index, item in enumerate(
        evidence,
        start=1,
    ):
        evidence_type = item.get(
            "evidence_type",
            "UNKNOWN",
        )

        with st.expander(
            f"Evidence {index}: {evidence_type}"
        ):
            st.write(
                f"**Value:** "
                f"{item.get('value', 'N/A')}"
            )

            st.write(
                f"**Source:** "
                f"{item.get('source') or 'N/A'}"
            )

            st.write(
                f"**Created:** "
                f"{item.get('created_at', 'N/A')}"
            )


def display_case_notes(notes):
    if not notes:
        return

    st.markdown(
        "#### Analyst Notes"
    )

    for note in notes:
        author = note.get(
            "author",
            "Unknown",
        )

        created_at = note.get(
            "created_at",
            "",
        )

        with st.expander(
            f"{author} — {created_at}"
        ):
            st.write(
                note.get(
                    "content",
                    "",
                )
            )


def display_soar_execution(execution):
    if not execution:
        st.info(
            "No SOAR execution selected."
        )
        return

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Execution ID",
        execution.get(
            "execution_id",
            "UNKNOWN",
        ),
    )

    col2.metric(
        "Playbook",
        execution.get(
            "playbook_name",
            "UNKNOWN",
        ),
    )

    col3.metric(
        "Status",
        execution.get(
            "status",
            "UNKNOWN",
        ),
    )

    st.write(
        f"**Case ID:** "
        f"{execution.get('case_id', 'UNKNOWN')}"
    )

    st.write(
        f"**Started:** "
        f"{execution.get('started_at', 'UNKNOWN')}"
    )

    st.write(
        f"**Completed:** "
        f"{execution.get('completed_at', 'UNKNOWN')}"
    )

    if execution.get("error"):
        st.error(
            execution.get("error")
        )

    actions = execution.get(
        "actions",
        [],
    )

    if not actions:
        st.info(
            "No actions recorded."
        )
        return

    st.markdown(
        "#### Executed Actions"
    )

    for index, action in enumerate(
        actions,
        start=1,
    ):
        action_type = action.get(
            "action_type",
            "UNKNOWN",
        )

        status = action.get(
            "status",
            "UNKNOWN",
        )

        with st.expander(
            f"{index}. {action_type} — {status}",
            expanded=True,
        ):
            st.write(
                f"**Action ID:** "
                f"{action.get('action_id', 'UNKNOWN')}"
            )

            st.write(
                f"**Description:** "
                f"{action.get('description', '')}"
            )

            st.write(
                f"**Target:** "
                f"{action.get('target') or 'N/A'}"
            )

            st.write(
                f"**Result:** "
                f"{action.get('result') or 'N/A'}"
            )

            st.write(
                f"**Executed At:** "
                f"{action.get('executed_at') or 'N/A'}"
            )


# ============================================================
# SESSION STATE
# ============================================================

if "stored_incidents" not in st.session_state:
    st.session_state.stored_incidents = None

if "cases" not in st.session_state:
    st.session_state.cases = None

if "soar_executions" not in st.session_state:
    st.session_state.soar_executions = None

if "soar_playbooks" not in st.session_state:
    st.session_state.soar_playbooks = None

if "last_soar_execution" not in st.session_state:
    st.session_state.last_soar_execution = None

if "last_ai_investigation" not in st.session_state:
    st.session_state.last_ai_investigation = None


# ============================================================
# HEADER
# ============================================================

st.title(
    "SentinelAI"
)

st.caption(
    "AI-Powered SOC Investigation & Incident Response Platform"
)


# ============================================================
# SOC OVERVIEW
# ============================================================

st.divider()

st.subheader(
    "SOC Overview"
)

dashboard_incidents = []

critical_count = 0
high_count = 0
medium_count = 0
low_count = 0
total_alerts = 0

try:
    stored_data = safe_get(
        INCIDENTS_API_URL,
        timeout=10,
    )

    dashboard_incidents = stored_data.get(
        "incidents",
        [],
    )

    total_incidents = len(
        dashboard_incidents
    )

    critical_count = sum(
        1
        for incident in dashboard_incidents
        if incident.get("risk") == "CRITICAL"
    )

    high_count = sum(
        1
        for incident in dashboard_incidents
        if incident.get("risk") == "HIGH"
    )

    medium_count = sum(
        1
        for incident in dashboard_incidents
        if incident.get("risk") == "MEDIUM"
    )

    low_count = sum(
        1
        for incident in dashboard_incidents
        if incident.get("risk") == "LOW"
    )

    total_alerts = sum(
        incident.get(
            "alert_count",
            0,
        )
        for incident in dashboard_incidents
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "Total Incidents",
        total_incidents,
    )

    col2.metric(
        "Critical",
        critical_count,
    )

    col3.metric(
        "High",
        high_count,
    )

    col4.metric(
        "Medium",
        medium_count,
    )

    col5.metric(
        "Total Alerts",
        total_alerts,
    )

except requests.RequestException as error:
    st.error(
        f"Unable to load SOC overview: {error}"
    )


# ============================================================
# RISK DISTRIBUTION
# ============================================================

st.subheader(
    "Risk Distribution"
)

risk_col1, risk_col2, risk_col3, risk_col4 = (
    st.columns(4)
)

risk_col1.metric(
    "CRITICAL",
    critical_count,
)

risk_col2.metric(
    "HIGH",
    high_count,
)

risk_col3.metric(
    "MEDIUM",
    medium_count,
)

risk_col4.metric(
    "LOW",
    low_count,
)


# ============================================================
# PHISHING ANALYSIS
# ============================================================

st.divider()

st.subheader(
    "Phishing Analysis"
)

phishing_message = st.text_area(
    "Enter an email, message, or URL to analyze",
    placeholder=(
        "Example: Urgent! Verify your account at "
        "https://example.com/login"
    ),
)


if st.button(
    "Analyze for Phishing",
    key="phishing_button",
):
    if not phishing_message.strip():
        st.warning(
            "Please enter a message to analyze."
        )

    else:
        try:
            phishing_result = safe_post(
                PHISHING_API_URL,
                json_data={
                    "message": phishing_message
                },
                timeout=30,
            )

            st.success(
                "Phishing analysis completed."
            )

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Risk",
                phishing_result.get(
                    "risk",
                    "UNKNOWN",
                ),
            )

            col2.metric(
                "Risk Score",
                phishing_result.get(
                    "risk_score",
                    0,
                ),
            )

            col3.metric(
                "Phishing Detected",
                (
                    "YES"
                    if phishing_result.get(
                        "is_phishing",
                        False,
                    )
                    else "NO"
                ),
            )

            matched_keywords = phishing_result.get(
                "matched_keywords",
                [],
            )

            if matched_keywords:
                st.markdown(
                    "#### Suspicious Content Indicators"
                )

                for keyword in matched_keywords:
                    st.write(
                        f"- {keyword}"
                    )

            message_indicators = phishing_result.get(
                "message_indicators",
                {},
            )

            credential_requests = (
                message_indicators.get(
                    "credential_requests",
                    [],
                )
            )

            financial_requests = (
                message_indicators.get(
                    "financial_requests",
                    [],
                )
            )

            urgency_indicators = (
                message_indicators.get(
                    "urgency_indicators",
                    [],
                )
            )

            if credential_requests:
                st.markdown(
                    "#### Credential Indicators"
                )

                for indicator in credential_requests:
                    st.write(
                        f"- {indicator}"
                    )

            if financial_requests:
                st.markdown(
                    "#### Financial Indicators"
                )

                for indicator in financial_requests:
                    st.write(
                        f"- {indicator}"
                    )

            if urgency_indicators:
                st.markdown(
                    "#### Urgency Indicators"
                )

                for indicator in urgency_indicators:
                    st.write(
                        f"- {indicator}"
                    )

            suspicious_urls = phishing_result.get(
                "suspicious_urls",
                [],
            )

            if suspicious_urls:
                st.markdown(
                    "#### Suspicious URLs"
                )

                for url in suspicious_urls:
                    if isinstance(url, dict):
                        st.markdown(
                            f"**Suspicious URL:** "
                            f"`{url.get('url', 'Unknown')}`"
                        )

                        for reason in url.get(
                            "reasons",
                            [],
                        ):
                            st.write(
                                f"- {reason}"
                            )
                    else:
                        st.write(
                            f"- {url}"
                        )

        except requests.RequestException as error:
            st.error(
                f"Unable to connect to SentinelAI API: {error}"
            )


# ============================================================
# STORED INCIDENTS
# ============================================================

st.divider()

st.subheader(
    "Stored Incidents"
)

if st.button(
    "Load Stored Incidents",
    key="load_incidents_button",
):
    try:
        stored_data = safe_get(
            INCIDENTS_API_URL,
            timeout=10,
        )

        st.session_state.stored_incidents = (
            stored_data.get(
                "incidents",
                [],
            )
        )

    except requests.RequestException as error:
        st.error(
            f"Unable to load stored incidents: {error}"
        )


stored_incidents = (
    st.session_state.stored_incidents
)

if stored_incidents is None:
    st.info(
        "Click 'Load Stored Incidents' "
        "to load incidents from the database."
    )

elif not stored_incidents:
    st.info(
        "No stored incidents found."
    )

else:
    st.success(
        f"{len(stored_incidents)} "
        f"stored incident(s) loaded."
    )

    st.markdown(
        "### Incident Filters"
    )

    filter_col1, filter_col2, filter_col3 = (
        st.columns(3)
    )

    risk_options = [
        "ALL",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]

    selected_risk = filter_col1.selectbox(
        "Risk",
        risk_options,
        key="incident_risk_filter",
    )

    status_options = [
        "ALL",
        *sorted(
            {
                str(
                    incident.get(
                        "status",
                        "UNKNOWN",
                    )
                )
                for incident in stored_incidents
            }
        ),
    ]

    selected_status = filter_col2.selectbox(
        "Status",
        status_options,
        key="incident_status_filter",
    )

    type_options = [
        "ALL",
        *sorted(
            {
                str(
                    incident.get(
                        "incident_type",
                        incident.get(
                            "type",
                            "UNKNOWN",
                        ),
                    )
                )
                for incident in stored_incidents
            }
        ),
    ]

    selected_type = filter_col3.selectbox(
        "Incident Type",
        type_options,
        key="incident_type_filter",
    )

    filtered_incidents = [
        incident
        for incident in stored_incidents
        if (
            selected_risk == "ALL"
            or incident.get("risk")
            == selected_risk
        )
        and (
            selected_status == "ALL"
            or incident.get("status")
            == selected_status
        )
        and (
            selected_type == "ALL"
            or incident.get(
                "incident_type",
                incident.get(
                    "type"
                ),
            )
            == selected_type
        )
    ]

    st.caption(
        f"Showing {len(filtered_incidents)} "
        f"of {len(stored_incidents)} "
        f"stored incident(s)."
    )

    if not filtered_incidents:
        st.warning(
            "No incidents match the selected filters."
        )

    else:
        incident_options = {}

        for incident in filtered_incidents:
            incident_type = incident.get(
                "incident_type",
                incident.get(
                    "type",
                    "UNKNOWN",
                ),
            )

            label = (
                f"{incident.get('incident_id')} — "
                f"{incident_type} — "
                f"{incident.get('risk')}"
            )

            incident_options[label] = incident

        selected_label = st.selectbox(
            "Select an incident to investigate",
            list(incident_options.keys()),
            key="stored_incident_selector",
        )

        selected_incident = incident_options[
            selected_label
        ]

        incident_type = selected_incident.get(
            "incident_type",
            selected_incident.get(
                "type",
                "UNKNOWN",
            ),
        )

        # ----------------------------------------------------
        # Incident summary
        # ----------------------------------------------------

        st.divider()

        st.markdown(
            f"## {incident_type}"
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Risk",
            selected_incident.get(
                "risk",
                "UNKNOWN",
            ),
        )

        col2.metric(
            "Risk Score",
            selected_incident.get(
                "risk_score",
                0,
            ),
        )

        col3.metric(
            "Status",
            selected_incident.get(
                "status",
                "UNKNOWN",
            ),
        )

        col4.metric(
            "Alerts",
            selected_incident.get(
                "alert_count",
                0,
            ),
        )

        st.write(
            f"**Incident ID:** "
            f"{selected_incident.get('incident_id')}"
        )

        st.write(
            f"**Source IP:** "
            f"{selected_incident.get('source_ip')}"
        )

        st.write(
            f"**Start Time:** "
            f"{selected_incident.get('start_time')}"
        )

        st.write(
            f"**End Time:** "
            f"{selected_incident.get('end_time')}"
        )

        # ----------------------------------------------------
        # MITRE
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "MITRE ATT&CK"
        )

        display_mitre_techniques(
            selected_incident.get(
                "mitre_techniques",
                [],
            )
        )

        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "Evidence"
        )

        display_evidence(
            selected_incident.get(
                "evidence",
                [],
            )
        )

        # ----------------------------------------------------
        # AI Investigation
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "AI Investigation"
        )

        display_ai_investigation(
            selected_incident.get(
                "ai_investigation"
            )
        )

        # ----------------------------------------------------
        # Response Playbook
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "Recommended Response Actions"
        )

        display_response_playbook(
            selected_incident.get(
                "response_playbook"
            )
        )


# ============================================================
# RUN SECURITY ANALYSIS
# ============================================================

st.divider()

st.subheader(
    "Security Analysis"
)

if st.button(
    "Run Security Analysis",
    type="primary",
    key="run_security_analysis",
):
    try:
        data = safe_get(
            API_URL,
            timeout=60,
        )

        alerts = data.get(
            "alerts",
            [],
        )

        incidents = data.get(
            "incidents",
            [],
        )

        st.success(
            "Security analysis completed."
        )

        critical_count_analysis = sum(
            1
            for incident in incidents
            if incident.get("risk")
            == "CRITICAL"
        )

        high_count_analysis = sum(
            1
            for incident in incidents
            if incident.get("risk")
            == "HIGH"
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Security Alerts",
            len(alerts),
        )

        col2.metric(
            "Incidents",
            len(incidents),
        )

        col3.metric(
            "Critical Incidents",
            critical_count_analysis,
        )

        col4.metric(
            "High-Risk Incidents",
            high_count_analysis,
        )

        # ----------------------------------------------------
        # Security alerts
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "Security Alerts"
        )

        if not alerts:
            st.info(
                "No security alerts detected."
            )

        for alert in alerts:
            risk = alert.get(
                "risk",
                "UNKNOWN",
            )

            with st.expander(
                f"{alert.get('type')} — {risk}"
            ):
                col1, col2, col3 = st.columns(3)

                col1.write(
                    f"**Username:** "
                    f"{alert.get('username')}"
                )

                col2.write(
                    f"**Source IP:** "
                    f"{alert.get('ip')}"
                )

                col3.write(
                    f"**Failed Attempts:** "
                    f"{alert.get('failed_attempts')}"
                )

                st.write(
                    f"**Timestamp:** "
                    f"{alert.get('timestamp')}"
                )

                st.write(
                    f"**Successful Login:** "
                    f"{alert.get('successful_login')}"
                )

                mitre = alert.get(
                    "mitre"
                )

                if mitre:
                    st.write(
                        f"**MITRE ATT&CK:** "
                        f"{mitre.get('technique_id')} — "
                        f"{mitre.get('technique')}"
                    )

        # ----------------------------------------------------
        # Security incidents
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "Security Incidents"
        )

        if not incidents:
            st.info(
                "No security incidents detected."
            )

        for incident in incidents:
            risk = incident.get(
                "risk",
                "UNKNOWN",
            )

            incident_type = incident.get(
                "incident_type",
                incident.get(
                    "type",
                    "UNKNOWN",
                ),
            )

            with st.expander(
                f"{incident.get('incident_id')} — "
                f"{incident_type} — "
                f"{risk}"
            ):
                col1, col2, col3 = st.columns(3)

                col1.write(
                    f"**Source IP:** "
                    f"{incident.get('source_ip')}"
                )

                col2.write(
                    f"**Risk Score:** "
                    f"{incident.get('risk_score')}"
                )

                col3.write(
                    f"**Status:** "
                    f"{incident.get('status')}"
                )

                st.write(
                    f"**Alert Count:** "
                    f"{incident.get('alert_count')}"
                )

                st.write(
                    f"**Start Time:** "
                    f"{incident.get('start_time')}"
                )

                st.write(
                    f"**End Time:** "
                    f"{incident.get('end_time')}"
                )

                mitre_techniques = incident.get(
                    "mitre_techniques",
                    [],
                )

                if mitre_techniques:
                    st.markdown(
                        "#### MITRE ATT&CK"
                    )

                    for technique in mitre_techniques:
                        st.write(
                            f"**"
                            f"{technique.get('technique_id')}"
                            f" — "
                            f"{technique.get('technique')}"
                            f"** "
                            f"({technique.get('tactic')})"
                        )

                ai = incident.get(
                    "ai_investigation"
                )

                if ai:
                    st.markdown(
                        "#### AI Investigation"
                    )

                    st.write(
                        f"**Status:** "
                        f"{ai.get('investigation_status')}"
                    )

                    st.write(
                        ai.get(
                            "analysis",
                            "No AI analysis available.",
                        )
                    )

                    recommendations = ai.get(
                        "recommendations",
                        [],
                    )

                    if recommendations:
                        st.markdown(
                            "**Recommendations:**"
                        )

                        for recommendation in recommendations:
                            st.write(
                                f"- {recommendation}"
                            )

                playbook = incident.get(
                    "response_playbook"
                )

                if playbook:
                    st.markdown(
                        "#### Recommended Response Actions"
                    )

                    st.write(
                        f"**Severity:** "
                        f"{playbook.get('severity')}"
                    )

                    for action in playbook.get(
                        "actions",
                        [],
                    ):
                        st.write(
                            f"- {action}"
                        )

    except requests.RequestException as error:
        st.error(
            f"Unable to connect to SentinelAI API: {error}"
        )


# ============================================================
# CASE MANAGEMENT
# ============================================================

st.divider()

st.header(
    "Case Management"
)

st.caption(
    "Investigate security cases, review evidence, "
    "and initiate SOAR response workflows."
)


if st.button(
    "Load Cases",
    key="load_cases_button",
):
    try:
        case_data = safe_get(
            CASES_API_URL,
            timeout=15,
        )

        st.session_state.cases = case_data.get(
            "cases",
            [],
        )

        st.session_state.last_ai_investigation = None
        st.session_state.last_soar_execution = None

    except requests.RequestException as error:
        st.error(
            f"Unable to load cases: {error}"
        )


cases = st.session_state.cases

if cases is None:
    st.info(
        "Click 'Load Cases' to load cases from the database."
    )

elif not cases:
    st.info(
        "No cases found."
    )

else:
    st.success(
        f"{len(cases)} case(s) loaded."
    )

    # --------------------------------------------------------
    # Case metrics
    # --------------------------------------------------------

    open_cases = sum(
        1
        for case in cases
        if str(
            case.get(
                "status",
                "",
            )
        ).upper()
        in {
            "OPEN",
            "INVESTIGATING",
        }
    )

    critical_cases = sum(
        1
        for case in cases
        if str(
            case.get(
                "severity",
                "",
            )
        ).upper()
        == "CRITICAL"
    )

    high_cases = sum(
        1
        for case in cases
        if str(
            case.get(
                "severity",
                "",
            )
        ).upper()
        == "HIGH"
    )

    metric1, metric2, metric3, metric4 = (
        st.columns(4)
    )

    metric1.metric(
        "Total Cases",
        len(cases),
    )

    metric2.metric(
        "Open / Investigating",
        open_cases,
    )

    metric3.metric(
        "Critical",
        critical_cases,
    )

    metric4.metric(
        "High",
        high_cases,
    )

    # --------------------------------------------------------
    # Case filters
    # --------------------------------------------------------

    st.markdown(
        "### Case Filters"
    )

    filter_col1, filter_col2 = st.columns(2)

    case_severity_options = [
        "ALL",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]

    selected_case_severity = filter_col1.selectbox(
        "Severity",
        case_severity_options,
        key="case_severity_filter",
    )

    case_status_options = [
        "ALL",
        *sorted(
            {
                str(
                    case.get(
                        "status",
                        "UNKNOWN",
                    )
                ).upper()
                for case in cases
            }
        ),
    ]

    selected_case_status = filter_col2.selectbox(
        "Status",
        case_status_options,
        key="case_status_filter",
    )

    filtered_cases = [
        case
        for case in cases
        if (
            selected_case_severity == "ALL"
            or str(
                case.get(
                    "severity",
                    "",
                )
            ).upper()
            == selected_case_severity
        )
        and (
            selected_case_status == "ALL"
            or str(
                case.get(
                    "status",
                    "",
                )
            ).upper()
            == selected_case_status
        )
    ]

    st.caption(
        f"Showing {len(filtered_cases)} "
        f"of {len(cases)} case(s)."
    )

    if not filtered_cases:
        st.warning(
            "No cases match the selected filters."
        )

    else:
        case_options = {}

        for case in filtered_cases:
            label = (
                f"{case.get('case_id')} — "
                f"{case.get('title')} — "
                f"{case.get('severity')}"
            )

            case_options[label] = case

        selected_case_label = st.selectbox(
            "Select a case",
            list(case_options.keys()),
            key="dashboard_case_selector",
        )

        selected_case = case_options[
            selected_case_label
        ]

        case_id = selected_case.get(
            "case_id"
        )

        # ----------------------------------------------------
        # Case details
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "Case Details"
        )

        detail_col1, detail_col2, detail_col3, detail_col4 = (
            st.columns(4)
        )

        detail_col1.metric(
            "Severity",
            selected_case.get(
                "severity",
                "UNKNOWN",
            ),
        )

        detail_col2.metric(
            "Status",
            selected_case.get(
                "status",
                "UNKNOWN",
            ),
        )

        detail_col3.metric(
            "Case ID",
            case_id or "UNKNOWN",
        )

        detail_col4.metric(
            "Incident ID",
            selected_case.get(
                "incident_id",
                "UNKNOWN",
            ),
        )

        st.write(
            f"**Title:** "
            f"{selected_case.get('title', 'Unknown')}"
        )

        st.write(
            f"**Assigned To:** "
            f"{selected_case.get('assigned_to') or 'Unassigned'}"
        )

        st.write(
            f"**Created:** "
            f"{selected_case.get('created_at', 'Unknown')}"
        )

        st.write(
            f"**Updated:** "
            f"{selected_case.get('updated_at', 'Unknown')}"
        )

        st.markdown(
            "#### Description"
        )

        st.write(
            selected_case.get(
                "description",
                "No description available.",
            )
        )

        # ----------------------------------------------------
        # Case evidence
        # ----------------------------------------------------

        st.markdown(
            "#### Case Evidence"
        )

        display_case_evidence(
            selected_case.get(
                "evidence",
                [],
            )
        )

        # ----------------------------------------------------
        # Notes
        # ----------------------------------------------------

        display_case_notes(
            selected_case.get(
                "notes",
                [],
            )
        )

        # ----------------------------------------------------
        # Existing AI investigation
        # ----------------------------------------------------

        st.markdown(
            "### AI Investigation"
        )

        existing_ai = selected_case.get(
            "ai_investigation"
        )

        if existing_ai:
            display_ai_investigation(
                existing_ai
            )
        else:
            st.info(
                "No AI investigation has been recorded for this case."
            )

        # ----------------------------------------------------
        # Case actions
        # ----------------------------------------------------

        action_col1, action_col2 = st.columns(2)

        if action_col1.button(
            "Run AI Investigation",
            key=f"investigate_case_{case_id}",
            type="primary",
        ):
            try:
                investigation_result = safe_post(
                    f"{CASES_API_URL}/"
                    f"{case_id}/investigate",
                    timeout=120,
                )

                st.session_state.last_ai_investigation = (
                    investigation_result
                )

                st.success(
                    "AI investigation completed."
                )

            except requests.RequestException as error:
                st.error(
                    f"Unable to investigate case: {error}"
                )

        if action_col2.button(
            "Execute SOAR Response",
            key=f"respond_case_{case_id}",
            type="primary",
        ):
            try:
                soar_result = safe_post(
                    f"{CASES_API_URL}/"
                    f"{case_id}/respond",
                    timeout=120,
                )

                st.session_state.last_soar_execution = (
                    soar_result
                )

                st.success(
                    "SOAR response completed."
                )

            except requests.RequestException as error:
                st.error(
                    f"Unable to execute SOAR response: {error}"
                )

        # ----------------------------------------------------
        # Latest AI investigation result
        # ----------------------------------------------------

        latest_ai = (
            st.session_state.last_ai_investigation
        )

        if latest_ai:
            st.divider()

            st.subheader(
                "Latest AI Investigation Result"
            )

            display_ai_investigation(
                latest_ai
            )

        # ----------------------------------------------------
        # Latest SOAR result
        # ----------------------------------------------------

        latest_soar = (
            st.session_state.last_soar_execution
        )

        if latest_soar:
            st.divider()

            st.subheader(
                "Latest SOAR Execution"
            )

            display_soar_execution(
                latest_soar
            )


# ============================================================
# SOAR OPERATIONS CENTER
# ============================================================

st.divider()

st.header(
    "SOAR Operations Center"
)

st.caption(
    "Review configured playbooks and execution history."
)


soar_button_col1, soar_button_col2 = st.columns(2)


if soar_button_col1.button(
    "Load SOAR Executions",
    key="load_soar_executions",
):
    try:
        soar_data = safe_get(
            SOAR_EXECUTIONS_API_URL,
            timeout=15,
        )

        st.session_state.soar_executions = (
            soar_data.get(
                "executions",
                [],
            )
        )

    except requests.RequestException as error:
        st.error(
            f"Unable to load SOAR executions: {error}"
        )


if soar_button_col2.button(
    "Load Playbooks",
    key="load_soar_playbooks",
):
    try:
        playbook_data = safe_get(
            SOAR_PLAYBOOKS_API_URL,
            timeout=15,
        )

        st.session_state.soar_playbooks = (
            playbook_data.get(
                "playbooks",
                [],
            )
        )

    except requests.RequestException as error:
        st.error(
            f"Unable to load SOAR playbooks: {error}"
        )


# ============================================================
# SOAR EXECUTION HISTORY
# ============================================================

soar_executions = (
    st.session_state.soar_executions
)

if soar_executions is not None:
    st.subheader(
        "Execution History"
    )

    if not soar_executions:
        st.info(
            "No SOAR executions recorded."
        )

    else:
        completed_executions = sum(
            1
            for execution in soar_executions
            if execution.get(
                "status"
            )
            == "COMPLETED"
        )

        failed_executions = sum(
            1
            for execution in soar_executions
            if execution.get(
                "status"
            )
            == "FAILED"
        )

        running_executions = sum(
            1
            for execution in soar_executions
            if execution.get(
                "status"
            )
            == "RUNNING"
        )

        metric1, metric2, metric3, metric4 = (
            st.columns(4)
        )

        metric1.metric(
            "Total Executions",
            len(soar_executions),
        )

        metric2.metric(
            "Completed",
            completed_executions,
        )

        metric3.metric(
            "Failed",
            failed_executions,
        )

        metric4.metric(
            "Running",
            running_executions,
        )

        execution_options = {}

        for execution in soar_executions:
            label = (
                f"{execution.get('execution_id')} — "
                f"{execution.get('playbook_name')} — "
                f"{execution.get('status')}"
            )

            execution_options[label] = execution

        selected_execution_label = st.selectbox(
            "Select SOAR execution",
            list(execution_options.keys()),
            key="soar_execution_selector",
        )

        selected_execution = execution_options[
            selected_execution_label
        ]

        display_soar_execution(
            selected_execution
        )


# ============================================================
# CONFIGURED SOAR PLAYBOOKS
# ============================================================

soar_playbooks = (
    st.session_state.soar_playbooks
)

if soar_playbooks is not None:
    st.divider()

    st.subheader(
        "Configured Playbooks"
    )

    if not soar_playbooks:
        st.info(
            "No SOAR playbooks configured."
        )

    else:
        for playbook in soar_playbooks:
            playbook_id = playbook.get(
                "playbook_id",
                "UNKNOWN",
            )

            playbook_name = playbook.get(
                "name",
                "Unknown Playbook",
            )

            with st.expander(
                f"{playbook_id} — {playbook_name}"
            ):
                st.write(
                    playbook.get(
                        "description",
                        "",
                    )
                )

                st.write(
                    f"**Minimum Severity:** "
                    f"{playbook.get('minimum_severity', 'UNKNOWN')}"
                )

                incident_types = playbook.get(
                    "incident_types",
                    [],
                )

                if incident_types:
                    st.write(
                        "**Incident Types:** "
                        + ", ".join(
                            incident_types
                        )
                    )
                else:
                    st.write(
                        "**Incident Types:** "
                        "Generic security incidents"
                    )

                actions = playbook.get(
                    "actions",
                    [],
                )

                if actions:
                    st.markdown(
                        "**Actions:**"
                    )

                    for index, action in enumerate(
                        actions,
                        start=1,
                    ):
                        st.write(
                            f"{index}. {action}"
                        )