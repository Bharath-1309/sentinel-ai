import streamlit as st
import requests

st.set_page_config(
    page_title="SentinelAI SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("SentinelAI")
st.caption("AI-Powered SOC Investigation & Incident Response Platform")

API_URL = "http://127.0.0.1:8000/analyze"

if st.button("Run Security Analysis", type="primary"):

    try:
        response = requests.get(API_URL, timeout=60)
        response.raise_for_status()

        data = response.json()

        alerts = data.get("alerts", [])
        incidents = data.get("incidents", [])

        st.success("Security analysis completed.")

        critical_count = sum(
            1 for incident in incidents
            if incident.get("risk") == "CRITICAL"
        )

        high_count = sum(
            1 for incident in incidents
            if incident.get("risk") == "HIGH"
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Security Alerts",
            len(alerts)
        )

        col2.metric(
            "Incidents",
            len(incidents)
        )

        col3.metric(
            "Critical Incidents",
            critical_count
        )

        col4.metric(
            "High-Risk Incidents",
            high_count
        )

        st.divider()

        st.subheader("Security Alerts")

        for alert in alerts:

            risk = alert.get("risk", "UNKNOWN")

            with st.expander(
                f"{alert.get('type')} — {risk}"
            ):

                col1, col2, col3 = st.columns(3)

                col1.write(
                    f"**Username:** {alert.get('username')}"
                )

                col2.write(
                    f"**Source IP:** {alert.get('ip')}"
                )

                col3.write(
                    f"**Failed Attempts:** {alert.get('failed_attempts')}"
                )

                st.write(
                    f"**Timestamp:** {alert.get('timestamp')}"
                )

                st.write(
                    f"**Successful Login:** {alert.get('successful_login')}"
                )

                mitre = alert.get("mitre")

                if mitre:
                    st.write(
                        f"**MITRE ATT&CK:** "
                        f"{mitre.get('technique_id')} — "
                        f"{mitre.get('technique')}"
                    )

        st.divider()

        st.subheader("Security Incidents")

        for incident in incidents:

            risk = incident.get("risk", "UNKNOWN")

            with st.expander(
                f"{incident.get('incident_id')} — "
                f"{incident.get('type')} — {risk}"
            ):

                col1, col2, col3 = st.columns(3)

                col1.write(
                    f"**Source IP:** {incident.get('source_ip')}"
                )

                col2.write(
                    f"**Risk Score:** {incident.get('risk_score')}"
                )

                col3.write(
                    f"**Status:** {incident.get('status')}"
                )

                st.write(
                    f"**Alert Count:** {incident.get('alert_count')}"
                )

                st.write(
                    f"**Start Time:** {incident.get('start_time')}"
                )

                st.write(
                    f"**End Time:** {incident.get('end_time')}"
                )

                ai = incident.get("ai_investigation")

                if ai:
                    st.markdown("#### AI Investigation")

                    st.write(
                        f"**Status:** "
                        f"{ai.get('investigation_status')}"
                    )

                    st.write(
                        ai.get(
                            "analysis",
                            "No AI analysis available."
                        )
                    )

                    recommendations = ai.get(
                        "recommendations",
                        []
                    )

                    if recommendations:
                        st.markdown("**Recommendations:**")

                        for recommendation in recommendations:
                            st.write(
                                f"- {recommendation}"
                            )

    except requests.RequestException as error:

        st.error(
            f"Unable to connect to SentinelAI API: {error}"
        )