import os
import requests
from analyzer.rag_engine import RAGEngine

from dotenv import load_dotenv

load_dotenv()


class AISOCAgent:

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model = os.getenv(
            "GEMINI_MODEL",
            "gemini-3.8-flash"
        )
        self.rag = RAGEngine()

        self.api_url = (
            "https://generativelanguage.googleapis.com/"
            "v1beta/models/"
            f"{self.model}:generateContent"
        )

    def investigate(self, incident):
        """
        Investigate a security incident using Gemini.
        """
        rag_results = self.rag.search(
            incident["type"]
        )

        rag_context = "\n\n".join(
            result["content"]
            for result in rag_results[:2]
        )

        prompt = f"""
You are an experienced SOC analyst.

Analyze the following security incident:

Incident ID: {incident["incident_id"]}
Incident Type: {incident["type"]}
Risk Level: {incident["risk"]}
Source IP: {incident["source_ip"]}

Relevant cybersecurity knowledge retrieved from the RAG knowledge base:

{rag_context}

Provide:
1. A concise investigation analysis.
2. Exactly 3 practical SOC recommendations.

Return the response in this format:

ANALYSIS:
<analysis>

RECOMMENDATIONS:
- <recommendation 1>
- <recommendation 2>
- <recommendation 3>
"""

        if not self.api_key:
           return {
            "incident_id": incident["incident_id"],
            "type": incident["type"],
            "risk": incident["risk"],
            "source_ip": incident["source_ip"],
            "investigation_status": "FAILED",
            "analysis": "Gemini API key is not configured.",
            "recommendations": []
        }

        headers = {
        "Content-Type": "application/json"
    }

        payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ]
    }

        try:
            response = None

            for attempt in range(3):
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    params={"key": self.api_key},
                    json=payload,
                    timeout=30
                )

                if response.status_code != 503:
                    break

            if response.status_code != 200:
               return {
                "incident_id": incident["incident_id"],
                "type": incident["type"],
                "risk": incident["risk"],
                "source_ip": incident["source_ip"],
                "investigation_status": "FAILED",
                "analysis": f"Gemini API request failed: {response.text}",
                "recommendations": []
            }

            data = response.json()

            text = data["candidates"][0]["content"]["parts"][0]["text"]
            text = text.strip()

            if "RECOMMENDATIONS:" not in text:
                return {
                    "incident_id": incident["incident_id"],
                    "type": incident["type"],
                    "risk": incident["risk"],
                    "source_ip": incident["source_ip"],
                    "investigation_status": "COMPLETED",
                    "analysis": text.replace("ANALYSIS:", "").strip(),
                    "recommendations": []
                }

            analysis = text
            recommendations = []

            if "RECOMMENDATIONS:" in text:
                analysis, recommendations_text = text.split(
                "RECOMMENDATIONS:",
                1
            )

                analysis = analysis.replace(
                "ANALYSIS:",
                ""
            ).strip()

                recommendations = [
                line.strip("- ").strip()
                for line in recommendations_text.splitlines()
                if line.strip().startswith("-")
            ]

            return {
            "incident_id": incident["incident_id"],
            "type": incident["type"],
            "risk": incident["risk"],
            "source_ip": incident["source_ip"],
            "investigation_status": "COMPLETED",
            "analysis": analysis,
            "recommendations": recommendations
        }

        except Exception as error:
            return {
            "incident_id": incident["incident_id"],
            "type": incident["type"],
            "risk": incident["risk"],
            "source_ip": incident["source_ip"],
            "investigation_status": "FAILED",
            "analysis": f"Gemini investigation failed: {error}",
            "recommendations": []
        }