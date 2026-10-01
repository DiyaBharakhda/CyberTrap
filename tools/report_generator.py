import os
import json
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=api_key)


def generate_final_report(case, results, decision):

    # -----------------------------------------------------
    # Extract investigation information
    # -----------------------------------------------------

    indicators = results.get(
        "indicators",
        []
    )

    patterns = results.get(
        "patterns",
        []
    )

    attack_chain = results.get(
        "attack_chain",
        []
    )

    risk = results.get(
        "risk",
        {}
    )


    # -----------------------------------------------------
    # Create prompt for Gemini
    # -----------------------------------------------------

    prompt = f"""
You are the final report generation module of Cyber Trap,
a defensive cybercrime investigation agent.

Create a professional, structured, and easy-to-understand
cybercrime investigation report based ONLY on the information
provided below.

=========================================================
ORIGINAL CASE
=========================================================

{case}


=========================================================
INVESTIGATION EVIDENCE
=========================================================

Detected Indicators:
{json.dumps(indicators, indent=2)}

Detected Cybercrime Patterns:
{json.dumps(patterns, indent=2)}

Attack Chain:
{json.dumps(attack_chain, indent=2)}

Risk Assessment:
{json.dumps(risk, indent=2)}


=========================================================
AGENT DECISION
=========================================================

{json.dumps(decision, indent=2)}


=========================================================
REPORT REQUIREMENTS
=========================================================

The report must contain the following sections:


Create a SHORT investigation summary.

The output must be easy to read and should NOT contain
long paragraphs or detailed explanations.

Use ONLY these sections:

## INCIDENT
One or two short sentences explaining what happened.

## THREAT DETECTED
List the most likely cybercrime/scam type in 1-2 lines.

## KEY WARNING SIGNS
List only the important indicators as short bullet points.

## ATTACK CHAIN
Show the attack in one short sequence using arrows.

Example:
SMS → Fake Website → Credential Request → OTP Request

## RISK
Show only:
Risk Score: XX/100
Risk Level: HIGH/CRITICAL/MEDIUM/LOW

## WHAT TO DO NOW
Give a maximum of 4 short defensive actions.

## VERDICT
Give ONE short sentence explaining the conclusion.

IMPORTANT:
- Keep the entire report under 250 words.
- No long explanations.
- No repeated information.
- No unnecessary technical details.
- Do not add extra sections.
- Do not use HTML.
- Do not invent evidence.
- Keep recommendations defensive and safe.


=========================================================
IMPORTANT RULES
=========================================================

- Base the report ONLY on the provided information.
- Do not invent evidence.
- Do not invent URLs, phone numbers, IP addresses,
  transactions, or attackers.
- Do not claim certainty when the evidence is uncertain.
- Distinguish between "possible", "likely", and
  "confirmed" when appropriate.
- The attack chain must reflect the evidence.
- Keep recommendations defensive and safe.
- Do not provide instructions for committing cybercrime.
- Keep the language professional but understandable.
- Make the report suitable for a cybercrime investigation
  project demonstration.

Return ONLY the report.
"""


    # -----------------------------------------------------
    # Generate report using Gemini
    # -----------------------------------------------------

    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt
    )

    return response.text