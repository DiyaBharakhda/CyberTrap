import os
import json
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=api_key)


def replan_investigation(case, results):

    prompt = f"""
You are the reasoning and replanning module of
Cyber Trap, a defensive cybercrime investigation agent.

ORIGINAL CASE:
{case}

CURRENT INVESTIGATION RESULTS:
{json.dumps(results, indent=2)}

The investigation has already performed some actions.

Your job is to decide whether the evidence is sufficient
to produce a reliable conclusion.

Ask yourself:

1. Do we have enough evidence?
2. Is an important investigation step missing?
3. Is another tool necessary?
4. Would another investigation step provide meaningful
   additional information?

Available actions:

- analyze_cyber_indicators
- detect_scam_pattern
- calculate_risk

If the evidence is sufficient, return:

{{
    "continue": false,
    "reason": "Evidence is sufficient."
}}

If more investigation is needed, return:

{{
    "continue": true,
    "reason": "Explain what is missing.",
    "next_actions": [
        "action_name"
    ]
}}

Return ONLY valid JSON.
"""

    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt
    )

    text = response.text.strip()

    if text.startswith("```"):
        text = text.replace("```json", "")
        text = text.replace("```", "")
        text = text.strip()

    return json.loads(text)