import os
import json
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=api_key)


def create_investigation_plan(case):

    prompt = f"""
You are the planning module of Cyber Trap,
a defensive cybercrime investigation agent.

Your job is to decide which investigation actions
are relevant for the given case.

CASE:
{case}

You have ONLY these actions available:

1. analyze_cyber_indicators

   Finds suspicious warning signs such as:
   urgency, threats, financial requests,
   OTP/password requests, impersonation,
   suspicious links, account compromise,
   unauthorized account changes,
   credential exposure and social engineering.

2. detect_scam_pattern

   Identifies possible cybercrime patterns such as:
   phishing, vishing, banking fraud,
   account takeover, credential theft,
   social media fraud, investment scams,
   job scams, lottery scams, extortion,
   government impersonation and tech support scams.

3. analyze_attack_chain

   Identifies the possible sequence of events
   in a cyberattack.

   For example:

   Initial contact
        ↓
   Suspicious link
        ↓
   Credential collection
        ↓
   Account compromise
        ↓
   Unauthorized activity
        ↓
   Secondary fraud

   Use this action when the case describes
   multiple stages of an attack or a possible
   progression from one cybercrime stage to another.

4. calculate_risk

   Calculates the risk level using the indicators
   discovered by analyze_cyber_indicators.

IMPORTANT RULES:

- analyze_cyber_indicators should normally happen first.
- detect_scam_pattern should normally happen after
  analyze_cyber_indicators.
- analyze_attack_chain should be used when the case
  contains a sequence of events, compromise stages,
  or multiple connected actions.
- calculate_risk MUST happen after
  analyze_cyber_indicators.
- Do not use actions that are not listed above.
- Only include actions relevant to the case.
- Avoid unnecessary actions.
- The same action should not appear more than once.
- If risk assessment is relevant, include calculate_risk.
- Make sure every action name exactly matches the
  available action names.

Return ONLY valid JSON.

Example:

[
    {{
        "step": 1,
        "action": "analyze_cyber_indicators"
    }},
    {{
        "step": 2,
        "action": "detect_scam_pattern"
    }},
    {{
        "step": 3,
        "action": "analyze_attack_chain"
    }},
    {{
        "step": 4,
        "action": "calculate_risk"
    }}
]
"""

    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt
    )

    text = response.text.strip()

    # Remove markdown code fences if Gemini adds them
    if text.startswith("```"):
        text = text.replace("```json", "")
        text = text.replace("```", "")
        text = text.strip()

    plan = json.loads(text)

    return plan