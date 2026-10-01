import streamlit as st
import textwrap
import re
import os
import time
import hashlib
import hmac
import secrets

from io import BytesIO

from memory.database import (
    create_tables,
    get_dashboard_stats,
    get_recent_cases,
    get_case_evidence,
    get_case_investigations,
    get_case_report,
    get_user_cases,
    get_all_users,
    get_user_by_email,
    create_user,
    generate_user_id,
    email_exists,
    assign_case_to_user
)

from tools.hypothesis_engine import generate_hypotheses
from tools.evidence_timeline import build_evidence_timeline
from tools.evidence_graph import build_evidence_graph
from tools.agent import run_investigation
from tools.cyber_tools import extract_evidence, analyze_evidence


# =========================================================
# REAL GEMINI AI AGENT BRAIN
# =========================================================

def _gemini_json(prompt, model=None):
    """Call Google Gemini with automatic fallback to an available model."""
    import json

    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        try:
            api_key = st.secrets["GEMINI_API_KEY"].strip()
        except Exception:
            api_key = ""

    if not api_key:
        return {"error": "GEMINI_API_KEY is not set."}

    requested_model = model or os.getenv("CYBERTRAP_GEMINI_MODEL", "gemini-2.5-flash")

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        def clean_model_name(name):
            name = str(name or "").strip()
            return name.replace("models/", "", 1) if name.startswith("models/") else name

        def available_models():
            """Return models exposed by this API key that can generate content."""
            found = []
            try:
                for item in client.models.list():
                    raw_name = getattr(item, "name", "")
                    name = clean_model_name(raw_name)
                    if not name:
                        continue

                    actions = getattr(item, "supported_actions", None)
                    if actions:
                        action_text = {str(a).lower() for a in actions}
                        if not any("generatecontent" in a or "generate_content" in a for a in action_text):
                            continue

                    found.append(name)
            except Exception:
                return []

            # Prefer current Flash models because Cyber Trap needs fast structured JSON.
            def rank(name):
                n = name.lower()
                if "flash-lite" in n:
                    return 0
                if "flash" in n:
                    return 1
                if "pro" in n:
                    return 2
                return 3

            return sorted(set(found), key=rank)

        def call(selected_model):
            response = client.models.generate_content(
                model=clean_model_name(selected_model),
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    response_mime_type="application/json"
                )
            )
            text = response.text or ""
            if not text.strip():
                return {"error": "Gemini returned an empty response."}
            return {
                "data": json.loads(text),
                "provider": "Google Gemini",
                "model": clean_model_name(selected_model)
            }

        # Try the configured model first, unless it is the known unavailable
        # default shown by the current API error.
        known_unavailable_default = clean_model_name(requested_model) == "gemini-2.5-flash"
        if not known_unavailable_default:
            try:
                return call(requested_model)
            except json.JSONDecodeError as exc:
                return {"error": f"Gemini returned invalid JSON: {exc}"}
            except Exception as exc:
                error_text = str(exc)
                if "404" not in error_text and "NOT_FOUND" not in error_text and "not found" not in error_text.lower():
                    return {"error": f"Gemini AI Agent call failed: {exc}"}

        # The configured/default model is unavailable. Discover a model that
        # this exact API key is currently allowed to use.
        candidates = available_models()
        if not candidates:
            return {
                "error": (
                    "Gemini could not find an available generateContent model for this API key. "
                    "Open Google AI Studio > API keys and verify that the key has Gemini API access."
                )
            }

        # Try candidates in order until one succeeds.
        last_error = None
        for candidate in candidates:
            if candidate == clean_model_name(requested_model):
                continue
            try:
                result = call(candidate)
                os.environ["CYBERTRAP_GEMINI_MODEL"] = candidate
                return result
            except json.JSONDecodeError as exc:
                return {"error": f"Gemini returned invalid JSON from {candidate}: {exc}"}
            except Exception as exc:
                last_error = exc
                continue

        return {
            "error": (
                "Gemini model discovery succeeded, but every available model failed. "
                f"Last error: {last_error}"
            )
        }

    except Exception as exc:
        return {"error": f"Gemini AI Agent setup failed: {exc}"}


def _agent_payload(incident, evidence_analysis, hypothesis_analysis, timeline):
    import json
    findings = (evidence_analysis or {}).get("findings", {}) or {}
    hypotheses = (hypothesis_analysis or {}).get("hypotheses", []) or []
    return json.dumps({
        "incident": incident[:12000],
        "findings": findings,
        "url_analysis": (evidence_analysis or {}).get("url_analysis", [])[:8],
        "hypotheses": [
            {"name": h.get("name", "Unknown"), "score": h.get("score", 0),
             "explanation": h.get("explanation", "")}
            for h in hypotheses[:5] if isinstance(h, dict)
        ],
        "timeline": (timeline or [])[:20]
    }, ensure_ascii=False)


def create_ai_investigation_plan(incident, evidence_analysis, hypothesis_analysis, timeline):
    """AI creates a concrete investigation artifact: a prioritized executable plan."""
    prompt = f"""
You are the planning brain of Cyber Trap, a defensive cybercrime investigation agent.
You MUST CREATE an investigation plan from the evidence below, not merely answer the user.
Choose 2 to 5 executable tasks from this exact list:
INVESTIGATE_URL, INVESTIGATE_SENDER, ANALYZE_FINANCIAL_ACTIVITY,
CHECK_MISSING_EVIDENCE, CHALLENGE_HYPOTHESIS.
Order them by value. The plan will be executed automatically by Cyber Trap's local
investigation tools. A task should only be included when the evidence makes it useful.
Return ONLY JSON with:
{{
  "plan_title": "short title",
  "objective": "one sentence",
  "hypotheses": [{{"name":"...","confidence":0-100}}],
  "tasks": [{{"step":1,"action":"EXACT_ACTION","reason":"short evidence-based reason","priority":"HIGH|MEDIUM|LOW"}}],
  "stop_condition": "what evidence would be sufficient to stop"
}}
Do not provide hidden chain-of-thought. Give concise, auditable reasons only.

CASE DATA:
{_agent_payload(incident, evidence_analysis, hypothesis_analysis, timeline)}
"""
    response = _gemini_json(prompt)
    if response.get("error"):
        return response
    plan = response.get("data") or {}
    plan["provider"] = response.get("provider")
    plan["model"] = response.get("model")
    return {"data": plan}


def execute_agent_tool(action, findings, evidence_analysis, hypothesis_analysis):
    """Execute a selected investigation action against the already-ingested evidence."""
    action = normalize_ai_action(action)
    findings = findings or {}
    evidence_analysis = evidence_analysis or {}
    if action == "INVESTIGATE_URL":
        urls = findings.get("urls", []) or []
        analyses = evidence_analysis.get("url_analysis", []) or []
        return {
            "tool": "URL Risk Analyzer",
            "evidence_created": [
                {"url": str(url), "assessment": analyses[i] if i < len(analyses) else {}}
                for i, url in enumerate(urls[:5])
            ]
        }
    if action == "INVESTIGATE_SENDER":
        return {"tool": "Sender / Identity Analyzer", "evidence_created": {
            "emails": findings.get("emails", [])[:8],
            "phone_numbers": findings.get("phone_numbers", [])[:8],
            "impersonation": findings.get("impersonation", [])[:8]
        }}
    if action == "ANALYZE_FINANCIAL_ACTIVITY":
        return {"tool": "Financial Activity Analyzer", "evidence_created": {
            "money_mentions": findings.get("money_mentions", [])[:8],
            "financial_requests": findings.get("financial_requests", [])[:8],
            "sensitive_requests": findings.get("sensitive_requests", [])[:10]
        }}
    if action == "CHECK_MISSING_EVIDENCE":
        gaps = []
        if not findings.get("urls"): gaps.append("Original URL or link")
        if not findings.get("emails"): gaps.append("Original sender email")
        if not findings.get("phone_numbers"): gaps.append("Original sender number")
        if not findings.get("sensitive_requests"): gaps.append("Exact information requested")
        gaps += ["Original screenshot/copy of communication", "Exact incident date and time"]
        return {"tool": "Evidence Gap Analyzer", "evidence_created": {"missing_evidence": list(dict.fromkeys(gaps))[:8]}}
    if action == "CHALLENGE_HYPOTHESIS":
        hypotheses = (hypothesis_analysis or {}).get("hypotheses", []) or []
        return {"tool": "Hypothesis Challenge Engine", "evidence_created": {
            "competing_hypotheses": [
                {"name": h.get("name"), "score": h.get("score"), "explanation": h.get("explanation", "")}
                for h in hypotheses[:5] if isinstance(h, dict)
            ]
        }}
    return {"tool": "Investigation Stop", "evidence_created": {"status": "Sufficient evidence for current agent pass."}}


def create_ai_investigation_artifacts(incident, evidence_analysis, hypothesis_analysis, timeline, plan, executions, reevaluation):
    """Ask Gemini to create concrete case artifacts from the investigation state."""
    import json
    prompt = f"""
You are the artifact-generation brain of Cyber Trap.
Create a concrete investigation dossier from the evidence and agent activity below.
This is NOT a chat response: you are creating structured case artifacts that the application will display and save as the investigation's AI-generated work product.

Return ONLY JSON with exactly these fields:
{{
  "case_title": "short professional case title",
  "executive_summary": "4-6 sentence evidence-based summary",
  "threat_classification": "most likely classification",
  "confidence": 0-100,
  "hypotheses": [{{"name":"...","confidence":0-100,"status":"LEADING|ALTERNATIVE|WEAKENED","reason":"short evidence-based reason"}}],
  "evidence_matrix": [{{"evidence":"...","significance":"CRITICAL|HIGH|MEDIUM|LOW","supports":"..."}}],
  "attack_chain": ["stage 1", "stage 2", "stage 3"],
  "missing_evidence": ["..."],
  "response_plan": ["action 1", "action 2", "action 3", "action 4"],
  "agent_decision": "short statement of what the agent decided after investigation",
  "next_recommended_action": "..."
}}

Do not invent facts. If something is unknown, say so. Do not provide hidden chain-of-thought.

CASE:
{incident[:12000]}

EVIDENCE:
{_agent_payload(incident, evidence_analysis, hypothesis_analysis, timeline)}

AI PLAN:
{json.dumps(plan, ensure_ascii=False, default=str)}

TOOL EXECUTIONS:
{json.dumps(executions, ensure_ascii=False, default=str)}

AI RE-EVALUATION:
{json.dumps(reevaluation, ensure_ascii=False, default=str)}
"""
    return _gemini_json(prompt)


def _build_dossier_markdown(artifacts, case_id):
    """Create a human-readable artifact from the AI-generated structured dossier."""
    lines = [
        f"# CYBER TRAP — AI INVESTIGATION DOSSIER",
        f"Case: CT-{case_id:04d}",
        "",
        f"## {artifacts.get('case_title', 'Investigation Dossier')}",
        f"**Threat classification:** {artifacts.get('threat_classification', 'Unknown')}",
        f"**AI confidence:** {artifacts.get('confidence', 0)}%",
        "",
        "## Executive Summary",
        artifacts.get('executive_summary', 'No summary generated.'),
        "",
        "## Hypotheses",
    ]
    for h in artifacts.get('hypotheses', []) or []:
        lines.append(f"- **{h.get('name','Unknown')}** — {h.get('confidence',0)}% — {h.get('status','')} — {h.get('reason','')}")
    lines += ["", "## Evidence Matrix"]
    for e in artifacts.get('evidence_matrix', []) or []:
        lines.append(f"- **{e.get('significance','MEDIUM')}** {e.get('evidence','')} → {e.get('supports','')}")
    lines += ["", "## Attack Chain"]
    for i, stage in enumerate(artifacts.get('attack_chain', []) or [], 1):
        lines.append(f"{i}. {stage}")
    lines += ["", "## Missing Evidence"]
    for item in artifacts.get('missing_evidence', []) or []:
        lines.append(f"- {item}")
    lines += ["", "## Response Plan"]
    for i, item in enumerate(artifacts.get('response_plan', []) or [], 1):
        lines.append(f"{i}. {item}")
    lines += ["", "## Agent Decision", artifacts.get('agent_decision', ''), "", "## Next Recommended Action", artifacts.get('next_recommended_action', '')]
    return "\n".join(lines)


def run_autonomous_ai_agent(incident, evidence_analysis, hypothesis_analysis, timeline, case_id=None):
    """Gemini creates a plan, tools execute it, Gemini replans, then creates case artifacts."""
    plan_response = create_ai_investigation_plan(incident, evidence_analysis, hypothesis_analysis, timeline)
    if plan_response.get("error"):
        return plan_response

    plan = plan_response.get("data", {}) or {}
    tasks = plan.get("tasks", []) or []
    findings = (evidence_analysis or {}).get("findings", {}) or {}
    executions = []

    for task in tasks[:5]:
        action = normalize_ai_action(task.get("action"))
        if action == "STOP_INVESTIGATION":
            break
        tool_result = execute_agent_tool(action, findings, evidence_analysis, hypothesis_analysis)
        executions.append({
            "step": task.get("step", len(executions) + 1),
            "action": action,
            "reason": task.get("reason", "Evidence-based task selected by AI."),
            "priority": task.get("priority", "MEDIUM"),
            "tool": tool_result.get("tool"),
            "evidence_created": tool_result.get("evidence_created")
        })

    import json
    replan_prompt = f"""
You are the re-planning brain of Cyber Trap. Gemini created the plan below and Cyber Trap executed it.
Now use the tool results to decide whether the agent should execute ONE MORE action or stop.
The selected action will actually be executed by the application.
Return ONLY JSON:
{{
  "observation":"short updated observation",
  "key_signal":"most important new signal",
  "hypotheses":[{{"name":"...","confidence":0-100}}],
  "next_action":"INVESTIGATE_URL|INVESTIGATE_SENDER|ANALYZE_FINANCIAL_ACTIVITY|CHECK_MISSING_EVIDENCE|CHALLENGE_HYPOTHESIS|STOP_INVESTIGATION",
  "rationale":"1-3 sentence auditable decision summary",
  "confidence":0-100,
  "should_continue":true,
  "replan_reason":"short explanation"
}}
No hidden chain-of-thought.
PLAN:
{json.dumps(plan, ensure_ascii=False)}
EXECUTED TOOL RESULTS:
{json.dumps(executions, ensure_ascii=False, default=str)}
ORIGINAL CASE:
{_agent_payload(incident, evidence_analysis, hypothesis_analysis, timeline)}
"""
    reevaluation = _gemini_json(replan_prompt)
    if reevaluation.get("error"):
        return {"data": {"plan": plan, "executions": executions, "reevaluation": {"error": reevaluation["error"]}, "provider": plan.get("provider"), "model": plan.get("model")}}

    decision = reevaluation.get("data", {}) or {}
    decision["next_action"] = normalize_ai_action(decision.get("next_action"))
    decision["provider"] = reevaluation.get("provider", plan.get("provider"))
    decision["model"] = reevaluation.get("model", plan.get("model"))

    # The agent's next action is actually executed once, not merely displayed.
    if decision["next_action"] != "STOP_INVESTIGATION":
        next_tool = execute_agent_tool(decision["next_action"], findings, evidence_analysis, hypothesis_analysis)
        executions.append({
            "step": len(executions) + 1,
            "action": decision["next_action"],
            "reason": decision.get("rationale", "AI selected a follow-up action after re-evaluation."),
            "priority": "AI FOLLOW-UP",
            "tool": next_tool.get("tool"),
            "evidence_created": next_tool.get("evidence_created")
        })
        decision["executed_follow_up"] = True
    else:
        decision["executed_follow_up"] = False

    artifact_response = create_ai_investigation_artifacts(
        incident, evidence_analysis, hypothesis_analysis, timeline, plan, executions, decision
    )
    artifacts = artifact_response.get("data", {}) if not artifact_response.get("error") else {"error": artifact_response.get("error")}
    if isinstance(artifacts, dict):
        artifacts["provider"] = artifact_response.get("provider", decision.get("provider"))
        artifacts["model"] = artifact_response.get("model", decision.get("model"))

    return {"data": {
        "plan": plan,
        "executions": executions,
        "reevaluation": decision,
        "artifacts": artifacts,
        "provider": decision.get("provider"),
        "model": decision.get("model")
    }}


def normalize_ai_action(action):
    allowed = {
        "INVESTIGATE_URL", "INVESTIGATE_SENDER",
        "ANALYZE_FINANCIAL_ACTIVITY", "CHECK_MISSING_EVIDENCE",
        "CHALLENGE_HYPOTHESIS", "STOP_INVESTIGATION"
    }
    action = str(action or "").strip().upper()
    return action if action in allowed else "CHECK_MISSING_EVIDENCE"


# =========================================================
# DATABASE
# =========================================================

create_tables()


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Cyber Trap",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# HTML HELPER
# =========================================================

def render_html(html):
    st.html(
        textwrap.dedent(html)
    )

# =========================================================
# CSS
# =========================================================

st.markdown("""
<style>
/* =========================================================
   CYBER TRAP — COMMAND CENTER UI
   ========================================================= */

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');

:root {
    --bg: #070b12;
    --panel: rgba(16, 23, 35, 0.82);
    --panel-2: rgba(20, 29, 44, 0.92);
    --line: rgba(120, 145, 180, 0.18);
    --muted: #8997aa;
    --text: #eef4ff;
    --cyan: #54d6ff;
    --violet: #8b7cff;
    --green: #52e0a1;
}

.stApp {
    background:
        radial-gradient(circle at 75% 5%, rgba(84,214,255,.10), transparent 28%),
        radial-gradient(circle at 15% 20%, rgba(139,124,255,.09), transparent 25%),
        linear-gradient(135deg, #070b12 0%, #0a101a 48%, #070b12 100%);
    color: var(--text);
    font-family: 'Inter', sans-serif;
}

.block-container {
    padding-top: 1.4rem;
    padding-bottom: 4rem;
    max-width: 1450px;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0b111b 0%, #080d15 100%);
    border-right: 1px solid rgba(84,214,255,.13);
}

section[data-testid="stSidebar"] > div {
    padding-top: 1.2rem;
}

section[data-testid="stSidebar"] hr {
    border-color: rgba(120,145,180,.16);
}

section[data-testid="stSidebar"] .stRadio label {
    border-radius: 10px;
    padding: 7px 10px;
    transition: .2s ease;
}

section[data-testid="stSidebar"] .stRadio label:hover {
    background: rgba(84,214,255,.07);
}

/* Typography */
h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    letter-spacing: -.5px;
}

h1 { font-size: 2.45rem !important; }
h2 { font-size: 1.75rem !important; }
h3 { font-size: 1.25rem !important; }

/* Glass cards */
.card, .section-card, .case-card, .metric-card {
    background: linear-gradient(145deg, rgba(18,27,41,.90), rgba(10,16,26,.92));
    border: 1px solid var(--line);
    box-shadow: 0 14px 40px rgba(0,0,0,.20);
    backdrop-filter: blur(14px);
}

.card {
    padding: 22px;
    border-radius: 16px;
    margin-bottom: 16px;
    transition: transform .2s ease, border-color .2s ease;
}

.card:hover {
    transform: translateY(-2px);
    border-color: rgba(84,214,255,.28);
}

.metric-card {
    padding: 20px;
    border-radius: 15px;
    text-align: left;
    min-height: 112px;
    position: relative;
    overflow: hidden;
}

.metric-card::after {
    content: '';
    position: absolute;
    width: 90px;
    height: 90px;
    right: -35px;
    top: -35px;
    border-radius: 50%;
    background: rgba(84,214,255,.08);
}

.metric-number {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 34px;
    font-weight: 700;
    margin-top: 9px;
}

.metric-label {
    color: var(--muted);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1.4px;
}

/* Dashboard hero */
.hero {
    position: relative;
    overflow: hidden;
    border: 1px solid rgba(84,214,255,.18);
    border-radius: 22px;
    padding: 32px 34px;
    margin: 6px 0 24px 0;
    background:
        radial-gradient(circle at 90% 10%, rgba(84,214,255,.15), transparent 30%),
        radial-gradient(circle at 65% 100%, rgba(139,124,255,.14), transparent 34%),
        linear-gradient(135deg, rgba(17,27,43,.96), rgba(9,15,25,.96));
    box-shadow: 0 22px 60px rgba(0,0,0,.28);
}

.hero-grid {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 25px;
}

.hero-title {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 42px;
    font-weight: 700;
    line-height: 1.05;
    margin: 10px 0 10px;
}

.hero-subtitle {
    color: #aab7c9;
    max-width: 720px;
    line-height: 1.65;
    font-size: 15px;
}

.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 7px 12px;
    border: 1px solid rgba(82,224,161,.25);
    border-radius: 999px;
    background: rgba(82,224,161,.07);
    color: #8ef0c2;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
}

.status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #52e0a1;
    box-shadow: 0 0 12px #52e0a1;
}

/* Section heading */
.section-heading {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 26px 0 14px;
}

.section-heading .accent {
    width: 4px;
    height: 23px;
    border-radius: 4px;
    background: linear-gradient(180deg, var(--cyan), var(--violet));
}

.section-heading span {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 19px;
    font-weight: 700;
}

/* Attack / investigation steps */
.attack-step {
    background: rgba(17,25,39,.78);
    border: 1px solid var(--line);
    border-left: 3px solid var(--violet);
    padding: 15px 17px;
    margin: 9px 0;
    border-radius: 10px;
}

.report-card {
    background: rgba(8,13,21,.88);
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 28px;
    margin-top: 10px;
}

/* Inputs */
textarea, input {
    background: rgba(10,16,26,.90) !important;
    border: 1px solid rgba(120,145,180,.24) !important;
    border-radius: 12px !important;
}

textarea:focus, input:focus {
    border-color: rgba(84,214,255,.65) !important;
    box-shadow: 0 0 0 1px rgba(84,214,255,.15) !important;
}

/* Buttons */
.stButton > button {
    border-radius: 11px;
    border: 1px solid rgba(84,214,255,.28);
    background: linear-gradient(135deg, rgba(84,214,255,.14), rgba(139,124,255,.16));
    color: #edf7ff;
    font-weight: 700;
    min-height: 44px;
    transition: all .2s ease;
}

.stButton > button:hover {
    border-color: rgba(84,214,255,.65);
    box-shadow: 0 0 24px rgba(84,214,255,.10);
    transform: translateY(-1px);
}

/* Expander */
details[data-testid="stExpander"] {
    background: rgba(12,19,30,.72);
    border: 1px solid rgba(120,145,180,.18);
    border-radius: 12px;
}

details[data-testid="stExpander"] summary:hover {
    background: rgba(84,214,255,.04);
}

/* File uploader */
section[data-testid="stFileUploaderDropzone"] {
    background: rgba(10,16,26,.65);
    border: 1px dashed rgba(84,214,255,.25);
    border-radius: 12px;
}

/* Dividers */
hr {
    border-color: rgba(120,145,180,.13) !important;
}

/* Alerts */
div[data-testid="stAlert"] {
    border-radius: 12px;
}


/* Animated command-center grid */
.stApp::before {
    content: '';
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: .18;
    background-image:
        linear-gradient(rgba(84,214,255,.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(84,214,255,.045) 1px, transparent 1px);
    background-size: 42px 42px;
    mask-image: linear-gradient(to bottom, black, transparent 85%);
}

/* Radar */
.radar {
    width: 185px;
    height: 185px;
    border-radius: 50%;
    position: relative;
    border: 1px solid rgba(84,214,255,.25);
    background:
        radial-gradient(circle, rgba(84,214,255,.10) 0 2px, transparent 3px),
        repeating-radial-gradient(circle, transparent 0 27px, rgba(84,214,255,.10) 28px 29px),
        linear-gradient(90deg, transparent 49.5%, rgba(84,214,255,.13) 50%, transparent 50.5%),
        linear-gradient(transparent 49.5%, rgba(84,214,255,.13) 50%, transparent 50.5%);
    box-shadow: 0 0 45px rgba(84,214,255,.08), inset 0 0 35px rgba(84,214,255,.05);
    overflow: hidden;
}
.radar::before {
    content: '';
    position: absolute;
    width: 50%;
    height: 50%;
    left: 50%;
    top: 50%;
    transform-origin: 0 0;
    background: conic-gradient(from 0deg, rgba(84,214,255,.42), transparent 24deg, transparent 360deg);
    animation: radarSweep 3.2s linear infinite;
}
.radar::after {
    content: '◉  ACTIVE';
    position: absolute;
    bottom: 12px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 9px;
    letter-spacing: 1.5px;
    color: #7de5ff;
    white-space: nowrap;
}
.radar-dot { position:absolute; width:7px; height:7px; border-radius:50%; background:#52e0a1; box-shadow:0 0 14px #52e0a1; }
.radar-dot.one { left: 64%; top: 30%; }
.radar-dot.two { left: 29%; top: 61%; background:#8b7cff; box-shadow:0 0 14px #8b7cff; }
.radar-dot.three { left: 71%; top: 68%; background:#ffbd5a; box-shadow:0 0 14px #ffbd5a; }
@keyframes radarSweep { to { transform: rotate(360deg); } }

/* Hero scan line */
.hero::after {
    content:'';
    position:absolute;
    left:0;
    right:0;
    height:1px;
    top:0;
    background:linear-gradient(90deg, transparent, rgba(84,214,255,.5), transparent);
    animation: scanLine 4s ease-in-out infinite;
}
@keyframes scanLine { 0%,100% { top:8%; opacity:.1; } 50% { top:92%; opacity:.7; } }

/* Tiny terminal strip */
.terminal-strip {
    margin-top: 18px;
    padding: 9px 12px;
    border-radius: 9px;
    background: rgba(4,9,15,.72);
    border: 1px solid rgba(84,214,255,.12);
    color: #718399;
    font: 11px Consolas, monospace;
}
.terminal-strip b { color:#52e0a1; }

</style>
""", unsafe_allow_html=True)


# =========================================================
# SESSION STATE + AUTHENTICATION
# =========================================================

if "investigation_result" not in st.session_state:
    st.session_state.investigation_result = None

if "investigation_action" not in st.session_state:
    st.session_state.investigation_action = None

if "revealed_sections" not in st.session_state:
    st.session_state.revealed_sections = set()

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_user_id" not in st.session_state:
    st.session_state.current_user_id = None
if "current_user_name" not in st.session_state:
    st.session_state.current_user_name = None
if "current_user_email" not in st.session_state:
    st.session_state.current_user_email = None
if "user_role" not in st.session_state:
    st.session_state.user_role = None
if "login_step" not in st.session_state:
    st.session_state.login_step = 1
if "login_identifier" not in st.session_state:
    st.session_state.login_identifier = ""
if "login_failures" not in st.session_state:
    st.session_state.login_failures = 0
if "login_locked_until" not in st.session_state:
    st.session_state.login_locked_until = 0.0
if "pending_page" not in st.session_state:
    st.session_state.pending_page = None


# ---------------------------------------------------------
# AUTH HELPERS
# ---------------------------------------------------------

ADMIN_USERNAME = os.getenv("CYBERTRAP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("CYBERTRAP_ADMIN_PASSWORD", "CyberTrap@Admin2026!")


def hash_password(password):
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64
    )
    return "scrypt$" + salt.hex() + "$" + derived.hex()


def verify_password(password, stored_hash):
    try:
        scheme, salt_hex, hash_hex = stored_hash.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def find_user(identifier):
    """
    Find a user by email or phone number only.
    Full name and User ID are NOT valid login identifiers.
    The admin account is the only exception and uses ADMIN_USERNAME.
    """
    identifier = str(identifier or "").strip()

    if not identifier:
        return None

    # Admin login
    if identifier.lower() == ADMIN_USERNAME.lower():
        return {
            "user_id": "ADMIN",
            "name": "Administrator",
            "email": "admin",
            "phone": "",
            "role": "admin",
            "password_hash": None
        }

    # Normal users: email or phone ONLY.
    # get_all_users() returns:
    # user_id, name, email, phone, role, created_at
    identifier_lower = identifier.lower()

    for user_id, name, email, phone, role, created_at in get_all_users():
        email_value = str(email or "").strip().lower()
        phone_value = str(phone or "").strip()

        if identifier_lower == email_value or identifier == phone_value:
            full_user = get_user_by_email(email)

            if full_user:
                return {
                    "user_id": full_user[0],
                    "name": full_user[1],
                    "email": full_user[2],
                    "phone": full_user[3],
                    "password_hash": full_user[4],
                    "role": full_user[5]
                }

    return None


def phone_exists(phone):
    """Return True when the normalized phone number is already registered."""
    target = re.sub(r"\D", "", str(phone or ""))
    if not target:
        return False

    for _user_id, _name, _email, existing_phone, _role, _created_at in get_all_users():
        existing = re.sub(r"\D", "", str(existing_phone or ""))
        if existing and existing == target:
            return True
    return False


def reset_investigation_state():
    st.session_state.investigation_result = None
    st.session_state.investigation_action = None
    st.session_state.revealed_sections = set()


# ---------------------------------------------------------
# LOGIN / SIGN-UP GATE
# ---------------------------------------------------------

if not st.session_state.authenticated:
    render_html("""
    <div class="hero" style="max-width:900px;margin:65px auto 22px auto;text-align:center;">
        <div class="status-pill"><span class="status-dot"></span> SECURE ACCESS</div>
        <div class="hero-title">CYBER TRAP</div>
        <div class="hero-subtitle" style="margin:0 auto;">
            AI-powered cybercrime investigation center. Sign in to access your
            investigations, evidence and case workspace.
        </div>
    </div>
    """)

    login_tab, signup_tab = st.tabs(["🔐 Sign In", "🆕 Create Account"])

    # =====================================================
    # SIGN IN
    # =====================================================
    with login_tab:
        render_html("""
        <div class="card" style="max-width:650px;margin:12px auto 18px auto;padding:26px 30px;">
            <div style="text-align:center;margin-bottom:18px;">
                <div style="font-size:22px;font-weight:700;">Welcome back</div>
                <div style="color:#8997aa;font-size:13px;margin-top:5px;">
                    Sign in using your email or phone number.
                </div>
            </div>
        </div>
        """)

        if time.time() < st.session_state.login_locked_until:
            remaining = int(st.session_state.login_locked_until - time.time()) + 1
            st.error(
                f"Too many failed attempts. Try again in {remaining} seconds."
            )
        else:
            identifier = st.text_input(
                "Email or phone number",
                value=st.session_state.login_identifier,
                placeholder="Enter your email or phone number",
                key="login_identifier_input"
            )

            login_password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password",
                key="login_password_input"
            )

            if st.button(
                "SIGN IN",
                type="primary",
                use_container_width=True,
                key="sign_in_button"
            ):
                identifier = identifier.strip()

                if not identifier or not login_password:
                    st.warning(
                        "Please enter both your email/phone number and password."
                    )
                else:
                    user = find_user(identifier)
                    valid = False

                    if user:
                        if user["role"].lower() == "admin":
                            valid = hmac.compare_digest(
                                login_password,
                                ADMIN_PASSWORD
                            )
                        else:
                            valid = verify_password(
                                login_password,
                                user["password_hash"]
                            )

                    if valid:
                        st.session_state.authenticated = True
                        st.session_state.current_user_id = user["user_id"]
                        st.session_state.current_user_name = user["name"]
                        st.session_state.current_user_email = user["email"]
                        st.session_state.user_role = (
                            "Admin"
                            if user["role"].lower() == "admin"
                            else "Investigator"
                        )
                        st.session_state.login_identifier = identifier
                        st.session_state.login_failures = 0
                        st.session_state.login_locked_until = 0.0
                        st.session_state.login_step = 1

                        reset_investigation_state()
                        st.rerun()
                    else:
                        st.session_state.login_failures += 1

                        if st.session_state.login_failures >= 5:
                            st.session_state.login_locked_until = time.time() + 60
                            st.session_state.login_failures = 0
                            st.error(
                                "Too many failed attempts. "
                                "Login is temporarily locked for 60 seconds."
                            )
                        else:
                            st.error(
                                "Invalid email/phone number or password."
                            )

        st.markdown(
            "<div style='text-align:center;color:#718096;font-size:12px;margin-top:14px;'>"
            "Administrator: use <b>admin</b> as the identifier.</div>",
            unsafe_allow_html=True
        )

    # =====================================================
    # CREATE ACCOUNT
    # =====================================================
    with signup_tab:
        st.subheader("Create a New Investigator Account")
        st.caption(
            "Your account receives a unique Cyber Trap User ID automatically."
        )

        name = st.text_input(
            "Full name",
            key="signup_name"
        )

        email = st.text_input(
            "Email address",
            key="signup_email"
        )

        phone = st.text_input(
            "Phone number",
            key="signup_phone"
        )

        signup_password = st.text_input(
            "Create password",
            type="password",
            key="signup_password"
        )

        confirm_password = st.text_input(
            "Confirm password",
            type="password",
            key="signup_confirm"
        )

        if st.button(
            "CREATE ACCOUNT",
            type="primary",
            use_container_width=True,
            key="create_account_button"
        ):
            if not name.strip() or not email.strip() or not phone.strip():
                st.warning(
                    "Name, email, and phone number are required."
                )
            elif "@" not in email or "." not in email.split("@")[-1]:
                st.warning("Enter a valid email address.")
            elif len(signup_password) < 8:
                st.warning(
                    "Password must contain at least 8 characters."
                )
            elif signup_password != confirm_password:
                st.error("Passwords do not match.")
            elif email_exists(email.strip()):
                st.error(
                    "An account with this email already exists."
                )
            elif phone_exists(phone):
                st.error(
                    "An account with this phone number already exists."
                )
            else:
                user_id = generate_user_id()

                created = create_user(
                    user_id,
                    name,
                    email,
                    phone,
                    hash_password(signup_password),
                    role="user"
                )

                if created:
                    st.success(
                        f"Account created successfully. "
                        f"Your User ID is **{user_id}**."
                    )
                    st.info(
                        "Sign in using your email or phone number "
                        "with your password."
                    )
                else:
                    st.error(
                        "The account could not be created. "
                        "The email or phone number may already be registered."
                    )

    st.stop()


# =========================================================
# DATABASE DATA
# =========================================================

stats = get_dashboard_stats()
recent_cases = get_recent_cases(5)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    render_html("""
    <div style="padding:10px 0 5px 0;">
        <div style="font-size:28px;font-weight:800;letter-spacing:1px;">
            <span style="color:#54d6ff;">◈</span> CYBER TRAP
        </div>
        <div style="color:#9aa4b2;font-size:12px;margin-top:6px;letter-spacing:1px;">
            AI CYBERCRIME • INVESTIGATION CENTER
        </div>
    </div>
    """)

    st.divider()

    if st.session_state.user_role == "Admin":
        st.markdown(f"**👑 {st.session_state.current_user_name}**")
        st.caption("Administrator")
        st.code("ADMIN")
        navigation_options = [
            "🏠 Command Center",
            "📁 All Cases",
            "📊 Analytics"
        ]
    else:
        st.markdown(f"**👤 {st.session_state.current_user_name}**")
        st.caption("Investigator")
        st.code(st.session_state.current_user_id)
        navigation_options = [
            "👤 My Dashboard",
            "🔍 New Investigation",
            "📁 My Cases"
        ]

    default_index = 0
    if st.session_state.pending_page in navigation_options:
        default_index = navigation_options.index(st.session_state.pending_page)
        st.session_state.pending_page = None

    page = st.radio("Navigation", navigation_options, index=default_index)

    if st.session_state.user_role == "Admin":
        st.success("🔐 ADMIN ACCESS • All cases")
    else:
        st.info("👤 INVESTIGATOR ACCESS • My cases only")

    st.divider()

    if st.button("🚪 LOG OUT", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.current_user_id = None
        st.session_state.current_user_name = None
        st.session_state.current_user_email = None
        st.session_state.user_role = None
        st.session_state.login_identifier = ""
        st.session_state.login_step = 1
        st.session_state.pending_page = None
        reset_investigation_state()
        st.rerun()

    st.caption("AI-powered defensive investigation system • Role-based access")


# =========================================================
# DASHBOARD
# =========================================================

if page == "🏠 Command Center":

    render_html(f"""
    <div class="hero">
        <div class="hero-grid">
            <div>
                <div class="status-pill"><span class="status-dot"></span> INVESTIGATION SYSTEM ONLINE</div>
                <div class="hero-title">CYBER TRAP</div>
                <div class="hero-subtitle">
                    AI-powered cybercrime investigation center for analyzing incidents,
                    connecting evidence, assessing threat risk, and reconstructing attack chains.
                </div>
            </div>
            <div style="text-align:center;min-width:210px;">
                <div class="radar">
                    <span class="radar-dot one"></span>
                    <span class="radar-dot two"></span>
                    <span class="radar-dot three"></span>
                </div>
                <div style="color:#718096;font-size:10px;letter-spacing:1.4px;margin-top:10px;">DEFENSIVE AI • v1.0</div>
            </div>
            <div class="terminal-strip"><b>●</b> SYSTEM READY&nbsp;&nbsp;|&nbsp;&nbsp; EVIDENCE ENGINE ONLINE&nbsp;&nbsp;|&nbsp;&nbsp; CASE MEMORY CONNECTED</div>
        </div>
    </div>
    """)

    # -----------------------------------------------------
    # METRICS
    # -----------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        render_html(f"""
        <div class="metric-card">

            <div class="metric-label">
                TOTAL CASES
            </div>

            <div class="metric-number">
                {stats["total_cases"]}
            </div>

        </div>
        """)

    with col2:

        render_html(f"""
        <div class="metric-card">

            <div class="metric-label">
                CRITICAL CASES
            </div>

            <div class="metric-number">
                {stats["critical_cases"]}
            </div>

        </div>
        """)

    with col3:

        render_html(f"""
        <div class="metric-card">

            <div class="metric-label">
                HIGH RISK
            </div>

            <div class="metric-number">
                {stats["high_cases"]}
            </div>

        </div>
        """)

    with col4:

        render_html(f"""
        <div class="metric-card">

            <div class="metric-label">
                INVESTIGATIONS
            </div>

            <div class="metric-number">
                {stats["total_investigations"]}
            </div>

        </div>
        """)

    st.divider()

    # -----------------------------------------------------
    # THREAT OVERVIEW
    # -----------------------------------------------------

    st.subheader("🛡️ Threat Overview")

    overview1, overview2, overview3 = st.columns(3)

    with overview1:

        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">
                CASES REQUIRING ATTENTION
            </div>
            <div class="metric-number">
                {}
            </div>
        </div>
        """.format(
            stats["critical_cases"] + stats["high_cases"]
        ), unsafe_allow_html=True)


    with overview2:

        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">
                MEDIUM RISK CASES
            </div>
            <div class="metric-number">
                {}
            </div>
        </div>
        """.format(
            stats["medium_cases"]
        ), unsafe_allow_html=True)


    with overview3:

        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">
                LOW RISK CASES
            </div>
            <div class="metric-number">
                {}
            </div>
        </div>
        """.format(
            stats["low_cases"]
        ), unsafe_allow_html=True)

    st.divider()

    # -----------------------------------------------------
    # REGISTERED INVESTIGATORS
    # -----------------------------------------------------

    if st.session_state.user_role == "Admin":
        st.subheader("👥 Registered Investigators")
        users = get_all_users()
        if users:
            for user_id, name, email, phone, role, created_at in users:
                render_html(f"""
                <div class="card" style="padding:15px 18px;">
                    <strong>{name}</strong>
                    <span style="color:#52e0a1;float:right;">{user_id}</span><br>
                    <small style="color:#9aa4b2;">{email} • {phone or 'No phone'} • Created {created_at}</small>
                </div>
                """)
        else:
            st.info("No investigator accounts have been registered yet.")

    st.divider()

    # -----------------------------------------------------
    # RECENT CASES
    # -----------------------------------------------------

    st.subheader("🚨 Recent Investigations")

    if not recent_cases:

        st.info(
            "No investigations have been recorded yet."
        )

    else:

        for i in range(
            0,
            len(recent_cases),
            2
        ):

            columns = st.columns(2)

            for j, column in enumerate(columns):

                index = i + j

                if index >= len(recent_cases):
                    break

                case_data = recent_cases[index]

                case_id = case_data[0]
                description = case_data[2] or "No case description available."
                crime_type = case_data[3]
                risk_score = case_data[4]
                risk_level = case_data[5]
                created_at = case_data[6]

                if risk_level == "CRITICAL":
                    icon = "🔴"
                elif risk_level == "HIGH":
                    icon = "🟠"
                elif risk_level == "MEDIUM":
                    icon = "🟡"
                else:
                    icon = "🟢"

                short_description = description

                if len(short_description) > 150:
                    short_description = (
                        short_description[:150] + "..."
                    )

                with column:

                    render_html(f"""
                    <div class="card">

                        <h3>
                            {icon} CT-{case_id:04d}
                        </h3>

                        <p style="
                            color:#c6ccd5;
                            line-height:1.5;
                        ">
                            {short_description}
                        </p>

                        <strong>
                            {risk_level} — {risk_score}/100
                        </strong>

                        <br><br>

                        <small style="
                            color:#9aa4b2;
                        ">
                            {crime_type}
                        </small>

                        <br>

                        <small style="
                            color:#737d8a;
                        ">
                            {created_at}
                        </small>

                    </div>
                    """)


# =========================================================
# USER DASHBOARD
# =========================================================

elif page == "👤 My Dashboard":

    user_name = st.session_state.current_user_name or "Investigator"
    user_id = st.session_state.current_user_id or "—"
    user_cases = get_user_cases(user_id)

    total_user_cases = len(user_cases)
    critical_user_cases = sum(1 for c in user_cases if len(c) > 5 and c[5] == "CRITICAL")
    high_user_cases = sum(1 for c in user_cases if len(c) > 5 and c[5] == "HIGH")
    medium_user_cases = sum(1 for c in user_cases if len(c) > 5 and c[5] == "MEDIUM")
    low_user_cases = sum(1 for c in user_cases if len(c) > 5 and c[5] == "LOW")

    render_html(f"""
    <div class="hero">
        <div class="hero-grid">
            <div>
                <div class="status-pill"><span class="status-dot"></span> INVESTIGATOR WORKSPACE</div>
                <div class="hero-title">Welcome, {user_name}</div>
                <div class="hero-subtitle">
                    Your private Cyber Trap workspace. Review your investigations,
                    start a new case, and track the evidence and risk findings assigned to you.
                </div>
                <div class="terminal-strip"><b>●</b> USER ID: {user_id}&nbsp;&nbsp;|&nbsp;&nbsp; PRIVATE CASE ACCESS&nbsp;&nbsp;|&nbsp;&nbsp; INVESTIGATION ENGINE ONLINE</div>
            </div>
            <div style="text-align:center;min-width:210px;">
                <div class="radar">
                    <span class="radar-dot one"></span>
                    <span class="radar-dot two"></span>
                    <span class="radar-dot three"></span>
                </div>
                <div style="color:#718096;font-size:10px;letter-spacing:1.4px;margin-top:10px;">INVESTIGATOR • PRIVATE</div>
            </div>
        </div>
    </div>
    """)

    st.subheader("📊 My Investigation Overview")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-label">MY CASES</div>
            <div class="metric-number">{total_user_cases}</div>
        </div>
        """)
    with c2:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-label">CRITICAL</div>
            <div class="metric-number">{critical_user_cases}</div>
        </div>
        """)
    with c3:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-label">HIGH RISK</div>
            <div class="metric-number">{high_user_cases}</div>
        </div>
        """)
    with c4:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-label">MEDIUM / LOW</div>
            <div class="metric-number">{medium_user_cases + low_user_cases}</div>
        </div>
        """)

    st.divider()

    quick1, quick2 = st.columns([1.15, 1])

    with quick1:
        render_html("""
        <div class="card" style="min-height:210px;">
            <div style="font-size:12px;color:#54d6ff;font-weight:700;letter-spacing:1px;">QUICK START</div>
            <h2 style="margin-top:8px;">Start a New Investigation</h2>
            <p style="color:#aab7c9;line-height:1.6;">
                Submit an incident and optional evidence. Cyber Trap will extract indicators,
                reconstruct the attack chain, assess risk and run the autonomous AI investigation workflow.
            </p>
        </div>
        """)
        if st.button("🔍 START NEW INVESTIGATION", type="primary", use_container_width=True, key="user_dashboard_new_case"):
            st.session_state.pending_page = "🔍 New Investigation"
            st.rerun()

    with quick2:
        render_html(f"""
        <div class="card" style="min-height:210px;">
            <div style="font-size:12px;color:#8b7cff;font-weight:700;letter-spacing:1px;">ACCOUNT</div>
            <h2 style="margin-top:8px;">Investigator Profile</h2>
            <p style="color:#aab7c9;line-height:1.8;margin-bottom:4px;"><strong>Name:</strong> {user_name}</p>
            <p style="color:#aab7c9;line-height:1.8;margin-bottom:4px;"><strong>User ID:</strong> {user_id}</p>
            <p style="color:#aab7c9;line-height:1.8;"><strong>Access:</strong> Investigator • My cases only</p>
        </div>
        """)
        if st.button("📁 VIEW MY CASES", use_container_width=True, key="user_dashboard_cases"):
            st.session_state.pending_page = "📁 My Cases"
            st.rerun()

    st.divider()
    st.subheader("🚨 Recent Cases")

    if not user_cases:
        st.info("You have not created any investigations yet. Start your first case above.")
    else:
        for case_data in user_cases[:5]:
            case_id = case_data[0]
            description = case_data[2] or "No case description available."
            crime_type = case_data[3]
            risk_score = case_data[4]
            risk_level = case_data[5]
            created_at = case_data[6]

            if risk_level == "CRITICAL":
                icon = "🔴"
            elif risk_level == "HIGH":
                icon = "🟠"
            elif risk_level == "MEDIUM":
                icon = "🟡"
            else:
                icon = "🟢"

            short_description = str(description)
            if len(short_description) > 180:
                short_description = short_description[:180] + "..."

            render_html(f"""
            <div class="card" style="padding:18px 20px;">
                <div style="display:flex;justify-content:space-between;gap:18px;align-items:flex-start;">
                    <div>
                        <div style="font-size:18px;font-weight:700;">{icon} CT-{case_id:04d}</div>
                        <div style="color:#8997aa;font-size:12px;margin-top:5px;">{crime_type} • {created_at}</div>
                    </div>
                    <div style="font-weight:700;white-space:nowrap;">{risk_level} — {risk_score}/100</div>
                </div>
                <p style="color:#c6ccd5;line-height:1.55;margin-top:13px;">{short_description}</p>
            </div>
            """)

# =========================================================
# NEW INVESTIGATION
# =========================================================

elif page == "🔍 New Investigation":

    render_html("""
    <div class="hero" style="padding:25px 30px;margin-bottom:22px;">
        <div class="status-pill"><span class="status-dot"></span> NEW CASE INTAKE</div>
        <div class="hero-title" style="font-size:32px;">Start an Investigation</div>
        <div class="hero-subtitle">
            Give Cyber Trap the incident details and supporting evidence. The investigation engine
            will extract indicators, correlate evidence, assess risk and build the case timeline.
        </div>
    </div>
    """)

    case = st.text_area(
        "Describe the incident",
        placeholder=(
            "Example:\n\n"
            "I received a message claiming to be from my bank. "
            "It said my account would be blocked unless I "
            "verified my details using a link..."
        ),
        height=280
    )

    st.subheader("📎 Add Evidence")

    evidence_file = st.file_uploader(
        "Upload evidence",
        type=["txt", "csv", "png", "jpg", "jpeg"],
        help="Upload text evidence or an image/screenshot of an email, SMS, website, or document."
    )

    evidence_text = ""
    evidence_image = None
    evidence_is_image = False
    image_ocr_status = ""

    if evidence_file is not None:
        file_bytes = evidence_file.getvalue()
        file_name = evidence_file.name.lower()
        evidence_is_image = file_name.endswith((".png", ".jpg", ".jpeg"))

        st.success(f"Evidence loaded: {evidence_file.name}")

        if evidence_is_image:
            try:
                from PIL import Image
                evidence_image = Image.open(BytesIO(file_bytes))
                with st.expander("🖼️ Preview Image Evidence", expanded=True):
                    st.image(evidence_image, caption=evidence_file.name, use_container_width=True)
            except Exception as image_error:
                st.warning(f"The image could not be previewed: {image_error}")

            try:
                import pytesseract
                import os
                if os.name == "nt":
                    for tesseract_path in (
                        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                    ):
                        if os.path.exists(tesseract_path):
                            pytesseract.pytesseract.tesseract_cmd = tesseract_path
                            break
                if evidence_image is None:
                    from PIL import Image
                    evidence_image = Image.open(BytesIO(file_bytes))
                evidence_text = pytesseract.image_to_string(evidence_image).strip()
                if evidence_text:
                    image_ocr_status = "success"
                    st.success("🔎 Image evidence analyzed — readable text extracted from the screenshot.")
                    with st.expander("📝 Extracted Text from Image"):
                        st.text(evidence_text[:5000])
                else:
                    image_ocr_status = "empty"
                    st.warning("The image was uploaded, but no readable text could be extracted.")
            except Exception:
                image_ocr_status = "unavailable"
                st.warning(
                    "Image uploaded successfully, but OCR is not available. "
                    "Install Tesseract OCR and the Python package `pytesseract` to analyze image text."
                )
        else:
            evidence_text = file_bytes.decode("utf-8", errors="ignore")
            with st.expander("👁️ Preview Evidence"):
                st.text(evidence_text[:3000])

    if st.button(
        "🔍 START INVESTIGATION",
        use_container_width=True,
        type="primary"
    ):

        if not case.strip():

            st.warning(
                "Please describe what happened first."
            )

        else:

            try:

                with st.spinner(
                    "🧠 Cyber Trap is investigating the case..."
                ):

                    investigation_input = case.strip()

                    if evidence_text:
                        investigation_input += (
                            "\n\n--- ATTACHED EVIDENCE ---\n"
                            + evidence_text
                        )

                    # Track the investigation stages so the user can see
                    # how Cyber Trap reached its conclusion.
                    activity_log = [
                        {
                            "step": "Evidence intake",
                            "detail": "Incident description and attached evidence were ingested.",
                            "status": "completed"
                        }
                    ]

                    if evidence_is_image:
                        if image_ocr_status == "success":
                            activity_log.append({
                                "step": "Image evidence analysis",
                                "detail": "OCR extracted readable text from the uploaded screenshot and added it to the investigation evidence.",
                                "status": "completed"
                            })
                        else:
                            activity_log.append({
                                "step": "Image evidence analysis",
                                "detail": "Image was received, but readable text could not be extracted. The written incident description was still analyzed.",
                                "status": "completed"
                            })

                    result = run_investigation(
                        investigation_input
                    )
                    activity_log.append({
                        "step": "AI investigation engine",
                        "detail": "The investigation agent analyzed the incident and evaluated the initial threat indicators.",
                        "status": "completed"
                    })

                    evidence_analysis = analyze_evidence(
                        investigation_input
                    )

                    result["evidence_findings"] = evidence_analysis["findings"]  
                    result["evidence_analysis"] = evidence_analysis

                    extracted = evidence_analysis.get("findings", {})
                    evidence_count = (
                        len(extracted.get("urls", []))
                        + len(extracted.get("emails", []))
                        + len(extracted.get("phone_numbers", []))
                        + len(extracted.get("sensitive_requests", []))
                    )
                    activity_log.append({
                        "step": "Structured evidence extraction",
                        "detail": f"Extracted {evidence_count} relevant evidence indicators from the supplied material.",
                        "status": "completed"
                    })

                    url_count = len(evidence_analysis.get("url_analysis", []))
                    activity_log.append({
                        "step": "Indicator analysis",
                        "detail": f"Analyzed {url_count} suspicious URL(s) and related indicators without visiting the URLs.",
                        "status": "completed"
                    })

                    correlation_count = len(evidence_analysis.get("correlations", []))
                    activity_log.append({
                        "step": "Evidence correlation",
                        "detail": f"Cross-checked evidence relationships and found {correlation_count} correlation(s).",
                        "status": "completed"
                    })

                    # Build evidence relationship graph
                    evidence_graph = build_evidence_graph(
                        investigation_input,
                        evidence_analysis
                    )

                    result["evidence_graph"] = evidence_graph
                    activity_log.append({
                        "step": "Evidence relationship mapping",
                        "detail": f"Connected {len(evidence_graph.get('nodes', []))} evidence element(s) to reconstruct the incident.",
                        "status": "completed"
                    })

                    # Build investigation timeline
                    evidence_timeline = build_evidence_timeline(
                        investigation_input,
                        evidence_analysis
                    )

                    result["evidence_timeline"] = evidence_timeline
                    activity_log.append({
                        "step": "Attack timeline reconstruction",
                        "detail": f"Reconstructed {len(evidence_timeline)} investigation event(s) from the evidence.",
                        "status": "completed"
                    })

                    # Generate competing investigation hypotheses
                    hypothesis_analysis = generate_hypotheses(
                        investigation_input,
                        evidence_analysis,
                        evidence_timeline
                    )

                    result["hypothesis_analysis"] = hypothesis_analysis
                    hypothesis_count = len(hypothesis_analysis.get("hypotheses", [])) if isinstance(hypothesis_analysis, dict) else 0
                    activity_log.append({
                        "step": "Competing hypothesis analysis",
                        "detail": f"Compared {hypothesis_count} possible explanations against the available evidence.",
                        "status": "completed"
                    })

                    # AUTONOMOUS AI AGENT: Gemini creates an executable investigation plan,
                    # Cyber Trap executes the selected local tools, then Gemini re-evaluates.
                    agent_response = run_autonomous_ai_agent(
                        investigation_input,
                        evidence_analysis,
                        hypothesis_analysis,
                        evidence_timeline,
                        case_id=result.get("case_id")
                    )
                    if agent_response.get("error"):
                        result["ai_agent_decision"] = agent_response
                        activity_log.append({
                            "step": "🤖 Gemini AI Agent",
                            "detail": agent_response["error"],
                            "status": "attention"
                        })
                    else:
                        agent_data = agent_response.get("data", {}) or {}
                        result["ai_agent_decision"] = agent_data.get("reevaluation", {})
                        result["ai_agent_plan"] = agent_data.get("plan", {})
                        result["ai_agent_executions"] = agent_data.get("executions", [])
                        result["ai_generated_artifacts"] = agent_data.get("artifacts", {})
                        activity_log.append({
                            "step": "🤖 AI-created investigation plan",
                            "detail": f"Gemini created {len(agent_data.get('plan', {}).get('tasks', []) or [])} prioritized investigation task(s).",
                            "status": "completed"
                        })
                        for execution in agent_data.get("executions", [])[:5]:
                            activity_log.append({
                                "step": f"⚙️ Agent tool: {execution.get('action')}",
                                "detail": f"Executed {execution.get('tool')} and produced new structured evidence.",
                                "status": "completed"
                            })
                        activity_log.append({
                            "step": "📦 AI artifact creation",
                            "detail": "Gemini created a structured investigation dossier, attack chain, evidence matrix and response plan.",
                            "status": "completed"
                        })
                        activity_log.append({
                            "step": "🔄 AI re-planning",
                            "detail": f"Gemini re-evaluated the tool results and selected {result['ai_agent_decision'].get('next_action', 'CHECK_MISSING_EVIDENCE')} as the next action.",
                            "status": "completed"
                        })

                    decision = result.get("decision", {}) or {}
                    if decision.get("continue", False):
                        decision_detail = "Evidence may be insufficient; the agent recommends additional investigation."
                        decision_status = "attention"
                    else:
                        decision_detail = "Available evidence was judged sufficient for the current investigation."
                        decision_status = "completed"

                    activity_log.append({
                        "step": "Investigation sufficiency decision",
                        "detail": decision_detail,
                        "status": decision_status
                    })

                    if result.get("final_report"):
                        activity_log.append({
                            "step": "Final investigation report",
                            "detail": "The investigation findings and recommended actions were assembled into the final report.",
                            "status": "completed"
                        })

                    result["activity_log"] = activity_log
                # Permanently assign the case to the authenticated investigator.
                if (
                    st.session_state.user_role == "Investigator"
                    and result.get("case_id") is not None
                ):
                    assign_case_to_user(
                        result["case_id"],
                        st.session_state.current_user_id
                    )

                st.session_state.investigation_result = result
                st.session_state.investigation_action = None
                st.session_state.revealed_sections = set()

                st.success(
                    f"Investigation completed — "
                    f"Case CT-{result['case_id']:04d}"
                )

            except Exception as error:

                st.error(
                    "The investigation could not be completed."
                )

                st.exception(error)

    # =====================================================
    # SIMPLE USER-FRIENDLY INVESTIGATION RESULT
    # =====================================================

    result = st.session_state.investigation_result

    if result is None:
        st.info("Start an investigation to see the result here.")
    else:
        findings = result.get("evidence_findings", {}) or {}
        evidence_analysis = result.get("evidence_analysis", {}) or {}
        results = result.get("results", {}) or {}
        risk = results.get("risk", {}) or {}

        try:
            score = int(risk.get("score", 0))
        except (TypeError, ValueError):
            score = 0
        score = max(0, min(100, score))

        level = str(risk.get("level", "UNKNOWN")).upper()
        patterns = results.get("patterns", []) or []

        ai = result.get("ai_agent_decision", {}) or {}
        plan = result.get("ai_agent_plan", {}) or {}
        executions = result.get("ai_agent_executions", []) or []
        artifacts = result.get("ai_generated_artifacts", {}) or {}

        risk_icon = (
            "🔴" if level == "CRITICAL"
            else "🟠" if level == "HIGH"
            else "🟡" if level == "MEDIUM"
            else "🟢" if level == "LOW"
            else "⚪"
        )

        classification = (
            artifacts.get("threat_classification")
            or (str(patterns[0]) if patterns else "Suspicious cyber activity")
        )

        # -----------------------------------------------------
        # SHORT CASE SUMMARY
        # -----------------------------------------------------

        executive_summary = artifacts.get("executive_summary", "")
        if not executive_summary:
            reasons = []
            if findings.get("urls"):
                reasons.append("a suspicious link was found")
            if findings.get("impersonation"):
                reasons.append("possible impersonation was detected")
            if findings.get("urgency"):
                reasons.append("pressure or urgency was used")
            if findings.get("sensitive_requests"):
                reasons.append("sensitive information was requested")
            if findings.get("money_mentions"):
                reasons.append("financial information was mentioned")

            executive_summary = (
                "This case shows " + ", ".join(reasons[:3]) + "."
                if reasons
                else "The available evidence is not sufficient for a strong conclusion."
            )

        # -----------------------------------------------------
        # RESULT HEADER
        # -----------------------------------------------------

        st.header(f"🔎 Investigation Result — CT-{result['case_id']:04d}")

        c1, c2 = st.columns([1, 2])

        with c1:
            render_html(f"""
            <div class="report-card" style="text-align:center;padding:22px;">
                <div style="color:#9aa4b2;font-size:11px;letter-spacing:1px;">RISK SCORE</div>
                <div style="font-size:40px;margin:7px 0;">{risk_icon}</div>
                <div style="font-size:24px;font-weight:800;">{level} RISK</div>
                <div style="font-size:42px;font-weight:900;margin-top:8px;">{score}%</div>
                <div style="color:#9aa4b2;font-size:12px;">{score} / 100</div>
                <div style="margin:12px auto 0;max-width:260px;height:9px;background:#202833;border-radius:999px;overflow:hidden;">
                    <div style="width:{score}%;height:100%;background:linear-gradient(90deg,#4ade80 0%,#facc15 50%,#ef4444 100%);"></div>
                </div>
            </div>
            """)

        with c2:
            st.markdown(f"### {classification}")
            st.write(executive_summary)

        # -----------------------------------------------------
        # ONLY THE MOST IMPORTANT FINDINGS
        # -----------------------------------------------------

        st.divider()
        st.subheader("🔎 Key Findings")

        key_findings = []
        if findings.get("urls"):
            key_findings.append("🔗 Suspicious link detected")
        if findings.get("impersonation"):
            key_findings.append("🏦 Possible impersonation detected")
        if findings.get("urgency"):
            key_findings.append("⏰ Urgency or pressure detected")
        if findings.get("sensitive_requests"):
            key_findings.append("🔐 Sensitive information requested")
        if findings.get("money_mentions"):
            key_findings.append("💰 Financial activity mentioned")
        if findings.get("phone_numbers") and len(key_findings) < 4:
            key_findings.append("📱 Sender information detected")

        if key_findings:
            for item in key_findings[:4]:
                st.markdown(f"• {item}")
        else:
            st.info("No major warning signs were identified.")

        # -----------------------------------------------------
        # WHAT TO DO — SHORT
        # -----------------------------------------------------

        st.divider()
        st.subheader("🛡️ What should you do?")

        response_plan = artifacts.get("response_plan", []) or []
        if not response_plan:
            response_plan = [
                "Do not share passwords, OTPs, PINs or CVVs.",
                "Do not open or revisit suspicious links.",
                "Verify the claim through the organization's official channel."
            ]

        for action_text in response_plan[:3]:
            st.markdown(f"• {action_text}")

        # -----------------------------------------------------
        # MISSING EVIDENCE — OPTIONAL
        # -----------------------------------------------------

        missing = artifacts.get("missing_evidence", []) or []
        if not missing:
            if not findings.get("urls"):
                missing.append("Original link or website address, if applicable")
            if not findings.get("phone_numbers") and not findings.get("emails"):
                missing.append("Original sender details")
            missing.append("Original screenshot or copy of the communication")

        with st.expander("📎 Evidence still needed", expanded=False):
            for item in list(dict.fromkeys(missing))[:4]:
                st.markdown(f"• {item}")

        # -----------------------------------------------------
        # AI DETAILS — HIDDEN FROM NORMAL USERS
        # -----------------------------------------------------

        with st.expander("🤖 View AI Investigation Details", expanded=False):
            if ai.get("error") and not plan:
                st.warning("The AI investigation could not be completed for this case.")
            else:
                provider = ai.get("provider") or plan.get("provider", "Google Gemini")
                model = ai.get("model") or plan.get("model", "Gemini")
                st.caption(f"AI agent: {provider} • {model}")

                if plan:
                    st.markdown("**AI investigation plan**")
                    for task in (plan.get("tasks", []) or [])[:5]:
                        label = str(task.get("action", "Investigation task")).replace("_", " ").title()
                        st.markdown(f"• {label}")

                if executions:
                    st.markdown("**Agent actions completed**")
                    for execution in executions[:5]:
                        label = str(execution.get("action", "Investigation")).replace("_", " ").title()
                        st.markdown(f"✓ {label}")

                if ai.get("observation"):
                    st.markdown("**AI re-evaluation**")
                    st.write(ai.get("observation"))

                if artifacts and not artifacts.get("error"):
                    st.markdown("**AI-created work products**")
                    if artifacts.get("agent_decision"):
                        st.write(artifacts.get("agent_decision"))
                    if artifacts.get("next_recommended_action"):
                        st.caption(f"Next action: {artifacts.get('next_recommended_action')}")

                    dossier = _build_dossier_markdown(artifacts, result.get("case_id", 0))
                    st.download_button(
                        "📄 Download Investigation Dossier",
                        data=dossier,
                        file_name=f"CT-{int(result.get('case_id', 0)):04d}_AI_Investigation_Dossier.md",
                        mime="text/markdown",
                        use_container_width=True
                    )

        # -----------------------------------------------------
        # OPTIONAL TECHNICAL VIEWS
        # -----------------------------------------------------

        with st.expander("📚 More investigation details", expanded=False):
            d1, d2, d3 = st.columns(3)

            # Only ONE detailed view can be open at a time.
            # Selecting another view automatically closes the previous one.
            detail_views = {"timeline", "graph", "advanced", "report"}

            with d1:
                if st.button("🕒 Timeline", use_container_width=True):
                    st.session_state.revealed_sections.difference_update(detail_views)
                    st.session_state.revealed_sections.add("timeline")
                    st.rerun()

            with d2:
                if st.button("🕸️ Evidence Connections", use_container_width=True):
                    st.session_state.revealed_sections.difference_update(detail_views)
                    st.session_state.revealed_sections.add("graph")
                    st.rerun()

            with d3:
                if st.button("📊 Technical Evidence", use_container_width=True):
                    st.session_state.revealed_sections.difference_update(detail_views)
                    st.session_state.revealed_sections.add("advanced")
                    st.rerun()

        if "timeline" in st.session_state.revealed_sections:
            st.subheader("🕒 Evidence Timeline")
            timeline = result.get("evidence_timeline", []) or []
            if timeline:
                for i, event in enumerate(timeline[:8], 1):
                    if isinstance(event, dict):
                        st.markdown(f"**{i}. {event.get('event', 'Event')}**")
                        if event.get("detail"):
                            st.caption(event.get("detail"))
                    else:
                        st.markdown(f"**{i}. {event}**")
            else:
                st.info("No timeline events were reconstructed.")

        if "graph" in st.session_state.revealed_sections:
            st.subheader("🕸️ Evidence Connections")
            graph = result.get("evidence_graph", {}) or {}
            nodes = graph.get("nodes", []) or []
            edges = graph.get("edges", []) or []
            for node in nodes[:10]:
                st.markdown(f"• **{node.get('label', 'Evidence')}**")
            for edge in edges[:10]:
                st.caption(f"{edge.get('source')} → {edge.get('relationship', 'related to')} → {edge.get('target')}")

        if "advanced" in st.session_state.revealed_sections:
            st.subheader("📊 Technical Evidence")
            severity = evidence_analysis.get("severity", {}) or {}
            a, b, c = st.columns(3)
            with a:
                st.metric("URLs", len(findings.get("urls", [])))
            with b:
                st.metric("Emails", len(findings.get("emails", [])))
            with c:
                st.metric("Evidence Score", f"{severity.get('score', 0)}/100")

            with st.expander("AI Agent Activity Log"):
                for index, activity in enumerate(result.get("activity_log", [])[:10], 1):
                    st.markdown(f"**{index}. {activity.get('step', 'Investigation step')}**")
                    st.caption(activity.get("detail", ""))

        st.caption(
            "💾 Case and investigation data are saved to Cyber Trap memory. "
            "Advanced AI and technical details are available only when requested."
        )


# =========================================================
# CASE HISTORY
# =========================================================
# =========================================================
# CASE HISTORY
# =========================================================

elif page in ("📁 All Cases", "📁 My Cases"):

    if st.session_state.user_role == "Admin":
        st.title("📁 All Cases")
        st.markdown("Admin case archive — review stored investigations across the system.")
    else:
        st.title("📁 My Cases")
        st.markdown("Your case workspace — only cases created in this investigator session are shown.")

    st.divider()

    if st.session_state.user_role == "Admin":
        cases = get_recent_cases(100)
    else:
        cases = get_user_cases(st.session_state.current_user_id)

    if not cases:

        st.info("No cases found.")

    else:

        for case_data in cases:

            case_id = case_data[0]
            description = case_data[2] or "No case description available."
            crime_type = case_data[3]
            risk_score = case_data[4]
            risk_level = case_data[5]
            created_at = case_data[6]

            # -------------------------------------------------
            # RISK ICON
            # -------------------------------------------------

            if risk_level == "CRITICAL":
                icon = "🔴"
            elif risk_level == "HIGH":
                icon = "🟠"
            elif risk_level == "MEDIUM":
                icon = "🟡"
            else:
                icon = "🟢"

            # -------------------------------------------------
            # CASE EXPANDER
            # -------------------------------------------------

            with st.expander(
                f"CT-{case_id:04d} | "
                f"{icon} {risk_level} | "
                f"{risk_score}/100"
            ):

                # =================================================
                # CASE OVERVIEW
                # =================================================

                render_html(f"""
                <div class="case-card">

                    <h2>
                        {icon} CT-{case_id:04d}
                    </h2>

                    <p>
                        <strong>Risk Level:</strong>
                        {risk_level}
                    </p>

                    <p>
                        <strong>Risk Score:</strong>
                        {risk_score}/100
                    </p>

                    <p>
                        <strong>Crime Pattern:</strong>
                        {crime_type}
                    </p>

                    <p>
                        <strong>Investigation Date:</strong>
                        {created_at}
                    </p>

                </div>
                """)

                # =================================================
                # CASE DESCRIPTION
                # =================================================

                st.subheader("📝 Case Description")

                st.write(description)

                st.divider()

                # =================================================
                # EVIDENCE
                # =================================================

                st.subheader("🔎 Evidence Intelligence")

                evidence = get_case_evidence(case_id)

                if evidence:

                    for evidence_type, evidence_text in evidence:

                        if evidence_type == "indicator":

                            render_html(f"""
                            <div style="
                                background:#25291b;
                                border-left:4px solid #f5c542;
                                border-radius:8px;
                                padding:13px 16px;
                                margin:8px 0;
                            ">
                                ⚠️ {evidence_text}
                            </div>
                            """)

                        elif evidence_type == "scam_pattern":

                            render_html(f"""
                            <div style="
                                background:#17263b;
                                border-left:4px solid #4c8bf5;
                                border-radius:8px;
                                padding:13px 16px;
                                margin:8px 0;
                            ">
                                🧩 <strong>Cybercrime Pattern:</strong>
                                {evidence_text}
                            </div>
                            """)

                        elif evidence_type == "attack_chain":

                            render_html(f"""
                            <div style="
                                background:#151b23;
                                border-left:4px solid #7c5cff;
                                border-radius:8px;
                                padding:13px 16px;
                                margin:8px 0;
                            ">
                                🔗 <strong>Attack Chain:</strong>
                                {evidence_text}
                            </div>
                            """)

                        else:

                            render_html(f"""
                            <div class="section-card">
                                <strong>{evidence_type}</strong>
                                <p>{evidence_text}</p>
                            </div>
                            """)

                else:

                    st.info(
                        "No stored evidence was found for this case."
                    )

                st.divider()

                # =================================================
                # INVESTIGATION PROCESS
                # =================================================

                st.subheader("🧠 Investigation Process")

                investigations = get_case_investigations(
                    case_id
                )

                if investigations:

                    action_labels = {

                        "analyze_cyber_indicators":
                            "🔎 Warning signs analyzed",

                        "detect_scam_pattern":
                            "🧩 Cybercrime pattern analyzed",

                        "analyze_attack_chain":
                            "🔗 Attack chain reconstructed",

                        "calculate_risk":
                            "⚠️ Risk assessed"
                    }

                    for action, investigation_result in investigations:

                        label = action_labels.get(
                            action,
                            "✓ Investigation step completed"
                        )

                        render_html(f"""
                        <div style="
                            background:#151b23;
                            border:1px solid #27303b;
                            border-radius:8px;
                            padding:12px 15px;
                            margin:7px 0;
                        ">
                            {label}
                        </div>
                        """)

                else:

                    st.info(
                        "No investigation history is available."
                    )

                st.divider()

                # =================================================
                # FINAL REPORT
                # =================================================

                st.subheader("📄 Investigation Report")

                report = get_case_report(case_id)

                if report:

                    with st.expander(
                        "📄 View Full Investigation Report",
                        expanded=False
                    ):

                        st.markdown(report)

                else:

                    st.info(
                        "No final investigation report was found."
                    )

                st.divider()

                # =================================================
                # STORED CASE SUMMARY
                # =================================================

                st.subheader("🛡️ Case Summary")

                render_html(f"""
                <div class="section-card">

                    <p>
                        <strong>Case:</strong>
                        CT-{case_id:04d}
                    </p>

                    <p>
                        <strong>Classification:</strong>
                        {crime_type}
                    </p>

                    <p>
                        <strong>Risk:</strong>
                        {risk_level} — {risk_score}/100
                    </p>

                    <p style="
                        color:#c6ccd5;
                        line-height:1.6;
                    ">
                        This case has been preserved in Cyber Trap's
                        investigation history for future review.
                    </p>

                </div>
                """)

# =========================================================
# ANALYTICS
# =========================================================

elif page == "📊 Analytics":

    st.title(
        "📊 Investigation Analytics"
    )

    st.markdown(
        "Overview of Cyber Trap's investigation activity "
        "and detected risk levels."
    )

    st.divider()

    st.subheader(
        "Risk Distribution"
    )

    risk_data = {
        "Critical": stats["critical_cases"],
        "High": stats["high_cases"],
        "Medium": stats["medium_cases"],
        "Low": stats["low_cases"]
    }

    st.bar_chart(
        risk_data
    )

    st.divider()

    st.subheader(
        "📊 Investigation Summary"
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "🔴 Critical",
            stats["critical_cases"]
        )

    with c2:
        st.metric(
            "🟠 High",
            stats["high_cases"]
        )

    with c3:
        st.metric(
            "🟡 Medium",
            stats["medium_cases"]
        )

    with c4:
        st.metric(
            "🟢 Low",
            stats["low_cases"]
        )

