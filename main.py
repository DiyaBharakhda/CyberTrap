from tools.planner import create_investigation_plan
from tools.executor import execute_investigation
from tools.replanner import replan_investigation
from tools.report_generator import generate_final_report

from memory.database import (
    create_tables,
    save_case,
    save_evidence,
    save_investigation,
    save_report
)

# =========================================================
# INITIALIZE DATABASE
# =========================================================

create_tables()


print("=" * 65)
print("                    CYBER TRAP")
print("             AI CYBERCRIME INVESTIGATOR")
print("=" * 65)


# =========================================================
# 1. GET CASE
# =========================================================

case = input("\nDescribe what happened:\n> ")


# =========================================================
# 2. CREATE INITIAL PLAN
# =========================================================

print("\n🧠 Cyber Trap is analyzing the case...")

plan = create_investigation_plan(case)


print("\n" + "=" * 65)
print("                 INVESTIGATION PLAN")
print("=" * 65)

for step in plan:

    print(
        f"{step['step']}. {step['action']}"
    )


# =========================================================
# 3. EXECUTE INITIAL PLAN
# =========================================================

results = execute_investigation(
    case,
    plan
)


# =========================================================
# 4. REPLANNING LOOP
# =========================================================

max_rounds = 2
round_number = 1

decision = {
    "continue": False,
    "reason": "Investigation completed."
}


while round_number <= max_rounds:

    print("\n" + "=" * 65)
    print(
        f"              AGENT REVIEW — ROUND {round_number}"
    )
    print("=" * 65)

    print(
        "\n🧠 Cyber Trap is reviewing the evidence..."
    )

    decision = replan_investigation(
        case,
        results
    )


    # -----------------------------------------------------
    # CASE 1: ENOUGH EVIDENCE
    # -----------------------------------------------------

    if not decision["continue"]:

        print("\n✓ Evidence is sufficient.")

        print("\nReason:")
        print(decision["reason"])

        break


    # -----------------------------------------------------
    # CASE 2: MORE INVESTIGATION NEEDED
    # -----------------------------------------------------

    print("\n🔄 More investigation is required.")

    print("\nReason:")
    print(decision["reason"])

    next_actions = decision.get(
        "next_actions",
        []
    )


    if not next_actions:

        print(
            "\n⚠️ No additional actions were provided."
        )

        break


    print("\nNext investigation actions:")

    for action in next_actions:

        print(
            "   →",
            action
        )


    # -----------------------------------------------------
    # CREATE NEW PLAN
    # -----------------------------------------------------

    new_plan = []

    for index, action in enumerate(
        next_actions,
        start=1
    ):

        new_plan.append({
            "step": index,
            "action": action
        })


    # -----------------------------------------------------
    # EXECUTE NEW PLAN
    # -----------------------------------------------------

    new_results = execute_investigation(
        case,
        new_plan
    )


    # -----------------------------------------------------
    # MERGE NEW EVIDENCE
    # -----------------------------------------------------

    for key, value in new_results.items():

        if key not in results:

            results[key] = value

        else:

            if isinstance(
                results[key],
                list
            ):

                for item in value:

                    if item not in results[key]:

                        results[key].append(item)

            else:

                results[key] = value


    round_number += 1


# =========================================================
# 5. SAVE CASE TO DATABASE
# =========================================================

crime_type = "Unknown"
risk_score = 0
risk_level = "UNKNOWN"


# ---------------------------------------------------------
# GET CRIME PATTERNS
# ---------------------------------------------------------

if (
    "patterns" in results
    and results["patterns"]
):

    crime_type = ", ".join(
        results["patterns"]
    )


# ---------------------------------------------------------
# GET RISK
# ---------------------------------------------------------

if "risk" in results:

    risk_score = results["risk"]["score"]

    risk_level = results["risk"]["level"]


# ---------------------------------------------------------
# SAVE CASE
# ---------------------------------------------------------

case_id = save_case(
    case,
    crime_type,
    risk_score,
    risk_level
)


print(
    "\n💾 Case saved to Cyber Trap memory."
)

print(
    "Case ID:",
    f"CT-{case_id:04d}"
)


# =========================================================
# 6. SAVE EVIDENCE
# =========================================================

# ---------------------------------------------------------
# INDICATORS
# ---------------------------------------------------------

if "indicators" in results:

    for indicator in results["indicators"]:

        save_evidence(
            case_id,
            "indicator",
            indicator
        )


# ---------------------------------------------------------
# SCAM PATTERNS
# ---------------------------------------------------------

if "patterns" in results:

    for pattern in results["patterns"]:

        save_evidence(
            case_id,
            "scam_pattern",
            pattern
        )


# ---------------------------------------------------------
# ATTACK CHAIN
# ---------------------------------------------------------

if "attack_chain" in results:

    for stage in results["attack_chain"]:

        save_evidence(
            case_id,
            "attack_chain",
            stage
        )


# =========================================================
# 7. SAVE INVESTIGATION ACTIONS
# =========================================================

# Combine the original plan and any
# additional investigation actions.

all_plans = []

all_plans.extend(plan)


# If replanning happened, add the additional actions.
if round_number > 1:

    if "next_actions" in decision:

        for index, action in enumerate(
            decision["next_actions"],
            start=len(all_plans) + 1
        ):

            all_plans.append({
                "step": index,
                "action": action
            })


# ---------------------------------------------------------
# SAVE EACH ACTION
# ---------------------------------------------------------

for step in all_plans:

    action = step["action"]


    if action == "analyze_cyber_indicators":

        result = str(
            results.get(
                "indicators",
                []
            )
        )


    elif action == "detect_scam_pattern":

        result = str(
            results.get(
                "patterns",
                []
            )
        )


    elif action == "analyze_attack_chain":

        result = str(
            results.get(
                "attack_chain",
                []
            )
        )


    elif action == "calculate_risk":

        result = str(
            results.get(
                "risk",
                {}
            )
        )


    else:

        result = "Completed"


    save_investigation(
        case_id,
        action,
        result
    )


# =========================================================
# 8. GENERATE FINAL AI REPORT
# =========================================================

print("\n" + "=" * 65)
print("              GENERATING FINAL REPORT")
print("=" * 65)

print(
    "\n🧠 Cyber Trap is preparing "
    "the final investigation report..."
)


final_report = generate_final_report(
    case,
    results,
    decision
)


# =========================================================
# 9. SAVE FINAL REPORT
# =========================================================

save_report(
    case_id,
    final_report
)


print(
    "\n💾 Final report saved to Cyber Trap memory."
)


# =========================================================
# 10. DISPLAY FINAL REPORT
# =========================================================

print("\n" + "=" * 65)
print("             CYBER TRAP INVESTIGATION REPORT")
print("=" * 65)

print(final_report)


# =========================================================
# 11. FINAL EVIDENCE
# =========================================================

print("\n" + "=" * 65)
print("                  FINAL EVIDENCE")
print("=" * 65)


# ---------------------------------------------------------
# INDICATORS
# ---------------------------------------------------------

if "indicators" in results:

    print("\n🔎 Indicators:")

    for indicator in results["indicators"]:

        print(
            "   ⚠",
            indicator
        )


# ---------------------------------------------------------
# PATTERNS
# ---------------------------------------------------------

if "patterns" in results:

    print("\n🧩 Possible Patterns:")

    for pattern in results["patterns"]:

        print(
            "   •",
            pattern
        )


# ---------------------------------------------------------
# ATTACK CHAIN
# ---------------------------------------------------------

if "attack_chain" in results:

    print("\n🔗 Attack Chain:")

    for index, stage in enumerate(
        results["attack_chain"],
        start=1
    ):

        print(
            f"   {index}. {stage}"
        )


# ---------------------------------------------------------
# RISK
# ---------------------------------------------------------

if "risk" in results:

    print("\n⚠️ Risk Assessment:")

    print(
        "   Score:",
        results["risk"]["score"]
    )

    print(
        "   Level:",
        results["risk"]["level"]
    )


# =========================================================
# FINISHED
# =========================================================

print("\n" + "=" * 65)
print("              INVESTIGATION FINISHED")
print("=" * 65)