from tools.planner import create_investigation_plan
from tools.executor import execute_investigation
from tools.replanner import replan_investigation
from tools.report_generator import generate_final_report

from memory.database import (
    save_case,
    save_evidence,
    save_investigation,
    save_report
)


# =========================================================
# RUN COMPLETE CYBER TRAP INVESTIGATION
# =========================================================

def run_investigation(case):

    # -----------------------------------------------------
    # 1. CREATE INITIAL PLAN
    # -----------------------------------------------------

    plan = create_investigation_plan(case)


    # -----------------------------------------------------
    # 2. EXECUTE INITIAL PLAN
    # -----------------------------------------------------

    results = execute_investigation(
        case,
        plan
    )


    # Keep track of every plan/action
    all_plans = [plan]


    # -----------------------------------------------------
    # 3. AGENT REPLANNING LOOP
    # -----------------------------------------------------

    max_rounds = 2
    round_number = 1

    decision = {
        "continue": False,
        "reason": "Investigation completed."
    }


    while round_number <= max_rounds:

        decision = replan_investigation(
            case,
            results
        )


        # -------------------------------------------------
        # ENOUGH EVIDENCE
        # -------------------------------------------------

        if not decision.get("continue", False):

            break


        # -------------------------------------------------
        # MORE INVESTIGATION REQUIRED
        # -------------------------------------------------

        next_actions = decision.get(
            "next_actions",
            []
        )


        if not next_actions:

            break


        # Create another plan

        new_plan = []

        for index, action in enumerate(
            next_actions,
            start=1
        ):

            new_plan.append({
                "step": index,
                "action": action
            })


        all_plans.append(new_plan)


        # Execute additional investigation

        new_results = execute_investigation(
            case,
            new_plan
        )


        # -------------------------------------------------
        # MERGE RESULTS
        # -------------------------------------------------

        for key, value in new_results.items():

            if key not in results:

                results[key] = value

            else:

                if isinstance(
                    results[key],
                    list
                ):

                    if isinstance(value, list):

                        for item in value:

                            if item not in results[key]:

                                results[key].append(item)

                else:

                    results[key] = value


        round_number += 1


    # -----------------------------------------------------
    # 4. DETERMINE CASE INFORMATION
    # -----------------------------------------------------

    crime_type = "Unknown"

    risk_score = 0

    risk_level = "UNKNOWN"


    if results.get("patterns"):

        crime_type = ", ".join(
            results["patterns"]
        )


    if results.get("risk"):

        risk_score = results["risk"].get(
            "score",
            0
        )

        risk_level = results["risk"].get(
            "level",
            "UNKNOWN"
        )


    # -----------------------------------------------------
    # 5. SAVE CASE
    # -----------------------------------------------------

    case_id = save_case(
        case,
        crime_type,
        risk_score,
        risk_level
    )


    # -----------------------------------------------------
    # 6. SAVE EVIDENCE
    # -----------------------------------------------------

    if results.get("indicators"):

        for indicator in results["indicators"]:

            save_evidence(
                case_id,
                "indicator",
                indicator
            )


    if results.get("patterns"):

        for pattern in results["patterns"]:

            save_evidence(
                case_id,
                "scam_pattern",
                pattern
            )


    # -----------------------------------------------------
    # 7. SAVE ATTACK CHAIN
    # -----------------------------------------------------

    if results.get("attack_chain"):

        for step in results["attack_chain"]:

            save_evidence(
                case_id,
                "attack_chain",
                step
            )


    # -----------------------------------------------------
    # 8. SAVE ALL INVESTIGATION ACTIONS
    # -----------------------------------------------------

    for current_plan in all_plans:

        for step in current_plan:

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


            elif action == "calculate_risk":

                result = str(
                    results.get(
                        "risk",
                        {}
                    )
                )


            elif action == "analyze_attack_chain":

                result = str(
                    results.get(
                        "attack_chain",
                        []
                    )
                )


            else:

                result = "Completed"


            save_investigation(
                case_id,
                action,
                result
            )


    # -----------------------------------------------------
    # 9. GENERATE FINAL REPORT
    # -----------------------------------------------------

    final_report = generate_final_report(
        case,
        results,
        decision
    )


    # -----------------------------------------------------
    # 10. SAVE REPORT
    # -----------------------------------------------------

    save_report(
        case_id,
        final_report
    )


    # -----------------------------------------------------
    # 11. RETURN EVERYTHING TO FRONTEND
    # -----------------------------------------------------

    return {

        "case_id": case_id,

        "plan": plan,

        "results": results,

        "decision": decision,

        "final_report": final_report

    }