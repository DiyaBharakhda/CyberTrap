from tools.cyber_tools import (
    analyze_cyber_indicators,
    detect_scam_pattern,
    calculate_risk,
    analyze_attack_chain
)


def execute_investigation(case, plan):

    results = {}

    print("\n" + "=" * 60)
    print("              INVESTIGATION STARTED")
    print("=" * 60)

    for step in plan:

        action = step["action"]

        print(f"\n▶ Step {step['step']}: {action}")

        # --------------------------------
        # INDICATOR ANALYZER
        # --------------------------------

        if action == "analyze_cyber_indicators":

            print("🔎 Running Indicator Analyzer...")

            indicators = analyze_cyber_indicators(case)

            results["indicators"] = indicators

            print("✓ Indicator analysis completed.")

            if indicators:

                for indicator in indicators:
                    print("   ⚠", indicator)


        # --------------------------------
        # SCAM PATTERN DETECTOR
        # --------------------------------

        elif action == "detect_scam_pattern":

            print("🧩 Running Scam Pattern Detector...")

            patterns = detect_scam_pattern(case)

            results["patterns"] = patterns

            print("✓ Scam pattern analysis completed.")

            if patterns:

                for pattern in patterns:
                    print("   •", pattern)


        # --------------------------------
        # ATTACK CHAIN ANALYZER
        # --------------------------------

        elif action == "analyze_attack_chain":

            print("🔗 Running Attack Chain Analyzer...")

            attack_chain = analyze_attack_chain(case)

            results["attack_chain"] = attack_chain

            print("✓ Attack chain analysis completed.")

            if attack_chain:

                for index, stage in enumerate(
                    attack_chain,
                    start=1
                ):

                    print(
                        f"   {index}. {stage}"
                    )

            else:

                print(
                    "   No clear attack chain identified."
                )


        # --------------------------------
        # RISK ENGINE
        # --------------------------------

        elif action == "calculate_risk":

            print("⚠️ Running Risk Engine...")

            # Risk MUST use indicators already found
            indicators = results.get(
                "indicators",
                []
            )

            risk = calculate_risk(
                indicators
            )

            results["risk"] = risk

            print("✓ Risk assessment completed.")

            print(
                "   Score:",
                risk["score"]
            )

            print(
                "   Level:",
                risk["level"]
            )


        # --------------------------------
        # UNKNOWN TOOL
        # --------------------------------

        else:

            print(
                f"⚠️ Unknown investigation action: {action}"
            )


    print("\n" + "=" * 60)
    print("              INVESTIGATION COMPLETE")
    print("=" * 60)

    return results