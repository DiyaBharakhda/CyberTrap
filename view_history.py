from memory.database import get_all_cases


print("=" * 70)
print("                    CYBER TRAP")
print("                    CASE HISTORY")
print("=" * 70)


cases = get_all_cases()


if not cases:

    print("\nNo previous cases found.")

else:

    for case in cases:

        case_id = case[0]
        description = case[1]
        crime_type = case[2]
        risk_score = case[3]
        risk_level = case[4]
        created_at = case[5]

        print("\n" + "-" * 70)

        print(f"Case ID: CT-{case_id:04d}")

        print(f"Crime Type: {crime_type}")

        print(f"Risk Score: {risk_score}/100")

        print(f"Risk Level: {risk_level}")

        print(f"Created: {created_at}")

        print(f"Description: {description}")