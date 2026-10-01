from memory.database import (
    get_case_by_id,
    get_case_evidence,
    get_case_investigations
)


print("=" * 70)
print("                 CYBER TRAP")
print("                  CASE DETAILS")
print("=" * 70)


case_number = input("\nEnter Case ID (example: CT-0001): ")


# Remove CT- if user enters it
case_number = case_number.upper().replace("CT-", "")

try:
    case_id = int(case_number)

except ValueError:
    print("\n❌ Invalid Case ID.")
    exit()


# -----------------------------------------
# GET CASE
# -----------------------------------------

case = get_case_by_id(case_id)


if not case:

    print("\n❌ Case not found.")
    exit()


case_id = case[0]
description = case[1]
crime_type = case[2]
risk_score = case[3]
risk_level = case[4]
created_at = case[5]


# -----------------------------------------
# CASE INFORMATION
# -----------------------------------------

print("\n" + "=" * 70)
print(f"CASE CT-{case_id:04d}")
print("=" * 70)

print("\n📝 ORIGINAL CASE")
print(description)

print("\n🧩 CRIME / SCAM TYPE")
print(crime_type)

print("\n⚠️ RISK")
print(f"{risk_score}/100 — {risk_level}")

print("\n📅 CREATED")
print(created_at)


# -----------------------------------------
# EVIDENCE
# -----------------------------------------

evidence = get_case_evidence(case_id)


print("\n" + "=" * 70)
print("🔎 EVIDENCE DISCOVERED")
print("=" * 70)


if evidence:

    for evidence_type, evidence_text in evidence:

        print(
            f"\n⚠ [{evidence_type.upper()}]"
        )

        print(
            f"   {evidence_text}"
        )

else:

    print("\nNo evidence recorded.")


# -----------------------------------------
# INVESTIGATION HISTORY
# -----------------------------------------

investigations = get_case_investigations(case_id)


print("\n" + "=" * 70)
print("🔧 INVESTIGATION HISTORY")
print("=" * 70)


if investigations:

    for action, result in investigations:

        print(f"\n▶ {action}")

        print(f"   Result: {result}")

else:

    print("\nNo investigation history recorded.")


print("\n" + "=" * 70)
print("             END OF CASE")
print("=" * 70)