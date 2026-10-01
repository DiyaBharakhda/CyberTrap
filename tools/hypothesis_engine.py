def generate_hypotheses(case_text, evidence_analysis, timeline):
    text = case_text.lower()

    hypotheses = []

    findings = evidence_analysis.get("findings", [])
    correlations = evidence_analysis.get("correlations", [])

    def has_any(words):
        return any(word in text for word in words)

    # --------------------------------------------------
    # HYPOTHESIS 1 — PHISHING
    # --------------------------------------------------

    phishing_score = 0
    phishing_evidence = []

    if has_any(["link", "website", "login page", "url"]):
        phishing_score += 30
        phishing_evidence.append(
            "A link or website was involved."
        )

    if has_any([
        "password",
        "username",
        "card number",
        "cvv",
        "otp",
        "account number"
    ]):
        phishing_score += 30
        phishing_evidence.append(
            "Sensitive credentials or financial information were requested."
        )

    if has_any([
        "verify",
        "verification",
        "kyc",
        "update your account"
    ]):
        phishing_score += 20
        phishing_evidence.append(
            "The victim was pressured to verify or update an account."
        )

    if has_any([
        "urgent",
        "immediately",
        "within 30 minutes",
        "account will be blocked"
    ]):
        phishing_score += 15
        phishing_evidence.append(
            "Urgency was used to influence the victim."
        )

    phishing_score = min(phishing_score, 100)

    hypotheses.append({
        "name": "Phishing / Credential Harvesting",
        "score": phishing_score,
        "evidence": phishing_evidence,
        "explanation": (
            "The incident may involve a deceptive communication "
            "designed to direct the victim toward a malicious or "
            "fraudulent website."
        )
    })

    # --------------------------------------------------
    # HYPOTHESIS 2 — SOCIAL ENGINEERING
    # --------------------------------------------------

    social_score = 0
    social_evidence = []

    if has_any([
        "urgent",
        "immediately",
        "act now",
        "within 30 minutes",
        "legal action"
    ]):
        social_score += 35
        social_evidence.append(
            "Fear or urgency was used to pressure the victim."
        )

    if has_any([
        "bank",
        "police",
        "government",
        "officer",
        "official"
    ]):
        social_score += 25
        social_evidence.append(
            "The attacker appears to have relied on authority or trust."
        )

    if has_any([
        "verify",
        "confirm",
        "update",
        "provide",
        "enter your details"
    ]):
        social_score += 25
        social_evidence.append(
            "The victim was encouraged to perform a specific action."
        )

    social_score = min(social_score, 100)

    hypotheses.append({
        "name": "Social Engineering",
        "score": social_score,
        "evidence": social_evidence,
        "explanation": (
            "The attacker may have manipulated the victim "
            "through urgency, authority, fear, or trust."
        )
    })

    # --------------------------------------------------
    # HYPOTHESIS 3 — ACCOUNT TAKEOVER
    # --------------------------------------------------

    takeover_score = 0
    takeover_evidence = []

    if has_any([
        "password",
        "username",
        "otp",
        "login",
        "credentials"
    ]):
        takeover_score += 40
        takeover_evidence.append(
            "Account authentication information was targeted."
        )

    if has_any([
        "account hacked",
        "account compromised",
        "unauthorized login",
        "account accessed"
    ]):
        takeover_score += 40
        takeover_evidence.append(
            "The evidence mentions possible unauthorized account access."
        )

    takeover_score = min(takeover_score, 100)

    hypotheses.append({
        "name": "Account Takeover Attempt",
        "score": takeover_score,
        "evidence": takeover_evidence,
        "explanation": (
            "The attacker may have attempted to obtain "
            "authentication information to access the victim's account."
        )
    })

    # --------------------------------------------------
    # HYPOTHESIS 4 — FINANCIAL FRAUD
    # --------------------------------------------------

    financial_score = 0
    financial_evidence = []

    if has_any([
        "money",
        "payment",
        "transfer",
        "bank",
        "card",
        "refund",
        "transaction"
    ]):
        financial_score += 40
        financial_evidence.append(
            "The incident has a financial component."
        )

    if has_any([
        "card number",
        "cvv",
        "account number",
        "bank account"
    ]):
        financial_score += 35
        financial_evidence.append(
            "Financial account or card information was targeted."
        )

    financial_score = min(financial_score, 100)

    hypotheses.append({
        "name": "Financial Fraud",
        "score": financial_score,
        "evidence": financial_evidence,
        "explanation": (
            "The incident may be intended to obtain financial "
            "information or facilitate unauthorized transactions."
        )
    })

    # --------------------------------------------------
    # HYPOTHESIS 5 — BENIGN / LEGITIMATE COMMUNICATION
    # --------------------------------------------------

    benign_score = 10
    benign_evidence = [
        "No strong evidence of legitimacy was identified."
    ]

    if not has_any([
        "password",
        "cvv",
        "otp",
        "card number",
        "account number",
        "urgent",
        "immediately"
    ]):
        benign_score += 30
        benign_evidence.append(
            "The evidence does not contain several common high-risk indicators."
        )

    hypotheses.append({
        "name": "Legitimate Communication",
        "score": min(benign_score, 100),
        "evidence": benign_evidence,
        "explanation": (
            "The communication could potentially be legitimate, "
            "although this hypothesis should be evaluated against "
            "the available evidence."
        )
    })

    # --------------------------------------------------
    # RANK
    # --------------------------------------------------

    hypotheses.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    for index, hypothesis in enumerate(hypotheses, 1):
        hypothesis["rank"] = index

    # --------------------------------------------------
    # WINNER
    # --------------------------------------------------

    if hypotheses:
        strongest = hypotheses[0]

        if len(hypotheses) > 1:
            difference = (
                strongest["score"] -
                hypotheses[1]["score"]
            )
        else:
            difference = strongest["score"]

        if difference >= 25:
            confidence = "HIGH"
        elif difference >= 10:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        conclusion = {
            "strongest_hypothesis": strongest["name"],
            "score": strongest["score"],
            "confidence": confidence,
            "reason": (
                f"The strongest explanation is "
                f"'{strongest['name']}' because it has the "
                f"highest evidence-supported score."
            )
        }

    else:
        conclusion = {
            "strongest_hypothesis": "Unknown",
            "score": 0,
            "confidence": "LOW",
            "reason": "Insufficient evidence."
        }

    return {
        "hypotheses": hypotheses,
        "conclusion": conclusion
    }