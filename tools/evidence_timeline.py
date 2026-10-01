import re


def build_evidence_timeline(text, evidence_analysis=None):
    """
    Reconstruct a logical sequence of events from cybercrime evidence.

    Uses confirmed analyzer findings where available so that ordinary
    mentions of words such as "bank", "password", or "OTP" are not
    automatically treated as malicious behavior.
    """

    text_lower = text.lower()
    events = []

    def add_event(order, event, detail, severity="INFO"):
        events.append({
            "order": order,
            "event": event,
            "detail": detail,
            "severity": severity
        })

    findings = (evidence_analysis or {}).get("findings", {}) or {}

    sensitive_requests = findings.get("sensitive_requests", []) or []
    impersonation_findings = findings.get("impersonation", []) or []
    urgency_findings = findings.get("urgency", []) or []
    financial_requests = findings.get("financial_requests", []) or []
    suspicious_links = findings.get("suspicious_links", []) or []

    # --------------------------------------------------
    # 1. INITIAL CONTACT
    # --------------------------------------------------

    if any(word in text_lower for word in [
        "sms",
        "text message",
        "message",
        "received a message"
    ]):
        add_event(
            1,
            "Initial Contact",
            "Victim received a message.",
            "MEDIUM"
        )

    elif any(word in text_lower for word in [
        "email",
        "emailed",
        "received an email"
    ]):
        add_event(
            1,
            "Initial Contact",
            "Victim received an email.",
            "MEDIUM"
        )

    elif any(word in text_lower for word in [
        "call",
        "called",
        "phone call",
        "voice call"
    ]):
        add_event(
            1,
            "Initial Contact",
            "Victim was contacted through a phone or voice call.",
            "MEDIUM"
        )

    # --------------------------------------------------
    # 2. IMPERSONATION
    # --------------------------------------------------

    # Only add this event when the analyzer has actually
    # identified impersonation.
    if impersonation_findings:

        label = "Possible Impersonation"

        for item in impersonation_findings:

            item_text = str(item).lower()

            if "government" in item_text or "police" in item_text:
                label = "Government / Police Impersonation"
                break

            if "bank" in item_text:
                label = "Bank Impersonation"
                break

        add_event(
            2,
            "Impersonation",
            f"The evidence indicates possible {label.lower()}.",
            "HIGH"
        )

    # --------------------------------------------------
    # 3. URGENCY / PRESSURE
    # --------------------------------------------------

    if urgency_findings:

        add_event(
            3,
            "Psychological Pressure",
            "The evidence indicates urgency or pressure intended to influence the victim's actions.",
            "HIGH"
        )

    # --------------------------------------------------
    # 4. SUSPICIOUS LINK
    # --------------------------------------------------

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        text
    )

    if suspicious_links and urls:

        add_event(
            4,
            "Suspicious Link",
            f"{len(urls)} suspicious URL(s) were identified in the evidence.",
            "HIGH"
        )

    # --------------------------------------------------
    # 5. FAKE WEBSITE
    # --------------------------------------------------

    if any(word in text_lower for word in [
        "fake website",
        "fake login",
        "looked like my bank",
        "looked like the bank",
        "fake page",
        "website looked"
    ]):

        add_event(
            5,
            "Fake Website",
            "The evidence indicates that the victim was directed to a deceptive website or page.",
            "CRITICAL"
        )

    # A login page alone is not enough to call something a
    # fake website. Require a confirmed suspicious link.
    elif (
        "login page" in text_lower
        and suspicious_links
    ):

        add_event(
            5,
            "Suspicious Login Page",
            "A login page was associated with a suspicious link.",
            "HIGH"
        )

    # --------------------------------------------------
    # 6. INFORMATION REQUEST
    # --------------------------------------------------

    if sensitive_requests:

        requested_labels = []

        for item in sensitive_requests:

            item_text = str(item).lower()

            if "account number" in item_text or "bank account" in item_text:
                label = "account number"
            elif "username" in item_text or "user name" in item_text:
                label = "username"
            elif "password" in item_text:
                label = "password"
            elif "card number" in item_text:
                label = "card number"
            elif "cvv" in item_text:
                label = "cvv"
            elif "otp" in item_text or "one time password" in item_text:
                label = "otp"
            else:
                label = str(item)

            if label not in requested_labels:
                requested_labels.append(label)

        add_event(
            6,
            "Credential / Data Harvesting",
            "Sensitive information was requested: " +
            ", ".join(requested_labels),
            "CRITICAL"
        )

    # --------------------------------------------------
    # 7. FINANCIAL REQUEST
    # --------------------------------------------------

    if financial_requests:

        add_event(
            6.5,
            "Financial Request",
            "The evidence indicates a request involving money or financial activity.",
            "HIGH"
        )

    # --------------------------------------------------
    # 8. VICTIM ACTION
    # --------------------------------------------------

    action_terms = [
        "i entered",
        "i provided",
        "i shared",
        "i gave",
        "entered my",
        "provided my",
        "shared my"
    ]

    if any(term in text_lower for term in action_terms):

        add_event(
            7,
            "Victim Interaction",
            "The evidence indicates that the victim interacted with the attacker or provided information.",
            "HIGH"
        )

    # --------------------------------------------------
    # 9. SUSPICION / INTERRUPTION
    # --------------------------------------------------

    if any(word in text_lower for word in [
        "became suspicious",
        "realized it was fake",
        "realised it was fake",
        "noticed it was fake",
        "suspected",
        "stopped",
        "did not enter",
        "didn't enter"
    ]):

        add_event(
            8,
            "Attack Interrupted",
            "The victim detected suspicious activity and appears to have interrupted the attack.",
            "MEDIUM"
        )

    # --------------------------------------------------
    # 10. POSSIBLE COMPROMISE
    # --------------------------------------------------

    if any(word in text_lower for word in [
        "account hacked",
        "account compromised",
        "unauthorized transaction",
        "money was transferred",
        "money was withdrawn",
        "lost money",
        "transaction occurred",
        "account accessed"
    ]):

        add_event(
            9,
            "Possible Compromise",
            "The evidence indicates possible account compromise or financial loss.",
            "CRITICAL"
        )

    # --------------------------------------------------
    # 11. FINAL RESPONSE
    # --------------------------------------------------

    if any(word in text_lower for word in [
        "reported",
        "report",
        "blocked the number",
        "blocked the card",
        "contacted the bank",
        "contacted police",
        "changed my password"
    ]):

        add_event(
            10,
            "Incident Response",
            "The victim appears to have taken action after detecting the incident.",
            "INFO"
        )

    # --------------------------------------------------
    # FALLBACK
    # --------------------------------------------------

    if not events:

        add_event(
            1,
            "Evidence Review",
            "No clear sequence of attack events could be reconstructed.",
            "INFO"
        )

    # Ensure chronological order
    events.sort(key=lambda event: event["order"])

    return events