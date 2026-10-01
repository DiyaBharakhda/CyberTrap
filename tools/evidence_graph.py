import re


def build_evidence_graph(text, evidence_analysis=None):
    """
    Build a relationship graph from investigation evidence.

    The graph relies on confirmed evidence findings where possible,
    rather than treating simple keyword mentions as suspicious.
    """

    nodes = []
    edges = []

    def add_node(node_id, label, node_type):
        if not any(n["id"] == node_id for n in nodes):
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type
            })

    def add_edge(source, target, relationship):
        edge = {
            "source": source,
            "target": target,
            "relationship": relationship
        }

        if edge not in edges:
            edges.append(edge)

    text_lower = text.lower()

    # --------------------------------------------------
    # CONFIRMED FINDINGS FROM CYBER ANALYZER
    # --------------------------------------------------

    findings = (evidence_analysis or {}).get("findings", {}) or {}

    sensitive_requests = findings.get("sensitive_requests", []) or []
    impersonation_findings = findings.get("impersonation", []) or []
    urgency_findings = findings.get("urgency", []) or []
    financial_requests = findings.get("financial_requests", []) or []
    suspicious_links = findings.get("suspicious_links", []) or []

    # --------------------------------------------------
    # CASE / INCIDENT
    # --------------------------------------------------

    add_node(
        "incident",
        "Cyber Incident",
        "incident"
    )

    # --------------------------------------------------
    # URLS
    # --------------------------------------------------

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        text
    )

    url_nodes = []

    for index, url in enumerate(urls):

        url = url.rstrip(".,);]")

        url_id = f"url_{index}"
        url_nodes.append(url_id)

        add_node(
            url_id,
            url,
            "url"
        )

        add_edge(
            "incident",
            url_id,
            "contains URL"
        )

        domain_match = re.search(
            r'https?://([^/:?#]+)',
            url
        )

        if domain_match:

            domain = domain_match.group(1)
            domain_id = f"domain_{index}"

            add_node(
                domain_id,
                domain,
                "domain"
            )

            add_edge(
                url_id,
                domain_id,
                "uses domain"
            )

    # --------------------------------------------------
    # EMAILS
    # --------------------------------------------------

    emails = re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        text
    )

    for index, email in enumerate(emails):

        email_id = f"email_{index}"

        add_node(
            email_id,
            email,
            "email"
        )

        add_edge(
            "incident",
            email_id,
            "contains email"
        )

    # --------------------------------------------------
    # PHONE NUMBERS
    # --------------------------------------------------

    phones = re.findall(
        r'(?<!\d)(?:\+?\d[\d\s\-]{8,}\d)(?!\d)',
        text
    )

    for index, phone in enumerate(phones):

        phone = phone.strip()

        phone_id = f"phone_{index}"

        add_node(
            phone_id,
            phone,
            "phone"
        )

        add_edge(
            "incident",
            phone_id,
            "sender/contact"
        )

    # --------------------------------------------------
    # IP ADDRESSES
    # --------------------------------------------------

    ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        text
    )

    for index, ip in enumerate(ips):

        ip_id = f"ip_{index}"

        add_node(
            ip_id,
            ip,
            "ip"
        )

        add_edge(
            "incident",
            ip_id,
            "contains IP"
        )

    # --------------------------------------------------
    # SENSITIVE INFORMATION
    #
    # IMPORTANT:
    # Only add these nodes when the analyzer has actually
    # detected a request for the information.
    # --------------------------------------------------

    sensitive_labels = {
        "account": "Account Number",
        "account number": "Account Number",
        "bank account": "Account Number",
        "username": "Username",
        "user name": "Username",
        "password": "Password",
        "card": "Card Number",
        "card number": "Card Number",
        "debit card": "Card Number",
        "credit card": "Card Number",
        "cvv": "CVV",
        "cvv number": "CVV",
        "otp": "OTP",
        "one time password": "OTP"
    }

    data_nodes = []

    for item in sensitive_requests:

        item_text = str(item).lower()

        matched_label = None

        for keyword, label in sensitive_labels.items():

            if keyword in item_text:
                matched_label = label
                break

        if matched_label:

            node_id = (
                "data_"
                + matched_label.lower().replace(" ", "_")
            )

            add_node(
                node_id,
                matched_label,
                "sensitive_data"
            )

            add_edge(
                "incident",
                node_id,
                "requests"
            )

            data_nodes.append(node_id)

    # --------------------------------------------------
    # FINANCIAL REQUEST
    # --------------------------------------------------

    if financial_requests:

        add_node(
            "financial_request",
            "Financial Request",
            "financial"
        )

        add_edge(
            "incident",
            "financial_request",
            "requests payment"
        )

    # --------------------------------------------------
    # IMPERSONATION
    #
    # Only create this node from confirmed analyzer
    # findings. Do not infer impersonation from "my bank".
    # --------------------------------------------------

    if impersonation_findings:

        # Use the analyzer's finding when available.
        label = "Possible Impersonation"

        if isinstance(impersonation_findings, list):
            for item in impersonation_findings:
                item_text = str(item).lower()

                if "government" in item_text or "police" in item_text:
                    label = "Government / Police Impersonation"
                    break

                if "bank" in item_text:
                    label = "Bank Impersonation"
                    break

        add_node(
            "impersonation",
            label,
            "impersonation"
        )

        add_edge(
            "incident",
            "impersonation",
            "impersonates"
        )

    # --------------------------------------------------
    # URGENCY
    # --------------------------------------------------

    if urgency_findings:

        add_node(
            "urgency",
            "Urgency / Pressure",
            "behavior"
        )

        add_edge(
            "incident",
            "urgency",
            "uses pressure"
        )

    # --------------------------------------------------
    # SUSPICIOUS LINKS
    #
    # A URL by itself is not treated as malicious.
    # Only confirmed suspicious links get this relationship.
    # --------------------------------------------------

    if suspicious_links and url_nodes:

        add_node(
            "suspicious_link",
            "Suspicious Link",
            "behavior"
        )

        add_edge(
            "incident",
            "suspicious_link",
            "contains suspicious link"
        )

        add_edge(
            "suspicious_link",
            url_nodes[0],
            "points to"
        )

    # --------------------------------------------------
    # SOCIAL ENGINEERING
    #
    # Only create this when there are confirmed suspicious
    # behaviors, not simply because words such as "verify"
    # or "password" appear.
    # --------------------------------------------------

    if (
        urgency_findings
        or sensitive_requests
        or financial_requests
        or suspicious_links
        or impersonation_findings
    ):

        add_node(
            "social_engineering",
            "Social Engineering",
            "behavior"
        )

        add_edge(
            "incident",
            "social_engineering",
            "uses"
        )

    # --------------------------------------------------
    # URL -> DATA RELATIONSHIP
    # --------------------------------------------------

    if url_nodes and data_nodes and suspicious_links:

        for data_node in data_nodes:

            add_edge(
                url_nodes[0],
                data_node,
                "requests data"
            )

    # --------------------------------------------------
    # IMPERSONATION -> URL
    # --------------------------------------------------

    if impersonation_findings and url_nodes:

        add_edge(
            "impersonation",
            url_nodes[0],
            "directs victim to"
        )

    # --------------------------------------------------
    # URGENCY -> URL
    # --------------------------------------------------

    if urgency_findings and url_nodes:

        add_edge(
            "urgency",
            url_nodes[0],
            "pushes victim toward"
        )

    return {
        "nodes": nodes,
        "edges": edges
    }