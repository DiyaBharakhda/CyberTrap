import re
# =========================================================
# CYBER TRAP - CYBER INTELLIGENCE TOOLS
# =========================================================


# =========================================================
# 1. CYBER INDICATOR ANALYZER
# =========================================================


def _has_any(text, phrases):
    return any(p in text for p in phrases)


def _has_positive_request(text, terms):
    """Detect an actual request for sensitive information, not a mention of it."""
    request_verbs = (
        r"(?:enter|provide|share|send|give|submit|type|tell|reveal|disclose|"
        r"upload|confirm|reply with|fill in|fill out|key in|update|verify|"
        r"ask|asks|asked|request|requests|required|requires|need|needs)"
    )
    negative = r"(?:do not|don't|never|without|not|no need to)"

    for term in terms:
        t = re.escape(term)
        patterns = [
            rf"\b{request_verbs}\b[^.!?\n]{{0,70}}\b{t}\b",
            rf"\b{t}\b[^.!?\n]{{0,70}}\b{request_verbs}\b",
        ]
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
            # A negation anywhere earlier in the same sentence means the
            # statement is warning against the action, not requesting it.
            sentence_start = max(text.rfind('.', 0, max(0, text.find(term))),
                                 text.rfind('!', 0, max(0, text.find(term))),
                                 text.rfind('?', 0, max(0, text.find(term))),
                                 text.rfind('\n', 0, max(0, text.find(term)))) + 1
            sentence = text[sentence_start:text.find(term) + len(term)]
            if re.search(rf"(?:{negative}).{{0,100}}\b{t}\b", sentence, re.IGNORECASE):
                continue
            return True
    return False


def _has_positive_financial_request(text):
    direct_actions = [
        "pay", "make a payment", "transfer money", "transfer funds",
        "send money", "send cash", "pay a fee", "registration fee"
    ]
    if _has_any(text, direct_actions):
        return True
    return _has_positive_request(text, [
        "money", "cash", "payment", "fee", "funds", "bank details",
        "account number", "upi", "upi id", "credit card", "debit card",
        "wire transfer", "deposit", "transfer"
    ])


def analyze_cyber_indicators(case):
    """Analyze a cybercrime case using context-aware warning signs."""
    text = case.lower()
    indicators = []

    if _has_any(text, [
        "urgent", "immediately", "hurry", "within 5 minutes", "within 10 minutes",
        "within 30 minutes", "within 1 hour", "within an hour", "act now",
        "last chance", "quickly", "right away", "as soon as possible", "limited time"
    ]) or re.search(
        r"\bwithin\s+\d+\s+(?:minute|minutes|hour|hours|day|days)\b",
        text
    ):
        indicators.append("Urgency / time pressure")

    if _has_positive_financial_request(text):
        indicators.append("Financial request")

    if _has_positive_request(text, [
        "otp", "password", "pin", "cvv", "card number", "account number",
        "bank details", "verification code", "security code", "login credentials",
        "username", "credentials", "passcode", "security answer", "date of birth"
    ]):
        indicators.append("Request for sensitive information")

    if _has_any(text, [
        "arrest", "account will be closed", "account would be closed",
        "account will be frozen", "account would be frozen", "legal action", "police",
        "penalty", "fine", "lawsuit", "court", "permanently blocked",
        "delete your account", "account will be deleted", "account will be suspended",
        "you will be arrested", "you will lose access", "account will be blocked",
        "account would be blocked"
    ]):
        indicators.append("Threat / intimidation")

    if _has_any(text, [
        "bank employee", "bank representative", "bank official", "bank staff",
        "police officer", "government officer",
        "company representative", "pretending to be", "claiming to be",
        "impersonating", "posing as", "someone pretending to be"
    ]):
        indicators.append("Possible impersonation")

    has_url = bool(re.search(r"https?://|www\.", text, re.IGNORECASE))
    suspicious_link_phrases = [
        "click this link", "click the link", "open this link", "click here",
        "verify through the link", "login through the link", "open the website",
        "verification website", "fake website", "lookalike website", "suspicious website",
        "spoofed website", "verification link", "included this link", "link included"
    ]
    suspicious_url_terms = [
        "login", "verify", "verification", "account", "kyc", "refund",
        "payment", "bank", "secure", "delivery", "claim", "confirm"
    ]
    url_has_suspicious_terms = has_url and sum(term in text for term in suspicious_url_terms) >= 2
    if _has_any(text, suspicious_link_phrases) or url_has_suspicious_terms or (has_url and _has_any(text, ["suspicious", "fake", "lookalike", "spoofed", "phishing"])):
        indicators.append("Suspicious link / website")

    if _has_any(text, [
        "password no longer works", "password stopped working", "password doesn't work",
        "password does not work", "cannot log in", "can't log in", "unable to log in",
        "unable to access", "locked out", "lost access", "account was hacked",
        "account hacked", "account compromised", "someone accessed my account",
        "unauthorized login", "someone logged into my account", "someone took over my account",
        "account takeover"
    ]):
        indicators.append("Possible account compromise")

    if _has_any(text, [
        "password changed", "password was changed", "profile picture changed",
        "profile picture was changed", "profile picture modified", "bio changed",
        "bio was changed", "profile was changed", "profile was modified",
        "settings were changed", "settings were modified", "email was changed",
        "email changed", "phone number was changed", "phone number changed",
        "unauthorized changes", "account details changed"
    ]):
        indicators.append("Unauthorized account changes")

    if _has_any(text, [
        "entered my password", "entered my username", "entered my credentials",
        "entered my card details", "entered my account number", "entered the password",
        "entered the credentials", "submitted my password", "submitted my credentials",
        "gave them my password", "gave them my credentials", "shared my password",
        "shared my credentials", "provided my password", "provided my credentials"
    ]):
        indicators.append("Credentials may have been exposed")

    if _has_any(text, [
        "my friends received", "my contacts received", "friends received messages",
        "contacts received messages", "sent messages to my friends", "sent messages to my contacts",
        "messages from my account", "pretending to be me", "impersonating me",
        "asked my friends for money", "asked my contacts for money", "asked them to send money",
        "asking them to send money"
    ]):
        indicators.append("Possible social engineering")

    if _has_any(text, [
        "blackmail", "blackmailing", "pay or", "send money or", "unless you pay",
        "threatening to publish", "publish my photos", "release my photos", "private photos",
        "private videos", "threatening to expose", "expose my photos", "expose my information"
    ]):
        indicators.append("Possible extortion")

    return indicators


def detect_scam_pattern(case):
    """Identify possible cybercrime patterns using contextual evidence."""
    text = case.lower()
    patterns = []

    bank_context = _has_any(text, [
        "bank", "bank account", "banking", "kyc", "debit card", "credit card", "upi"
    ])
    sensitive_request = _has_positive_request(text, [
        "otp", "password", "pin", "cvv", "card number", "account number",
        "bank details", "verification code", "login credentials", "username", "credentials"
    ])
    has_url_for_pattern = bool(re.search(r"https?://|www\.", text))
    has_suspicious_link = _has_any(text, [
        "fake website", "lookalike website", "spoofed website", "suspicious link",
        "suspicious website", "verification link", "click this link", "click the link",
        "included this link", "link included"
    ]) or (has_url_for_pattern and sum(term in text for term in [
        "login", "verify", "verification", "account", "kyc", "refund",
        "payment", "bank", "secure", "delivery", "claim", "confirm"
    ]) >= 2) or (has_url_for_pattern and _has_any(text, [
        "fake", "suspicious", "phishing", "lookalike", "spoofed"
    ]))
    urgency_or_threat = _has_any(text, [
        "urgent", "immediately", "act now",
        "account will be blocked", "account would be blocked", "account will be suspended",
        "account will be frozen", "legal action", "arrest"
    ]) or bool(re.search(
        r"\bwithin\s+\d+\s+(?:minute|minutes|hour|hours|day|days)\b",
        text
    ))
    impersonation = _has_any(text, [
        "bank employee", "bank representative", "bank official", "bank staff",
        "claiming to be", "pretending to be", "impersonating", "posing as",
        "someone pretending to be"
    ])

    banking_signal_count = sum([
        sensitive_request, has_suspicious_link, urgency_or_threat,
        impersonation, _has_positive_financial_request(text)
    ])
    if bank_context and banking_signal_count >= 2:
        patterns.append("Possible Banking Fraud")

    phishing_signal_count = sum([
        has_suspicious_link,
        sensitive_request,
        _has_any(text, ["verify your account", "verify your identity", "verification"]),
        urgency_or_threat
    ])
    if has_suspicious_link and phishing_signal_count >= 2:
        patterns.append("Possible Phishing")

    if _has_any(text, [
        "called me", "phone call", "received a call", "caller", "called claiming",
        "over the phone", "bank employee called", "someone called", "phone scam"
    ]):
        patterns.append("Possible Vishing / Voice Phishing")

    if _has_any(text, [
        "account was hacked", "account hacked", "account compromised", "cannot log in",
        "can't log in", "lost access", "locked out", "password no longer works",
        "password stopped working", "someone accessed my account", "unauthorized login",
        "account takeover", "someone took over my account"
    ]):
        patterns.append("Possible Account Takeover")

    if _has_any(text, [
        "entered my password", "entered my username", "entered my credentials",
        "stole my password", "stole my credentials", "asked for my password",
        "asked for my credentials", "credential theft", "credentials were stolen",
        "password was stolen"
    ]):
        patterns.append("Possible Credential Theft")

    if _has_any(text, [
        "friends received messages", "contacts received messages", "messages from my account",
        "impersonating me", "pretending to be me"
    ]):
        patterns.append("Possible Social Media Fraud")

    if _has_any(text, [
        "work from home", "registration fee", "job offer", "pay to get the job",
        "employment offer", "part time job"
    ]):
        patterns.append("Possible Job Scam")

    if _has_any(text, [
        "lottery", "you won", "prize", "processing fee", "lucky draw", "cash prize"
    ]):
        patterns.append("Possible Lottery / Prize Scam")

    if _has_any(text, [
        "guaranteed returns", "double your money", "guaranteed profit",
        "investment opportunity", "stock tips", "crypto investment"
    ]):
        patterns.append("Possible Investment Scam")

    if _has_any(text, [
        "police officer", "police department", "government officer", "government department",
        "income tax officer", "income tax department", "customs officer", "customs department",
        "arrest warrant", "court notice", "court order", "official government notice"
    ]):
        patterns.append("Possible Government / Police Impersonation")

    if _has_any(text, [
        "romance scam", "dating app", "online relationship", "lover", "boyfriend",
        "girlfriend", "romantic relationship", "online dating"
    ]):
        patterns.append("Possible Romance Scam")

    if _has_any(text, [
        "computer infected", "technical support", "remote access", "anydesk",
        "teamviewer", "remote desktop", "computer support", "tech support"
    ]):
        patterns.append("Possible Tech Support Scam")

    if _has_any(text, [
        "blackmail", "blackmailing", "pay or", "unless you pay", "publish my photos",
        "release my photos", "private photos", "private videos", "threatening to expose",
        "expose my photos"
    ]):
        patterns.append("Possible Extortion / Blackmail")

    return patterns


def analyze_attack_chain(case):
    """
    Identify the possible sequence of events
    in a cyberattack.
    """

    text = case.lower()

    chain = []


    # =====================================================
    # INITIAL CONTACT
    # =====================================================

    if any(
        word in text
        for word in [
            "email",
            "sms",
            "text message",
            "message",
            "whatsapp",
            "telegram",
            "called me",
            "phone call",
            "received a call",
            "received an email"
        ]
    ):

        chain.append(
            "Initial contact / social engineering"
        )


    # =====================================================
    # THREAT / PRESSURE
    # =====================================================

    if any(
        word in text
        for word in [
            "urgent",
            "immediately",
            "hurry",
            "act now",
            "account will be blocked",
            "account would be frozen",
            "account will be frozen",
            "arrest",
            "legal action",
            "within 30 minutes",
            "within 10 minutes"
        ]
    ):

        chain.append(
            "Pressure or intimidation applied"
        )


    # =====================================================
    # PHISHING LINK / FAKE WEBSITE
    # =====================================================

    if any(
        word in text
        for word in [
            "link",
            "website",
            "fake website",
            "lookalike website",
            "spoofed website",
            "click here",
            "click the link",
            "verification link"
        ]
    ):

        chain.append(
            "Suspicious link or fake website"
        )


    # =====================================================
    # CREDENTIAL COLLECTION
    # =====================================================

    if any(
        word in text
        for word in [
            "password",
            "username",
            "credentials",
            "otp",
            "cvv",
            "card number",
            "account number",
            "pin",
            "verification code"
        ]
    ):

        chain.append(
            "Attempted credential / sensitive-data collection"
        )


    # =====================================================
    # CREDENTIAL EXPOSURE
    # =====================================================

    if any(
        word in text
        for word in [
            "entered my password",
            "entered my username",
            "entered my credentials",
            "entered my card details",
            "submitted my password",
            "submitted my credentials",
            "gave them my password",
            "gave them my credentials",
            "shared my password"
        ]
    ):

        chain.append(
            "Credentials may have been exposed"
        )


    # =====================================================
    # ACCOUNT TAKEOVER
    # =====================================================

    if any(
        word in text
        for word in [
            "account was hacked",
            "account hacked",
            "cannot log in",
            "can't log in",
            "lost access",
            "locked out",
            "password no longer works",
            "password stopped working",
            "account compromised",
            "someone took over my account",
            "account takeover"
        ]
    ):

        chain.append(
            "Possible account takeover"
        )


    # =====================================================
    # UNAUTHORIZED ACCOUNT CHANGES
    # =====================================================

    if any(
        word in text
        for word in [
            "profile picture changed",
            "profile picture was changed",
            "profile picture modified",
            "bio changed",
            "bio was changed",
            "profile was changed",
            "profile was modified",
            "settings were changed",
            "settings were modified",
            "password changed",
            "password was changed",
            "email was changed",
            "phone number was changed"
        ]
    ):

        chain.append(
            "Unauthorized account changes"
        )


    # =====================================================
    # SECONDARY SOCIAL ENGINEERING / FRAUD
    # =====================================================

    if any(
        word in text
        for word in [
            "friends received",
            "contacts received",
            "friends told me",
            "my friends",
            "my contacts",
            "sent messages to my friends",
            "sent messages to my contacts",
            "messages from my account",
            "messages to my friends",
            "messages to my contacts",
            "asking them to send money",
            "asked them to send money",
            "asked my friends for money",
            "asked my contacts for money"
        ]
    ):

        chain.append(
            "Secondary social-engineering / financial fraud"
        )


    # =====================================================
    # EXTORTION
    # =====================================================

    if any(
        word in text
        for word in [
            "blackmail",
            "blackmailing",
            "pay or",
            "unless you pay",
            "publish my photos",
            "release my photos",
            "private photos",
            "private videos",
            "threatening to expose",
            "expose my photos"
        ]
    ):

        chain.append(
            "Extortion / coercion"
        )


    return chain


# =========================================================
# 4. RISK ENGINE
# =========================================================

def calculate_risk(indicators):
    """
    Calculate a preliminary risk score
    from detected cybercrime indicators.
    """

    score = 0


    # =====================================================
    # RISK WEIGHTS
    # =====================================================

    weights = {

        "Urgency / time pressure": 10,

        "Financial request": 15,

        "Request for sensitive information": 20,

        "Threat / intimidation": 20,

        "Possible impersonation": 10,

        "Suspicious link / website": 15,

        "Possible account compromise": 25,

        "Unauthorized account changes": 20,

        "Credentials may have been exposed": 25,

        "Possible social engineering": 15,

        "Possible extortion": 30
    }


    # =====================================================
    # CALCULATE SCORE
    # =====================================================

    for indicator in indicators:

        score += weights.get(
            indicator,
            0
        )


    # Maximum possible displayed score = 100
    score = min(
        score,
        100
    )


    # =====================================================
    # DETERMINE RISK LEVEL
    # =====================================================

    if score >= 76:

        level = "CRITICAL"

    elif score >= 51:

        level = "HIGH"

    elif score >= 26:

        level = "MEDIUM"

    else:

        level = "LOW"


    return {
        "score": score,
        "level": level
    }

def extract_evidence(text):
    """Extract structured evidence while distinguishing requests from mentions."""
    findings = {
        "urls": [], "emails": [], "phone_numbers": [], "money_mentions": [],
        "sensitive_requests": [], "urgency": [], "impersonation": []
    }

    findings["urls"] = re.findall(r'https?://[^\s]+|www\.[^\s]+', text, re.IGNORECASE)
    findings["emails"] = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    findings["phone_numbers"] = re.findall(r'(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)', text)
    findings["money_mentions"] = re.findall(
    r'(?:₹|rs\.?|inr)\s?[\d,]+(?:\.\d+)?',
    text,
    re.IGNORECASE
)
    text_lower = text.lower()
    sensitive_keywords = [
        "otp", "password", "cvv", "card number", "account number", "pin",
        "verification code", "login details", "bank details", "username", "credentials"
    ]
    for keyword in sensitive_keywords:
        if _has_positive_request(text_lower, [keyword]):
            findings["sensitive_requests"].append(keyword)

    urgency_keywords = [
        "urgent", "immediately", "act now", "last warning", "expire", "deadline",
        "account will be blocked", "account will be suspended",
        "account will be frozen", "legal action", "limited time"
    ]
    for keyword in urgency_keywords:
        if keyword in text_lower:
            findings["urgency"].append(keyword)

    # Detect arbitrary short deadlines such as "within 15 minutes" or
    # "within 2 hours", rather than relying on a few hard-coded values.
    for match in re.findall(r"\bwithin\s+\d+\s+(?:minute|minutes|hour|hours|day|days)\b", text_lower):
        if match not in findings["urgency"]:
            findings["urgency"].append(match)

    for keyword in [
        "bank employee", "bank representative", "bank official", "police officer",
        "government officer", "delivery company", "courier company",
        "claiming to be", "pretending to be", "impersonating", "posing as"
    ]:
        if keyword in text_lower:
            findings["impersonation"].append(keyword)

    return findings


def analyze_url(url):
    """
    Analyze a URL using offline suspiciousness indicators.
    This does not visit the URL.
    """

    import re

    findings = []
    score = 0

    url_lower = url.lower()

    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    if not url_lower.startswith("https://"):
        findings.append("URL does not use HTTPS")
        score += 15

    # -----------------------------------------------------
    # IP ADDRESS IN URL
    # -----------------------------------------------------

    if re.search(
        r'https?://(?:\d{1,3}\.){3}\d{1,3}',
        url_lower
    ):
        findings.append("URL contains an IP address")
        score += 25

    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "kyc",
        "payment",
        "refund",
        "otp",
        "bank",
        "wallet",
        "claim",
        "prize",
        "delivery"
    ]

    matched_words = []

    for word in suspicious_words:
        if word in url_lower:
            matched_words.append(word)

    if matched_words:
        findings.append(
            "Suspicious keywords: " +
            ", ".join(matched_words)
        )
        score += min(len(matched_words) * 5, 25)

    # Compound action/domain wording is more meaningful than a single
    # generic word. Examples: delivery-refund-check, bank-verify-login.
    compound_terms = [
        "refund", "delivery", "verify", "verification", "login", "account",
        "bank", "kyc", "payment", "claim", "confirm", "secure", "check"
    ]
    compound_matches = [word for word in compound_terms if word in url_lower]
    if len(compound_matches) >= 2:
        findings.append("Multiple account, transaction or verification terms appear in the URL.")
        score += 20

    # -----------------------------------------------------
    # URL LENGTH
    # -----------------------------------------------------

    if len(url) > 100:
        findings.append("Unusually long URL")
        score += 10

    # -----------------------------------------------------
    # @ SYMBOL
    # -----------------------------------------------------

    if "@" in url:
        findings.append("URL contains @ symbol")
        score += 20

    # -----------------------------------------------------
    # MANY SUBDOMAINS
    # -----------------------------------------------------

    try:
        domain_part = url_lower.split("//", 1)[-1].split("/", 1)[0]

        if domain_part.count(".") >= 3:
            findings.append("Multiple subdomains detected")
            score += 10

    except Exception:
        pass

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "url": url,
        "score": score,
        "level": level,
        "findings": findings
    }


# =========================================================
# 6. EVIDENCE CORRELATION ENGINE
# =========================================================

def correlate_evidence(findings):
    """
    Correlate extracted evidence to identify
    relationships between digital indicators.
    """

    correlations = []

    urls = findings.get("urls", [])
    emails = findings.get("emails", [])
    phones = findings.get("phone_numbers", [])
    money = findings.get("money_mentions", [])
    sensitive = findings.get("sensitive_requests", [])
    urgency = findings.get("urgency", [])
    impersonation = findings.get("impersonation", [])

    # -----------------------------------------------------
    # PHISHING CORRELATION
    # -----------------------------------------------------

    if urls and sensitive:
        correlations.append(
            "Suspicious URL combined with sensitive-data request"
        )

    # -----------------------------------------------------
    # FINANCIAL FRAUD CORRELATION
    # -----------------------------------------------------

    if money and sensitive:
        correlations.append(
            "Financial request combined with sensitive information"
        )

    # -----------------------------------------------------
    # IMPERSONATION CORRELATION
    # -----------------------------------------------------

    if impersonation and urls:
        correlations.append(
            "Possible impersonation combined with suspicious URL"
        )

    # -----------------------------------------------------
    # URGENCY CORRELATION
    # -----------------------------------------------------

    if urgency and (urls or sensitive):
        correlations.append(
            "Urgency or pressure used to encourage risky action"
        )

    # -----------------------------------------------------
    # MULTI-CHANNEL EVIDENCE
    # -----------------------------------------------------

    if emails and phones:
        correlations.append(
            "Multiple communication identifiers detected"
        )

    return correlations


# =========================================================
# 7. EVIDENCE SEVERITY ENGINE
# =========================================================

def calculate_evidence_severity(findings, correlations):
    """
    Calculate severity specifically for uploaded evidence.
    """

    score = 0

    if findings.get("urls"):
        score += 20

    if findings.get("emails"):
        score += 5

    if findings.get("phone_numbers"):
        score += 5

    if findings.get("money_mentions"):
        score += 15

    if findings.get("sensitive_requests"):
        score += 25

    if findings.get("urgency"):
        score += 10

    if findings.get("impersonation"):
        score += 10

    score += min(len(correlations) * 5, 20)

    score = min(score, 100)

    if score >= 76:
        level = "CRITICAL"
    elif score >= 51:
        level = "HIGH"
    elif score >= 26:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level
    }


# =========================================================
# 8. COMPLETE EVIDENCE ANALYSIS
# =========================================================

def analyze_evidence(text):
    """
    Complete evidence investigation pipeline.

    Evidence
       ↓
    Extraction
       ↓
    URL analysis
       ↓
    Correlation
       ↓
    Evidence severity
    """

    # Extract indicators using existing function
    findings = extract_evidence(text)

    # Analyze every detected URL
    url_analysis = []

    for url in findings.get("urls", []):

        url_result = analyze_url(url)

        url_analysis.append(url_result)

    # Correlate extracted evidence
    correlations = correlate_evidence(
        findings
    )

    # Calculate evidence severity
    severity = calculate_evidence_severity(
        findings,
        correlations
    )

    return {
        "findings": findings,
        "url_analysis": url_analysis,
        "correlations": correlations,
        "severity": severity
    }