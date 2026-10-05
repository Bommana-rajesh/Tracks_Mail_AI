import re


# ============================================================
# TraceMail AI - Explainable Evidence Classification Engine
# ============================================================

CATEGORIES = [
    "Phishing",
    "Credential Theft",
    "Business Email Compromise",
    "Malware / Suspicious",
    "Spam",
    "Legitimate",
]


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize(text):
    if not text:
        return ""

    return re.sub(r"\s+", " ", str(text)).strip().lower()


def extract_domain(value):
    if not value:
        return ""

    value = str(value).strip().lower()

    if "@" in value and "://" not in value:
        return value.split("@")[-1].strip(" >")

    match = re.search(
        r"(?:https?://)?(?:www\.)?([^/\s>]+)",
        value
    )

    return match.group(1).lower() if match else ""


def add_score(scores, category, points):
    if category in scores:
        scores[category] += points


def calculate_normalized_scores(scores):
    """
    Converts evidence scores into relative percentages.

    These are NOT probabilities.
    """

    total = sum(max(0, value) for value in scores.values())

    if total <= 0:
        return {
            category: 0.0
            for category in scores
        }

    return {
        category: round(
            (max(0, value) / total) * 100,
            1
        )
        for category, value in scores.items()
    }


# ============================================================
# EMAIL DATA HELPERS
# ============================================================

def _get_body(email_data):
    return str(
        email_data.get("body")
        or email_data.get("text")
        or email_data.get("body_text")
        or email_data.get("content")
        or ""
    )


def _get_subject(email_data):
    return str(
        email_data.get("subject")
        or ""
    )


def _get_urls(email_data):
    urls = email_data.get("urls", [])

    if isinstance(urls, str):
        return [urls]

    if isinstance(urls, list):
        return urls

    return []


def _get_domains(email_data):
    domains = email_data.get("domains", [])

    if isinstance(domains, str):
        return [domains]

    if isinstance(domains, list):
        return domains

    return []


def _get_authentication(email_data):
    return (
        email_data.get("authentication_results")
        or email_data.get("authentication")
        or email_data.get("auth")
        or {}
    )


def _authentication_text(authentication):
    if isinstance(authentication, dict):
        return normalize(str(authentication))

    if isinstance(authentication, list):
        return normalize(
            " ".join(str(x) for x in authentication)
        )

    return normalize(authentication)


def _get_sender(email_data):
    return str(
        email_data.get("from")
        or email_data.get("sender")
        or email_data.get("from_address")
        or ""
    )


def _get_reply_to(email_data):
    return str(
        email_data.get("reply_to")
        or email_data.get("reply-to")
        or ""
    )


def _get_return_path(email_data):
    return str(
        email_data.get("return_path")
        or email_data.get("return-path")
        or ""
    )


# ============================================================
# STRONG CREDENTIAL THEFT DETECTION
# ============================================================

def strong_credential_patterns(text):

    patterns = [
        r"\benter\s+(your\s+)?password\b",
        r"\bprovide\s+(your\s+)?password\b",
        r"\bsubmit\s+(your\s+)?password\b",
        r"\bconfirm\s+(your\s+)?password\b",

        r"\benter\s+(your\s+)?otp\b",
        r"\bprovide\s+(your\s+)?otp\b",
        r"\bsubmit\s+(your\s+)?otp\b",

        r"\benter\s+(your\s+)?credentials\b",
        r"\bprovide\s+(your\s+)?credentials\b",
        r"\bsubmit\s+(your\s+)?credentials\b",

        r"\benter\s+(your\s+)?username\s+and\s+password\b",

        r"\benter\s+(your\s+)?login\s+details\b",
        r"\bprovide\s+(your\s+)?login\s+details\b",

        r"\bverify\s+(your\s+)?identity\s+by\s+entering\b",
        r"\bverify\s+(your\s+)?account\s+by\s+entering\b",

        r"\bclick\s+.*\bto\s+(enter|provide|submit)\b.*\b(password|credentials|otp)\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)

    return matches


# ============================================================
# CLASSIFIER
# ============================================================

def classify_email(
    email_data=None,
    correlation=None,
    correlation_result=None
):

    email_data = email_data or {}

    if correlation_result is None:
        correlation_result = correlation or {}

    # --------------------------------------------------------
    # Gather information
    # --------------------------------------------------------

    subject = _get_subject(email_data)
    body = _get_body(email_data)

    urls = _get_urls(email_data)
    domains = _get_domains(email_data)

    sender = _get_sender(email_data)
    reply_to = _get_reply_to(email_data)
    return_path = _get_return_path(email_data)

    authentication = _get_authentication(email_data)

    auth_text = _authentication_text(
        authentication
    )

    full_text = normalize(
        subject + " " + body
    )

    # --------------------------------------------------------
    # Scores
    # --------------------------------------------------------

    scores = {
        "Phishing": 0,
        "Credential Theft": 0,
        "Business Email Compromise": 0,
        "Malware / Suspicious": 0,
        "Spam": 0,
        "Legitimate": 0,
    }

    indicators = []
    evidence_groups = []

    # ========================================================
    # 1. LEGITIMATE CONTEXT
    # ========================================================

    legitimate_patterns = [
        r"\bcourse\s+schedule\b",
        r"\bclass\s+schedule\b",
        r"\btimetable\b",
        r"\bacademic\s+office\b",
        r"\buniversity\b",
        r"\bcollege\b",
        r"\bsemester\b",
        r"\bcourse\b",
        r"\blecture\b",
        r"\bdepartment\b",
        r"\bstudent\b",
        r"\bprofessor\b",
        r"\bfaculty\b",
        r"\bacademic\b",
        r"\bmeeting\s+schedule\b",
        r"\bappointment\s+schedule\b",
    ]

    legitimate_matches = []

    for pattern in legitimate_patterns:

        if re.search(
            pattern,
            full_text,
            re.IGNORECASE
        ):
            legitimate_matches.append(pattern)

    if legitimate_matches:

        add_score(
            scores,
            "Legitimate",
            min(
                len(legitimate_matches) * 5,
                30
            )
        )

        evidence_groups.append(
            "legitimate_context"
        )

        indicators.append(
            "Normal organizational or informational email context detected."
        )

    # ========================================================
    # 2. CREDENTIAL THEFT
    # ========================================================

    credential_matches = strong_credential_patterns(
        full_text
    )

    if credential_matches:

        credential_score = 35

        if len(credential_matches) >= 2:
            credential_score += 20

        if len(credential_matches) >= 3:
            credential_score += 15

        add_score(
            scores,
            "Credential Theft",
            credential_score
        )

        evidence_groups.append(
            "credential_request"
        )

        indicators.append(
            "Direct request for password, OTP, credentials, "
            "or sensitive authentication information detected."
        )

    # ========================================================
    # 3. PHISHING LANGUAGE
    # ========================================================

    # IMPORTANT:
    # These are intentionally strong patterns.
    # Generic words like "login", "account", "verify"
    # do NOT count as phishing by themselves.

    strong_phishing_patterns = [

        r"\baccount\s+(has\s+been|will\s+be)\s+suspended\b",

        r"\baccount\s+(has\s+been|will\s+be)\s+closed\b",

        r"\baccount\s+(has\s+been|will\s+be)\s+locked\b",

        r"\bunauthorized\s+activity\s+(was|has\s+been)\s+detected\b",

        r"\bsuspicious\s+activity\s+(was|has\s+been)\s+detected\b",

        r"\bverify\s+your\s+account\s+immediately\b",

        r"\bconfirm\s+your\s+account\s+immediately\b",

        r"\bimmediate\s+action\s+required\b",

        r"\bfinal\s+warning\b",

        r"\bsecurity\s+alert\b.*\bverify\b",

        r"\bclick\s+(here|the\s+link)\b.*\bverify\b",

        r"\bclick\s+(here|the\s+link)\b.*\baccount\b",

        r"\byour\s+account\s+will\s+be\s+suspended\b",

        r"\bfailure\s+to\s+verify\b.*\bsuspend",

        r"\bwithin\s+\d+\s+hours?\b.*\bverify\b",
    ]

    phishing_matches = []

    for pattern in strong_phishing_patterns:

        if re.search(
            pattern,
            full_text,
            re.IGNORECASE
        ):
            phishing_matches.append(pattern)

    if phishing_matches:

        phishing_score = 30

        if len(phishing_matches) >= 2:
            phishing_score += 20

        if len(phishing_matches) >= 3:
            phishing_score += 15

        add_score(
            scores,
            "Phishing",
            phishing_score
        )

        evidence_groups.append(
            "strong_phishing_language"
        )

        indicators.append(
            "Strong phishing/social-engineering language detected."
        )

    # ========================================================
    # 4. SUSPICIOUS URLS
    # ========================================================

    suspicious_url_count = 0

    suspicious_url_words = [
        "login",
        "verify",
        "password",
        "credential",
        "confirm",
        "account-security",
        "secure-update",
        "account-verification",
    ]

    for url in urls:

        url_text = normalize(url)

        if any(
            word in url_text
            for word in suspicious_url_words
        ):
            suspicious_url_count += 1

    # IMPORTANT:
    # A suspicious URL alone gives only supporting evidence.
    # It cannot make a clean email phishing by itself.

    if suspicious_url_count:

        add_score(
            scores,
            "Phishing",
            min(
                suspicious_url_count * 8,
                24
            )
        )

        evidence_groups.append(
            "suspicious_urls"
        )

        indicators.append(
            f"{suspicious_url_count} suspicious URL(s) detected."
        )

    # ========================================================
    # 5. SENDER / REPLY-TO / RETURN-PATH
    # ========================================================

    sender_domain = extract_domain(sender)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    identity_mismatch = False

    if sender_domain and reply_domain:

        if sender_domain != reply_domain:

            identity_mismatch = True

            add_score(
                scores,
                "Phishing",
                15
            )

            evidence_groups.append(
                "reply_to_mismatch"
            )

            indicators.append(
                "Sender and Reply-To domains do not match."
            )

    if sender_domain and return_domain:

        if sender_domain != return_domain:

            identity_mismatch = True

            add_score(
                scores,
                "Phishing",
                10
            )

            evidence_groups.append(
                "return_path_mismatch"
            )

            indicators.append(
                "Sender and Return-Path domains do not match."
            )

    # ========================================================
    # 6. AUTHENTICATION
    # ========================================================

    auth_failures = []

    if re.search(
        r"\bspf\s*=\s*fail\b",
        auth_text
    ):
        auth_failures.append("SPF")

    if re.search(
        r"\bdkim\s*=\s*fail\b",
        auth_text
    ):
        auth_failures.append("DKIM")

    if re.search(
        r"\bdmarc\s*=\s*fail\b",
        auth_text
    ):
        auth_failures.append("DMARC")

    auth_passes = []

    if re.search(
        r"\bspf\s*=\s*pass\b",
        auth_text
    ):
        auth_passes.append("SPF")

    if re.search(
        r"\bdkim\s*=\s*pass\b",
        auth_text
    ):
        auth_passes.append("DKIM")

    if re.search(
        r"\bdmarc\s*=\s*pass\b",
        auth_text
    ):
        auth_passes.append("DMARC")

    # Authentication failures are ONLY supporting evidence.
    # They do NOT automatically mean phishing.

    if auth_failures:

        add_score(
            scores,
            "Phishing",
            min(
                len(auth_failures) * 5,
                15
            )
        )

        evidence_groups.append(
            "authentication_failure"
        )

        indicators.append(
            "Authentication failure(s): "
            + ", ".join(auth_failures)
        )

    if auth_passes:

        add_score(
            scores,
            "Legitimate",
            min(
                len(auth_passes) * 6,
                18
            )
        )

        evidence_groups.append(
            "authentication_pass"
        )

        indicators.append(
            "Authentication pass result(s): "
            + ", ".join(auth_passes)
        )

    # ========================================================
    # 7. URGENCY
    # ========================================================

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\blast\s+warning\b",
        r"\bfinal\s+warning\b",
        r"\baction\s+required\b",
        r"\bwithin\s+\d+\s+hours?\b",
        r"\bwithin\s+\d+\s+minutes?\b",
    ]

    urgency_count = 0

    for pattern in urgency_patterns:

        if re.search(
            pattern,
            full_text,
            re.IGNORECASE
        ):
            urgency_count += 1

    # Urgency alone is NOT enough for phishing.
    # It becomes meaningful when combined with another
    # suspicious signal.

    if urgency_count:

        evidence_groups.append(
            "urgency"
        )

        indicators.append(
            "Urgency or pressure-based language detected."
        )

        if (
            phishing_matches
            or credential_matches
            or suspicious_url_count
            or identity_mismatch
        ):

            add_score(
                scores,
                "Phishing",
                min(
                    urgency_count * 5,
                    15
                )
            )

    # ========================================================
    # 8. MALWARE / SUSPICIOUS
    # ========================================================

    malware_patterns = [
        r"\bmalware\b",
        r"\bransomware\b",
        r"\btrojan\b",
        r"\bpayload\b",
        r"\bexecutable\b",
        r"\bmacro\b",
        r"\b\.exe\b",
        r"\b\.scr\b",
        r"\b\.bat\b",
        r"\b\.cmd\b",
        r"\bpassword[- ]protected\s+attachment\b",
        r"\benable\s+macros\b",
        r"\bsecurity\s+update\s+package\b",
    ]

    malware_matches = []

    for pattern in malware_patterns:

        if re.search(
            pattern,
            full_text,
            re.IGNORECASE
        ):
            malware_matches.append(pattern)

    if malware_matches:

        add_score(
            scores,
            "Malware / Suspicious",
            min(
                30 + len(malware_matches) * 7,
                65
            )
        )

        evidence_groups.append(
            "malware_indicators"
        )

        indicators.append(
            "Suspicious attachment, executable, "
            "macro, or malware-related indicators detected."
        )

    # ========================================================
    # 9. BEC
    # ========================================================

    bec_patterns = [
        r"\bwire\s+transfer\b",
        r"\bbank\s+transfer\b",
        r"\btransfer\s+funds\b",
        r"\bsend\s+(the\s+)?payment\b",
        r"\bchange\s+(the\s+)?bank\s+account\b",
        r"\bnew\s+bank\s+details\b",
        r"\bpay\s+this\s+invoice\b",
        r"\bconfidential\s+payment\b",
        r"\bgift\s+cards?\b",
    ]

    bec_matches = []

    for pattern in bec_patterns:

        if re.search(
            pattern,
            full_text,
            re.IGNORECASE
        ):
            bec_matches.append(pattern)

    if bec_matches:

        add_score(
            scores,
            "Business Email Compromise",
            min(
                30 + len(bec_matches) * 10,
                65
            )
        )

        evidence_groups.append(
            "bec_indicators"
        )

        indicators.append(
            "Business/payment manipulation pattern detected."
        )

    # ========================================================
    # 10. SPAM
    # ========================================================

    spam_patterns = [
        r"\bfree\s+offer\b",
        r"\bcongratulations\b",
        r"\byou\s+have\s+won\b",
        r"\bclaim\s+your\s+prize\b",
        r"\blimited\s+time\s+offer\b",
        r"\bmake\s+money\s+fast\b",
        r"\blottery\b",
        r"\bcasino\b",
    ]

    spam_matches = []

    for pattern in spam_patterns:

        if re.search(
            pattern,
            full_text,
            re.IGNORECASE
        ):
            spam_matches.append(pattern)

    if spam_matches:

        add_score(
            scores,
            "Spam",
            min(
                len(spam_matches) * 12,
                45
            )
        )

        evidence_groups.append(
            "spam_indicators"
        )

        indicators.append(
            "Spam/promotional patterns detected."
        )

    # ========================================================
    # 11. CORRELATION SIGNALS
    # ========================================================

    correlation_text = normalize(
        str(correlation_result)
    )

    # Only use correlation when an actual suspicious
    # relationship exists.

    if (
        "multiple_auth_failures" in correlation_text
        or "multiple authentication failures"
        in correlation_text
    ):

        add_score(
            scores,
            "Phishing",
            8
        )

        evidence_groups.append(
            "auth_correlation"
        )

        indicators.append(
            "Multiple authentication failures correlate."
        )

    if (
        "identity_url_correlation"
        in correlation_text
    ):

        add_score(
            scores,
            "Phishing",
            10
        )

        evidence_groups.append(
            "identity_url_correlation"
        )

        indicators.append(
            "Identity and URL evidence correlate."
        )

    if (
        "auth_identity_correlation"
        in correlation_text
    ):

        add_score(
            scores,
            "Phishing",
            8
        )

        evidence_groups.append(
            "auth_identity_correlation"
        )

        indicators.append(
            "Authentication and identity evidence correlate."
        )

    # ========================================================
    # 12. CLEAN LEGITIMATE EMAIL BOOST
    # ========================================================

    suspicious_evidence = (
        len(credential_matches)
        + len(phishing_matches)
        + len(malware_matches)
        + len(bec_matches)
        + len(spam_matches)
        + suspicious_url_count
        + len(auth_failures)
        + int(identity_mismatch)
    )

    # If the email has legitimate context and no suspicious
    # evidence, strongly favor Legitimate.

    if (
        legitimate_matches
        and suspicious_evidence == 0
        and not urls
    ):

        add_score(
            scores,
            "Legitimate",
            60
        )

        evidence_groups.append(
            "clean_legitimate_email"
        )

        indicators.append(
            "No significant threat indicators detected."
        )

    # Even without special legitimate keywords, an email with
    # no threat evidence should NOT automatically become phishing.

    if suspicious_evidence == 0:

        add_score(
            scores,
            "Legitimate",
            25
        )

    # ========================================================
    # 13. NORMALIZE
    # ========================================================

    normalized_scores = calculate_normalized_scores(
        scores
    )

    # ========================================================
    # 14. CLASSIFICATION SAFETY OVERRIDE
    # ========================================================

    # This is the important regression fix.
    #
    # Phishing must NOT win merely because it has a small
    # amount of supporting evidence.

    strongest_threat_evidence = (
        len(phishing_matches)
        + len(credential_matches)
        + len(malware_matches)
        + len(bec_matches)
    )

    # If there is no strong threat evidence and no suspicious
    # identity/URL/authentication evidence, classify as
    # Legitimate rather than Phishing.

    if strongest_threat_evidence == 0:

        if (
            suspicious_url_count == 0
            and not identity_mismatch
            and not auth_failures
            and not spam_matches
        ):

            category = "Legitimate"

        elif legitimate_matches and not malware_matches:

            category = "Legitimate"

        else:

            category = max(
                normalized_scores,
                key=normalized_scores.get
            )

    else:

        category = max(
            normalized_scores,
            key=normalized_scores.get
        )

    # ========================================================
    # 15. CONFIDENCE
    # ========================================================

    sorted_values = sorted(
        normalized_scores.values(),
        reverse=True
    )

    top_score = (
        sorted_values[0]
        if sorted_values
        else 0
    )

    second_score = (
        sorted_values[1]
        if len(sorted_values) > 1
        else 0
    )

    confidence = top_score

    separation = (
        top_score - second_score
    )

    if separation >= 40:
        confidence += 5

    elif separation >= 25:
        confidence += 3

    confidence = round(
        min(max(confidence, 0), 99),
        1
    )

    # ========================================================
    # 16. EXPLANATION
    # ========================================================

    explanations = {

        "Legitimate":
            "The email contains normal informational or organizational "
            "characteristics without strong threat evidence.",

        "Phishing":
            "The email contains strong phishing indicators such as "
            "social-engineering language, suspicious identity relationships, "
            "authentication anomalies, or suspicious URLs.",

        "Credential Theft":
            "The email contains direct evidence of attempts to collect "
            "passwords, OTPs, credentials, or other authentication secrets.",

        "Malware / Suspicious":
            "The email contains suspicious executable, attachment, macro, "
            "or malware-related indicators.",

        "Business Email Compromise":
            "The email contains financial, payment, invoice, or business "
            "impersonation indicators.",

        "Spam":
            "The email contains multiple unsolicited promotional or "
            "spam-like indicators.",
    }

    explanation = explanations.get(
        category,
        "The available evidence does not provide a strong classification."
    )

    # ========================================================
    # 17. CLEAN OUTPUT
    # ========================================================

    unique_indicators = []

    for item in indicators:

        if item not in unique_indicators:
            unique_indicators.append(item)

    unique_groups = []

    for item in evidence_groups:

        if item not in unique_groups:
            unique_groups.append(item)

    # Convert indicator strings into objects expected by the dashboard.
    indicator_objects = []

    for item in unique_indicators:
        item_text = str(item)
        low = item_text.lower()

        indicator_type = "THREAT SIGNAL"

        if "password" in low or "otp" in low or "credentials" in low:
            indicator_type = "CREDENTIAL THEFT"
        elif "phishing/social-engineering" in low:
            indicator_type = "PHISHING LANGUAGE"
        elif "suspicious url" in low:
            indicator_type = "SUSPICIOUS URL"
        elif "reply-to" in low or "return-path" in low:
            indicator_type = "IDENTITY MISMATCH"
        elif "authentication failure" in low:
            indicator_type = "AUTHENTICATION ANOMALY"
        elif "authentication pass" in low:
            indicator_type = "AUTHENTICATION"
        elif "urgency" in low or "pressure-based" in low:
            indicator_type = "SOCIAL ENGINEERING"
        elif (
            "attachment" in low
            or "executable" in low
            or "macro" in low
            or "malware" in low
        ):
            indicator_type = "MALWARE / SUSPICIOUS"
        elif "business/payment" in low:
            indicator_type = "BUSINESS EMAIL COMPROMISE"
        elif "spam/promotional" in low:
            indicator_type = "SPAM"
        elif "correlate" in low or "correlates" in low:
            indicator_type = "EVIDENCE CORRELATION"
        elif "normal organizational" in low or "no significant threat" in low:
            indicator_type = "LEGITIMATE CONTEXT"

        indicator = {
            "type": indicator_type,
            "description": item_text
        }

        if indicator_type == "SUSPICIOUS URL" and urls:
            indicator["urls"] = list(urls)

        if indicator_type == "AUTHENTICATION ANOMALY" and auth_failures:
            indicator["matches"] = list(auth_failures)

        if indicator_type == "AUTHENTICATION" and auth_passes:
            indicator["matches"] = list(auth_passes)

        indicator_objects.append(indicator)

    return {
        "category": category,
        "confidence": confidence,
        "explanation": explanation,

        "indicators": indicator_objects,


        "raw_scores": scores.copy(),

        "normalized_scores": normalized_scores,

        "class_scores": scores.copy(),

        "evidence_groups": len(
            unique_groups
        ),

        "correlation_signals": [],

        "indicator_count": len(
            indicator_objects
        ),
    }