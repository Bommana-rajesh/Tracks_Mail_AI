# ============================================================
# TRACEMAIL AI - THREAT SCORING ENGINE
# ============================================================

import re


# ============================================================
# SCORE LIMITS
# ============================================================

MAX_SCORE = 100


# ============================================================
# SCORE CLAMPING
# ============================================================

def clamp_score(score):
    """
    Keep the final score between 0 and 100.
    """

    return max(
        0,
        min(MAX_SCORE, round(score))
    )


# ============================================================
# SEVERITY
# ============================================================

def get_severity(score):
    """
    Convert numerical score into a threat severity.
    """

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


# ============================================================
# AUTHENTICATION SCORE
# ============================================================

def score_authentication(authentication):
    """
    Score SPF, DKIM and DMARC evidence.

    Authentication results are treated as evidence from the
    email headers. They are not independently verified here.
    """

    score = 0
    reasons = []

    spf = authentication.get(
        "spf",
        "unknown"
    )

    dkim = authentication.get(
        "dkim",
        "unknown"
    )

    dmarc = authentication.get(
        "dmarc",
        "unknown"
    )

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if spf == "fail":

        score += 20

        reasons.append({
            "category": "Authentication",
            "signal": "SPF failure",
            "points": 20,
            "explanation": (
                "The reported SPF result is fail."
            )
        })

    elif spf == "softfail":

        score += 10

        reasons.append({
            "category": "Authentication",
            "signal": "SPF softfail",
            "points": 10,
            "explanation": (
                "The reported SPF result is softfail."
            )
        })

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if dkim == "fail":

        score += 20

        reasons.append({
            "category": "Authentication",
            "signal": "DKIM failure",
            "points": 20,
            "explanation": (
                "The reported DKIM result is fail."
            )
        })

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if dmarc == "fail":

        score += 25

        reasons.append({
            "category": "Authentication",
            "signal": "DMARC failure",
            "points": 25,
            "explanation": (
                "The reported DMARC result is fail."
            )
        })

    # --------------------------------------------------------
    # Multiple failures
    # --------------------------------------------------------

    failures = 0

    if spf in ["fail", "softfail"]:
        failures += 1

    if dkim == "fail":
        failures += 1

    if dmarc == "fail":
        failures += 1

    if failures >= 2:

        score += 10

        reasons.append({
            "category": "Correlation",
            "signal": "Multiple authentication failures",
            "points": 10,
            "explanation": (
                "More than one authentication mechanism "
                "reported a failure."
            )
        })

    return score, reasons


# ============================================================
# IDENTITY ANALYSIS
# ============================================================

def extract_email_address(value):
    """
    Extract an email address from a header value.
    """

    if not value:
        return ""

    match = re.search(
        r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',
        value
    )

    if match:
        return match.group(0).lower()

    return ""


def get_email_domain(value):
    """
    Extract domain from an email address/header.
    """

    email = extract_email_address(
        value
    )

    if "@" not in email:
        return ""

    return email.split(
        "@",
        1
    )[1].lower()


def score_identity(email_data):
    """
    Look for identity inconsistencies.

    Examples:
    From domain != Reply-To domain
    From domain != Return-Path domain
    """

    score = 0
    reasons = []

    sender = email_data.get(
        "sender",
        ""
    )

    reply_to = email_data.get(
        "reply_to",
        ""
    )

    return_path = email_data.get(
        "return_path",
        ""
    )

    sender_domain = get_email_domain(
        sender
    )

    reply_domain = get_email_domain(
        reply_to
    )

    return_domain = get_email_domain(
        return_path
    )

    # --------------------------------------------------------
    # From vs Reply-To
    # --------------------------------------------------------

    if (
        sender_domain
        and reply_domain
        and sender_domain != reply_domain
    ):

        score += 20

        reasons.append({
            "category": "Identity",
            "signal": "From / Reply-To mismatch",
            "points": 20,
            "explanation": (
                f"From domain '{sender_domain}' differs "
                f"from Reply-To domain '{reply_domain}'."
            )
        })

    # --------------------------------------------------------
    # From vs Return-Path
    # --------------------------------------------------------

    if (
        sender_domain
        and return_domain
        and sender_domain != return_domain
    ):

        score += 15

        reasons.append({
            "category": "Identity",
            "signal": "From / Return-Path mismatch",
            "points": 15,
            "explanation": (
                f"From domain '{sender_domain}' differs "
                f"from Return-Path domain '{return_domain}'."
            )
        })

    return score, reasons


# ============================================================
# URL ANALYSIS
# ============================================================

SUSPICIOUS_URL_WORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "account",
    "password",
    "confirm",
    "authenticate",
    "wallet",
    "payment",
    "invoice"
]


def score_urls(urls):
    """
    Analyze URLs for basic suspicious indicators.

    This is a heuristic signal, not proof that a URL is malicious.
    """

    score = 0
    reasons = []

    if not urls:
        return score, reasons

    # --------------------------------------------------------
    # URL presence
    # --------------------------------------------------------

    score += min(
        len(urls) * 5,
        15
    )

    reasons.append({
        "category": "URL",
        "signal": f"{len(urls)} URL(s) detected",
        "points": min(len(urls) * 5, 15),
        "explanation": (
            "The email contains external URLs."
        )
    })

    # --------------------------------------------------------
    # Suspicious URL keywords
    # --------------------------------------------------------

    suspicious_matches = []

    for url in urls:

        lower_url = url.lower()

        for word in SUSPICIOUS_URL_WORDS:

            if word in lower_url:

                if word not in suspicious_matches:
                    suspicious_matches.append(word)

    if suspicious_matches:

        points = min(
            len(suspicious_matches) * 5,
            15
        )

        score += points

        reasons.append({
            "category": "URL",
            "signal": "Suspicious URL keywords",
            "points": points,
            "explanation": (
                "URL(s) contain indicators such as: "
                + ", ".join(suspicious_matches)
            )
        })

    return score, reasons


# ============================================================
# CONTENT ANALYSIS
# ============================================================

SUSPICIOUS_CONTENT_PATTERNS = [

    r"\burgent\b",

    r"\bimmediately\b",

    r"\bverify your account\b",

    r"\baccount.{0,30}suspended\b",

    r"\baccount.{0,30}blocked\b",

    r"\bpassword\b",

    r"\botp\b",

    r"\bclick.{0,20}link\b",

    r"\bwithin\s+\d+\s+(hours?|days?)\b",

    r"\bpermanently suspended\b",

    r"\bconfirm your identity\b"
]


def score_content(body_text, subject=""):
    """
    Detect basic social-engineering language.
    """

    score = 0
    reasons = []

    combined_text = (
        (subject or "")
        + "\n"
        + (body_text or "")
    ).lower()

    matched_patterns = []

    for pattern in SUSPICIOUS_CONTENT_PATTERNS:

        if re.search(
            pattern,
            combined_text,
            flags=re.IGNORECASE
        ):

            matched_patterns.append(
                pattern
            )

    if matched_patterns:

        points = min(
            len(matched_patterns) * 4,
            20
        )

        score += points

        reasons.append({
            "category": "Content",
            "signal": "Social-engineering indicators",
            "points": points,
            "explanation": (
                f"{len(matched_patterns)} suspicious "
                "language pattern(s) detected."
            )
        })

    return score, reasons


# ============================================================
# INFRASTRUCTURE ANALYSIS
# ============================================================

def score_infrastructure(ip_locations):
    """
    Add a small evidence contribution based on infrastructure
    characteristics.

    Known providers are NOT automatically considered malicious.
    """

    score = 0
    reasons = []

    if not ip_locations:
        return score, reasons

    known_provider_count = 0

    for item in ip_locations:

        provider = item.get(
            "provider",
            "Unknown"
        )

        if provider != "Unknown":
            known_provider_count += 1

    if known_provider_count:

        reasons.append({
            "category": "Infrastructure",
            "signal": "Known cloud/mail infrastructure",
            "points": 0,
            "explanation": (
                f"{known_provider_count} IP(s) were "
                "associated with a recognized infrastructure "
                "provider. This is contextual evidence, "
                "not a maliciousness verdict."
            )
        })

    return score, reasons


# ============================================================
# CORRELATION SCORE
# ============================================================

def score_correlations(correlation_result):
    """
    Score evidence correlations produced by correlation.py.
    """

    score = 0
    reasons = []

    if not correlation_result:
        return score, reasons

    correlations = correlation_result.get(
        "correlations",
        []
    )

    for correlation in correlations:

        correlation_type = correlation.get(
            "type",
            ""
        )

        if correlation_type == (
            "MULTIPLE_AUTHENTICATION_FAILURES"
        ):

            score += 10

            reasons.append({
                "category": "Correlation",
                "signal": "Multiple authentication failures",
                "points": 10,
                "explanation": (
                    "Authentication failures are "
                    "correlated as a combined signal."
                )
            })

        elif correlation_type == (
            "AUTHENTICATION_PLUS_URL"
        ):

            score += 10

            reasons.append({
                "category": "Correlation",
                "signal": "Authentication failure + URL",
                "points": 10,
                "explanation": (
                    "Authentication evidence and URL "
                    "evidence occur together."
                )
            })

        elif correlation_type == (
            "MULTIPLE_THREAT_SIGNALS"
        ):

            score += 10

            reasons.append({
                "category": "Correlation",
                "signal": "Multiple threat signals",
                "points": 10,
                "explanation": (
                    "Several independent threat signals "
                    "were detected."
                )
            })

    return score, reasons


# ============================================================
# MAIN SCORING FUNCTION
# ============================================================

def calculate_threat_score(
    email_data,
    authentication=None,
    correlation_result=None,
    ip_locations=None
):
    """
    Calculate the final TraceMail threat score.

    Returns:
        score
        severity
        reasons
        breakdown
    """

    authentication = authentication or {}
    ip_locations = ip_locations or []

    total_score = 0

    all_reasons = []

    breakdown = {
        "authentication": 0,
        "identity": 0,
        "urls": 0,
        "content": 0,
        "infrastructure": 0,
        "correlation": 0
    }

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    score, reasons = score_authentication(
        authentication
    )

    breakdown["authentication"] = score

    total_score += score

    all_reasons.extend(
        reasons
    )

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    score, reasons = score_identity(
        email_data
    )

    breakdown["identity"] = score

    total_score += score

    all_reasons.extend(
        reasons
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    score, reasons = score_urls(
        email_data.get(
            "urls",
            []
        )
    )

    breakdown["urls"] = score

    total_score += score

    all_reasons.extend(
        reasons
    )

    # --------------------------------------------------------
    # Content
    # --------------------------------------------------------

    score, reasons = score_content(
        email_data.get(
            "body_text",
            ""
        ),
        email_data.get(
            "subject",
            ""
        )
    )

    breakdown["content"] = score

    total_score += score

    all_reasons.extend(
        reasons
    )

    # --------------------------------------------------------
    # Infrastructure
    # --------------------------------------------------------

    score, reasons = score_infrastructure(
        ip_locations
    )

    breakdown["infrastructure"] = score

    total_score += score

    all_reasons.extend(
        reasons
    )

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    score, reasons = score_correlations(
        correlation_result
    )

    breakdown["correlation"] = score

    total_score += score

    all_reasons.extend(
        reasons
    )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    final_score = clamp_score(
        total_score
    )

    severity = get_severity(
        final_score
    )

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return {

        "score": final_score,

        "severity": severity,

        "reasons": all_reasons,

        "breakdown": breakdown,

        "signal_count": len(
            all_reasons
        )
    }