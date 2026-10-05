import re


def normalize(value):
    if value is None:
        return ""

    return str(value).strip().lower()


def create_evidence(
    evidence_type,
    value,
    source,
    severity,
    reliability,
    explanation
):
    return {
        "type": evidence_type,
        "value": value,
        "source": source,
        "severity": severity,
        "reliability": reliability,
        "explanation": explanation
    }


# ============================================================
# AUTHENTICATION CORRELATION
# ============================================================

def correlate_authentication(authentication):

    evidence = []

    if not isinstance(authentication, dict):
        return evidence

    spf = normalize(authentication.get("spf"))
    dkim = normalize(authentication.get("dkim"))
    dmarc = normalize(authentication.get("dmarc"))

    if spf == "fail":
        evidence.append(
            create_evidence(
                "SPF_FAIL",
                "SPF fail",
                "Authentication-Results",
                "high",
                "high",
                "The sending server did not pass SPF authentication."
            )
        )

    elif spf == "pass":
        evidence.append(
            create_evidence(
                "SPF_PASS",
                "SPF pass",
                "Authentication-Results",
                "low",
                "high",
                "SPF authentication passed."
            )
        )

    if dkim == "fail":
        evidence.append(
            create_evidence(
                "DKIM_FAIL",
                "DKIM fail",
                "Authentication-Results",
                "high",
                "high",
                "The message did not pass DKIM authentication."
            )
        )

    elif dkim == "pass":
        evidence.append(
            create_evidence(
                "DKIM_PASS",
                "DKIM pass",
                "Authentication-Results",
                "low",
                "high",
                "DKIM authentication passed."
            )
        )

    if dmarc == "fail":
        evidence.append(
            create_evidence(
                "DMARC_FAIL",
                "DMARC fail",
                "Authentication-Results",
                "high",
                "high",
                "The message did not pass DMARC authentication."
            )
        )

    elif dmarc == "pass":
        evidence.append(
            create_evidence(
                "DMARC_PASS",
                "DMARC pass",
                "Authentication-Results",
                "low",
                "high",
                "DMARC authentication passed."
            )
        )

    return evidence


# ============================================================
# IDENTITY CORRELATION
# ============================================================

def extract_email_domain(value):

    value = str(value or "")

    match = re.search(
        r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})",
        value
    )

    if match:
        return match.group(1).lower()

    return ""


def correlate_identity(sender, reply_to, return_path):

    evidence = []

    sender_domain = extract_email_domain(sender)
    reply_domain = extract_email_domain(reply_to)
    return_domain = extract_email_domain(return_path)

    if sender_domain and reply_domain:

        if sender_domain != reply_domain:

            evidence.append(
                create_evidence(
                    "REPLY_TO_MISMATCH",
                    f"{sender_domain} -> {reply_domain}",
                    "Sender / Reply-To",
                    "high",
                    "high",
                    "The Reply-To domain differs from the sender domain."
                )
            )

    if sender_domain and return_domain:

        if sender_domain != return_domain:

            evidence.append(
                create_evidence(
                    "RETURN_PATH_MISMATCH",
                    f"{sender_domain} -> {return_domain}",
                    "Sender / Return-Path",
                    "medium",
                    "high",
                    "The Return-Path domain differs from the sender domain."
                )
            )

    return evidence


# ============================================================
# URL CORRELATION
# ============================================================

def correlate_urls(urls):

    evidence = []

    if not isinstance(urls, list):
        return evidence

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "update",
        "account",
        "password",
        "confirm",
        "signin",
        "unlock"
    ]

    for url in urls:

        url_text = str(url)
        lower_url = url_text.lower()

        matches = [
            word
            for word in suspicious_words
            if word in lower_url
        ]

        if matches:

            evidence.append(
                create_evidence(
                    "SUSPICIOUS_URL",
                    url_text,
                    "Email body",
                    "medium",
                    "medium",
                    "URL contains security-sensitive keywords: "
                    + ", ".join(matches)
                )
            )

    return evidence


# ============================================================
# DOMAIN CORRELATION
# ============================================================

def correlate_domains(domains):

    evidence = []

    if not isinstance(domains, list):
        return evidence

    suspicious_terms = [
        "login",
        "secure",
        "verify",
        "account",
        "update",
        "payment"
    ]

    for domain in domains:

        domain_text = str(domain).lower()

        if "xn--" in domain_text:

            evidence.append(
                create_evidence(
                    "PUNYCODE_DOMAIN",
                    domain_text,
                    "URL/domain extraction",
                    "medium",
                    "medium",
                    "Domain uses Punycode and may require additional inspection."
                )
            )

        matches = [
            term
            for term in suspicious_terms
            if term in domain_text
        ]

        if matches:

            evidence.append(
                create_evidence(
                    "SUSPICIOUS_DOMAIN",
                    domain_text,
                    "URL/domain extraction",
                    "medium",
                    "low",
                    "Domain contains security-related keywords: "
                    + ", ".join(matches)
                )
            )

    return evidence


# ============================================================
# CONTENT CORRELATION
# ============================================================

def correlate_content(body):

    evidence = []

    body = str(body or "")
    lower_body = body.lower()

    urgency_words = [
        "urgent",
        "immediately",
        "24 hours",
        "suspended",
        "permanently",
        "act now",
        "verify immediately"
    ]

    credential_words = [
        "password",
        "otp",
        "login",
        "credentials",
        "verification code"
    ]

    urgency_matches = [
        word
        for word in urgency_words
        if word in lower_body
    ]

    credential_matches = [
        word
        for word in credential_words
        if word in lower_body
    ]

    if urgency_matches:

        evidence.append(
            create_evidence(
                "URGENCY_LANGUAGE",
                ", ".join(urgency_matches),
                "Email body",
                "medium",
                "medium",
                "The message uses urgency or pressure-based language."
            )
        )

    if credential_matches:

        evidence.append(
            create_evidence(
                "CREDENTIAL_REQUEST",
                ", ".join(credential_matches),
                "Email body",
                "high",
                "medium",
                "The message contains language associated with credential or OTP requests."
            )
        )

    return evidence


# ============================================================
# INFRASTRUCTURE CORRELATION
# ============================================================

def correlate_infrastructure(ips=None, ip_locations=None):

    evidence = []

    ips = ips or []
    ip_locations = ip_locations or []

    for item in ip_locations:

        if not isinstance(item, dict):
            continue

        ip = item.get("ip", "")
        provider = item.get("provider", "")
        organization = item.get("org", "")
        role = item.get("role", "")

        provider_text = normalize(provider)
        organization_text = normalize(organization)
        role_text = normalize(role)

        if (
            "google" in provider_text
            or "google" in organization_text
            or "google" in role_text
        ):

            evidence.append(
                create_evidence(
                    "GOOGLE_INFRASTRUCTURE",
                    ip,
                    organization or "Google infrastructure",
                    "low",
                    "high",
                    "IP appears to belong to Google infrastructure."
                )
            )

        elif (
            "amazon" in provider_text
            or "aws" in provider_text
            or "amazon" in organization_text
            or "aws" in organization_text
        ):

            evidence.append(
                create_evidence(
                    "AWS_INFRASTRUCTURE",
                    ip,
                    organization or "Amazon/AWS infrastructure",
                    "low",
                    "high",
                    "IP appears to belong to Amazon/AWS infrastructure."
                )
            )

        elif (
            "microsoft" in provider_text
            or "azure" in provider_text
            or "microsoft" in organization_text
            or "azure" in organization_text
        ):

            evidence.append(
                create_evidence(
                    "MICROSOFT_INFRASTRUCTURE",
                    ip,
                    organization or "Microsoft infrastructure",
                    "low",
                    "high",
                    "IP appears to belong to Microsoft infrastructure."
                )
            )

        elif (
            "cloudflare" in provider_text
            or "cloudflare" in organization_text
        ):

            evidence.append(
                create_evidence(
                    "CLOUDFLARE_INFRASTRUCTURE",
                    ip,
                    organization or "Cloudflare infrastructure",
                    "low",
                    "high",
                    "IP appears to belong to Cloudflare infrastructure."
                )
            )

        elif (
            "sender" in role_text
            or "relay" in role_text
        ):

            evidence.append(
                create_evidence(
                    "UNKNOWN_RELAY",
                    ip,
                    organization or "Unknown network",
                    "medium",
                    "medium",
                    "IP appears in the routing path but could not be associated with a known major provider."
                )
            )

    return evidence


# ============================================================
# CROSS-EVIDENCE CORRELATION
# ============================================================

def correlate_relationships(evidence):

    relationships = []

    evidence_types = {
        item.get("type")
        for item in evidence
    }

    # --------------------------------------------------------
    # Multiple authentication failures
    # --------------------------------------------------------

    auth_failures = {
        "SPF_FAIL",
        "DKIM_FAIL",
        "DMARC_FAIL"
    }

    failed_auth = evidence_types.intersection(auth_failures)

    if len(failed_auth) >= 2:

        relationships.append(
            create_evidence(
                "MULTIPLE_AUTH_FAILURES",
                ", ".join(sorted(failed_auth)),
                "Authentication correlation",
                "critical",
                "high",
                "Multiple email authentication mechanisms failed simultaneously."
            )
        )

    # --------------------------------------------------------
    # Identity + URL correlation
    # --------------------------------------------------------

    identity_mismatch = (
        "REPLY_TO_MISMATCH" in evidence_types
        or "RETURN_PATH_MISMATCH" in evidence_types
    )

    suspicious_url = (
        "SUSPICIOUS_URL" in evidence_types
        or "SUSPICIOUS_DOMAIN" in evidence_types
    )

    if identity_mismatch and suspicious_url:

        relationships.append(
            create_evidence(
                "IDENTITY_URL_CORRELATION",
                "Identity mismatch + suspicious URL",
                "Cross-evidence correlation",
                "high",
                "high",
                "The message combines sender identity inconsistency with a suspicious URL or domain."
            )
        )

    # --------------------------------------------------------
    # Social engineering correlation
    # --------------------------------------------------------

    urgency = "URGENCY_LANGUAGE" in evidence_types
    credentials = "CREDENTIAL_REQUEST" in evidence_types

    if urgency and credentials:

        relationships.append(
            create_evidence(
                "SOCIAL_ENGINEERING_CORRELATION",
                "Urgency + credential request",
                "Content correlation",
                "high",
                "medium",
                "The message combines pressure-based language with requests associated with credentials or OTPs."
            )
        )

    # --------------------------------------------------------
    # Authentication + identity correlation
    # --------------------------------------------------------

    authentication_failure = bool(
        failed_auth
    )

    if authentication_failure and identity_mismatch:

        relationships.append(
            create_evidence(
                "AUTH_IDENTITY_CORRELATION",
                "Authentication failure + identity mismatch",
                "Cross-evidence correlation",
                "critical",
                "high",
                "Authentication failure occurs together with sender identity inconsistency."
            )
        )

    # --------------------------------------------------------
    # Authentication + suspicious URL correlation
    # --------------------------------------------------------

    if authentication_failure and suspicious_url:

        relationships.append(
            create_evidence(
                "AUTH_URL_CORRELATION",
                "Authentication failure + suspicious URL",
                "Cross-evidence correlation",
                "high",
                "high",
                "Authentication failure occurs together with a suspicious URL or domain."
            )
        )

    return relationships


# ============================================================
# CORRELATION SCORE
# ============================================================

def calculate_correlation_score(evidence):

    score = 0

    severity_weights = {
        "low": 2,
        "medium": 5,
        "high": 10,
        "critical": 15
    }

    for item in evidence:

        severity = normalize(
            item.get("severity")
        )

        reliability = normalize(
            item.get("reliability")
        )

        base = severity_weights.get(
            severity,
            0
        )

        if reliability == "high":
            base = int(base * 1.0)

        elif reliability == "medium":
            base = int(base * 0.7)

        elif reliability == "low":
            base = int(base * 0.4)

        score += base

    return min(score, 100)


# ============================================================
# MAIN CORRELATION ENGINE
# ============================================================

def correlate_evidence(
    authentication,
    sender,
    reply_to,
    return_path,
    urls,
    domains,
    body
):

    evidence = []

    # Authentication
    evidence.extend(
        correlate_authentication(
            authentication
        )
    )

    # Sender identity
    evidence.extend(
        correlate_identity(
            sender,
            reply_to,
            return_path
        )
    )

    # URLs
    evidence.extend(
        correlate_urls(
            urls
        )
    )

    # Domains
    evidence.extend(
        correlate_domains(
            domains
        )
    )

    # Email body
    evidence.extend(
        correlate_content(
            body
        )
    )

    # --------------------------------------------------------
    # NEW: Cross-evidence relationships
    # --------------------------------------------------------

    relationship_evidence = correlate_relationships(
        evidence
    )

    evidence.extend(
        relationship_evidence
    )

    # Calculate final correlation score
    correlation_score = calculate_correlation_score(
        evidence
    )

    return {
        "evidence": evidence,
        "score": correlation_score,
        "count": len(evidence)
    }