import re


# ============================================================
# NORMALIZE AUTHENTICATION RESULT
# ============================================================

def normalize_result(value):
    """
    Convert authentication results into a standard format.
    """

    if not value:
        return "unknown"

    value = value.lower().strip()

    if value in ["pass", "passed"]:
        return "pass"

    if value in ["fail", "failed"]:
        return "fail"

    if value in ["softfail", "soft-fail"]:
        return "softfail"

    if value in ["neutral"]:
        return "neutral"

    if value in ["none"]:
        return "none"

    if value in ["temperror", "temp-error"]:
        return "temperror"

    if value in ["permerror", "perm-error"]:
        return "permerror"

    return value


# ============================================================
# EXTRACT AUTHENTICATION METHOD
# ============================================================

def extract_auth_result(auth_header, method):
    """
    Extract SPF, DKIM or DMARC result from
    Authentication-Results.
    """

    if not auth_header:
        return "unknown"

    pattern = rf"\b{method}\s*=\s*([a-zA-Z0-9_-]+)"

    match = re.search(
        pattern,
        auth_header,
        flags=re.IGNORECASE
    )

    if match:
        return normalize_result(
            match.group(1)
        )

    return "unknown"


# ============================================================
# EXTRACT AUTHENTICATION DETAILS
# ============================================================

def extract_auth_details(auth_header):
    """
    Extract additional authentication information such as:

    SPF domain
    DKIM domain
    DKIM selector
    DMARC policy
    """

    details = {
        "spf_domain": "",
        "dkim_domain": "",
        "dkim_selector": "",
        "dmarc_policy": ""
    }

    if not auth_header:
        return details

    # --------------------------------------------------------
    # SPF domain
    # Example:
    # spf=pass smtp.mailfrom=example.com
    # --------------------------------------------------------

    spf_domain = re.search(
        r"smtp\.mailfrom=([^\s;]+)",
        auth_header,
        flags=re.IGNORECASE
    )

    if spf_domain:
        details["spf_domain"] = (
            spf_domain.group(1)
        )

    # --------------------------------------------------------
    # DKIM domain
    # Example:
    # dkim=pass header.d=example.com
    # --------------------------------------------------------

    dkim_domain = re.search(
        r"header\.d=([^\s;]+)",
        auth_header,
        flags=re.IGNORECASE
    )

    if dkim_domain:
        details["dkim_domain"] = (
            dkim_domain.group(1)
        )

    # --------------------------------------------------------
    # DKIM selector
    # Example:
    # header.s=selector1
    # --------------------------------------------------------

    dkim_selector = re.search(
        r"header\.s=([^\s;]+)",
        auth_header,
        flags=re.IGNORECASE
    )

    if dkim_selector:
        details["dkim_selector"] = (
            dkim_selector.group(1)
        )

    # --------------------------------------------------------
    # DMARC policy
    # Example:
    # p=none
    # p=quarantine
    # p=reject
    # --------------------------------------------------------

    dmarc_policy = re.search(
        r"\bp=(none|quarantine|reject)\b",
        auth_header,
        flags=re.IGNORECASE
    )

    if dmarc_policy:
        details["dmarc_policy"] = (
            dmarc_policy.group(1).lower()
        )

    return details


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================

def analyze_authentication(auth_header):
    """
    Analyze SPF, DKIM and DMARC results.

    IMPORTANT:
    This function analyzes the Authentication-Results
    header present in the EML.

    It does NOT independently verify SPF/DKIM/DMARC.
    """

    spf = extract_auth_result(
        auth_header,
        "spf"
    )

    dkim = extract_auth_result(
        auth_header,
        "dkim"
    )

    dmarc = extract_auth_result(
        auth_header,
        "dmarc"
    )

    details = extract_auth_details(
        auth_header
    )

    reasons = []

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if spf == "fail":

        reasons.append({
            "type": "SPF_FAILURE",
            "severity": "high",
            "message": (
                "SPF authentication failed."
            )
        })

    elif spf == "softfail":

        reasons.append({
            "type": "SPF_SOFTFAIL",
            "severity": "medium",
            "message": (
                "SPF returned a soft failure."
            )
        })

    elif spf == "pass":

        reasons.append({
            "type": "SPF_PASS",
            "severity": "low",
            "message": (
                "SPF authentication passed."
            )
        })

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if dkim == "fail":

        reasons.append({
            "type": "DKIM_FAILURE",
            "severity": "high",
            "message": (
                "DKIM authentication failed."
            )
        })

    elif dkim == "pass":

        reasons.append({
            "type": "DKIM_PASS",
            "severity": "low",
            "message": (
                "DKIM authentication passed."
            )
        })

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if dmarc == "fail":

        reasons.append({
            "type": "DMARC_FAILURE",
            "severity": "high",
            "message": (
                "DMARC authentication failed."
            )
        })

    elif dmarc == "pass":

        reasons.append({
            "type": "DMARC_PASS",
            "severity": "low",
            "message": (
                "DMARC authentication passed."
            )
        })

    # --------------------------------------------------------
    # Multiple authentication failures
    # --------------------------------------------------------

    failures = 0

    if spf in ["fail", "softfail"]:
        failures += 1

    if dkim == "fail":
        failures += 1

    if dmarc == "fail":
        failures += 1

    if failures >= 2:

        reasons.append({
            "type": "MULTIPLE_AUTH_FAILURES",
            "severity": "critical",
            "message": (
                "Multiple email authentication mechanisms "
                "failed."
            )
        })

    # --------------------------------------------------------
    # Overall authentication status
    # --------------------------------------------------------

    if failures >= 2:
        overall = "suspicious"

    elif failures == 1:
        overall = "warning"

    elif (
        spf == "pass"
        and dkim == "pass"
        and dmarc == "pass"
    ):
        overall = "authenticated"

    else:
        overall = "inconclusive"

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {

        "spf": spf,

        "dkim": dkim,

        "dmarc": dmarc,

        "overall": overall,

        "failures": failures,

        "details": details,

        "reasons": reasons
    }