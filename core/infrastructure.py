import ipaddress
import requests


# ============================================================
# CONFIGURATION
# ============================================================

IP_API_URL = "https://ipapi.co/{ip}/json/"

HEADERS = {
    "User-Agent": "TraceMailAI/1.0"
}


# ============================================================
# PROVIDER DETECTION
# ============================================================

def detect_provider(organization="", asn=""):
    """
    Try to identify major infrastructure providers.
    """

    organization = (organization or "").lower()
    asn = (asn or "").lower()

    combined = f"{organization} {asn}"

    if (
        "google" in combined
        or "googleusercontent" in combined
        or "gmail" in combined
        or "as15169" in combined
    ):
        return "Google"

    if (
        "amazon" in combined
        or "aws" in combined
        or "amazonaws" in combined
        or "as16509" in combined
    ):
        return "Amazon AWS"

    if (
        "microsoft" in combined
        or "azure" in combined
        or "outlook" in combined
        or "as8075" in combined
    ):
        return "Microsoft"

    if (
        "cloudflare" in combined
        or "as13335" in combined
    ):
        return "Cloudflare"

    return "Unknown"


# ============================================================
# IP VALIDATION
# ============================================================

def validate_public_ip(ip):
    """
    Check whether an IP is a valid globally routable IP.
    """

    try:
        address = ipaddress.ip_address(
            ip
        )

        return address.is_global

    except ValueError:
        return False


# ============================================================
# LOCATION CONFIDENCE
# ============================================================

def calculate_location_confidence(data):
    """
    Estimate confidence based on the amount of location
    information returned by the IP intelligence provider.

    This is NOT a probability that the physical location
    is correct.
    """

    city = data.get("city")
    region = data.get("region")
    country = data.get("country_name")

    latitude = data.get("latitude")
    longitude = data.get("longitude")

    if (
        city
        and region
        and country
        and latitude is not None
        and longitude is not None
    ):
        return "Medium"

    if country:
        return "Low"

    return "Unavailable"


# ============================================================
# ROLE CONFIDENCE
# ============================================================

def calculate_role_confidence(provider):
    """
    Estimate confidence in infrastructure-provider
    classification.
    """

    if provider != "Unknown":
        return "High"

    return "Medium"


# ============================================================
# IP LOOKUP
# ============================================================

def lookup_ip(ip):
    """
    Query IP intelligence information for one IP address.
    """

    if not validate_public_ip(ip):

        return {
            "ip": ip,
            "success": False,
            "error": "Invalid or non-public IP address."
        }

    url = IP_API_URL.format(
        ip=ip
    )

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as error:

        return {
            "ip": ip,
            "success": False,
            "error": f"IP lookup failed: {error}"
        }

    except ValueError:

        return {
            "ip": ip,
            "success": False,
            "error": "Invalid response from IP intelligence service."
        }

    # --------------------------------------------------------
    # Extract information
    # --------------------------------------------------------

    city = data.get("city") or ""

    region = (
        data.get("region")
        or data.get("region_code")
        or ""
    )

    country = (
        data.get("country_name")
        or data.get("country")
        or ""
    )

    latitude = data.get("latitude")
    longitude = data.get("longitude")

    organization = (
        data.get("org")
        or data.get("organization")
        or ""
    )

    asn = (
        data.get("asn")
        or ""
    )

    hostname = (
        data.get("hostname")
        or ""
    )

    timezone = (
        data.get("timezone")
        or ""
    )

    network = (
        data.get("network")
        or ""
    )

    # --------------------------------------------------------
    # Provider
    # --------------------------------------------------------

    provider = detect_provider(
        organization,
        asn
    )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    location_confidence = calculate_location_confidence(
        data
    )

    role_confidence = calculate_role_confidence(
        provider
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {

        "ip": ip,

        "success": True,

        "city": city,

        "region": region,

        "country": country,

        "latitude": latitude,

        "longitude": longitude,

        "organization": organization,

        "isp": organization,

        "asn": asn,

        "hostname": hostname,

        "timezone": timezone,

        "network": network,

        "provider": provider,

        "location_confidence": location_confidence,

        "role_confidence": role_confidence
    }


# ============================================================
# IP ROLE CLASSIFICATION
# ============================================================

def classify_ip_role(ip, received_headers=None):
    """
    Classify the likely role of an IP in the email evidence.

    This is an analytical label, not proof of sender identity.
    """

    received_headers = received_headers or []

    provider_data = lookup_ip(ip)

    provider = provider_data.get(
        "provider",
        "Unknown"
    )

    # --------------------------------------------------------
    # Check whether IP occurs in Received headers
    # --------------------------------------------------------

    appears_in_received = False

    for header in received_headers:

        if ip in header:
            appears_in_received = True
            break

    # --------------------------------------------------------
    # Known mail/cloud infrastructure
    # --------------------------------------------------------

    if appears_in_received:

        if provider != "Unknown":

            role = "Mail / Cloud Infrastructure"

        else:

            role = "Possible Sender / Relay Network"

    else:

        role = "Header / Body Reference"

    provider_data["role"] = role

    return provider_data


# ============================================================
# MULTIPLE IP LOOKUP
# ============================================================

def analyze_ips(ips, received_headers=None):
    """
    Analyze multiple IP addresses.
    """

    received_headers = received_headers or []

    results = []

    for ip in ips:

        result = classify_ip_role(
            ip,
            received_headers
        )

        results.append(
            result
        )

    return results


# ============================================================
# MAP DATA
# ============================================================

def create_map_data(ip_locations):
    """
    Convert IP intelligence results into simplified
    data suitable for Leaflet/OpenStreetMap.
    """

    map_data = []

    for item in ip_locations:

        if not item.get("success"):
            continue

        latitude = item.get(
            "latitude"
        )

        longitude = item.get(
            "longitude"
        )

        if latitude is None or longitude is None:
            continue

        map_data.append({

            "ip": item.get("ip"),

            "latitude": latitude,

            "longitude": longitude,

            "city": item.get("city"),

            "region": item.get("region"),

            "country": item.get("country"),

            "provider": item.get("provider"),

            "organization": item.get("organization"),

            "asn": item.get("asn"),

            "hostname": item.get("hostname"),

            "role": item.get("role"),

            "location_confidence": item.get(
                "location_confidence"
            )
        })

    return map_data