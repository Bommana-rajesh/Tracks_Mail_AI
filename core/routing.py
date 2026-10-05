import re
import ipaddress
from datetime import datetime


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ip_from_text(text):
    """
    Find the first valid IP address in a Received header.
    """

    if not text:
        return None

    # IPv4 candidates
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    candidates = re.findall(
        ipv4_pattern,
        text
    )

    # IPv6 candidates
    ipv6_pattern = (
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}"
        r"[0-9a-fA-F]{1,4}\b"
    )

    candidates += re.findall(
        ipv6_pattern,
        text
    )

    for candidate in candidates:

        try:
            ip = ipaddress.ip_address(candidate)

            if ip.is_global:
                return candidate

        except ValueError:
            continue

    return None


# ============================================================
# HOSTNAME EXTRACTION
# ============================================================

def extract_hostnames(text):
    """
    Extract possible hostnames from a Received header.

    This is intentionally conservative because email headers
    can contain several different hostnames.
    """

    if not text:
        return []

    hostname_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}\b"
    )

    matches = re.findall(
        hostname_pattern,
        text
    )

    # Remove duplicates while preserving order
    hostnames = []

    for hostname in matches:

        hostname = hostname.lower()

        if hostname not in hostnames:
            hostnames.append(hostname)

    return hostnames


# ============================================================
# TIMESTAMP EXTRACTION
# ============================================================

def extract_timestamp(received_header):
    """
    Try to extract the timestamp at the end of a Received header.
    """

    if not received_header:
        return None

    # Typical format:
    #
    # Thu, 17 Sep 2026 14:00:00 +0530
    #
    timestamp_pattern = (
        r"([A-Z][a-z]{2},\s+"
        r"\d{1,2}\s+"
        r"[A-Z][a-z]{2}\s+"
        r"\d{4}\s+"
        r"\d{2}:\d{2}:\d{2}\s+"
        r"[+-]\d{4})"
    )

    match = re.search(
        timestamp_pattern,
        received_header
    )

    if not match:
        return None

    timestamp = match.group(1)

    try:
        parsed = datetime.strptime(
            timestamp,
            "%a, %d %b %Y %H:%M:%S %z"
        )

        return parsed.isoformat()

    except ValueError:
        return timestamp


# ============================================================
# ROUTING HOP PARSER
# ============================================================

def parse_received_header(header, hop_number):
    """
    Convert one Received header into a structured routing hop.
    """

    ip = extract_ip_from_text(
        header
    )

    hostnames = extract_hostnames(
        header
    )

    timestamp = extract_timestamp(
        header
    )

    # --------------------------------------------------------
    # Extract "from" server
    # --------------------------------------------------------

    from_server = ""

    from_match = re.search(
        r"\bfrom\s+([^\s(;)]+)",
        header,
        flags=re.IGNORECASE
    )

    if from_match:
        from_server = from_match.group(1)

    # --------------------------------------------------------
    # Extract "by" server
    # --------------------------------------------------------

    by_server = ""

    by_match = re.search(
        r"\bby\s+([^\s(;)]+)",
        header,
        flags=re.IGNORECASE
    )

    if by_match:
        by_server = by_match.group(1)

    # --------------------------------------------------------
    # Determine whether IP is private/reserved
    # --------------------------------------------------------

    ip_scope = "unknown"

    if ip:

        try:
            parsed_ip = ipaddress.ip_address(ip)

            if parsed_ip.is_private:
                ip_scope = "private"

            elif parsed_ip.is_global:
                ip_scope = "public"

            else:
                ip_scope = "reserved"

        except ValueError:
            ip_scope = "invalid"

    # --------------------------------------------------------
    # Return structured hop
    # --------------------------------------------------------

    return {
        "hop": hop_number,
        "raw": header,
        "from_server": from_server,
        "by_server": by_server,
        "ip": ip,
        "ip_scope": ip_scope,
        "hostnames": hostnames,
        "timestamp": timestamp
    }


# ============================================================
# BUILD ROUTING CHAIN
# ============================================================

def build_routing_chain(received_headers):
    """
    Build a chronological routing chain from Received headers.

    IMPORTANT:
    Received headers are normally added by mail servers as the
    message travels through the infrastructure. Their displayed
    order is therefore not necessarily the chronological order.

    For forensic analysis, we preserve the original headers and
    also provide a hop-numbered structure.
    """

    if not received_headers:
        return []

    routing_chain = []

    for index, header in enumerate(
        received_headers,
        start=1
    ):

        hop = parse_received_header(
            header,
            index
        )

        routing_chain.append(
            hop
        )

    return routing_chain


# ============================================================
# CALCULATE RELAY DELAYS
# ============================================================

def calculate_relay_delays(routing_chain):
    """
    Calculate time differences between available Received
    timestamps.

    The result is informational only. Missing or malformed
    timestamps are skipped.
    """

    if not routing_chain:
        return []

    delays = []

    parsed_hops = []

    for hop in routing_chain:

        timestamp = hop.get(
            "timestamp"
        )

        if not timestamp:
            continue

        try:

            dt = datetime.fromisoformat(
                timestamp
            )

            parsed_hops.append(
                (hop, dt)
            )

        except ValueError:
            continue

    for index in range(
        1,
        len(parsed_hops)
    ):

        previous_hop, previous_time = (
            parsed_hops[index - 1]
        )

        current_hop, current_time = (
            parsed_hops[index]
        )

        difference = (
            current_time - previous_time
        ).total_seconds()

        delays.append({
            "from_hop": previous_hop["hop"],
            "to_hop": current_hop["hop"],
            "seconds": difference
        })

    return delays


# ============================================================
# ROUTING ANALYSIS
# ============================================================

def analyze_routing(received_headers):
    """
    Main routing-analysis function.

    Input:
        received_headers -> list of Received headers

    Output:
        structured routing and timing information.
    """

    routing_chain = build_routing_chain(
        received_headers
    )

    relay_delays = calculate_relay_delays(
        routing_chain
    )

    public_ip_count = 0
    private_ip_count = 0

    for hop in routing_chain:

        if hop["ip_scope"] == "public":
            public_ip_count += 1

        elif hop["ip_scope"] == "private":
            private_ip_count += 1

    return {
        "routing_chain": routing_chain,

        "relay_delays": relay_delays,

        "statistics": {
            "total_hops": len(routing_chain),
            "public_ip_hops": public_ip_count,
            "private_ip_hops": private_ip_count,
            "timed_hops": len(relay_delays)
        }
    }