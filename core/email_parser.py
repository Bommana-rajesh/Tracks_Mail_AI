import re
import hashlib
import ipaddress
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from urllib.parse import urlparse


# ============================================================
# HEADER DECODING
# ============================================================

def decode_header_value(value):
    """
    Safely decode an email header such as Subject, From, etc.
    """
    if not value:
        return ""

    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


# ============================================================
# BODY EXTRACTION
# ============================================================

def extract_body(message):
    """
    Extract plain-text and HTML content from an email.
    """

    body_text = ""
    body_html = ""

    if message.is_multipart():

        for part in message.walk():

            # Ignore attachments
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            try:
                content = part.get_content()
            except Exception:
                try:
                    payload = part.get_payload(decode=True)

                    if payload:
                        content = payload.decode(
                            "utf-8",
                            errors="replace"
                        )
                    else:
                        content = ""
                except Exception:
                    content = ""

            if content_type == "text/plain":
                body_text += str(content) + "\n"

            elif content_type == "text/html":
                body_html += str(content) + "\n"

    else:

        content_type = message.get_content_type()

        try:
            content = message.get_content()
        except Exception:
            try:
                payload = message.get_payload(decode=True)

                if payload:
                    content = payload.decode(
                        "utf-8",
                        errors="replace"
                    )
                else:
                    content = ""
            except Exception:
                content = ""

        if content_type == "text/plain":
            body_text = str(content)

        elif content_type == "text/html":
            body_html = str(content)

    return body_text.strip(), body_html.strip()


# ============================================================
# ATTACHMENT EXTRACTION
# ============================================================

def extract_attachments(message):
    """
    Extract basic metadata about email attachments.
    """

    attachments = []

    for part in message.walk():

        if part.get_content_disposition() != "attachment":
            continue

        filename = decode_header_value(
            part.get_filename()
        )

        content_type = part.get_content_type()

        try:
            data = part.get_payload(decode=True)

            if data:
                size = len(data)
                sha256 = hashlib.sha256(data).hexdigest()
            else:
                size = 0
                sha256 = ""

        except Exception:
            size = 0
            sha256 = ""

        attachments.append({
            "filename": filename,
            "content_type": content_type,
            "size": size,
            "sha256": sha256
        })

    return attachments


# ============================================================
# RECEIVED HEADER EXTRACTION
# ============================================================

def extract_received_headers(message):
    """
    Extract all Received headers.

    Received headers describe the mail routing path.
    """

    received_headers = []

    for value in message.get_all("Received", []):

        received_headers.append(
            decode_header_value(value)
        )

    return received_headers


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ips(received_headers):
    """
    Extract valid public IP addresses from Received headers.

    This does NOT determine the physical location of the sender.
    """

    found_ips = []

    # IPv4
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # IPv6
    ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"

    for header in received_headers:

        candidates = re.findall(
            ipv4_pattern,
            header
        )

        candidates += re.findall(
            ipv6_pattern,
            header
        )

        for candidate in candidates:

            try:
                ip = ipaddress.ip_address(candidate)

                # Keep globally routable IPs only
                if ip.is_global:

                    if candidate not in found_ips:
                        found_ips.append(candidate)

            except ValueError:
                continue

    return found_ips


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from email content.
    """

    if not text:
        return []

    url_pattern = r'https?://[^\s<>"\'\]]+'

    urls = re.findall(
        url_pattern,
        text,
        flags=re.IGNORECASE
    )

    cleaned_urls = []

    for url in urls:

        # Remove common punctuation attached to URLs
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domains(urls):
    """
    Extract domains from URLs.
    """

    domains = []

    for url in urls:

        try:
            parsed = urlparse(url)

            hostname = parsed.hostname

            if hostname:

                hostname = hostname.lower()

                if hostname not in domains:
                    domains.append(hostname)

        except Exception:
            continue

    return domains


# ============================================================
# RAW HEADER EXTRACTION
# ============================================================

def extract_headers(message):
    """
    Convert all email headers into a structured list.
    """

    headers = []

    for name, value in message.items():

        headers.append({
            "name": str(name),
            "value": decode_header_value(value)
        })

    return headers


# ============================================================
# MAIN EML PARSER
# ============================================================

def parse_eml(file_bytes):
    """
    Main TraceMail AI .eml parser.

    Input:
        file_bytes -> raw bytes of an .eml file

    Output:
        structured dictionary containing email evidence.
    """

    if not file_bytes:
        raise ValueError("Empty EML file.")

    try:

        message = BytesParser(
            policy=policy.default
        ).parsebytes(file_bytes)

    except Exception as e:

        raise ValueError(
            f"Unable to parse EML file: {e}"
        )

    # --------------------------------------------------------
    # Basic headers
    # --------------------------------------------------------

    sender = decode_header_value(
        message.get("From", "")
    )

    recipient = decode_header_value(
        message.get("To", "")
    )

    cc = decode_header_value(
        message.get("Cc", "")
    )

    reply_to = decode_header_value(
        message.get("Reply-To", "")
    )

    return_path = decode_header_value(
        message.get("Return-Path", "")
    )

    subject = decode_header_value(
        message.get("Subject", "")
    )

    date = decode_header_value(
        message.get("Date", "")
    )

    message_id = decode_header_value(
        message.get("Message-ID", "")
    )

    authentication_results = decode_header_value(
        message.get("Authentication-Results", "")
    )

    # --------------------------------------------------------
    # Body
    # --------------------------------------------------------

    body_text, body_html = extract_body(
        message
    )

    # --------------------------------------------------------
    # Routing
    # --------------------------------------------------------

    received_headers = extract_received_headers(
        message
    )

    ips = extract_ips(
        received_headers
    )

    # --------------------------------------------------------
    # URLs and domains
    # --------------------------------------------------------

    combined_content = (
        body_text + "\n" + body_html
    )

    urls = extract_urls(
        combined_content
    )

    domains = extract_domains(
        urls
    )

    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    attachments = extract_attachments(
        message
    )

    # --------------------------------------------------------
    # All headers
    # --------------------------------------------------------

    headers = extract_headers(
        message
    )

    # --------------------------------------------------------
    # Final structured result
    # --------------------------------------------------------

    result = {

        # Identity
        "sender": sender,
        "to": recipient,
        "cc": cc,
        "reply_to": reply_to,
        "return_path": return_path,

        # Message information
        "subject": subject,
        "date": date,
        "message_id": message_id,

        # Authentication
        "authentication_results": authentication_results,

        # Body
        "body_text": body_text,
        "body_html": body_html,

        # Routing
        "received_headers": received_headers,
        "ips": ips,

        # Indicators
        "urls": urls,
        "domains": domains,

        # Attachments
        "attachments": attachments,

        # Raw headers
        "headers": headers,

        # Basic statistics
        "statistics": {
            "received_hops": len(received_headers),
            "unique_ips": len(ips),
            "url_count": len(urls),
            "domain_count": len(domains),
            "attachment_count": len(attachments),
            "body_length": len(body_text)
        }
    }

    return result


# ============================================================
# OPTIONAL FILE-BASED HELPER
# ============================================================

def parse_eml_file(file_path):
    """
    Parse an EML file directly from a file path.
    """

    with open(
        file_path,
        "rb"
    ) as file:

        file_bytes = file.read()

    return parse_eml(
        file_bytes
    )