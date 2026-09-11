from flask import Flask, request, render_template_string, jsonify, make_response
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
import json
import os
import re
import uuid
import ssl
import socket
import time
import threading
import html

app = Flask(__name__)

# ============================================================
# SECURITY AUDIT CONSOLE
# V1 -> V6 COMPLETE
# 23 SECURITY FEATURES
# ============================================================

APP_NAME = "Security Audit Console"
APP_VERSION = "6.0"

HISTORY_FILE = "scan_history.json"
FEEDBACK_FILE = "feedback.json"
PROJECTS_FILE = "projects.json"
SETTINGS_FILE = "settings.json"

REQUEST_TIMEOUT = 12
PORT_TIMEOUT = 0.8
MAX_HISTORY = 150

# Common TCP ports for authorized security auditing.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "mail",
    "dev",
    "test",
    "staging",
    "beta",
    "demo",
    "shop",
    "cdn",
    "static",
    "m"
]

SCAN_PROFILES = {
    "quick": {
        "label": "Quick Scan",
        "ports": False,
        "subdomains": False
    },
    "full": {
        "label": "Full Scan",
        "ports": True,
        "subdomains": True
    },
    "passive": {
        "label": "Passive Intelligence",
        "ports": False,
        "subdomains": True
    }
}


# ============================================================
# BASIC HELPERS
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def human_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_json(filename, default):
    try:
        if not os.path.exists(filename):
            return default

        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(filename, data):
    try:
        temp = filename + ".tmp"

        with open(temp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        os.replace(temp, filename)
        return True
    except Exception:
        return False


def normalize_url(url):
    if not url:
        return ""

    url = url.strip()

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        return ""

    return url


def get_hostname(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def safe_text(value):
    if value is None:
        return ""
    return str(value)


def make_finding(
    name,
    description,
    severity="INFO",
    status="PASS",
    evidence="",
    remediation="",
    cwe="",
    category="Security"
):
    return {
        "name": name,
        "description": description,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "remediation": remediation,
        "cwe": cwe,
        "category": category
    }


# ============================================================
# 1. HTTPS / SSL
# ============================================================

def check_https(response):
    scheme = urlparse(response.url).scheme.lower()

    if scheme == "https":
        return make_finding(
            "HTTPS / SSL",
            "Checks whether the final connection uses HTTPS.",
            "INFO",
            "PASS",
            f"Final connection: {response.url}",
            "Keep HTTPS enabled and redirect HTTP traffic to HTTPS.",
            "CWE-319",
            "Transport Security"
        )

    return make_finding(
        "HTTPS / SSL",
        "Checks whether the final connection uses HTTPS.",
        "HIGH",
        "FAIL",
        f"Final connection: {response.url}",
        "Install a valid TLS certificate and force HTTP traffic to HTTPS.",
        "CWE-319",
        "Transport Security"
    )


# ============================================================
# 2-5. SECURITY HEADERS
# ============================================================

def check_required_headers(response):
    checks = []

    header_data = [
        (
            "X-Frame-Options",
            "Checks whether the website has protection against being embedded inside another website.",
            "CWE-1021",
            "Add X-Frame-Options: DENY or SAMEORIGIN."
        ),
        (
            "Content-Security-Policy",
            "Controls which scripts, styles and other resources a browser is allowed to load.",
            "CWE-693",
            "Create and deploy an appropriate Content-Security-Policy."
        ),
        (
            "Strict-Transport-Security",
            "Tells the browser to continue using HTTPS when connecting to the website.",
            "CWE-319",
            "Add Strict-Transport-Security after HTTPS is fully configured."
        ),
        (
            "X-Content-Type-Options",
            "Helps prevent browsers from guessing the content type of a response.",
            "CWE-16",
            "Add X-Content-Type-Options: nosniff."
        )
    ]

    for header, description, cwe, fix in header_data:
        value = response.headers.get(header)

        if value:
            checks.append(
                make_finding(
                    header,
                    description,
                    "INFO",
                    "PASS",
                    f"{header}: {value}",
                    fix,
                    cwe,
                    "Security Headers"
                )
            )
        else:
            checks.append(
                make_finding(
                    header,
                    description,
                    "MEDIUM",
                    "FAIL",
                    f"{header}: Not Found",
                    fix,
                    cwe,
                    "Security Headers"
                )
            )

    return checks


# ============================================================
# 6. SERVER INFORMATION DISCLOSURE
# ============================================================

def check_server_disclosure(response):
    value = response.headers.get("Server")

    if value:
        return make_finding(
            "Server Information Disclosure",
            "Checks whether the Server response header exposes server details.",
            "LOW",
            "WARNING",
            f"Server: {value}",
            "Hide unnecessary server and version information.",
            "CWE-200",
            "Information Disclosure"
        )

    return make_finding(
        "Server Information Disclosure",
        "The Server response header was not exposed.",
        "INFO",
        "PASS",
        "Server: Not exposed",
        "Continue hiding unnecessary technology information.",
        "CWE-200",
        "Information Disclosure"
    )


# ============================================================
# 7. COOKIE SECURITY - FIXED SAME-SITE LOGIC
# ============================================================

def get_set_cookie_headers(response):
    cookies = []

    try:
        raw_headers = response.raw.headers

        if hasattr(raw_headers, "get_all"):
            values = raw_headers.get_all("Set-Cookie")

            if values:
                cookies.extend(values)
    except Exception:
        pass

    if not cookies:
        value = response.headers.get("Set-Cookie")

        if value:
            cookies.append(value)

    return cookies


def parse_cookie_header(cookie_header):
    parts = [x.strip() for x in cookie_header.split(";") if x.strip()]

    if not parts:
        return {
            "name": "Unknown",
            "secure": False,
            "httponly": False,
            "samesite": None
        }

    first = parts[0]

    if "=" in first:
        name = first.split("=", 1)[0].strip()
    else:
        name = first.strip()

    secure = False
    httponly = False
    samesite = None

    for attr in parts[1:]:
        lower = attr.lower()

        if lower == "secure":
            secure = True

        elif lower == "httponly":
            httponly = True

        elif lower.startswith("samesite"):
            if "=" in attr:
                samesite = attr.split("=", 1)[1].strip().lower()
            else:
                samesite = True

    return {
        "name": name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite
    }


def check_cookie_security(response):
    headers = get_set_cookie_headers(response)

    if not headers:
        return make_finding(
            "Cookie Security",
            "Checks Secure, HttpOnly and SameSite protection on cookies.",
            "INFO",
            "INFO",
            "No Set-Cookie header was observed.",
            "Review session cookies separately on authenticated pages.",
            "CWE-614",
            "Cookie Security"
        )

    findings = []

    for cookie_header in headers:
        cookie = parse_cookie_header(cookie_header)

        missing = []

        if not cookie["secure"]:
            missing.append("Secure")

        if not cookie["httponly"]:
            missing.append("HttpOnly")

        samesite = cookie["samesite"]

        if samesite is None:
            missing.append("SameSite")

        # SameSite=None MUST normally be accompanied by Secure.
        same_site_issue = (
            isinstance(samesite, str)
            and samesite.lower() == "none"
            and not cookie["secure"]
        )

        if same_site_issue:
            missing.append("Secure required for SameSite=None")

        if same_site_issue:
            severity = "MEDIUM"
            status = "FAIL"

            description = (
                f"Cookie '{cookie['name']}' uses SameSite=None "
                "without Secure."
            )

        elif len(missing) >= 2:
            severity = "MEDIUM"
            status = "FAIL"

            description = (
                f"Cookie '{cookie['name']}' is missing: "
                + ", ".join(missing)
                + "."
            )

        elif len(missing) == 1:
            severity = "LOW"
            status = "WARNING"

            description = (
                f"Cookie '{cookie['name']}' is missing: "
                + ", ".join(missing)
                + "."
            )

        else:
            severity = "INFO"
            status = "PASS"

            description = (
                f"Cookie '{cookie['name']}' has Secure, HttpOnly "
                f"and SameSite protection."
            )

        evidence = (
            f"Cookie: {cookie['name']} | "
            f"Secure={cookie['secure']} | "
            f"HttpOnly={cookie['httponly']} | "
            f"SameSite={cookie['samesite'] or 'Missing'}"
        )

        findings.append(
            make_finding(
                "Cookie Security",
                description,
                severity,
                status,
                evidence,
                (
                    "For sensitive cookies, use Secure and HttpOnly. "
                    "Use SameSite=Lax or Strict when suitable. "
                    "If SameSite=None is required, also use Secure."
                ),
                "CWE-614",
                "Cookie Security"
            )
        )

    # Combine multiple cookies into one dashboard feature.
    highest = "INFO"
    final_status = "PASS"

    priority = {
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    for item in findings:
        if priority.get(item["severity"], 1) > priority.get(highest, 1):
            highest = item["severity"]

        if item["status"] == "FAIL":
            final_status = "FAIL"
        elif item["status"] == "WARNING" and final_status != "FAIL":
            final_status = "WARNING"

    descriptions = []

    for item in findings:
        descriptions.append(item["description"])

    return make_finding(
        "Cookie Security",
        " ".join(descriptions),
        highest,
        final_status,
        " | ".join(item["evidence"] for item in findings),
        (
            "Use Secure and HttpOnly for sensitive cookies. "
            "Use an appropriate SameSite value. "
            "SameSite=None should be combined with Secure."
        ),
        "CWE-614",
        "Cookie Security"
    )


# ============================================================
# 8. CORS
# ============================================================

def check_cors(response):
    value = response.headers.get("Access-Control-Allow-Origin")

    if not value:
        return make_finding(
            "CORS Policy",
            "Checks whether a permissive Access-Control-Allow-Origin header is exposed.",
            "INFO",
            "PASS",
            "Access-Control-Allow-Origin: Not Found",
            "Keep CORS restricted to trusted origins where cross-origin access is required.",
            "CWE-942",
            "CORS"
        )

    if value.strip() == "*":
        return make_finding(
            "CORS Policy",
            "Checks whether a permissive Access-Control-Allow-Origin header is exposed.",
            "MEDIUM",
            "WARNING",
            f"Access-Control-Allow-Origin: {value}",
            "Replace wildcard CORS with a trusted origin allow-list when sensitive data is involved.",
            "CWE-942",
            "CORS"
        )

    return make_finding(
        "CORS Policy",
        "No permissive wildcard Access-Control-Allow-Origin header was observed.",
        "INFO",
        "PASS",
        f"Access-Control-Allow-Origin: {value}",
        "Keep the origin allow-list limited to trusted sites.",
        "CWE-942",
        "CORS"
    )


# ============================================================
# 9. PERMISSIONS-POLICY
# ============================================================

def check_permissions_policy(response):
    value = response.headers.get("Permissions-Policy")

    if value:
        return make_finding(
            "Permissions-Policy",
            "Controls access to selected browser features.",
            "INFO",
            "PASS",
            f"Permissions-Policy: {value}",
            "Keep browser feature permissions as restrictive as practical.",
            "CWE-16",
            "Browser Security"
        )

    return make_finding(
        "Permissions-Policy",
        "Controls access to selected browser features.",
        "LOW",
        "WARNING",
        "Permissions-Policy: Not Found",
        "Consider defining Permissions-Policy for browser features your application uses.",
        "CWE-16",
        "Browser Security"
    )


# ============================================================
# 10. TLS CERTIFICATE
# ============================================================

def inspect_certificate(hostname):
    context = ssl.create_default_context()

    with socket.create_connection(
        (hostname, 443),
        timeout=REQUEST_TIMEOUT
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=hostname
        ) as secure_sock:

            cert = secure_sock.getpeercert()
            cipher = secure_sock.cipher()
            version = secure_sock.version()

    return cert, cipher, version


def check_tls_certificate(response):
    hostname = get_hostname(response.url)

    if not hostname:
        return make_finding(
            "TLS Certificate",
            "TLS certificate was inspected.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Use a valid HTTPS hostname.",
            "CWE-295",
            "TLS"
        )

    try:
        cert, cipher, version = inspect_certificate(hostname)

        expiry_text = cert.get("notAfter", "")

        if expiry_text:
            expiry = datetime.strptime(
                expiry_text,
                "%b %d %H:%M:%S %Y %Z"
            )

            remaining = (expiry - datetime.utcnow()).days

            if remaining < 0:
                return make_finding(
                    "TLS Certificate",
                    "TLS certificate appears to be expired.",
                    "HIGH",
                    "FAIL",
                    f"Expires: {expiry.isoformat()}",
                    "Renew and correctly deploy the TLS certificate.",
                    "CWE-295",
                    "TLS"
                )

            return make_finding(
                "TLS Certificate",
                "TLS certificate was successfully inspected.",
                "INFO",
                "PASS",
                (
                    f"TLS Version: {version} | "
                    f"Cipher: {cipher[0] if cipher else 'Unknown'} | "
                    f"Expires: {expiry.isoformat()} | "
                    f"Days Left: {remaining}"
                ),
                "Keep certificate renewal automated and monitored.",
                "CWE-295",
                "TLS"
            )

        return make_finding(
            "TLS Certificate",
            "TLS certificate was successfully inspected.",
            "INFO",
            "PASS",
            f"TLS Version: {version}",
            "Continue monitoring certificate validity.",
            "CWE-295",
            "TLS"
        )

    except ssl.SSLCertVerificationError as exc:
        return make_finding(
            "TLS Certificate",
            "TLS certificate validation failed.",
            "HIGH",
            "FAIL",
            str(exc)[:1000],
            "Install a valid trusted certificate and correct the chain.",
            "CWE-295",
            "TLS"
        )

    except Exception as exc:
        return make_finding(
            "TLS Certificate",
            "TLS certificate could not be fully inspected.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Verify the HTTPS/TLS configuration.",
            "CWE-295",
            "TLS"
        )


# ============================================================
# 11. DNS INFORMATION
# ============================================================

def check_dns(response):
    hostname = get_hostname(response.url)

    if not hostname:
        return make_finding(
            "DNS Information",
            "Shows public host addresses resolved by the scanner.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Provide a valid hostname.",
            "CWE-706",
            "DNS"
        )

    try:
        infos = socket.getaddrinfo(
            hostname,
            None
        )

        addresses = sorted(
            {
                item[4][0]
                for item in infos
                if item and item[4]
            }
        )

        return make_finding(
            "DNS Information",
            "Shows public host addresses resolved by the scanner.",
            "INFO",
            "INFO",
            f"{hostname}: {', '.join(addresses)}",
            "Keep DNS records accurate and remove unused records.",
            "CWE-706",
            "DNS"
        )

    except Exception as exc:
        return make_finding(
            "DNS Information",
            "DNS resolution failed.",
            "HIGH",
            "FAIL",
            str(exc)[:1000],
            "Verify A/AAAA records and DNS configuration.",
            "CWE-706",
            "DNS"
        )


# ============================================================
# 12. REDIRECT CHAIN
# ============================================================

def check_redirect_chain(response):
    history = response.history

    if not history:
        return make_finding(
            "Redirect Chain",
            "Shows redirects followed before reaching the final target.",
            "INFO",
            "INFO",
            f"Final target: {response.url}",
            "Keep redirects intentional and minimal.",
            "CWE-601",
            "Redirects"
        )

    chain = []

    for item in history:
        chain.append(
            f"{item.status_code}: {item.url}"
        )

    chain.append(
        f"{response.status_code}: {response.url}"
    )

    if len(history) >= 5:
        return make_finding(
            "Redirect Chain",
            "A relatively long redirect chain was detected.",
            "MEDIUM",
            "WARNING",
            " -> ".join(chain),
            "Reduce unnecessary redirects and verify all redirect destinations.",
            "CWE-601",
            "Redirects"
        )

    return make_finding(
        "Redirect Chain",
        "Shows redirects followed before reaching the final target.",
        "INFO",
        "INFO",
        " -> ".join(chain),
        "Keep redirects intentional and avoid unnecessary hops.",
        "CWE-601",
        "Redirects"
    )


# ============================================================
# 13. X-XSS-PROTECTION
# ============================================================

def check_x_xss(response):
    value = response.headers.get("X-XSS-Protection")

    if value:
        return make_finding(
            "X-XSS-Protection",
            "Checks whether the legacy browser XSS filter header is present.",
            "INFO",
            "PASS",
            f"X-XSS-Protection: {value}",
            (
                "For modern applications, prioritize CSP. "
                "Keep this legacy header only where it matches your browser policy."
            ),
            "CWE-79",
            "Legacy Browser Security"
        )

    return make_finding(
        "X-XSS-Protection",
        "Checks whether the legacy browser XSS filter header is present.",
        "INFO",
        "INFO",
        "X-XSS-Protection: Not Found",
        (
            "Modern browsers rely more on CSP. "
            "Focus on a strong Content-Security-Policy rather than relying on this legacy header."
        ),
        "CWE-79",
        "Legacy Browser Security"
    )


# ============================================================
# 14. REFERRER-POLICY
# ============================================================

def check_referrer_policy(response):
    value = response.headers.get("Referrer-Policy")

    if value:
        return make_finding(
            "Referrer-Policy",
            "Controls how much referral information is shared with other websites.",
            "INFO",
            "PASS",
            f"Referrer-Policy: {value}",
            "Keep a privacy-conscious policy such as strict-origin-when-cross-origin.",
            "CWE-200",
            "Privacy Headers"
        )

    return make_finding(
        "Referrer-Policy",
        "Controls how much referral information is shared with other websites.",
        "LOW",
        "WARNING",
        "Referrer-Policy: Not Found",
        "Consider adding strict-origin-when-cross-origin or another suitable policy.",
        "CWE-200",
        "Privacy Headers"
    )


# ============================================================
# 15. COOP
# ============================================================

def check_coop(response):
    value = response.headers.get("Cross-Origin-Opener-Policy")

    if value:
        return make_finding(
            "Cross-Origin-Opener-Policy (COOP)",
            "Helps isolate the browsing context from cross-origin documents.",
            "INFO",
            "PASS",
            f"Cross-Origin-Opener-Policy: {value}",
            "Use a suitable COOP value where cross-origin isolation is required.",
            "CWE-693",
            "Cross-Origin Isolation"
        )

    return make_finding(
        "Cross-Origin-Opener-Policy (COOP)",
        "Helps isolate the browsing context from cross-origin documents.",
        "LOW",
        "WARNING",
        "Cross-Origin-Opener-Policy: Not Found",
        "Consider COOP for applications that need stronger browser isolation.",
        "CWE-693",
        "Cross-Origin Isolation"
    )


# ============================================================
# 16. COEP
# ============================================================

def check_coep(response):
    value = response.headers.get("Cross-Origin-Embedder-Policy")

    if value:
        return make_finding(
            "Cross-Origin-Embedder-Policy (COEP)",
            "Controls whether cross-origin resources must explicitly grant permission.",
            "INFO",
            "PASS",
            f"Cross-Origin-Embedder-Policy: {value}",
            "Use COEP where your application requires cross-origin isolation.",
            "CWE-693",
            "Cross-Origin Isolation"
        )

    return make_finding(
        "Cross-Origin-Embedder-Policy (COEP)",
        "Controls whether cross-origin resources must explicitly grant permission.",
        "INFO",
        "INFO",
        "Cross-Origin-Embedder-Policy: Not Found",
        "Consider COEP when cross-origin isolation is needed.",
        "CWE-693",
        "Cross-Origin Isolation"
    )


# ============================================================
# 17. X-POWERED-BY / ASP.NET DISCLOSURE
# ============================================================

def check_framework_disclosure(response):
    exposed = []

    for header in [
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version"
    ]:
        value = response.headers.get(header)

        if value:
            exposed.append(
                f"{header}: {value}"
            )

    if exposed:
        return make_finding(
            "X-Powered-By / Framework Disclosure",
            "Checks whether backend framework names or versions are exposed.",
            "LOW",
            "WARNING",
            " | ".join(exposed),
            "Remove unnecessary framework/version disclosure headers.",
            "CWE-200",
            "Information Disclosure"
        )

    return make_finding(
        "X-Powered-By / Framework Disclosure",
        "Checks whether backend framework names or versions are exposed.",
        "INFO",
        "PASS",
        "No common framework disclosure headers were observed.",
        "Keep backend technology and version details hidden.",
        "CWE-200",
        "Information Disclosure"
    )


# ============================================================
# TLS VERSION / CIPHER TESTS
# ============================================================

def tls_probe(hostname, minimum_version=None, maximum_version=None):
    context = ssl.create_default_context()

    if minimum_version is not None:
        context.minimum_version = minimum_version

    if maximum_version is not None:
        context.maximum_version = maximum_version

    with socket.create_connection(
        (hostname, 443),
        timeout=PORT_TIMEOUT
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=hostname
        ) as secure_sock:

            return secure_sock.version(), secure_sock.cipher()


# ============================================================
# 18. TLS PROTOCOL VERSION
# ============================================================

def check_tls_protocol(response):
    hostname = get_hostname(response.url)

    if not hostname or urlparse(response.url).scheme != "https":
        return make_finding(
            "SSL/TLS Protocol Version",
            "Checks whether modern TLS protocol versions are available.",
            "INFO",
            "INFO",
            "Skipped because target is not HTTPS.",
            "Use HTTPS and modern TLS versions.",
            "CWE-327",
            "TLS"
        )

    detected = []

    modern_versions = []

    for version in [
        getattr(ssl.TLSVersion, "TLSv1_2", None),
        getattr(ssl.TLSVersion, "TLSv1_3", None)
    ]:
        if version is None:
            continue

        try:
            actual, _ = tls_probe(
                hostname,
                version,
                version
            )

            if actual:
                detected.append(actual)
                modern_versions.append(actual)

        except Exception:
            pass

    unique_versions = sorted(set(detected))

    if modern_versions:
        return make_finding(
            "SSL/TLS Protocol Version",
            "Checks whether modern TLS protocol versions are available.",
            "INFO",
            "PASS",
            f"Supported tested versions: {', '.join(unique_versions)}",
            "Prefer TLS 1.2 or TLS 1.3 and disable obsolete protocols.",
            "CWE-327",
            "TLS"
        )

    return make_finding(
        "SSL/TLS Protocol Version",
        "No tested modern TLS version could be confirmed.",
        "HIGH",
        "WARNING",
        "TLS 1.2 / TLS 1.3 could not be confirmed.",
        "Enable TLS 1.2 and TLS 1.3 and disable obsolete protocols.",
        "CWE-327",
        "TLS"
    )


# ============================================================
# 19. WEAK CIPHER
# ============================================================

def check_weak_cipher(response):
    hostname = get_hostname(response.url)

    if not hostname or urlparse(response.url).scheme != "https":
        return make_finding(
            "Weak Cipher Suites",
            "Checks the negotiated TLS cipher for obvious legacy algorithms.",
            "INFO",
            "INFO",
            "Skipped because target is not HTTPS.",
            "Use HTTPS with modern cipher suites.",
            "CWE-327",
            "TLS"
        )

    try:
        version, cipher = tls_probe(hostname)

        cipher_name = cipher[0] if cipher else "Unknown"

        weak_keywords = [
            "RC4",
            "3DES",
            "DES-CBC",
            "NULL",
            "EXPORT",
            "MD5"
        ]

        upper_cipher = cipher_name.upper()

        matched = [
            word
            for word in weak_keywords
            if word in upper_cipher
        ]

        if matched:
            return make_finding(
                "Weak Cipher Suites",
                "The negotiated TLS cipher contains a legacy/weak algorithm.",
                "HIGH",
                "FAIL",
                f"TLS: {version} | Cipher: {cipher_name}",
                "Disable legacy ciphers and use modern AEAD suites.",
                "CWE-327",
                "TLS"
            )

        return make_finding(
            "Weak Cipher Suites",
            "Checks the negotiated TLS cipher for obvious legacy algorithms.",
            "INFO",
            "PASS",
            f"TLS: {version} | Cipher: {cipher_name}",
            "Continue using modern authenticated encryption cipher suites.",
            "CWE-327",
            "TLS"
        )

    except Exception as exc:
        return make_finding(
            "Weak Cipher Suites",
            "The negotiated TLS cipher could not be inspected.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Verify modern TLS/cipher configuration manually if required.",
            "CWE-327",
            "TLS"
        )


# ============================================================
# 20. CERTIFICATE EXPIRY ALERT
# ============================================================

def check_certificate_expiry(response):
    hostname = get_hostname(response.url)

    if not hostname or urlparse(response.url).scheme != "https":
        return make_finding(
            "SSL Certificate Expiration Alert",
            "Checks whether the TLS certificate is close to expiration.",
            "INFO",
            "INFO",
            "Skipped because target is not HTTPS.",
            "Use HTTPS with a valid certificate.",
            "CWE-295",
            "TLS"
        )

    try:
        cert, _, _ = inspect_certificate(hostname)

        expiry_text = cert.get("notAfter", "")

        if not expiry_text:
            raise RuntimeError("Certificate expiry date unavailable.")

        expiry = datetime.strptime(
            expiry_text,
            "%b %d %H:%M:%S %Y %Z"
        )

        days_left = (expiry - datetime.utcnow()).days

        if days_left < 0:
            return make_finding(
                "SSL Certificate Expiration Alert",
                "Certificate is expired.",
                "HIGH",
                "FAIL",
                f"Expired: {expiry.isoformat()}",
                "Renew the certificate immediately.",
                "CWE-295",
                "TLS"
            )

        if days_left <= 7:
            severity = "HIGH"
            status = "WARNING"
        elif days_left <= 14:
            severity = "MEDIUM"
            status = "WARNING"
        elif days_left <= 30:
            severity = "LOW"
            status = "WARNING"
        else:
            severity = "INFO"
            status = "PASS"

        return make_finding(
            "SSL Certificate Expiration Alert",
            f"Certificate has approximately {days_left} days remaining.",
            severity,
            status,
            f"Expires: {expiry.isoformat()} | Days left: {days_left}",
            "Renew certificates before the expiration window.",
            "CWE-295",
            "TLS"
        )

    except Exception as exc:
        return make_finding(
            "SSL Certificate Expiration Alert",
            "Certificate expiration date could not be checked.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Check the certificate manually or through certificate monitoring.",
            "CWE-295",
            "TLS"
        )


# ============================================================
# 21. SUBRESOURCE INTEGRITY
# ============================================================

def check_sri(response):
    content_type = response.headers.get("Content-Type", "").lower()

    if "html" not in content_type:
        return make_finding(
            "Subresource Integrity (SRI)",
            "Checks external JavaScript resources for integrity attributes.",
            "INFO",
            "INFO",
            "Final response was not identified as HTML.",
            "Use SRI on trusted external scripts where appropriate.",
            "CWE-829",
            "Frontend Security"
        )

    try:
        body = response.text

        script_tags = re.findall(
            r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>",
            body,
            flags=re.I
        )

        if not script_tags:
            return make_finding(
                "Subresource Integrity (SRI)",
                "No external script tags were observed.",
                "INFO",
                "INFO",
                "External <script src=...> tags: 0",
                "Use SRI for appropriate third-party script resources.",
                "CWE-829",
                "Frontend Security"
            )

        missing = []
        checked = 0

        # Find individual script tags.
        tags = re.findall(
            r"<script\b[^>]*>",
            body,
            flags=re.I
        )

        for tag in tags:
            src_match = re.search(
                r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]",
                tag,
                flags=re.I
            )

            if not src_match:
                continue

            src = src_match.group(1)
            full_url = urljoin(response.url, src)

            parsed = urlparse(full_url)

            is_external = (
                parsed.hostname
                and parsed.hostname != get_hostname(response.url)
            )

            if not is_external:
                continue

            checked += 1

            has_integrity = re.search(
                r"\bintegrity\s*=\s*['\"][^'\"]+['\"]",
                tag,
                flags=re.I
            )

            if not has_integrity:
                missing.append(full_url)

        if missing:
            return make_finding(
                "Subresource Integrity (SRI)",
                f"{len(missing)} external script(s) were found without integrity attributes.",
                "LOW",
                "WARNING",
                " | ".join(missing[:10]),
                "Add an appropriate integrity hash and crossorigin configuration for trusted external scripts.",
                "CWE-829",
                "Frontend Security"
            )

        return make_finding(
            "Subresource Integrity (SRI)",
            "External scripts were checked for integrity attributes.",
            "INFO",
            "PASS",
            f"External scripts checked: {checked}",
            "Continue using SRI for third-party scripts where supported.",
            "CWE-829",
            "Frontend Security"
        )

    except Exception as exc:
        return make_finding(
            "Subresource Integrity (SRI)",
            "SRI analysis could not be completed.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Review third-party JavaScript resources manually.",
            "CWE-829",
            "Frontend Security"
        )


# ============================================================
# 22. OPEN PORT DETECTION
# ============================================================

def check_open_ports(response):
    hostname = get_hostname(response.url)

    if not hostname:
        return make_finding(
            "Open Port Detection",
            "Checks a limited set of common TCP service ports.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Provide a valid hostname.",
            "CWE-668",
            "Network Exposure"
        )

    open_ports = []

    for port, service in COMMON_PORTS.items():

        # Avoid duplicate test for the already-used HTTPS/HTTP port.
        try:
            with socket.create_connection(
                (hostname, port),
                timeout=PORT_TIMEOUT
            ):
                open_ports.append(
                    f"{port}/{service}"
                )
        except Exception:
            continue

    high_risk_services = {
        "FTP",
        "Telnet",
        "SMB",
        "MySQL",
        "PostgreSQL",
        "Redis"
    }

    risky = []

    for value in open_ports:
        service = value.split("/", 1)[1]

        if service in high_risk_services:
            risky.append(value)

    if risky:
        return make_finding(
            "Open Port Detection",
            "One or more potentially sensitive service ports responded.",
            "HIGH",
            "WARNING",
            "Open: " + ", ".join(risky),
            (
                "Confirm that these services are intentionally exposed. "
                "Restrict administration/database services with firewall rules, "
                "VPNs or private networking where possible."
            ),
            "CWE-668",
            "Network Exposure"
        )

    if open_ports:
        return make_finding(
            "Open Port Detection",
            "Common TCP ports were checked for network exposure.",
            "INFO",
            "INFO",
            "Open ports: " + ", ".join(open_ports),
            "Verify that every exposed service is intentional and securely configured.",
            "CWE-668",
            "Network Exposure"
        )

    return make_finding(
        "Open Port Detection",
        "No tested common TCP service ports responded.",
        "INFO",
        "PASS",
        "No common tested ports responded.",
        "Continue limiting unnecessary public services.",
        "CWE-668",
        "Network Exposure"
    )


# ============================================================
# 23. SUBDOMAIN ENUMERATION
# ============================================================

def check_subdomains(response):
    hostname = get_hostname(response.url)

    if not hostname:
        return make_finding(
            "Subdomain Enumeration",
            "Checks a limited list of common subdomain names.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Provide a valid hostname.",
            "CWE-200",
            "DNS Intelligence"
        )

    # Avoid enumerating IP addresses.
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        return make_finding(
            "Subdomain Enumeration",
            "Common subdomain enumeration requires a DNS hostname.",
            "INFO",
            "INFO",
            "Target is an IP address.",
            "Use a hostname for DNS-based subdomain checks.",
            "CWE-200",
            "DNS Intelligence"
        )

    discovered = []

    # Find base domain.
    parts = hostname.split(".")

    if len(parts) < 2:
        base = hostname
    else:
        base = ".".join(parts[-2:])

    for prefix in COMMON_SUBDOMAINS:
        candidate = f"{prefix}.{base}"

        try:
            socket.gethostbyname(candidate)
            discovered.append(candidate)
        except Exception:
            pass

    if discovered:
        return make_finding(
            "Subdomain Enumeration",
            f"{len(discovered)} common subdomain(s) resolved.",
            "INFO",
            "INFO",
            ", ".join(discovered),
            (
                "Review discovered subdomains and remove unused or forgotten "
                "development/staging hosts."
            ),
            "CWE-200",
            "DNS Intelligence"
        )

    return make_finding(
        "Subdomain Enumeration",
        "No tested common subdomains resolved.",
        "INFO",
        "INFO",
        "No common candidates resolved.",
        "Keep DNS records clean and remove unused hosts.",
        "CWE-200",
        "DNS Intelligence"
    )


# ============================================================
# SCAN ENGINE
# ============================================================

def audit_website(target, profile="full"):

    started = time.time()

    target = normalize_url(target)

    if not target:
        raise ValueError("Please enter a valid website URL.")

    if profile not in SCAN_PROFILES:
        profile = "full"

    response = requests.get(
        target,
        headers={
            "User-Agent": (
                "Security-Audit-Console/6.0 "
                "(authorized defensive security assessment)"
            ),
            "Accept": "*/*"
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True
    )

    findings = []

    # 1
    findings.append(check_https(response))

    # 2-5
    findings.extend(check_required_headers(response))

    # 6
    findings.append(check_server_disclosure(response))

    # 7
    findings.append(check_cookie_security(response))

    # 8
    findings.append(check_cors(response))

    # 9
    findings.append(check_permissions_policy(response))

    # 10
    findings.append(check_tls_certificate(response))

    # 11
    findings.append(check_dns(response))

    # 12
    findings.append(check_redirect_chain(response))

    # 13
    findings.append(check_x_xss(response))

    # 14
    findings.append(check_referrer_policy(response))

    # 15
    findings.append(check_coop(response))

    # 16
    findings.append(check_coep(response))

    # 17
    findings.append(check_framework_disclosure(response))

    # 18
    findings.append(check_tls_protocol(response))

    # 19
    findings.append(check_weak_cipher(response))

    # 20
    findings.append(check_certificate_expiry(response))

    # 21
    findings.append(check_sri(response))

    # 22 only on full scan
    if SCAN_PROFILES[profile]["ports"]:
        findings.append(check_open_ports(response))
    else:
        findings.append(
            make_finding(
                "Open Port Detection",
                "Checks a limited set of common TCP service ports.",
                "INFO",
                "INFO",
                "Skipped for this scan profile.",
                "Use Full Scan for the network exposure check.",
                "CWE-668",
                "Network Exposure"
            )
        )

    # 23
    if SCAN_PROFILES[profile]["subdomains"]:
        findings.append(check_subdomains(response))
    else:
        findings.append(
            make_finding(
                "Subdomain Enumeration",
                "Checks a limited list of common subdomain names.",
                "INFO",
                "INFO",
                "Skipped for this scan profile.",
                "Use Full Scan or Passive Intelligence for DNS enumeration.",
                "CWE-200",
                "DNS Intelligence"
            )
        )

    score = 100

    deductions = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 4,
        "INFO": 0
    }

    for item in findings:

        if item["status"] == "FAIL":
            score -= deductions.get(item["severity"], 10)

        elif item["status"] == "WARNING":
            score -= deductions.get(item["severity"], 4)

    score = max(0, min(100, score))

    passed = sum(
        1 for x in findings
        if x["status"] == "PASS"
    )

    failed = sum(
        1 for x in findings
        if x["status"] == "FAIL"
    )

    warnings = sum(
        1 for x in findings
        if x["status"] == "WARNING"
    )

    info = sum(
        1 for x in findings
        if x["status"] == "INFO"
    )

    high = sum(
        1 for x in findings
        if x["severity"] == "HIGH"
        and x["status"] in ["FAIL", "WARNING"]
    )

    medium = sum(
        1 for x in findings
        if x["severity"] == "MEDIUM"
        and x["status"] in ["FAIL", "WARNING"]
    )

    low = sum(
        1 for x in findings
        if x["severity"] == "LOW"
        and x["status"] in ["FAIL", "WARNING"]
    )

    if high > 0:
        risk = "CRITICAL"
    elif medium >= 2:
        risk = "HIGH"
    elif medium == 1 or low >= 3:
        risk = "MEDIUM"
    elif low > 0:
        risk = "LOW"
    else:
        risk = "MINIMAL"

    if failed > 0:
        overall = "VULNERABLE"
    elif warnings > 0:
        overall = "SECURE WITH WARNINGS"
    else:
        overall = "SECURE"

    duration = round(
        time.time() - started,
        2
    )

    result = {
        "scan_id": uuid.uuid4().hex[:12],
        "target": target,
        "final_url": response.url,
        "profile": profile,
        "profile_label": SCAN_PROFILES[profile]["label"],
        "scan_time": human_time(),
        "timestamp": now_iso(),
        "duration": duration,
        "score": score,
        "overall": overall,
        "risk": risk,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "info": info,
        "high": high,
        "medium": medium,
        "low": low,
        "response_status": response.status_code,
        "redirect_count": len(response.history),
        "feature_count": len(findings),
        "features": findings,
        "engine": APP_VERSION
    }

    return result


# ============================================================
# HISTORY
# ============================================================

def load_history():
    data = load_json(
        HISTORY_FILE,
        []
    )

    return data if isinstance(data, list) else []


def save_scan(result):

    history = load_history()

    history.insert(
        0,
        result
    )

    history = history[:MAX_HISTORY]

    save_json(
        HISTORY_FILE,
        history
    )


def get_scan(scan_id):

    for item in load_history():

        if item.get("scan_id") == scan_id:
            return item

    return None


# ============================================================
# SETTINGS
# ============================================================

def get_settings():

    settings = load_json(
        SETTINGS_FILE,
        {
            "plan": "PRO",
            "monthly_scan_limit": 500
        }
    )

    return settings


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1.0">

<title>Security Audit Console</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:#070b12;
    color:#e9eef5;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

body:before{
    content:"";
    position:fixed;
    inset:0;
    pointer-events:none;
    background:
        linear-gradient(rgba(255,255,255,.014) 1px,transparent 1px),
        linear-gradient(90deg,rgba(255,255,255,.014) 1px,transparent 1px);
    background-size:38px 38px;
}

.container{
    width:min(1500px,94%);
    margin:auto;
}

.topbar{
    display:flex;
    justify-content:space-between;
    align-items:center;
    padding:22px 0;
    border-bottom:1px solid #1e2936;
}

.brand{
    display:flex;
    gap:13px;
    align-items:center;
}

.logo{
    width:46px;
    height:46px;
    border:1px solid #2e9d70;
    border-radius:12px;
    background:#09130f;
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:22px;
}

.brand h1{
    margin:0;
    font-size:21px;
}

.brand p{
    margin:4px 0 0;
    color:#748294;
    letter-spacing:2px;
    font-size:10px;
}

.actions{
    display:flex;
    gap:9px;
    align-items:center;
}

.ready{
    border:1px solid #193d2d;
    color:#6ee0a4;
    background:#09150f;
    padding:9px 12px;
    border-radius:8px;
    font-size:10px;
    font-weight:800;
}

.btn{
    border:1px solid #283545;
    background:#0c121a;
    color:#eaf0f5;
    border-radius:8px;
    padding:10px 14px;
    cursor:pointer;
}

.btn.primary{
    border-color:#2e9d70;
    background:#143728;
    color:#abf1c9;
}

.hero{
    padding:28px 0 18px;
}

.hero h2{
    margin:0 0 8px;
    font-size:29px;
}

.hero p{
    margin:0;
    color:#8190a0;
    line-height:1.6;
    max-width:900px;
}

.scanbox{
    margin-top:20px;
    padding:17px;
    border:1px solid #202c39;
    background:#0a1018;
    border-radius:14px;
}

.formrow{
    display:grid;
    grid-template-columns:1fr 160px 140px;
    gap:10px;
}

input,select{
    width:100%;
    background:#080d14;
    border:1px solid #263343;
    border-radius:8px;
    padding:12px;
    color:#e8eef4;
    outline:none;
}

input:focus,select:focus{
    border-color:#2e9d70;
}

.progress{
    height:5px;
    background:#121b25;
    margin-top:12px;
    border-radius:20px;
    overflow:hidden;
    display:none;
}

.bar{
    width:0;
    height:100%;
    background:#2e9d70;
    transition:.2s;
}

.stats{
    display:grid;
    grid-template-columns:repeat(7,1fr);
    gap:10px;
    margin:18px 0;
}

.stat{
    background:#0a1018;
    border:1px solid #202c39;
    border-radius:12px;
    padding:15px;
}

.stat small{
    color:#708092;
    text-transform:uppercase;
    letter-spacing:1px;
    font-size:9px;
}

.stat strong{
    display:block;
    margin-top:7px;
    font-size:22px;
}

.main{
    display:grid;
    grid-template-columns:minmax(0,1.55fr) minmax(320px,.75fr);
    gap:13px;
}

.card{
    background:#0a1018;
    border:1px solid #202c39;
    border-radius:14px;
    overflow:hidden;
}

.head{
    padding:14px 16px;
    border-bottom:1px solid #1d2733;
    display:flex;
    justify-content:space-between;
    align-items:center;
}

.head h3{
    margin:0;
    font-size:14px;
}

.head span{
    color:#748293;
    font-size:10px;
}

.table{
    overflow:auto;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,td{
    text-align:left;
    padding:12px 13px;
    border-bottom:1px solid #18222e;
    font-size:11px;
    vertical-align:top;
}

th{
    color:#6f7d8d;
    font-size:9px;
    text-transform:uppercase;
    letter-spacing:1px;
}

.badge{
    display:inline-block;
    padding:5px 7px;
    border-radius:6px;
    font-weight:800;
    font-size:9px;
}

.pass{
    color:#7ce2a7;
    background:#0c291b;
}

.warning{
    color:#ffd17b;
    background:#2d2413;
}

.fail{
    color:#ff929c;
    background:#32161b;
}

.info{
    color:#9ac2f5;
    background:#152439;
}

.detail{
    padding:17px;
}

.empty{
    color:#718091;
    line-height:1.7;
    text-align:center;
    padding:35px 10px;
}

.meta{
    display:flex;
    gap:7px;
    flex-wrap:wrap;
    margin:10px 0;
}

.meta span{
    padding:5px 7px;
    border:1px solid #253140;
    border-radius:6px;
    color:#8998a8;
    font-size:9px;
}

.section{
    margin-top:16px;
}

.section label{
    display:block;
    color:#718091;
    font-size:9px;
    letter-spacing:1.2px;
    margin-bottom:5px;
}

.section p{
    margin:0;
    color:#c8d1db;
    font-size:11px;
    line-height:1.65;
    word-break:break-word;
}

.feature-number{
    color:#687787;
    width:30px;
}

.feature-title{
    font-weight:700;
    color:#e2e9ef;
}

.footer{
    margin:30px 0 40px;
    border-top:1px solid #1d2733;
    padding-top:18px;
    display:flex;
    justify-content:space-between;
    align-items:center;
    color:#718091;
    font-size:10px;
}

.profile{
    display:flex;
    align-items:center;
    gap:9px;
}

.profile img{
    width:38px;
    height:38px;
    border-radius:50%;
    object-fit:cover;
    border:1px solid #2b3948;
}

.modal{
    display:none;
    position:fixed;
    inset:0;
    background:rgba(0,0,0,.72);
    align-items:center;
    justify-content:center;
    z-index:100;
    padding:20px;
}

.modalbox{
    width:min(420px,100%);
    background:#0a1018;
    border:1px solid #263546;
    border-radius:15px;
    padding:25px;
}

.modalprofile{
    text-align:center;
}

.modalprofile img{
    width:92px;
    height:92px;
    border-radius:50%;
    object-fit:cover;
    border:1px solid #2e9d70;
}

.modalprofile h3{
    margin:13px 0 4px;
}

.muted{
    color:#718091;
}

@media(max-width:1100px){
    .stats{
        grid-template-columns:repeat(4,1fr);
    }

    .main{
        grid-template-columns:1fr;
    }
}

@media(max-width:700px){
    .formrow{
        grid-template-columns:1fr;
    }

    .stats{
        grid-template-columns:repeat(2,1fr);
    }

    .ready{
        display:none;
    }

    .topbar{
        align-items:flex-start;
    }

    .footer{
        flex-direction:column;
        align-items:flex-start;
        gap:12px;
    }
}

</style>

</head>

<body>

<div class="container">

<div class="topbar">

<div class="brand">

<div class="logo">🛡️</div>

<div>

<h1>Security Audit Console</h1>
<p>SCAN • ANALYZE • PROTECT</p>

</div>

</div>

<div class="actions">

<div class="ready">
● SCANNER READY
</div>

<button class="btn" onclick="openContact()">
Contact Us
</button>

</div>

</div>


<div class="hero">

<h2>Professional Web Security Assessment</h2>

<p>
Passive web security auditing with transport security,
security headers, cookies, CORS, TLS, DNS,
frontend integrity, network exposure and subdomain intelligence.
</p>


<div class="scanbox">

<form method="POST" onsubmit="startProgress()">

<div class="formrow">

<input
name="url"
placeholder="https://example.com"
required
>

<select name="profile">

<option value="quick">
Quick Scan
</option>

<option value="full" selected>
Full Scan — 23 Checks
</option>

<option value="passive">
Passive Intelligence
</option>

</select>

<button
class="btn primary"
type="submit"
>
🔍 Run Assessment
</button>

</div>

<div class="progress" id="progress">
<div class="bar" id="bar"></div>
</div>

</form>

<div style="margin-top:10px">

<a
class="btn"
href="/history"
style="display:inline-block"
>
Scan History
</a>

<a
class="btn"
href="/api/history"
style="display:inline-block"
>
JSON API
</a>

</div>

</div>

</div>


{% if result %}

<div class="stats">

<div class="stat">
<small>Score</small>
<strong>{{ result.score }}/100</strong>
</div>

<div class="stat">
<small>Passed</small>
<strong>{{ result.passed }}</strong>
</div>

<div class="stat">
<small>Failed</small>
<strong>{{ result.failed }}</strong>
</div>

<div class="stat">
<small>Warnings</small>
<strong>{{ result.warnings }}</strong>
</div>

<div class="stat">
<small>High</small>
<strong>{{ result.high }}</strong>
</div>

<div class="stat">
<small>Medium</small>
<strong>{{ result.medium }}</strong>
</div>

<div class="stat">
<small>Low</small>
<strong>{{ result.low }}</strong>
</div>

</div>


<div class="main">

<div class="card">

<div class="head">

<h3>
Security Findings
</h3>

<span>
{{ result.feature_count }} Features
</span>

</div>


<div class="table">

<table>

<thead>

<tr>

<th>#</th>
<th>Feature</th>
<th>Severity</th>
<th>Status</th>
<th>Details</th>

</tr>

</thead>

<tbody>

{% for item in result.features %}

<tr
onclick='showFinding({{ item|tojson }})'
style="cursor:pointer"
>

<td class="feature-number">
{{ loop.index }}
</td>

<td class="feature-title">
{{ item.name }}
</td>

<td>
<span class="badge {{ item.severity|lower }}">
{{ item.severity }}
</span>
</td>

<td>
<span class="badge {{ item.status|lower }}">
{{ item.status }}
</span>
</td>

<td>
View Details →
</td>

</tr>

{% endfor %}

</tbody>

</table>

</div>

</div>


<div class="card">

<div class="head">

<h3>
Finding Intelligence
</h3>

<span>
Evidence / Remediation
</span>

</div>

<div id="detailPanel" class="detail">

<div class="empty">
Select a finding to view its explanation,
evidence and recommended fix.
</div>

</div>

</div>

</div>


<div class="card" style="margin-top:13px">

<div class="head">

<h3>
Assessment Summary
</h3>

<span>
{{ result.scan_time }}
</span>

</div>

<div class="detail">

<div class="meta">

<span>
Status: {{ result.overall }}
</span>

<span>
Risk: {{ result.risk }}
</span>

<span>
Profile: {{ result.profile_label }}
</span>

<span>
HTTP: {{ result.response_status }}
</span>

<span>
Redirects: {{ result.redirect_count }}
</span>

<span>
Duration: {{ result.duration }}s
</span>

<span>
Scan ID: {{ result.scan_id }}
</span>

</div>


<div class="section">

<label>TARGET</label>

<p>
{{ result.final_url }}
</p>

</div>


<div style="margin-top:13px">

<a
class="btn primary"
href="/report?id={{ result.scan_id }}"
style="display:inline-block"
>
Open Report
</a>

<a
class="btn"
href="/download-report?id={{ result.scan_id }}"
style="display:inline-block"
>
Download Report
</a>

</div>

</div>

</div>

{% endif %}


{% if error %}

<div class="card" style="margin-top:15px">

<div class="detail">

<h3>
Scan Error
</h3>

<p class="muted">
{{ error }}
</p>

</div>

</div>

{% endif %}


<div class="footer">

<div>
Security Audit Console V6 · 23 Security Features
</div>

<div class="profile">

<img
src="/static/ahmed.jpg"
alt="Ahmed Sidhu"
onerror="this.style.display='none'"
>

<div>
<strong style="color:#ccd5de">
Ahmed Sidhu
</strong>

<div>
Security Enthusiast
</div>

</div>

</div>

</div>

</div>


<div class="modal" id="contactModal">

<div class="modalbox">

<div
onclick="closeContact()"
style="float:right;cursor:pointer;color:#758495"
>
✕
</div>

<div class="modalprofile">

<img
src="/static/ahmed.jpg"
alt="Ahmed Sidhu"
onerror="this.style.display='none'"
>

<h3>
Ahmed Sidhu
</h3>

<p class="muted">
Security Enthusiast
</p>

<div
style="
margin-top:16px;
border:1px solid #263342;
border-radius:8px;
padding:12px;
"
>
sidhuahmed9886@gmail.com
</div>

</div>

</div>

</div>


<script>

function openContact(){
    document.getElementById("contactModal").style.display="flex";
}

function closeContact(){
    document.getElementById("contactModal").style.display="none";
}

window.onclick=function(event){

    const modal=document.getElementById("contactModal");

    if(event.target===modal){
        modal.style.display="none";
    }

};


function startProgress(){

    const progress=document.getElementById("progress");
    const bar=document.getElementById("bar");

    progress.style.display="block";

    let value=0;

    const timer=setInterval(function(){

        value += Math.floor(Math.random()*8)+4;

        if(value>=94){

            value=94;

            clearInterval(timer);

        }

        bar.style.width=value+"%";

    },180);

}


function esc(value){

    return String(value ?? "")
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");

}


function showFinding(item){

    const panel=document.getElementById("detailPanel");

    panel.innerHTML=`

        <h3>${esc(item.name)}</h3>

        <div class="meta">

            <span>
            Severity: ${esc(item.severity)}
            </span>

            <span>
            Status: ${esc(item.status)}
            </span>

            <span>
            CWE: ${esc(item.cwe || "-")}
            </span>

            <span>
            Category: ${esc(item.category || "-")}
            </span>

        </div>


        <div class="section">

            <label>WHY IT MATTERS</label>

            <p>
            ${esc(item.description)}
            </p>

        </div>


        <div class="section">

            <label>EVIDENCE</label>

            <p>
            ${esc(item.evidence || "-")}
            </p>

        </div>


        <div class="section">

            <label>HOW TO FIX</label>

            <p>
            ${esc(item.remediation || "-")}
            </p>

        </div>
    `;

}

</script>

</body>
</html>
"""


# ============================================================
# REPORT
# ============================================================

REPORT_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<title>Security Audit Report</title>

<style>

body{
    margin:0;
    background:#081018;
    color:#e8eef5;
    font-family:Arial,Segoe UI,sans-serif;
}

.wrap{
    width:min(1150px,93%);
    margin:30px auto;
}

.card{
    background:#0c141d;
    border:1px solid #223040;
    border-radius:14px;
    padding:20px;
    margin-bottom:12px;
}

.score{
    font-size:46px;
    font-weight:800;
    margin-top:14px;
}

.muted{
    color:#768596;
}

.grid{
    display:grid;
    grid-template-columns:repeat(5,1fr);
    gap:9px;
}

.box{
    border:1px solid #223040;
    padding:13px;
    border-radius:9px;
}

.finding{
    border:1px solid #223040;
    border-radius:10px;
    padding:16px;
    margin-top:10px;
}

.row{
    display:grid;
    grid-template-columns:170px 1fr;
    gap:10px;
    margin-top:8px;
}

.label{
    color:#748395;
    font-size:10px;
    text-transform:uppercase;
}

@media(max-width:800px){

    .grid{
        grid-template-columns:repeat(2,1fr);
    }

    .row{
        grid-template-columns:1fr;
    }

}

</style>

</head>

<body>

<div class="wrap">


<div class="card">

<h1>
Security Audit Console
</h1>

<div class="muted">
SCAN • ANALYZE • PROTECT
</div>

<div style="margin-top:15px">
{{ result.final_url }}
</div>

<div class="score">
{{ result.score }}/100
</div>

<div class="muted">
{{ result.overall }} · Risk: {{ result.risk }}
</div>

</div>


<div class="grid">

<div class="box">
Passed<br>
<strong>{{ result.passed }}</strong>
</div>

<div class="box">
Failed<br>
<strong>{{ result.failed }}</strong>
</div>

<div class="box">
Warnings<br>
<strong>{{ result.warnings }}</strong>
</div>

<div class="box">
High<br>
<strong>{{ result.high }}</strong>
</div>

<div class="box">
Low<br>
<strong>{{ result.low }}</strong>
</div>

</div>


<div class="card">

<h2>
Scan Details
</h2>

<div class="row">

<div class="label">
Scan ID
</div>

<div>
{{ result.scan_id }}
</div>

</div>


<div class="row">

<div class="label">
Profile
</div>

<div>
{{ result.profile_label }}
</div>

</div>


<div class="row">

<div class="label">
Scan Time
</div>

<div>
{{ result.scan_time }}
</div>

</div>


<div class="row">

<div class="label">
Duration
</div>

<div>
{{ result.duration }} seconds
</div>

</div>

</div>


<div class="card">

<h2>
23 Security Features
</h2>


{% for item in result.features %}

<div class="finding">

<h3>
{{ loop.index }}. {{ item.name }}
</h3>

<div class="row">
<div class="label">Status</div>
<div>{{ item.status }}</div>
</div>

<div class="row">
<div class="label">Severity</div>
<div>{{ item.severity }}</div>
</div>

<div class="row">
<div class="label">CWE</div>
<div>{{ item.cwe or "-" }}</div>
</div>

<div class="row">
<div class="label">Category</div>
<div>{{ item.category }}</div>
</div>

<div class="row">
<div class="label">Explanation</div>
<div>{{ item.description }}</div>
</div>

<div class="row">
<div class="label">Evidence</div>
<div style="white-space:pre-wrap">
{{ item.evidence or "-" }}
</div>
</div>

<div class="row">
<div class="label">How To Fix</div>
<div>{{ item.remediation }}</div>
</div>

</div>

{% endfor %}


</div>


<div class="muted" style="margin-top:20px">
Generated by Security Audit Console V6
</div>


</div>

</body>
</html>
"""


# ============================================================
# ROUTES
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        profile = request.form.get(
            "profile",
            "full"
        ).strip()

        try:

            result = audit_website(
                url,
                profile
            )

            save_scan(result)

        except requests.exceptions.SSLError as exc:

            error = (
                "SSL/TLS connection error: "
                + str(exc)
            )

        except requests.exceptions.Timeout:

            error = (
                "Website request timed out."
            )

        except requests.exceptions.RequestException as exc:

            error = (
                "Website request failed: "
                + str(exc)
            )

        except Exception as exc:

            error = (
                "Scanner error: "
                + str(exc)
            )

    return render_template_string(
        DASHBOARD_HTML,
        result=result,
        error=error
    )


# ============================================================
# REPORT ROUTE
# ============================================================

@app.route("/report")
def report():

    scan_id = request.args.get(
        "id",
        ""
    ).strip()

    result = get_scan(scan_id)

    if not result:
        return "Scan not found.", 404

    return render_template_string(
        REPORT_HTML,
        result=result
    )


# ============================================================
# DOWNLOAD REPORT
# ============================================================

@app.route("/download-report")
def download_report():

    scan_id = request.args.get(
        "id",
        ""
    ).strip()

    result = get_scan(scan_id)

    if not result:
        return "Scan not found.", 404

    html_report = render_template_string(
        REPORT_HTML,
        result=result
    )

    response = make_response(
        html_report
    )

    response.headers[
        "Content-Type"
    ] = "text/html; charset=utf-8"

    response.headers[
        "Content-Disposition"
    ] = (
        f'attachment; '
        f'filename="security-report-{scan_id}.html"'
    )

    return response


# ============================================================
# HISTORY PAGE
# ============================================================

@app.route("/history")
def history():

    scans = load_history()

    rows = []

    for scan in scans:

        rows.append(
            f"""
            <tr>
                <td>{html.escape(str(scan.get("scan_time","")))}</td>
                <td>{html.escape(str(scan.get("target","")))}</td>
                <td>{scan.get("score",0)}/100</td>
                <td>{html.escape(str(scan.get("risk","")))}</td>
                <td>{html.escape(str(scan.get("profile_label","")))}</td>
                <td>
                    <a href="/report?id={scan.get("scan_id","")}"
                       style="color:#76dfa8">
                       Open
                    </a>
                </td>
            </tr>
            """
        )

    page = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <title>Scan History</title>

    <style>

    body{{
        margin:0;
        background:#070b12;
        color:#e8eef5;
        font-family:Arial,Segoe UI,sans-serif;
    }}

    .wrap{{
        width:min(1250px,94%);
        margin:30px auto;
    }}

    .card{{
        background:#0a1018;
        border:1px solid #202c39;
        border-radius:14px;
        overflow:auto;
    }}

    .head{{
        padding:18px;
        border-bottom:1px solid #202c39;
    }}

    table{{
        width:100%;
        border-collapse:collapse;
    }}

    th,td{{
        padding:12px;
        border-bottom:1px solid #18222d;
        text-align:left;
        font-size:11px;
    }}

    th{{
        color:#708091;
        text-transform:uppercase;
        font-size:9px;
    }}

    a{{
        color:#76dfa8;
        text-decoration:none;
    }}

    .back{{
        display:inline-block;
        padding:9px 12px;
        border:1px solid #263342;
        border-radius:8px;
        margin-bottom:13px;
    }}

    </style>

    </head>

    <body>

    <div class="wrap">

    <a class="back" href="/">
    ← Dashboard
    </a>

    <div class="card">

    <div class="head">
    <h2>Scan History</h2>
    <div style="color:#708091">
    {len(scans)} saved scans
    </div>
    </div>

    <table>

    <tr>
    <th>Time</th>
    <th>Target</th>
    <th>Score</th>
    <th>Risk</th>
    <th>Profile</th>
    <th>Report</th>
    </tr>

    {''.join(rows) if rows else '<tr><td colspan="6">No scans yet.</td></tr>'}

    </table>

    </div>

    </div>

    </body>
    </html>
    """

    return page


# ============================================================
# JSON HISTORY API
# ============================================================

@app.route("/api/history")
def api_history():

    scans = load_history()

    return jsonify({
        "success": True,
        "count": len(scans),
        "scans": scans
    })


# ============================================================
# API SCAN
# ============================================================

@app.route("/api/scan", methods=["POST"])
def api_scan():

    data = request.get_json(
        silent=True
    ) or {}

    url = str(
        data.get("url", "")
    ).strip()

    profile = str(
        data.get("profile", "full")
    ).strip()

    if not url:
        return jsonify({
            "success": False,
            "error": "URL required."
        }), 400

    try:

        result = audit_website(
            url,
            profile
        )

        save_scan(result)

        return jsonify({
            "success": True,
            "scan": result
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# PROJECTS
# ============================================================

@app.route("/api/projects", methods=["GET", "POST"])
def projects():

    projects = load_json(
        PROJECTS_FILE,
        []
    )

    if request.method == "GET":

        return jsonify({
            "success": True,
            "projects": projects
        })

    data = request.get_json(
        silent=True
    ) or {}

    name = str(
        data.get("name", "")
    ).strip()

    target = str(
        data.get("target", "")
    ).strip()

    if not name:
        return jsonify({
            "success": False,
            "error": "Project name required."
        }), 400

    item = {
        "id": uuid.uuid4().hex[:10],
        "name": name,
        "target": target,
        "created": human_time()
    }

    projects.insert(
        0,
        item
    )

    save_json(
        PROJECTS_FILE,
        projects
    )

    return jsonify({
        "success": True,
        "project": item
    })


# ============================================================
# SETTINGS
# ============================================================

@app.route("/api/settings")
def settings():

    config = get_settings()

    return jsonify({
        "success": True,
        "product": APP_NAME,
        "version": APP_VERSION,
        "plan": config.get("plan", "PRO"),
        "monthly_scan_limit": config.get(
            "monthly_scan_limit",
            500
        ),
        "features": 23
    })


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "product": APP_NAME,
        "version": APP_VERSION,
        "features": 23,
        "time": now_iso()
    })


# ============================================================
# SECURITY HEADERS FOR OUR OWN APP
# ============================================================

@app.after_request
def security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    return response


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
