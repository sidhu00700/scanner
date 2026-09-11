from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    url_for,
    session,
    jsonify,
    make_response
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import sqlite3
import requests
import ssl
import socket
import json
import os
import re
import uuid
import time
import smtplib
import html
from email.message import EmailMessage
from urllib.parse import (
    urlparse,
    urljoin
)
from datetime import (
    datetime,
    timezone,
    timedelta
)


# ============================================================
# ETHICALGUARD
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "CHANGE_THIS_SECRET_KEY"
)

APP_NAME = "EthicalGuard"
APP_VERSION = "8.0"

PREMIUM_EMAIL = "ahmedsidhu97@gmail.com"

DATABASE = os.environ.get(
    "DATABASE_PATH",
    "ethicalguard.db"
)

REQUEST_TIMEOUT = 12
PORT_TIMEOUT = 0.8

FREE_SCAN_LIMIT = 8

CRON_SECRET = os.environ.get(
    "CRON_SECRET",
    "CHANGE_THIS_CRON_SECRET"
)


# ============================================================
# SCAN PROFILES
# ============================================================

SCAN_PROFILES = {
    "quick": {
        "label": "Quick Scan",
        "ports": False,
        "subdomains": False
    },
    "full": {
        "label": "Full Scan — 23 Checks",
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
# COMMON PORTS
# ============================================================

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


# ============================================================
# COMMON SUBDOMAINS
# ============================================================

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


# ============================================================
# DATABASE
# ============================================================

def get_db():

    connection = sqlite3.connect(
        DATABASE,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db():

    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT NOT NULL DEFAULT 'FREE',
            free_scans_remaining INTEGER NOT NULL DEFAULT 8,
            premium_until TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            target TEXT NOT NULL,
            final_url TEXT,
            profile TEXT NOT NULL,
            score INTEGER NOT NULL,
            overall TEXT NOT NULL,
            risk TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            duration REAL,
            data_json TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS monitored_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            profile TEXT NOT NULL,
            frequency TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            last_score INTEGER,
            last_risk TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    connection.commit()
    connection.close()


init_db()


# ============================================================
# BASIC HELPERS
# ============================================================

def now_text():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def now_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


def esc(value):
    return html.escape(
        str(value if value is not None else "")
    )


def normalize_url(value):

    if not value:
        return ""

    value = value.strip()

    if not re.match(
        r"^https?://",
        value,
        re.I
    ):
        value = "https://" + value

    parsed = urlparse(value)

    if not parsed.netloc:
        return ""

    return value


def hostname_of(url):

    try:
        return (
            urlparse(url).hostname
            or ""
        )
    except Exception:
        return ""


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
# AUTH
# ============================================================

def current_user():

    user_id = session.get(
        "user_id"
    )

    if not user_id:
        return None

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    return user


def valid_username(username):

    return bool(
        re.match(
            r"^[A-Za-z0-9_.-]{3,30}$",
            username
        )
    )


def valid_email(email):

    return bool(
        re.match(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            email
        )
    )


def create_user(
    username,
    email,
    password
):

    connection = get_db()

    try:

        connection.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                plan,
                free_scans_remaining,
                created_at
            )
            VALUES (?, ?, ?, 'FREE', ?, ?)
            """,
            (
                username,
                email.lower(),
                generate_password_hash(password),
                FREE_SCAN_LIMIT,
                now_text()
            )
        )

        connection.commit()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email.lower(),)
        ).fetchone()

        return user

    except sqlite3.IntegrityError:

        return None

    finally:

        connection.close()


def authenticate(
    identifier,
    password
):

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE lower(email) = lower(?)
           OR lower(username) = lower(?)
        """,
        (
            identifier,
            identifier
        )
    ).fetchone()

    if not user:

        connection.close()
        return None

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        connection.close()
        return None

    connection.execute(
        """
        UPDATE users
        SET last_login = ?
        WHERE id = ?
        """,
        (
            now_text(),
            user["id"]
        )
    )

    connection.commit()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user["id"],)
    ).fetchone()

    connection.close()

    return user


# ============================================================
# FREE / PREMIUM
# ============================================================

def user_is_premium(user):

    if not user:
        return False

    if user["plan"] != "PREMIUM":
        return False

    premium_until = user["premium_until"]

    if not premium_until:
        return True

    try:

        end = datetime.fromisoformat(
            premium_until
        )

        return datetime.now(
            timezone.utc
        ) < end

    except Exception:

        return True


def consume_free_scan(user_id):

    connection = get_db()

    row = connection.execute(
        """
        SELECT free_scans_remaining
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not row:

        connection.close()
        return False

    remaining = row[
        "free_scans_remaining"
    ]

    if remaining <= 0:

        connection.close()
        return False

    connection.execute(
        """
        UPDATE users
        SET free_scans_remaining = ?
        WHERE id = ?
        """,
        (
            remaining - 1,
            user_id
        )
    )

    connection.commit()
    connection.close()

    return True


def can_user_scan(user):

    if not user:
        return True

    if user_is_premium(user):
        return True

    return user[
        "free_scans_remaining"
    ] > 0


# ============================================================
# REQUEST
# ============================================================

def fetch_target(target):

    return requests.get(
        target,
        headers={
            "User-Agent":
                "EthicalGuard/8.0 "
                "(authorized security assessment)",
            "Accept": "*/*"
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True
    )


# ============================================================
# 1. HTTPS
# ============================================================

def check_https(response):

    if urlparse(
        response.url
    ).scheme.lower() == "https":

        return make_finding(
            "HTTPS / SSL",
            "Checks whether the final connection uses HTTPS.",
            "INFO",
            "PASS",
            f"Final URL: {response.url}",
            "Keep HTTPS enabled and redirect HTTP to HTTPS.",
            "CWE-319",
            "Transport Security"
        )

    return make_finding(
        "HTTPS / SSL",
        "Checks whether the final connection uses HTTPS.",
        "HIGH",
        "FAIL",
        f"Final URL: {response.url}",
        "Install a valid TLS certificate and force HTTPS.",
        "CWE-319",
        "Transport Security"
    )


# ============================================================
# 2-5. SECURITY HEADERS
# ============================================================

def check_required_headers(response):

    definitions = [

        (
            "X-Frame-Options",
            "Checks whether the website has protection against being embedded inside another website.",
            "CWE-1021",
            "Add X-Frame-Options: DENY or SAMEORIGIN."
        ),

        (
            "Content-Security-Policy",
            "Controls which scripts, styles and resources a browser is allowed to load.",
            "CWE-693",
            "Deploy an appropriate Content-Security-Policy."
        ),

        (
            "Strict-Transport-Security",
            "Tells browsers to continue using HTTPS.",
            "CWE-319",
            "Add Strict-Transport-Security."
        ),

        (
            "X-Content-Type-Options",
            "Helps prevent browsers from guessing content types.",
            "CWE-16",
            "Add X-Content-Type-Options: nosniff."
        )
    ]

    results = []

    for name, description, cwe, fix in definitions:

        value = response.headers.get(
            name
        )

        if value:

            results.append(
                make_finding(
                    name,
                    description,
                    "INFO",
                    "PASS",
                    f"{name}: {value}",
                    fix,
                    cwe,
                    "Security Headers"
                )
            )

        else:

            results.append(
                make_finding(
                    name,
                    description,
                    "MEDIUM",
                    "FAIL",
                    f"{name}: Not Found",
                    fix,
                    cwe,
                    "Security Headers"
                )
            )

    return results


# ============================================================
# 6. SERVER DISCLOSURE
# ============================================================

def check_server(response):

    value = response.headers.get(
        "Server"
    )

    if value:

        return make_finding(
            "Server Information Disclosure",
            "Checks whether server technology is exposed.",
            "LOW",
            "WARNING",
            f"Server: {value}",
            "Hide unnecessary server/version information.",
            "CWE-200",
            "Information Disclosure"
        )

    return make_finding(
        "Server Information Disclosure",
        "The Server response header was not exposed.",
        "INFO",
        "PASS",
        "Server: Not exposed",
        "Continue hiding unnecessary technology details.",
        "CWE-200",
        "Information Disclosure"
    )


# ============================================================
# 7. COOKIE SECURITY
# ============================================================

def get_cookie_headers(response):

    cookies = []

    try:

        headers = response.raw.headers

        if hasattr(
            headers,
            "get_all"
        ):

            values = headers.get_all(
                "Set-Cookie"
            )

            if values:
                cookies.extend(values)

    except Exception:
        pass

    if not cookies:

        one = response.headers.get(
            "Set-Cookie"
        )

        if one:
            cookies.append(one)

    return cookies


def parse_cookie(value):

    pieces = [
        item.strip()
        for item in value.split(";")
        if item.strip()
    ]

    name = "Unknown"

    if pieces and "=" in pieces[0]:

        name = pieces[0].split(
            "=",
            1
        )[0].strip()

    secure = False
    httponly = False
    samesite = None

    for attr in pieces[1:]:

        lower = attr.lower()

        if lower == "secure":

            secure = True

        elif lower == "httponly":

            httponly = True

        elif lower.startswith(
            "samesite"
        ):

            if "=" in attr:

                samesite = (
                    attr.split(
                        "=",
                        1
                    )[1]
                    .strip()
                    .lower()
                )

            else:

                samesite = True

    return {
        "name": name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite
    }


def check_cookies(response):

    headers = get_cookie_headers(
        response
    )

    if not headers:

        return make_finding(
            "Cookie Security",
            "No Set-Cookie header was observed.",
            "INFO",
            "INFO",
            "Set-Cookie: Not Found",
            "Review session cookies separately.",
            "CWE-614",
            "Cookie Security"
        )

    results = []

    for raw in headers:

        cookie = parse_cookie(
            raw
        )

        missing = []

        if not cookie["secure"]:
            missing.append("Secure")

        if not cookie["httponly"]:
            missing.append("HttpOnly")

        if cookie["samesite"] is None:
            missing.append("SameSite")

        same_none_bad = (
            isinstance(
                cookie["samesite"],
                str
            )
            and cookie["samesite"] == "none"
            and not cookie["secure"]
        )

        if same_none_bad:

            missing.append(
                "Secure required for SameSite=None"
            )

        if same_none_bad:

            status = "FAIL"
            severity = "MEDIUM"

        elif len(missing) >= 2:

            status = "FAIL"
            severity = "MEDIUM"

        elif len(missing) == 1:

            status = "WARNING"
            severity = "LOW"

        else:

            status = "PASS"
            severity = "INFO"

        description = (
            f"Cookie '{cookie['name']}' has all recommended "
            "cookie protections."
            if status == "PASS"
            else
            f"Cookie '{cookie['name']}' needs: "
            + ", ".join(missing)
        )

        evidence = (
            f"{cookie['name']} | "
            f"Secure={cookie['secure']} | "
            f"HttpOnly={cookie['httponly']} | "
            f"SameSite={cookie['samesite'] or 'Missing'}"
        )

        results.append({
            "status": status,
            "severity": severity,
            "description": description,
            "evidence": evidence
        })

    rank = {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4
    }

    highest = "INFO"
    final_status = "PASS"

    for item in results:

        if rank[
            item["severity"]
        ] > rank[highest]:

            highest = item["severity"]

        if item["status"] == "FAIL":

            final_status = "FAIL"

        elif (
            item["status"] == "WARNING"
            and final_status != "FAIL"
        ):

            final_status = "WARNING"

    return make_finding(
        "Cookie Security",
        " ".join(
            x["description"]
            for x in results
        ),
        highest,
        final_status,
        " | ".join(
            x["evidence"]
            for x in results
        ),
        (
            "Use Secure and HttpOnly for sensitive cookies. "
            "Use SameSite=Lax or Strict where appropriate. "
            "SameSite=None requires Secure."
        ),
        "CWE-614",
        "Cookie Security"
    )


# ============================================================
# 8. CORS
# ============================================================

def check_cors(response):

    value = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    if not value:

        return make_finding(
            "CORS Policy",
            "No permissive Access-Control-Allow-Origin header was observed.",
            "INFO",
            "PASS",
            "Access-Control-Allow-Origin: Not Found",
            "Keep CORS limited to trusted origins.",
            "CWE-942",
            "CORS"
        )

    if value.strip() == "*":

        return make_finding(
            "CORS Policy",
            "Wildcard CORS policy was observed.",
            "MEDIUM",
            "WARNING",
            f"Access-Control-Allow-Origin: {value}",
            "Use a trusted origin allow-list for sensitive resources.",
            "CWE-942",
            "CORS"
        )

    return make_finding(
        "CORS Policy",
        "CORS was restricted to a specific origin.",
        "INFO",
        "PASS",
        f"Access-Control-Allow-Origin: {value}",
        "Keep the allow-list restricted.",
        "CWE-942",
        "CORS"
    )


# ============================================================
# 9. PERMISSIONS POLICY
# ============================================================

def check_permissions(response):

    value = response.headers.get(
        "Permissions-Policy"
    )

    if value:

        return make_finding(
            "Permissions-Policy",
            "Controls access to selected browser features.",
            "INFO",
            "PASS",
            f"Permissions-Policy: {value}",
            "Keep browser features restricted.",
            "CWE-16",
            "Browser Security"
        )

    return make_finding(
        "Permissions-Policy",
        "Controls access to selected browser features.",
        "LOW",
        "WARNING",
        "Permissions-Policy: Not Found",
        "Consider adding Permissions-Policy.",
        "CWE-16",
        "Browser Security"
    )


# ============================================================
# TLS
# ============================================================

def certificate_info(host):

    context = ssl.create_default_context()

    with socket.create_connection(
        (host, 443),
        timeout=REQUEST_TIMEOUT
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=host
        ) as secure_sock:

            return (
                secure_sock.getpeercert(),
                secure_sock.cipher(),
                secure_sock.version()
            )


def tls_probe(
    host,
    minimum=None,
    maximum=None
):

    context = ssl.create_default_context()

    if minimum is not None:
        context.minimum_version = minimum

    if maximum is not None:
        context.maximum_version = maximum

    with socket.create_connection(
        (host, 443),
        timeout=PORT_TIMEOUT
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=host
        ) as secure_sock:

            return (
                secure_sock.version(),
                secure_sock.cipher()
            )


# ============================================================
# 10. TLS CERTIFICATE
# ============================================================

def check_tls_certificate(response):

    host = hostname_of(
        response.url
    )

    try:

        cert, cipher, version = certificate_info(
            host
        )

        expiry_text = cert.get(
            "notAfter",
            ""
        )

        if expiry_text:

            expiry = datetime.strptime(
                expiry_text,
                "%b %d %H:%M:%S %Y %Z"
            )

            days = (
                expiry - datetime.utcnow()
            ).days

            return make_finding(
                "TLS Certificate",
                "TLS certificate was successfully inspected.",
                "INFO",
                "PASS",
                (
                    f"TLS={version} | "
                    f"Cipher={cipher[0] if cipher else 'Unknown'} | "
                    f"Expires={expiry.isoformat()} | "
                    f"Days={days}"
                ),
                "Keep certificate renewal monitored.",
                "CWE-295",
                "TLS"
            )

        return make_finding(
            "TLS Certificate",
            "TLS certificate was successfully inspected.",
            "INFO",
            "PASS",
            f"TLS={version}",
            "Continue monitoring TLS.",
            "CWE-295",
            "TLS"
        )

    except ssl.SSLCertVerificationError as exc:

        return make_finding(
            "TLS Certificate",
            "Certificate validation failed.",
            "HIGH",
            "FAIL",
            str(exc),
            "Install a valid trusted certificate.",
            "CWE-295",
            "TLS"
        )

    except Exception as exc:

        return make_finding(
            "TLS Certificate",
            "Certificate details could not be fully inspected.",
            "LOW",
            "WARNING",
            str(exc),
            "Review TLS configuration.",
            "CWE-295",
            "TLS"
        )


# ============================================================
# 11. DNS
# ============================================================

def check_dns(response):

    host = hostname_of(
        response.url
    )

    try:

        records = socket.getaddrinfo(
            host,
            None
        )

        ips = sorted({
            item[4][0]
            for item in records
            if item and item[4]
        })

        return make_finding(
            "DNS Information",
            "Shows public host addresses resolved by EthicalGuard.",
            "INFO",
            "INFO",
            f"{host}: {', '.join(ips)}",
            "Keep DNS records accurate.",
            "CWE-706",
            "DNS"
        )

    except Exception as exc:

        return make_finding(
            "DNS Information",
            "DNS resolution failed.",
            "HIGH",
            "FAIL",
            str(exc),
            "Verify DNS records.",
            "CWE-706",
            "DNS"
        )


# ============================================================
# 12. REDIRECT CHAIN
# ============================================================

def check_redirects(response):

    if not response.history:

        return make_finding(
            "Redirect Chain",
            "Shows redirects followed before reaching the final target.",
            "INFO",
            "INFO",
            response.url,
            "Keep redirects intentional.",
            "CWE-601",
            "Redirects"
        )

    chain = []

    for item in response.history:

        chain.append(
            f"{item.status_code}: {item.url}"
        )

    chain.append(
        f"{response.status_code}: {response.url}"
    )

    if len(response.history) >= 5:

        return make_finding(
            "Redirect Chain",
            "A relatively long redirect chain was detected.",
            "MEDIUM",
            "WARNING",
            " -> ".join(chain),
            "Reduce unnecessary redirect hops.",
            "CWE-601",
            "Redirects"
        )

    return make_finding(
        "Redirect Chain",
        "Shows redirects followed before reaching the final target.",
        "INFO",
        "INFO",
        " -> ".join(chain),
        "Keep redirects intentional.",
        "CWE-601",
        "Redirects"
    )


# ============================================================
# 13. X-XSS
# ============================================================

def check_x_xss(response):

    value = response.headers.get(
        "X-XSS-Protection"
    )

    if value:

        return make_finding(
            "X-XSS-Protection",
            "Checks the legacy browser XSS filter header.",
            "INFO",
            "PASS",
            value,
            "Use CSP as the primary modern protection.",
            "CWE-79",
            "Legacy Browser Security"
        )

    return make_finding(
        "X-XSS-Protection",
        "Checks the legacy browser XSS filter header.",
        "INFO",
        "INFO",
        "Header not observed.",
        "Prioritize a strong CSP.",
        "CWE-79",
        "Legacy Browser Security"
    )


# ============================================================
# 14. REFERRER POLICY
# ============================================================

def check_referrer(response):

    value = response.headers.get(
        "Referrer-Policy"
    )

    if value:

        return make_finding(
            "Referrer-Policy",
            "Controls referral information shared with other sites.",
            "INFO",
            "PASS",
            value,
            "Keep a privacy-conscious policy.",
            "CWE-200",
            "Privacy"
        )

    return make_finding(
        "Referrer-Policy",
        "Controls referral information shared with other sites.",
        "LOW",
        "WARNING",
        "Header not observed.",
        "Consider strict-origin-when-cross-origin.",
        "CWE-200",
        "Privacy"
    )


# ============================================================
# 15. COOP
# ============================================================

def check_coop(response):

    value = response.headers.get(
        "Cross-Origin-Opener-Policy"
    )

    if value:

        return make_finding(
            "Cross-Origin-Opener-Policy (COOP)",
            "Helps isolate the browser context from cross-origin documents.",
            "INFO",
            "PASS",
            value,
            "Keep a suitable COOP policy.",
            "CWE-693",
            "Cross-Origin Isolation"
        )

    return make_finding(
        "Cross-Origin-Opener-Policy (COOP)",
        "Helps isolate the browser context from cross-origin documents.",
        "INFO",
        "INFO",
        "Header not observed.",
        "Consider COOP where isolation is required.",
        "CWE-693",
        "Cross-Origin Isolation"
    )


# ============================================================
# 16. COEP
# ============================================================

def check_coep(response):

    value = response.headers.get(
        "Cross-Origin-Embedder-Policy"
    )

    if value:

        return make_finding(
            "Cross-Origin-Embedder-Policy (COEP)",
            "Controls cross-origin resource embedding.",
            "INFO",
            "PASS",
            value,
            "Keep a suitable COEP policy where required.",
            "CWE-693",
            "Cross-Origin Isolation"
        )

    return make_finding(
        "Cross-Origin-Embedder-Policy (COEP)",
        "Controls cross-origin resource embedding.",
        "INFO",
        "INFO",
        "Header not observed.",
        "Consider COEP where isolation is required.",
        "CWE-693",
        "Cross-Origin Isolation"
    )


# ============================================================
# 17. FRAMEWORK DISCLOSURE
# ============================================================

def check_framework_disclosure(response):

    found = []

    for header in [
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version"
    ]:

        value = response.headers.get(
            header
        )

        if value:

            found.append(
                f"{header}: {value}"
            )

    if found:

        return make_finding(
            "X-Powered-By / Framework Disclosure",
            "Checks whether backend technology details are exposed.",
            "LOW",
            "WARNING",
            " | ".join(found),
            "Remove unnecessary technology/version headers.",
            "CWE-200",
            "Information Disclosure"
        )

    return make_finding(
        "X-Powered-By / Framework Disclosure",
        "No common framework disclosure headers were observed.",
        "INFO",
        "PASS",
        "Framework disclosure not observed.",
        "Continue hiding unnecessary framework details.",
        "CWE-200",
        "Information Disclosure"
    )


# ============================================================
# 18. TLS VERSION
# ============================================================

def check_tls_version(response):

    host = hostname_of(
        response.url
    )

    versions = []

    for version in [
        getattr(
            ssl.TLSVersion,
            "TLSv1_2",
            None
        ),
        getattr(
            ssl.TLSVersion,
            "TLSv1_3",
            None
        )
    ]:

        if version is None:
            continue

        try:

            actual, _ = tls_probe(
                host,
                version,
                version
            )

            if actual:
                versions.append(actual)

        except Exception:
            pass

    if versions:

        return make_finding(
            "SSL/TLS Protocol Version",
            "Checks whether modern TLS versions are available.",
            "INFO",
            "PASS",
            ", ".join(sorted(set(versions))),
            "Prefer TLS 1.2 and TLS 1.3.",
            "CWE-327",
            "TLS"
        )

    return make_finding(
        "SSL/TLS Protocol Version",
        "Modern TLS versions could not be confirmed.",
        "HIGH",
        "WARNING",
        "TLS 1.2 / TLS 1.3 not confirmed.",
        "Enable TLS 1.2 or TLS 1.3.",
        "CWE-327",
        "TLS"
    )


# ============================================================
# 19. WEAK CIPHER
# ============================================================

def check_cipher(response):

    host = hostname_of(
        response.url
    )

    try:

        version, cipher = tls_probe(
            host
        )

        name = (
            cipher[0]
            if cipher
            else "Unknown"
        )

        weak_patterns = [
            "RC4",
            "3DES",
            "DES-CBC",
            "NULL",
            "EXPORT",
            "MD5"
        ]

        weak = [
            x
            for x in weak_patterns
            if x in name.upper()
        ]

        if weak:

            return make_finding(
                "Weak Cipher Suites",
                "A legacy cipher pattern was detected.",
                "HIGH",
                "FAIL",
                f"{version} | {name}",
                "Disable legacy ciphers and use modern AEAD suites.",
                "CWE-327",
                "TLS"
            )

        return make_finding(
            "Weak Cipher Suites",
            "The negotiated cipher did not match the legacy patterns tested.",
            "INFO",
            "PASS",
            f"{version} | {name}",
            "Continue using modern cipher suites.",
            "CWE-327",
            "TLS"
        )

    except Exception as exc:

        return make_finding(
            "Weak Cipher Suites",
            "Cipher information could not be inspected.",
            "LOW",
            "WARNING",
            str(exc),
            "Review TLS cipher configuration.",
            "CWE-327",
            "TLS"
        )


# ============================================================
# 20. CERT EXPIRY
# ============================================================

def check_expiry(response):

    host = hostname_of(
        response.url
    )

    try:

        cert, _, _ = certificate_info(
            host
        )

        expiry_text = cert.get(
            "notAfter"
        )

        if not expiry_text:
            raise RuntimeError(
                "Certificate expiry unavailable."
            )

        expiry = datetime.strptime(
            expiry_text,
            "%b %d %H:%M:%S %Y %Z"
        )

        days = (
            expiry - datetime.utcnow()
        ).days

        if days < 0:

            return make_finding(
                "SSL Certificate Expiration Alert",
                "Certificate has expired.",
                "HIGH",
                "FAIL",
                expiry.isoformat(),
                "Renew the certificate immediately.",
                "CWE-295",
                "TLS"
            )

        if days <= 7:

            return make_finding(
                "SSL Certificate Expiration Alert",
                f"Certificate expires in {days} days.",
                "HIGH",
                "WARNING",
                expiry.isoformat(),
                "Renew immediately.",
                "CWE-295",
                "TLS"
            )

        if days <= 14:

            return make_finding(
                "SSL Certificate Expiration Alert",
                f"Certificate expires in {days} days.",
                "MEDIUM",
                "WARNING",
                expiry.isoformat(),
                "Schedule renewal.",
                "CWE-295",
                "TLS"
            )

        if days <= 30:

            return make_finding(
                "SSL Certificate Expiration Alert",
                f"Certificate expires in {days} days.",
                "LOW",
                "WARNING",
                expiry.isoformat(),
                "Plan certificate renewal.",
                "CWE-295",
                "TLS"
            )

        return make_finding(
            "SSL Certificate Expiration Alert",
            f"Certificate has {days} days remaining.",
            "INFO",
            "PASS",
            expiry.isoformat(),
            "Continue monitoring expiry.",
            "CWE-295",
            "TLS"
        )

    except Exception as exc:

        return make_finding(
            "SSL Certificate Expiration Alert",
            "Certificate expiry could not be checked.",
            "LOW",
            "WARNING",
            str(exc),
            "Review certificate manually.",
            "CWE-295",
            "TLS"
        )


# ============================================================
# 21. SRI
# ============================================================

def check_sri(response):

    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    if "html" not in content_type:

        return make_finding(
            "Subresource Integrity (SRI)",
            "Checks external scripts for integrity attributes.",
            "INFO",
            "INFO",
            "Response not identified as HTML.",
            "Review third-party scripts where appropriate.",
            "CWE-829",
            "Frontend Security"
        )

    try:

        body = response.text

        tags = re.findall(
            r"<script\b[^>]*>",
            body,
            re.I
        )

        external = 0
        missing = []

        for tag in tags:

            src = re.search(
                r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]",
                tag,
                re.I
            )

            if not src:
                continue

            full = urljoin(
                response.url,
                src.group(1)
            )

            parsed = urlparse(
                full
            )

            if (
                parsed.hostname
                and parsed.hostname != hostname_of(
                    response.url
                )
            ):

                external += 1

                if not re.search(
                    r"\bintegrity\s*=",
                    tag,
                    re.I
                ):

                    missing.append(full)

        if missing:

            return make_finding(
                "Subresource Integrity (SRI)",
                f"{len(missing)} external script(s) lack integrity.",
                "LOW",
                "WARNING",
                " | ".join(missing[:8]),
                "Add SRI hashes to suitable external scripts.",
                "CWE-829",
                "Frontend Security"
            )

        return make_finding(
            "Subresource Integrity (SRI)",
            "External scripts were checked for integrity.",
            "INFO",
            "PASS",
            f"External scripts checked: {external}",
            "Continue using SRI where appropriate.",
            "CWE-829",
            "Frontend Security"
        )

    except Exception as exc:

        return make_finding(
            "Subresource Integrity (SRI)",
            "SRI analysis could not be completed.",
            "LOW",
            "WARNING",
            str(exc),
            "Review third-party scripts manually.",
            "CWE-829",
            "Frontend Security"
        )


# ============================================================
# 22. OPEN PORTS
# ============================================================

def check_ports(response):

    host = hostname_of(
        response.url
    )

    open_ports = []

    for port, service in COMMON_PORTS.items():

        try:

            with socket.create_connection(
                (host, port),
                timeout=PORT_TIMEOUT
            ):
                open_ports.append(
                    f"{port}/{service}"
                )

        except Exception:
            pass

    risky = []

    for item in open_ports:

        service = item.split(
            "/",
            1
        )[1]

        if service in {
            "FTP",
            "Telnet",
            "SMB",
            "MySQL",
            "PostgreSQL",
            "Redis"
        }:

            risky.append(item)

    if risky:

        return make_finding(
            "Open Port Detection",
            "Potentially sensitive service ports responded.",
            "HIGH",
            "WARNING",
            ", ".join(risky),
            "Confirm that exposure is intentional and restrict unnecessary services.",
            "CWE-668",
            "Network Exposure"
        )

    return make_finding(
        "Open Port Detection",
        "Checks common TCP service ports.",
        "INFO",
        "INFO",
        (
            ", ".join(open_ports)
            if open_ports
            else "No tested ports responded."
        ),
        "Keep publicly exposed services intentional.",
        "CWE-668",
        "Network Exposure"
    )


# ============================================================
# 23. SUBDOMAINS
# ============================================================

def check_subdomains(response):

    host = hostname_of(
        response.url
    )

    parts = host.split(".")

    if len(parts) >= 2:
        base = ".".join(parts[-2:])
    else:
        base = host

    found = []

    for prefix in COMMON_SUBDOMAINS:

        candidate = (
            f"{prefix}.{base}"
        )

        try:

            socket.gethostbyname(
                candidate
            )

            found.append(
                candidate
            )

        except Exception:
            pass

    return make_finding(
        "Subdomain Enumeration",
        (
            f"{len(found)} common subdomain(s) resolved."
            if found
            else "No tested common subdomains resolved."
        ),
        "INFO",
        "INFO",
        (
            ", ".join(found)
            if found
            else "None"
        ),
        "Review discovered hosts and remove unused subdomains.",
        "CWE-200",
        "DNS Intelligence"
    )


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

def detect_technologies(response):

    technologies = []

    headers = response.headers
    body = response.text.lower()

    server = headers.get(
        "Server",
        ""
    ).lower()

    powered = headers.get(
        "X-Powered-By",
        ""
    ).lower()

    if "wordpress" in body:
        technologies.append(
            "WordPress"
        )

    if "wp-content" in body:
        technologies.append(
            "WordPress"
        )

    if "woocommerce" in body:
        technologies.append(
            "WooCommerce"
        )

    if "react" in body:
        technologies.append(
            "React"
        )

    if "__next_data__" in body:
        technologies.append(
            "Next.js"
        )

    if "jquery" in body:
        technologies.append(
            "jQuery"
        )

    if "bootstrap" in body:
        technologies.append(
            "Bootstrap"
        )

    if "php" in server or "php" in powered:
        technologies.append(
            "PHP"
        )

    if "express" in powered:
        technologies.append(
            "Express.js"
        )

    if "nginx" in server:
        technologies.append(
            "Nginx"
        )

    if "apache" in server:
        technologies.append(
            "Apache"
        )

    unique = list(
        dict.fromkeys(
            technologies
        )
    )

    return unique


# ============================================================
# OWASP MAPPING
# ============================================================

def owasp_mapping(features):

    mapping = []

    for item in features:

        name = item["name"].lower()

        if (
            "cookie" in name
            or "session" in name
        ):

            mapping.append(
                "A07 Identification & Authentication Failures"
            )

        elif (
            "cors" in name
            or "origin" in name
        ):

            mapping.append(
                "A05 Security Misconfiguration"
            )

        elif (
            "csp" in name
            or "frame" in name
            or "content-type" in name
        ):

            mapping.append(
                "A05 Security Misconfiguration"
            )

        elif (
            "tls" in name
            or "https" in name
        ):

            mapping.append(
                "A02 Cryptographic Failures"
            )

        elif (
            "server" in name
            or "framework" in name
        ):

            mapping.append(
                "A05 Security Misconfiguration"
            )

        else:

            mapping.append(
                "Security Configuration"
            )

    return list(
        dict.fromkeys(mapping)
    )


# ============================================================
# GLOBAL LATENCY
# ============================================================

def latency_check(url):

    points = [
        ("Primary", url)
    ]

    results = []

    for name, target in points:

        start = time.perf_counter()

        try:

            requests.head(
                target,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )

            elapsed = round(
                (
                    time.perf_counter()
                    - start
                ) * 1000,
                0
            )

            results.append(
                f"{name}: {int(elapsed)} ms"
            )

        except Exception as exc:

            results.append(
                f"{name}: unavailable"
            )

    return results


# ============================================================
# WHOIS / RDAP
# ============================================================

def rdap_lookup(domain):

    try:

        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=10,
            headers={
                "User-Agent":
                    "EthicalGuard/8.0"
            }
        )

        if response.status_code != 200:

            return {
                "available": False,
                "error":
                    f"RDAP status {response.status_code}"
            }

        data = response.json()

        events = {}

        for event in data.get(
            "events",
            []
        ):

            action = event.get(
                "eventAction"
            )

            date = event.get(
                "eventDate"
            )

            if action:
                events[action] = date

        return {
            "available": True,
            "handle": data.get(
                "handle"
            ),
            "status": data.get(
                "status",
                []
            ),
            "events": events,
            "name_servers": [
                x.get("ldhName")
                for x in data.get(
                    "nameservers",
                    []
                )
                if x.get("ldhName")
            ]
        }

    except Exception as exc:

        return {
            "available": False,
            "error": str(exc)
        }


# ============================================================
# CVE INTELLIGENCE
# ============================================================

def cve_lookup(
    technologies
):

    findings = []

    # Safe informational lookup.
    # NVD can rate-limit unauthenticated requests,
    # therefore failures are treated as INFO.

    for tech in technologies[:4]:

        try:

            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "keywordSearch": tech,
                    "resultsPerPage": 3
                },
                timeout=8,
                headers={
                    "User-Agent":
                        "EthicalGuard/8.0"
                }
            )

            if response.status_code != 200:
                continue

            data = response.json()

            for vulnerability in data.get(
                "vulnerabilities",
                []
            )[:3]:

                cve = vulnerability.get(
                    "cve",
                    {}
                )

                cve_id = cve.get(
                    "id"
                )

                descriptions = cve.get(
                    "descriptions",
                    []
                )

                description = ""

                for desc in descriptions:

                    if (
                        desc.get(
                            "lang"
                        ) == "en"
                    ):

                        description = desc.get(
                            "value",
                            ""
                        )

                        break

                if cve_id:

                    findings.append({
                        "technology": tech,
                        "cve": cve_id,
                        "description":
                            description[:500]
                    })

        except Exception:
            continue

    return findings[:10]


# ============================================================
# FULL SCAN
# ============================================================

def perform_scan(
    target,
    profile="full"
):

    started = time.time()

    target = normalize_url(
        target
    )

    if not target:

        raise ValueError(
            "Please enter a valid URL."
        )

    if profile not in SCAN_PROFILES:
        profile = "full"

    response = fetch_target(
        target
    )

    features = []

    # 1
    features.append(
        check_https(response)
    )

    # 2-5
    features.extend(
        check_required_headers(
            response
        )
    )

    # 6
    features.append(
        check_server(response)
    )

    # 7
    features.append(
        check_cookies(response)
    )

    # 8
    features.append(
        check_cors(response)
    )

    # 9
    features.append(
        check_permissions(response)
    )

    # 10
    features.append(
        check_tls_certificate(
            response
        )
    )

    # 11
    features.append(
        check_dns(response)
    )

    # 12
    features.append(
        check_redirects(response)
    )

    # 13
    features.append(
        check_x_xss(response)
    )

    # 14
    features.append(
        check_referrer(response)
    )

    # 15
    features.append(
        check_coop(response)
    )

    # 16
    features.append(
        check_coep(response)
    )

    # 17
    features.append(
        check_framework_disclosure(
            response
        )
    )

    # 18
    features.append(
        check_tls_version(response)
    )

    # 19
    features.append(
        check_cipher(response)
    )

    # 20
    features.append(
        check_expiry(response)
    )

    # 21
    features.append(
        check_sri(response)
    )

    # 22
    if SCAN_PROFILES[
        profile
    ]["ports"]:

        features.append(
            check_ports(response)
        )

    else:

        features.append(
            make_finding(
                "Open Port Detection",
                "Common TCP ports were skipped for this profile.",
                "INFO",
                "INFO",
                "Skipped",
                "Use Full Scan for this check.",
                "CWE-668",
                "Network Exposure"
            )
        )

    # 23
    if SCAN_PROFILES[
        profile
    ]["subdomains"]:

        features.append(
            check_subdomains(
                response
            )
        )

    else:

        features.append(
            make_finding(
                "Subdomain Enumeration",
                "Common subdomain discovery was skipped.",
                "INFO",
                "INFO",
                "Skipped",
                "Use Full or Passive Intelligence.",
                "CWE-200",
                "DNS Intelligence"
            )
        )

    # ========================================================
    # EXTRA INTELLIGENCE
    # ========================================================

    technologies = detect_technologies(
        response
    )

    cves = cve_lookup(
        technologies
    )

    domain = hostname_of(
        response.url
    )

    rdap = rdap_lookup(
        domain
    )

    latency = latency_check(
        response.url
    )

    owasp = owasp_mapping(
        features
    )

    # ========================================================
    # RISK SCORE
    # ========================================================

    score = 100

    deduction = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 4,
        "INFO": 0
    }

    for item in features:

        if item["status"] == "FAIL":

            score -= deduction.get(
                item["severity"],
                10
            )

        elif item["status"] == "WARNING":

            score -= deduction.get(
                item["severity"],
                4
            )

    score = max(
        0,
        min(100, score)
    )

    # ========================================================
    # COUNTERS
    # ========================================================

    passed = sum(
        1
        for item in features
        if item["status"] == "PASS"
    )

    failed = sum(
        1
        for item in features
        if item["status"] == "FAIL"
    )

    warnings = sum(
        1
        for item in features
        if item["status"] == "WARNING"
    )

    info = sum(
        1
        for item in features
        if item["status"] == "INFO"
    )

    high = sum(
        1
        for item in features
        if (
            item["severity"] == "HIGH"
            and item["status"]
            in ["FAIL", "WARNING"]
        )
    )

    medium = sum(
        1
        for item in features
        if (
            item["severity"] == "MEDIUM"
            and item["status"]
            in ["FAIL", "WARNING"]
        )
    )

    low = sum(
        1
        for item in features
        if (
            item["severity"] == "LOW"
            and item["status"]
            in ["FAIL", "WARNING"]
        )
    )

    # IMPORTANT:
    # Risk is now severity-based, not simply
    # "any warning = critical".

    if high >= 2:
        risk = "CRITICAL"

    elif high == 1:
        risk = "HIGH"

    elif medium >= 2:
        risk = "HIGH"

    elif medium == 1:
        risk = "MEDIUM"

    elif low >= 2:
        risk = "LOW"

    elif low == 1:
        risk = "LOW"

    else:
        risk = "MINIMAL"

    if high > 0:
        overall = "VULNERABLE"

    elif medium > 0 or low > 0:
        overall = "NEEDS ATTENTION"

    elif warnings > 0:
        overall = "SECURE WITH WARNINGS"

    else:
        overall = "SECURE"

    return {
        "scan_id":
            uuid.uuid4().hex[:12],

        "target":
            target,

        "final_url":
            response.url,

        "profile":
            profile,

        "profile_label":
            SCAN_PROFILES[
                profile
            ]["label"],

        "score":
            score,

        "overall":
            overall,

        "risk":
            risk,

        "passed":
            passed,

        "failed":
            failed,

        "warnings":
            warnings,

        "info":
            info,

        "high":
            high,

        "medium":
            medium,

        "low":
            low,

        "response_status":
            response.status_code,

        "redirect_count":
            len(response.history),

        "duration":
            round(
                time.time()
                - started,
                2
            ),

        "scan_time":
            now_text(),

        "timestamp":
            now_iso(),

        "features":
            features,

        "feature_count":
            len(features),

        "technologies":
            technologies,

        "cves":
            cves,

        "rdap":
            rdap,

        "latency":
            latency,

        "owasp":
            owasp,

        "engine":
            APP_VERSION
    }


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    result,
    user_id
):

    connection = get_db()

    owner_id = user_id

    data = dict(result)

    data["owner_id"] = owner_id

    connection.execute(
        """
        INSERT INTO scans (
            scan_id,
            user_id,
            target,
            final_url,
            profile,
            score,
            overall,
            risk,
            scan_time,
            duration,
            data_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result["scan_id"],
            user_id,
            result["target"],
            result["final_url"],
            result["profile"],
            result["score"],
            result["overall"],
            result["risk"],
            result["scan_time"],
            result["duration"],
            json.dumps(
                data,
                ensure_ascii=False
            )
        )
    )

    connection.commit()
    connection.close()


def load_scan(
    scan_id
):

    connection = get_db()

    row = connection.execute(
        """
        SELECT *
        FROM scans
        WHERE scan_id = ?
        """,
        (scan_id,)
    ).fetchone()

    connection.close()

    if not row:
        return None

    return json.loads(
        row["data_json"]
    )


# ============================================================
# AUTH HTML
# ============================================================

AUTH_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1.0">

<title>{{ title }} — EthicalGuard</title>

<style>

body{
    margin:0;
    min-height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    background:#070b12;
    color:#edf3f7;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

.card{
    width:min(450px,92%);
    background:#0a1018;
    border:1px solid #263443;
    border-radius:17px;
    padding:28px;
    box-shadow:0 30px 80px rgba(0,0,0,.45);
}

.logo{
    width:50px;
    height:50px;
    margin:auto;
    display:flex;
    justify-content:center;
    align-items:center;
    border:1px solid #2e9d70;
    border-radius:13px;
    background:#09150f;
    font-size:23px;
}

h1{
    text-align:center;
    margin:14px 0 5px;
}

.tag{
    text-align:center;
    color:#748294;
    font-size:10px;
    letter-spacing:2px;
}

.desc{
    text-align:center;
    color:#8290a0;
    line-height:1.6;
    margin:12px 0;
    font-size:11px;
}

label{
    display:block;
    color:#7b8998;
    font-size:9px;
    letter-spacing:1px;
    text-transform:uppercase;
    margin:17px 0 7px;
}

input{
    width:100%;
    padding:12px;
    background:#080d14;
    border:1px solid #293747;
    color:#edf3f7;
    border-radius:9px;
    outline:none;
}

input:focus{
    border-color:#2e9d70;
}

button,
a{
    width:100%;
    display:block;
    padding:12px;
    margin-top:11px;
    border-radius:9px;
    text-align:center;
    text-decoration:none;
    cursor:pointer;
}

button{
    border:1px solid #2e9d70;
    background:#143728;
    color:#acf1ca;
}

a{
    border:1px solid #293747;
    background:#0c121a;
    color:#dbe4eb;
}

.error{
    padding:10px;
    border-radius:8px;
    background:#32171c;
    border:1px solid #56262e;
    color:#ff9ca4;
    font-size:11px;
}

</style>

</head>

<body>

<div class="card">

<div class="logo">
🛡️
</div>

<h1>
EthicalGuard
</h1>

<div class="tag">
SCAN • ANALYZE • PROTECT
</div>

<div class="desc">

{% if mode == "signup" %}
Create your EthicalGuard account.
{% else %}
Login to your EthicalGuard account.
{% endif %}

</div>

{% if error %}
<div class="error">
{{ error }}
</div>
{% endif %}


<form method="POST">

{% if mode == "signup" %}

<label>
Username
</label>

<input
type="text"
name="username"
placeholder="e.g. ahmed123"
required
autocomplete="username"
>

<label>
Email
</label>

<input
type="email"
name="email"
placeholder="you@example.com"
required
autocomplete="email"
>

<label>
Password
</label>

<input
type="password"
name="password"
placeholder="Create a password"
required
autocomplete="new-password"
>

<button>
Create Account
</button>

{% else %}

<label>
Email or Username
</label>

<input
type="text"
name="identifier"
placeholder="Email or username"
required
autocomplete="username"
>

<label>
Password
</label>

<input
type="password"
name="password"
placeholder="Your password"
required
autocomplete="current-password"
>

<button>
Login
</button>

{% endif %}

</form>


{% if mode == "signup" %}

<a href="/login">
Already have an account? Login
</a>

{% else %}

<a href="/signup">
Create an account
</a>

{% endif %}

<a href="/">
Back to Scanner
</a>

</div>

</body>
</html>
"""


# ============================================================
# SIGNUP
# ============================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not valid_username(username):

            error = (
                "Username must be 3–30 characters."
            )

        elif not valid_email(email):

            error = (
                "Enter a valid email address."
            )

        elif len(password) < 8:

            error = (
                "Password must be at least 8 characters."
            )

        else:

            user = create_user(
                username,
                email,
                password
            )

            if not user:

                error = (
                    "Username or email already exists."
                )

            else:

                session[
                    "user_id"
                ] = user["id"]

                return redirect(
                    url_for("dashboard")
                )

    return render_template_string(
        AUTH_HTML,
        title="Sign Up",
        mode="signup",
        error=error
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    error = None

    if request.method == "POST":

        identifier = request.form.get(
            "identifier",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = authenticate(
            identifier,
            password
        )

        if not user:

            error = (
                "Invalid username/email or password."
            )

        else:

            session[
                "user_id"
            ] = user["id"]

            return redirect(
                url_for("dashboard")
            )

    return render_template_string(
        AUTH_HTML,
        title="Login",
        mode="login",
        error=error
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# MAIN DASHBOARD
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1.0">

<title>EthicalGuard</title>

<style>

:root{
    --bg:#070b12;
    --card:#0a1018;
    --border:#202c39;
    --text:#e9eff4;
    --muted:#748293;
    --accent:#2e9d70;
}

.light{
    --bg:#f4f7fa;
    --card:#ffffff;
    --border:#d9e0e6;
    --text:#17202a;
    --muted:#6d7883;
}

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:var(--bg);
    color:var(--text);
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

.container{
    width:min(1500px,94%);
    margin:auto;
}

.topbar{
    display:flex;
    justify-content:space-between;
    align-items:center;
    padding:20px 0;
    border-bottom:1px solid var(--border);
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
}

.shield{
    width:46px;
    height:46px;
    display:flex;
    align-items:center;
    justify-content:center;
    border:1px solid var(--accent);
    background:#09150f;
    border-radius:13px;
}

.brand h1{
    margin:0;
    font-size:21px;
}

.brand p{
    margin:4px 0 0;
    color:var(--muted);
    letter-spacing:2px;
    font-size:10px;
}

.actions{
    display:flex;
    align-items:center;
    gap:7px;
    flex-wrap:wrap;
}

.btn{
    border:1px solid var(--border);
    background:var(--card);
    color:var(--text);
    border-radius:8px;
    padding:10px 12px;
    text-decoration:none;
    cursor:pointer;
    font-size:10px;
}

.btn.primary{
    border-color:var(--accent);
    background:#143728;
    color:#aef1cb;
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
    color:var(--muted);
    line-height:1.6;
    max-width:900px;
}

.scanbox{
    margin-top:18px;
    padding:17px;
    background:var(--card);
    border:1px solid var(--border);
    border-radius:14px;
}

.formrow{
    display:grid;
    grid-template-columns:1fr 170px 145px;
    gap:9px;
}

input,
select{
    width:100%;
    border:1px solid var(--border);
    background:var(--bg);
    color:var(--text);
    padding:12px;
    border-radius:8px;
    outline:none;
}

.stats{
    display:grid;
    grid-template-columns:repeat(7,1fr);
    gap:9px;
    margin:17px 0;
}

.stat{
    border:1px solid var(--border);
    background:var(--card);
    border-radius:12px;
    padding:14px;
}

.stat small{
    display:block;
    color:var(--muted);
    text-transform:uppercase;
    font-size:8px;
}

.stat strong{
    display:block;
    margin-top:7px;
    font-size:22px;
}

.grid{
    display:grid;
    grid-template-columns:minmax(0,1.55fr) minmax(320px,.75fr);
    gap:12px;
}

.card{
    background:var(--card);
    border:1px solid var(--border);
    border-radius:14px;
    overflow:hidden;
}

.card-head{
    display:flex;
    justify-content:space-between;
    padding:14px 16px;
    border-bottom:1px solid var(--border);
}

.card-head h3{
    margin:0;
    font-size:14px;
}

.table{
    overflow:auto;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,
td{
    padding:12px;
    border-bottom:1px solid var(--border);
    text-align:left;
    font-size:10px;
}

th{
    color:var(--muted);
    font-size:8px;
    text-transform:uppercase;
}

.badge{
    display:inline-block;
    padding:5px 7px;
    border-radius:5px;
    font-weight:800;
    font-size:8px;
}

.pass{
    color:#7de2a7;
    background:#0c291b;
}

.warning{
    color:#ffd17b;
    background:#2d2413;
}

.fail{
    color:#ff949d;
    background:#32161b;
}

.info{
    color:#96bdf0;
    background:#152439;
}

.detail{
    padding:17px;
}

.detail-empty{
    padding:30px;
    text-align:center;
    color:var(--muted);
    line-height:1.7;
}

.meta{
    display:flex;
    flex-wrap:wrap;
    gap:7px;
    margin-top:10px;
}

.meta span{
    border:1px solid var(--border);
    padding:5px 7px;
    border-radius:6px;
    color:var(--muted);
    font-size:8px;
}

.section{
    margin-top:15px;
}

.section label{
    display:block;
    color:var(--muted);
    font-size:8px;
    letter-spacing:1px;
    margin-bottom:5px;
}

.section p{
    margin:0;
    font-size:10px;
    line-height:1.65;
    word-break:break-word;
}

.footer{
    margin:29px 0 40px;
    padding-top:17px;
    border-top:1px solid var(--border);
    display:flex;
    justify-content:space-between;
    align-items:center;
    color:var(--muted);
    font-size:9px;
}

.risk-gauge{
    margin-top:14px;
    width:150px;
    height:75px;
    border-radius:150px 150px 0 0;
    background:
        conic-gradient(
            from 270deg,
            #2e9d70 0deg 90deg,
            #d0a63a 90deg 140deg,
            #b9434b 140deg 180deg
        );
    position:relative;
    overflow:hidden;
}

.risk-gauge:after{
    content:"";
    position:absolute;
    inset:15px 15px 0;
    border-radius:120px 120px 0 0;
    background:var(--card);
}

.gauge-label{
    position:absolute;
    bottom:7px;
    left:0;
    right:0;
    text-align:center;
    z-index:2;
    font-size:10px;
}

.preview{
    margin-top:14px;
    padding:12px;
    border:1px solid var(--border);
    border-radius:9px;
}

@media(max-width:1100px){

    .stats{
        grid-template-columns:repeat(4,1fr);
    }

    .grid{
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

    .topbar{
        align-items:flex-start;
        gap:12px;
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

<div class="shield">
🛡️
</div>

<div>
<h1>EthicalGuard</h1>
<p>SCAN • ANALYZE • PROTECT</p>
</div>

</div>


<div class="actions">

{% if user %}

<a
class="btn"
href="/history"
>
History
</a>

<a
class="btn"
href="/monitoring"
>
Monitored Sites
</a>

<button
class="btn"
onclick="toggleTheme()"
>
Theme
</button>

<a
class="btn"
href="/logout"
>
Logout
</a>

{% else %}

<a
class="btn"
href="/login"
>
Login
</a>

<a
class="btn primary"
href="/signup"
>
Sign Up
</a>

{% endif %}

<a
class="btn"
href="/contact"
>
Contact Us
</a>

</div>

</div>


<div class="hero">

<h2>
Professional Web Security Assessment
</h2>

<p>
EthicalGuard performs authorized passive security auditing
with 23 core security checks plus technology intelligence,
CVE awareness, OWASP mapping and domain intelligence.
</p>


<div class="scanbox">

<form
method="POST"
onsubmit="startProgress()"
>

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

<option
value="full"
selected
>
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


<div
id="progress"
style="
display:none;
margin-top:10px;
height:4px;
background:#141d27;
border-radius:9px;
overflow:hidden;
"
>

<div
id="progressBar"
style="
width:0;
height:100%;
background:#2e9d70;
"
></div>

</div>

</form>

{% if user %}

<div
style="
margin-top:12px;
font-size:10px;
color:#788696;
"
>

{% if user["plan"] == "PREMIUM" %}

Premium account · Unlimited scan mode

{% else %}

Free scans remaining:
<strong>
{{ user["free_scans_remaining"] }}
</strong>
/
{{ free_limit }}

{% endif %}

</div>

{% endif %}

</div>


<div
class="preview"
id="headerTool"
>

<strong>
Raw Header Analyzer
</strong>

<div
style="
margin-top:7px;
color:var(--muted);
font-size:9px;
"
>
Paste response headers to analyze them without scanning a public URL.
</div>

<textarea
id="rawHeaders"
placeholder="Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000"
style="
margin-top:8px;
width:100%;
min-height:100px;
background:var(--bg);
color:var(--text);
border:1px solid var(--border);
border-radius:8px;
padding:10px;
"
></textarea>

<button
class="btn"
style="margin-top:8px"
onclick="analyzeHeaders()"
>
Analyze Headers
</button>

<div
id="headerResult"
style="margin-top:10px"
></div>

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


<div class="grid">

<div class="card">

<div class="card-head">

<h3>
Security Findings
</h3>

<span>
23 Features
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

<td>
{{ loop.index }}
</td>

<td>
<strong>
{{ item.name }}
</strong>
</td>

<td>
<span
class="badge {{ item.severity|lower }}"
>
{{ item.severity }}
</span>
</td>

<td>
<span
class="badge {{ item.status|lower }}"
>
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

<div class="card-head">

<h3>
Finding Intelligence
</h3>

<span>
Evidence / Remediation
</span>

</div>

<div
class="detail"
id="detailPanel"
>

<div class="detail-empty">
Select a finding.
</div>

</div>

</div>

</div>


<div
class="card"
style="margin-top:12px"
>

<div class="card-head">

<h3>
Security Overview
</h3>

<span>
{{ result.scan_time }}
</span>

</div>


<div class="detail">

<div style="display:flex;flex-wrap:wrap;gap:25px">

<div>

<div class="risk-gauge">

<div class="gauge-label">
{{ result.risk }}
</div>

</div>

</div>


<div style="flex:1;min-width:250px">

<div class="meta">

<span>
Overall: {{ result.overall }}
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
Duration: {{ result.duration }}s
</span>

{% if user %}
<span>
User: {{ user["username"] }}
</span>
{% else %}
<span>
Guest Scan
</span>
{% endif %}

</div>


<div class="section">

<label>
TECHNOLOGIES DETECTED
</label>

<p>
{{ result.technologies|join(", ") if result.technologies else "No common technology signatures detected." }}
</p>

</div>


<div class="section">

<label>
OWASP AREAS
</label>

<p>
{{ result.owasp|join(" · ") }}
</p>

</div>


<div class="section">

<label>
LATENCY
</label>

<p>
{{ result.latency|join(" · ") }}
</p>

</div>

</div>

</div>


<div style="margin-top:15px">

<a
class="btn primary"
href="/report?id={{ result.scan_id }}"
>
Open Report
</a>

<a
class="btn"
href="/download-report?id={{ result.scan_id }}"
>
Download
</a>

{% if user and user["plan"] == "PREMIUM" %}

<button
class="btn"
onclick="saveReportImage()"
>
Save Report as Image
</button>

{% endif %}

</div>

</div>

</div>


{% if result.cves %}

<div
class="card"
style="margin-top:12px"
>

<div class="card-head">

<h3>
CVE Intelligence
</h3>

<span>
Informational
</span>

</div>

<div class="detail">

{% for cve in result.cves %}

<div
style="
padding:9px 0;
border-bottom:1px solid var(--border);
"
>

<strong>
{{ cve.cve }}
</strong>

<span
style="
color:var(--muted);
font-size:10px;
"
>
· {{ cve.technology }}
</span>

<p
style="
color:var(--muted);
font-size:10px;
line-height:1.6;
"
>
{{ cve.description }}
</p>

</div>

{% endfor %}

</div>

</div>

{% endif %}


{% if result.rdap %}

<div
class="card"
style="margin-top:12px"
>

<div class="card-head">

<h3>
Domain Intelligence
</h3>

<span>
RDAP
</span>

</div>

<div class="detail">

<div class="meta">

<span>
Domain: {{ hostname }}
</span>

{% if result.rdap.events.get("registration") %}
<span>
Registered: {{ result.rdap.events.get("registration") }}
</span>
{% endif %}

{% if result.rdap.events.get("expiration") %}
<span>
Expires: {{ result.rdap.events.get("expiration") }}
</span>
{% endif %}

</div>

</div>

</div>

{% endif %}


<div
class="card"
style="margin-top:12px"
>

<div class="card-head">

<h3>
Security Badge
</h3>

<span>
Premium sharing feature
</span>

</div>

<div class="detail">

<p
style="
font-size:10px;
color:var(--muted)
"
>
Embed a simple EthicalGuard badge on your project.
</p>

<textarea
readonly
style="
width:100%;
min-height:75px;
background:var(--bg);
color:var(--text);
border:1px solid var(--border);
border-radius:8px;
padding:10px;
"
>
<a href="{{ base_url }}/badge/{{ result.scan_id }}" target="_blank">
<img src="{{ base_url }}/badge/{{ result.scan_id }}" alt="EthicalGuard Security Badge">
</a>
</textarea>

</div>

</div>

{% endif %}


{% if error %}

<div
class="card"
style="margin-top:12px"
>

<div class="detail">

<h3>
Scan Error
</h3>

<p>
{{ error }}
</p>

</div>

</div>

{% endif %}


{% if not user %}

<div
class="card"
style="margin-top:12px"
>

<div class="detail">

<h3>
Premium Features
</h3>

<p
style="color:var(--muted);font-size:10px;line-height:1.7"
>
Create an account to receive 8 free scans.
Premium unlocks unlimited scans, monitoring,
alerts, image reports, advanced intelligence and more.
</p>

<a
class="btn primary"
href="/signup"
>
Create Free Account
</a>

<a
class="btn"
href="/premium"
style="margin-left:7px"
>
View Premium
</a>

</div>

</div>

{% endif %}


<div class="footer">

<div>
EthicalGuard · Web Security Platform
</div>

<div>
Ahmed Sidhu · Security Enthusiast
</div>

</div>

</div>


<script>

function startProgress(){

    const box =
        document.getElementById("progress");

    const bar =
        document.getElementById("progressBar");

    if(!box || !bar){
        return;
    }

    box.style.display="block";

    let value=0;

    const timer=setInterval(function(){

        value +=
            Math.floor(
                Math.random()*8
            )+4;

        if(value>=94){

            value=94;
            clearInterval(timer);

        }

        bar.style.width =
            value+"%";

    },180);
}


function showFinding(item){

    const panel =
        document.getElementById(
            "detailPanel"
        );

    const safe = (value) =>
        String(value ?? "")
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");

    panel.innerHTML = `

        <h3>
        ${safe(item.name)}
        </h3>

        <div class="meta">

            <span>
            Severity: ${safe(item.severity)}
            </span>

            <span>
            Status: ${safe(item.status)}
            </span>

            <span>
            CWE: ${safe(item.cwe || "-")}
            </span>

            <span>
            Category: ${safe(item.category || "-")}
            </span>

        </div>

        <div class="section">

            <label>
            WHY IT MATTERS
            </label>

            <p>
            ${safe(item.description)}
            </p>

        </div>

        <div class="section">

            <label>
            EVIDENCE
            </label>

            <p>
            ${safe(item.evidence || "-")}
            </p>

        </div>

        <div class="section">

            <label>
            HOW TO FIX
            </label>

            <p>
            ${safe(item.remediation || "-")}
            </p>

        </div>
    `;
}


function toggleTheme(){

    document.body.classList.toggle(
        "light"
    );

    localStorage.setItem(
        "ethicalguard_theme",
        document.body.classList.contains(
            "light"
        )
        ? "light"
        : "dark"
    );
}


if(
    localStorage.getItem(
        "ethicalguard_theme"
    ) === "light"
){

    document.body.classList.add(
        "light"
    );
}


function analyzeHeaders(){

    const raw =
        document.getElementById(
            "rawHeaders"
        ).value
        .toLowerCase();

    const checks = [
        [
            "content-security-policy",
            "CSP"
        ],
        [
            "x-frame-options",
            "X-Frame-Options"
        ],
        [
            "strict-transport-security",
            "HSTS"
        ],
        [
            "x-content-type-options",
            "X-Content-Type-Options"
        ],
        [
            "referrer-policy",
            "Referrer-Policy"
        ],
        [
            "permissions-policy",
            "Permissions-Policy"
        ]
    ];

    let output="";

    checks.forEach(function(item){

        if(raw.includes(item[0])){

            output +=
                "<div style='color:#7de2a7;margin:5px 0'>" +
                "PASS · " +
                item[1] +
                "</div>";

        }else{

            output +=
                "<div style='color:#ffd17b;margin:5px 0'>" +
                "MISSING · " +
                item[1] +
                "</div>";

        }

    });

    document.getElementById(
        "headerResult"
    ).innerHTML=output;
}


async function saveReportImage(){

    const target =
        document.querySelector(
            ".container"
        );

    if(!target){
        return;
    }

    if(
        typeof html2canvas === "undefined"
    ){

        alert(
            "Image export library is not loaded yet."
        );

        return;
    }

    const canvas =
        await html2canvas(
            target,
            {
                backgroundColor:
                    "#070b12",
                scale: 2
            }
        );

    const link =
        document.createElement(
            "a"
        );

    link.download =
        "ethicalguard-report.png";

    link.href =
        canvas.toDataURL(
            "image/png"
        );

    link.click();
}

</script>


<script
src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"
></script>

</body>
</html>
"""


# ============================================================
# DASHBOARD ROUTE
# ============================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def dashboard():

    user = current_user()

    result = None
    error = None

    if request.method == "POST":

        target = request.form.get(
            "url",
            ""
        ).strip()

        profile = request.form.get(
            "profile",
            "full"
        )

        if user:

            if not can_user_scan(
                user
            ):

                return redirect(
                    url_for(
                        "premium"
                    )
                )

        try:

            result = perform_scan(
                target,
                profile
            )

            if user:

                if not user_is_premium(
                    user
                ):

                    if not consume_free_scan(
                        user["id"]
                    ):

                        return redirect(
                            url_for(
                                "premium"
                            )
                        )

                save_scan(
                    result,
                    user["id"]
                )

            else:

                # Guest result is displayed,
                # but not saved to account history.
                result["owner"] = "Guest"

        except requests.exceptions.Timeout:

            error = (
                "Website request timed out."
            )

        except requests.exceptions.SSLError as exc:

            error = (
                "SSL/TLS error: "
                + str(exc)
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

    remaining = (
        user["free_scans_remaining"]
        if user
        else None
    )

    return render_template_string(
        DASHBOARD_HTML,
        user=user,
        result=result,
        error=error,
        free_limit=FREE_SCAN_LIMIT,
        base_url=request.host_url.rstrip("/"),
        hostname=(
            hostname_of(
                result["final_url"]
            )
            if result
            else ""
        )
    )


# ============================================================
# HISTORY
# ============================================================

HISTORY_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">

<title>History — EthicalGuard</title>

<style>

body{
    margin:0;
    background:#070b12;
    color:#edf3f7;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

.container{
    width:min(1100px,94%);
    margin:30px auto;
}

.top{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:10px;
    margin-bottom:16px;
}

.actions{
    display:flex;
    gap:7px;
    flex-wrap:wrap;
}

.btn{
    display:inline-block;
    padding:9px 12px;
    border:1px solid #293747;
    border-radius:8px;
    background:#0c121a;
    color:#e7edf2;
    text-decoration:none;
    font-size:10px;
}

.grid{
    display:grid;
    gap:10px;
}

.card{
    background:#0a1018;
    border:1px solid #202c39;
    border-radius:14px;
    padding:16px;
}

.row{
    display:flex;
    justify-content:space-between;
    gap:10px;
    align-items:center;
}

.target{
    font-weight:800;
    overflow:hidden;
    text-overflow:ellipsis;
}

.score{
    min-width:75px;
    text-align:center;
    padding:9px;
    border-radius:8px;
    font-weight:800;
}

.good{
    background:#0c291b;
    color:#7de2a7;
}

.mid{
    background:#2d2413;
    color:#ffd17b;
}

.bad{
    background:#32161b;
    color:#ff949d;
}

.meta{
    display:flex;
    flex-wrap:wrap;
    gap:6px;
    margin-top:11px;
}

.meta span{
    color:#8a99a8;
    border:1px solid #263443;
    border-radius:6px;
    padding:5px 7px;
    font-size:8px;
}

.open{
    display:inline-block;
    margin-top:12px;
    color:#79dfa9;
    text-decoration:none;
    font-size:10px;
}

</style>

</head>

<body>

<div class="container">

<div class="top">

<div>

<h1>
Scan History
</h1>

<div style="color:#728192;font-size:10px">
{{ user["username"] }} · {{ user["email"] }}
</div>

</div>

<div class="actions">

<a class="btn" href="/">
Scanner
</a>

<a class="btn" href="/monitoring">
Monitored Sites
</a>

<a class="btn" href="/logout">
Logout
</a>

</div>

</div>


{% if scans %}

<div class="grid">

{% for scan in scans %}

<div class="card">

<div class="row">

<div class="target">
{{ scan["target"] }}
</div>

{% if scan["score"] >= 85 %}

<div class="score good">
{{ scan["score"] }}/100
</div>

{% elif scan["score"] >= 70 %}

<div class="score mid">
{{ scan["score"] }}/100
</div>

{% else %}

<div class="score bad">
{{ scan["score"] }}/100
</div>

{% endif %}

</div>


<div class="meta">

<span>
{{ scan["scan_time"] }}
</span>

<span>
{{ scan["profile"] }}
</span>

<span>
Risk: {{ scan["risk"] }}
</span>

<span>
{{ scan["overall"] }}
</span>

</div>


<a
class="open"
href="/report?id={{ scan["scan_id"] }}"
>
Open Report →
</a>

<a
class="open"
href="/compare?id={{ scan["scan_id"] }}"
style="margin-left:12px"
>
Compare
</a>

</div>

{% endfor %}

</div>

{% else %}

<div class="card">
No scan history yet.
</div>

{% endif %}

</div>

</body>
</html>
"""


@app.route("/history")
def history():

    user = current_user()

    if not user:

        return redirect(
            url_for(
                "login"
            )
        )

    connection = get_db()

    scans = connection.execute(
        """
        SELECT *
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 500
        """,
        (user["id"],)
    ).fetchall()

    connection.close()

    return render_template_string(
        HISTORY_HTML,
        user=user,
        scans=scans
    )


# ============================================================
# COMPARE
# ============================================================

@app.route("/compare")
def compare():

    user = current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    scan_id = request.args.get(
        "id",
        ""
    ).strip()

    connection = get_db()

    scans = connection.execute(
        """
        SELECT *
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (user["id"],)
    ).fetchall()

    connection.close()

    selected = None

    for item in scans:

        if item["scan_id"] == scan_id:

            selected = item
            break

    if not selected:

        return "Scan not found.", 404

    result = json.loads(
        selected["data_json"]
    )

    target = result["target"]

    previous = None

    for item in scans:

        if (
            item["scan_id"]
            != scan_id
            and item["target"]
            == target
        ):

            previous = item
            break

    change = None

    if previous:

        change = (
            selected["score"]
            - previous["score"]
        )

    return render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="UTF-8">
        <meta name="viewport"
        content="width=device-width,initial-scale=1.0">
        <title>Compare — EthicalGuard</title>
        <style>
        body{
            margin:0;
            background:#070b12;
            color:#edf3f7;
            font-family:Arial,Segoe UI,sans-serif;
        }
        .wrap{
            width:min(900px,94%);
            margin:30px auto;
        }
        .card{
            background:#0a1018;
            border:1px solid #202c39;
            border-radius:14px;
            padding:20px;
            margin-bottom:12px;
        }
        .muted{
            color:#718091;
        }
        .change{
            font-size:35px;
            font-weight:800;
            margin:20px 0;
        }
        a{
            color:#79dfa9;
            text-decoration:none;
        }
        </style>
        </head>
        <body>
        <div class="wrap">

        <a href="/history">
        ← Back to History
        </a>

        <div class="card">

        <h1>
        Historical Comparison
        </h1>

        <div class="muted">
        {{ target }}
        </div>

        {% if previous %}

        <p>
        Previous score:
        <strong>
        {{ previous["score"] }}/100
        </strong>
        </p>

        <p>
        Current score:
        <strong>
        {{ selected["score"] }}/100
        </strong>
        </p>

        <div class="change">
        {% if change > 0 %}
        +{{ change }}
        {% elif change < 0 %}
        {{ change }}
        {% else %}
        0
        {% endif %}
        </div>

        <div class="muted">
        Positive number means the score improved.
        </div>

        {% else %}

        <p class="muted">
        No earlier scan of this same target was found.
        </p>

        {% endif %}

        </div>

        </div>
        </body>
        </html>
        """,
        target=target,
        previous=previous,
        selected=selected,
        change=change
    )


# ============================================================
# REPORT
# ============================================================

REPORT_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1.0">

<title>EthicalGuard Report</title>

<style>

body{
    margin:0;
    background:#081018;
    color:#edf3f7;
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

.grid{
    display:grid;
    grid-template-columns:repeat(5,1fr);
    gap:9px;
}

.box{
    border:1px solid #223040;
    border-radius:9px;
    padding:13px;
}

.finding{
    border:1px solid #223040;
    border-radius:10px;
    padding:16px;
    margin-top:10px;
}

.row{
    display:grid;
    grid-template-columns:175px 1fr;
    gap:10px;
    margin-top:8px;
}

.label{
    color:#748394;
    font-size:10px;
    text-transform:uppercase;
}

.muted{
    color:#748394;
}

a{
    color:#79dfa9;
    text-decoration:none;
}

</style>

</head>

<body>

<div
class="wrap"
id="report"
>

<div class="card">

<h1>
EthicalGuard Security Report
</h1>

<div class="muted">
SCAN • ANALYZE • PROTECT
</div>

<div style="margin-top:15px">
{{ result["final_url"] }}
</div>

<div class="score">
{{ result["score"] }}/100
</div>

<div class="muted">
{{ result["overall"] }} · Risk:
{{ result["risk"] }}
</div>

</div>


<div class="grid">

<div class="box">
Passed<br>
<strong>{{ result["passed"] }}</strong>
</div>

<div class="box">
Failed<br>
<strong>{{ result["failed"] }}</strong>
</div>

<div class="box">
Warnings<br>
<strong>{{ result["warnings"] }}</strong>
</div>

<div class="box">
High<br>
<strong>{{ result["high"] }}</strong>
</div>

<div class="box">
Low<br>
<strong>{{ result["low"] }}</strong>
</div>

</div>


<div class="card">

<h2>
Assessment Details
</h2>

<div class="row">
<div class="label">Scan ID</div>
<div>{{ result["scan_id"] }}</div>
</div>

<div class="row">
<div class="label">Target</div>
<div>{{ result["target"] }}</div>
</div>

<div class="row">
<div class="label">Profile</div>
<div>{{ result["profile_label"] }}</div>
</div>

<div class="row">
<div class="label">Scan Time</div>
<div>{{ result["scan_time"] }}</div>
</div>

<div class="row">
<div class="label">Duration</div>
<div>{{ result["duration"] }} seconds</div>
</div>

</div>


<div class="card">

<h2>
Technology Intelligence
</h2>

<p>
{{ result["technologies"]|join(", ")
if result["technologies"]
else
"No common technologies detected."
}}
</p>

</div>


<div class="card">

<h2>
Security Findings
</h2>

{% for item in result["features"] %}

<div class="finding">

<h3>
{{ loop.index }}. {{ item["name"] }}
</h3>

<div class="row">
<div class="label">Status</div>
<div>{{ item["status"] }}</div>
</div>

<div class="row">
<div class="label">Severity</div>
<div>{{ item["severity"] }}</div>
</div>

<div class="row">
<div class="label">CWE</div>
<div>{{ item["cwe"] or "-" }}</div>
</div>

<div class="row">
<div class="label">Category</div>
<div>{{ item["category"] }}</div>
</div>

<div class="row">
<div class="label">Explanation</div>
<div>{{ item["description"] }}</div>
</div>

<div class="row">
<div class="label">Evidence</div>
<div style="white-space:pre-wrap">
{{ item["evidence"] or "-" }}
</div>
</div>

<div class="row">
<div class="label">How To Fix</div>
<div>{{ item["remediation"] }}</div>
</div>

</div>

{% endfor %}

</div>

</div>

</body>
</html>
"""


@app.route("/report")
def report():

    user = current_user()

    if not user:
        return redirect(
            url_for(
                "login"
            )
        )

    scan_id = request.args.get(
        "id",
        ""
    )

    result = load_scan(
        scan_id
    )

    if not result:
        return "Report not found.", 404

    connection = get_db()

    row = connection.execute(
        """
        SELECT user_id
        FROM scans
        WHERE scan_id = ?
        """,
        (scan_id,)
    ).fetchone()

    connection.close()

    if not row:
        return "Report not found.", 404

    if row["user_id"] != user["id"]:
        return "Access denied.", 403

    return render_template_string(
        REPORT_HTML,
        result=result
    )


# ============================================================
# DOWNLOAD REPORT
# ============================================================

@app.route("/download-report")
def download_report():

    user = current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    scan_id = request.args.get(
        "id",
        ""
    )

    result = load_scan(
        scan_id
    )

    if not result:
        return "Report not found.", 404

    connection = get_db()

    row = connection.execute(
        """
        SELECT user_id
        FROM scans
        WHERE scan_id = ?
        """,
        (scan_id,)
    ).fetchone()

    connection.close()

    if not row:
        return "Report not found.", 404

    if row["user_id"] != user["id"]:
        return "Access denied.", 403

    report = render_template_string(
        REPORT_HTML,
        result=result
    )

    response = make_response(
        report
    )

    response.headers[
        "Content-Disposition"
    ] = (
        f'attachment; '
        f'filename="ethicalguard-{scan_id}.html"'
    )

    response.headers[
        "Content-Type"
    ] = "text/html; charset=utf-8"

    return response


# ============================================================
# PREMIUM PAGE
# ============================================================

PREMIUM_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1.0">

<title>Premium — EthicalGuard</title>

<style>

body{
    margin:0;
    background:#070b12;
    color:#edf3f7;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

.wrap{
    width:min(900px,92%);
    margin:40px auto;
}

.card{
    background:#0a1018;
    border:1px solid #243241;
    border-radius:16px;
    padding:24px;
    margin-bottom:12px;
}

.plan{
    border-color:#2e9d70;
}

h1{
    margin:0;
}

.price{
    font-size:38px;
    font-weight:800;
    margin:16px 0;
}

.feature{
    padding:9px 0;
    border-bottom:1px solid #1d2833;
    color:#c7d0da;
}

.btn{
    display:inline-block;
    margin-top:15px;
    padding:11px 14px;
    background:#143728;
    border:1px solid #2e9d70;
    border-radius:8px;
    color:#aff1ca;
    text-decoration:none;
}

.muted{
    color:#758394;
    font-size:11px;
    line-height:1.7;
}

</style>

</head>

<body>

<div class="wrap">

<a
href="/"
style="color:#79dfa9;text-decoration:none"
>
← Back to EthicalGuard
</a>


<div class="card plan"
style="margin-top:15px"
>

<h1>
EthicalGuard Premium
</h1>

<div class="price">
Premium
</div>

<p class="muted">
Unlock the complete security monitoring experience.
</p>


<div class="feature">
Unlimited / expanded scanning
</div>

<div class="feature">
Full security intelligence
</div>

<div class="feature">
Historical scan comparison
</div>

<div class="feature">
Monitored sites
</div>

<div class="feature">
Scheduled scans
</div>

<div class="feature">
Security alerts
</div>

<div class="feature">
Save reports as images
</div>

<div class="feature">
Technology detection
</div>

<div class="feature">
CVE intelligence
</div>

<div class="feature">
Domain intelligence
</div>

<div class="feature">
Advanced reports
</div>


<a
class="btn"
href="mailto:ahmedsidhu97@gmail.com?subject=EthicalGuard%20Premium%20Upgrade&body=Hi%20Ahmed%2C%0A%0AI%20want%20to%20upgrade%20my%20EthicalGuard%20account%20to%20Premium.%0A%0AUsername%3A%20%0AEmail%3A%20"
>
Contact to Upgrade
</a>


<p class="muted">
Premium contact:
<strong>
ahmedsidhu97@gmail.com
</strong>
</p>

</div>

</div>

</body>
</html>
"""


@app.route("/premium")
def premium():

    return render_template_string(
        PREMIUM_HTML
    )


# ============================================================
# CONTACT
# ============================================================

@app.route("/contact")
def contact():

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <meta name="viewport"
    content="width=device-width,initial-scale=1.0">
    <title>Contact — EthicalGuard</title>
    <style>
    body{{
        margin:0;
        min-height:100vh;
        display:flex;
        align-items:center;
        justify-content:center;
        background:#070b12;
        color:#edf3f7;
        font-family:Arial,Segoe UI,sans-serif;
    }}
    .card{{
        width:min(430px,92%);
        text-align:center;
        padding:30px;
        background:#0a1018;
        border:1px solid #243140;
        border-radius:16px;
    }}
    .photo{{
        width:95px;
        height:95px;
        border-radius:50%;
        object-fit:cover;
        border:1px solid #2e9d70;
    }}
    .muted{{
        color:#718091;
    }}
    a{{
        display:block;
        margin-top:14px;
        color:#79dfa9;
        text-decoration:none;
    }}
    </style>
    </head>
    <body>
    <div class="card">

    <img
    class="photo"
    src="/static/ahmed.jpg"
    alt="Ahmed Sidhu"
    >

    <h2>
    Ahmed Sidhu
    </h2>

    <div class="muted">
    Security Enthusiast
    </div>

    <p>
    ahmedsidhu97@gmail.com
    </p>

    <a
    href="mailto:ahmedsidhu97@gmail.com"
    >
    Email Ahmed
    </a>

    <a href="/">
    ← Back to EthicalGuard
    </a>

    </div>
    </body>
    </html>
    """


# ============================================================
# MONITORING
# ============================================================

MONITORING_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1.0">

<title>Monitoring — EthicalGuard</title>

<style>

body{
    margin:0;
    background:#070b12;
    color:#edf3f7;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

.wrap{
    width:min(1050px,94%);
    margin:30px auto;
}

.top{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:10px;
    margin-bottom:15px;
}

.actions{
    display:flex;
    gap:7px;
}

.btn{
    display:inline-block;
    padding:9px 12px;
    border:1px solid #293747;
    border-radius:8px;
    background:#0c121a;
    color:#e7edf2;
    text-decoration:none;
    font-size:10px;
}

.primary{
    background:#143728;
    border-color:#2e9d70;
    color:#adf1cb;
}

.card{
    background:#0a1018;
    border:1px solid #202c39;
    border-radius:14px;
    padding:17px;
    margin-bottom:10px;
}

.form{
    display:grid;
    grid-template-columns:1fr 1fr 130px 150px;
    gap:9px;
}

input,
select{
    width:100%;
    background:#080d14;
    color:#edf3f7;
    border:1px solid #293747;
    border-radius:8px;
    padding:11px;
}

.site{
    display:flex;
    justify-content:space-between;
    gap:10px;
    align-items:center;
}

.name{
    font-weight:800;
}

.url{
    color:#768596;
    font-size:10px;
    margin-top:5px;
}

.meta{
    display:flex;
    flex-wrap:wrap;
    gap:7px;
    margin-top:10px;
}

.meta span{
    border:1px solid #263443;
    border-radius:6px;
    padding:5px 7px;
    color:#8a99a8;
    font-size:8px;
}

@media(max-width:800px){

    .form{
        grid-template-columns:1fr;
    }

    .site,
    .top{
        flex-direction:column;
        align-items:flex-start;
    }
}

</style>

</head>

<body>

<div class="wrap">

<div class="top">

<div>

<h1>
Monitored Sites
</h1>

<div style="color:#718091;font-size:10px">
Automated security monitoring
</div>

</div>

<div class="actions">

<a class="btn" href="/">
Dashboard
</a>

<a class="btn" href="/history">
History
</a>

<a class="btn" href="/logout">
Logout
</a>

</div>

</div>


<div class="card">

<h3>
Add Website
</h3>

<form method="POST">

<div class="form">

<input
name="name"
placeholder="Site name"
required
>

<input
name="url"
placeholder="https://example.com"
required
>

<select name="frequency">

<option value="weekly">
Weekly
</option>

<option value="monthly">
Monthly
</option>

</select>

<select name="profile">

<option value="full">
Full Scan
</option>

<option value="passive">
Passive Intelligence
</option>

<option value="quick">
Quick Scan
</option>

</select>

</div>

<button
class="btn primary"
style="margin-top:9px;cursor:pointer"
>
Add Site
</button>

</form>

</div>


{% for site in sites %}

<div class="card">

<div class="site">

<div>

<div class="name">
{{ site["name"] }}
</div>

<div class="url">
{{ site["url"] }}
</div>

<div class="meta">

<span>
{{ site["frequency"] }}
</span>

<span>
{{ site["profile"] }}
</span>

<span>
{% if site["enabled"] %}
ACTIVE
{% else %}
PAUSED
{% endif %}
</span>

<span>
Score: {{ site["last_score"] or "-" }}
</span>

</div>

</div>


<div>

<a
class="btn"
href="/monitoring/run/{{ site["id"] }}"
>
Run Now
</a>

<a
class="btn"
href="/monitoring/toggle/{{ site["id"] }}"
>
{% if site["enabled"] %}
Pause
{% else %}
Resume
{% endif %}
</a>

</div>

</div>

</div>

{% else %}

<div class="card">
No monitored sites yet.
</div>

{% endfor %}

</div>

</body>
</html>
"""


@app.route(
    "/monitoring",
    methods=["GET", "POST"]
)
def monitoring():

    user = current_user()

    if not user:

        return redirect(
            url_for(
                "login"
            )
        )

    if not user_is_premium(
        user
    ):

        return redirect(
            url_for(
                "premium"
            )
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        url = normalize_url(
            request.form.get(
                "url",
                ""
            )
        )

        frequency = request.form.get(
            "frequency",
            "weekly"
        )

        profile = request.form.get(
            "profile",
            "full"
        )

        if (
            name
            and url
            and frequency in [
                "weekly",
                "monthly"
            ]
            and profile in SCAN_PROFILES
        ):

            connection = get_db()

            connection.execute(
                """
                INSERT INTO monitored_sites (
                    user_id,
                    name,
                    url,
                    profile,
                    frequency,
                    enabled,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    user["id"],
                    name,
                    url,
                    profile,
                    frequency,
                    now_text()
                )
            )

            connection.commit()
            connection.close()

    connection = get_db()

    sites = connection.execute(
        """
        SELECT *
        FROM monitored_sites
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user["id"],)
    ).fetchall()

    connection.close()

    return render_template_string(
        MONITORING_HTML,
        sites=sites
    )


@app.route(
    "/monitoring/run/<int:site_id>"
)
def monitoring_run(site_id):

    user = current_user()

    if not user or not user_is_premium(
        user
    ):

        return redirect(
            url_for(
                "premium"
            )
        )

    connection = get_db()

    site = connection.execute(
        """
        SELECT *
        FROM monitored_sites
        WHERE id = ?
          AND user_id = ?
        """,
        (
            site_id,
            user["id"]
        )
    ).fetchone()

    connection.close()

    if not site:
        return "Site not found.", 404

    try:

        result = perform_scan(
            site["url"],
            site["profile"]
        )

        save_scan(
            result,
            user["id"]
        )

        connection = get_db()

        connection.execute(
            """
            UPDATE monitored_sites
            SET last_run = ?,
                last_score = ?,
                last_risk = ?
            WHERE id = ?
            """,
            (
                now_text(),
                result["score"],
                result["risk"],
                site_id
            )
        )

        if result["risk"] in [
            "HIGH",
            "CRITICAL"
        ]:

            connection.execute(
                """
                INSERT INTO alerts (
                    user_id,
                    site_id,
                    message,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    user["id"],
                    site_id,
                    (
                        f"{site['name']} security scan "
                        f"returned {result['score']}/100 "
                        f"with {result['risk']} risk."
                    ),
                    now_text()
                )
            )

        connection.commit()
        connection.close()

        return redirect(
            url_for(
                "report",
                id=result["scan_id"]
            )
        )

    except Exception as exc:

        return (
            "Monitoring error: "
            + esc(exc),
            500
        )


@app.route(
    "/monitoring/toggle/<int:site_id>"
)
def monitoring_toggle(site_id):

    user = current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    connection = get_db()

    site = connection.execute(
        """
        SELECT enabled
        FROM monitored_sites
        WHERE id = ?
          AND user_id = ?
        """,
        (
            site_id,
            user["id"]
        )
    ).fetchone()

    if site:

        new_value = (
            0
            if site["enabled"]
            else 1
        )

        connection.execute(
            """
            UPDATE monitored_sites
            SET enabled = ?
            WHERE id = ?
              AND user_id = ?
            """,
            (
                new_value,
                site_id,
                user["id"]
            )
        )

        connection.commit()

    connection.close()

    return redirect(
        url_for(
            "monitoring"
        )
    )


# ============================================================
# CRON
# ============================================================

def site_due(site):

    if not site["enabled"]:
        return False

    if not site["last_run"]:
        return True

    try:

        last = datetime.strptime(
            site["last_run"],
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:

        return True

    elapsed = (
        datetime.now() - last
    ).total_seconds()

    if site["frequency"] == "weekly":

        return elapsed >= (
            7 * 86400
        )

    if site["frequency"] == "monthly":

        return elapsed >= (
            30 * 86400
        )

    return False


def send_email(
    recipient,
    subject,
    body
):

    smtp_host = os.environ.get(
        "SMTP_HOST"
    )

    smtp_port = int(
        os.environ.get(
            "SMTP_PORT",
            "587"
        )
    )

    smtp_user = os.environ.get(
        "SMTP_USER"
    )

    smtp_password = os.environ.get(
        "SMTP_PASSWORD"
    )

    sender = os.environ.get(
        "SMTP_FROM",
        smtp_user
    )

    if not all([
        smtp_host,
        smtp_user,
        smtp_password,
        sender
    ]):

        return False

    message = EmailMessage()

    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content(
        body
    )

    try:

        with smtplib.SMTP(
            smtp_host,
            smtp_port,
            timeout=20
        ) as smtp:

            smtp.starttls()

            smtp.login(
                smtp_user,
                smtp_password
            )

            smtp.send_message(
                message
            )

        return True

    except Exception:

        return False


@app.route("/cron/run")
def cron_run():

    secret = request.args.get(
        "secret",
        ""
    )

    if secret != CRON_SECRET:

        return jsonify({
            "success": False,
            "error": "Unauthorized"
        }), 401

    connection = get_db()

    sites = connection.execute(
        """
        SELECT *
        FROM monitored_sites
        WHERE enabled = 1
        """
    ).fetchall()

    connection.close()

    results = []

    for site in sites:

        if not site_due(site):
            continue

        try:

            result = perform_scan(
                site["url"],
                site["profile"]
            )

            save_scan(
                result,
                site["user_id"]
            )

            connection = get_db()

            connection.execute(
                """
                UPDATE monitored_sites
                SET last_run = ?,
                    last_score = ?,
                    last_risk = ?
                WHERE id = ?
                """,
                (
                    now_text(),
                    result["score"],
                    result["risk"],
                    site["id"]
                )
            )

            user = connection.execute(
                """
                SELECT email
                FROM users
                WHERE id = ?
                """,
                (site["user_id"],)
            ).fetchone()

            alert_message = (
                f"EthicalGuard monitoring alert\n\n"
                f"Website: {site['url']}\n"
                f"Score: {result['score']}/100\n"
                f"Risk: {result['risk']}\n"
                f"Time: {result['scan_time']}\n"
            )

            if result["risk"] in [
                "HIGH",
                "CRITICAL"
            ]:

                connection.execute(
                    """
                    INSERT INTO alerts (
                        user_id,
                        site_id,
                        message,
                        created_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        site["user_id"],
                        site["id"],
                        alert_message,
                        now_text()
                    )
                )

                if user:

                    send_email(
                        user["email"],
                        "EthicalGuard Security Alert",
                        alert_message
                    )

            connection.commit()
            connection.close()

            results.append({
                "site": site["name"],
                "score": result["score"],
                "risk": result["risk"]
            })

        except Exception as exc:

            results.append({
                "site": site["name"],
                "error": str(exc)
            })

    return jsonify({
        "success": True,
        "results": results
    })


# ============================================================
# ALERTS API
# ============================================================

@app.route("/alerts")
def alerts():

    user = current_user()

    if not user:

        return redirect(
            url_for("login")
        )

    connection = get_db()

    alerts = connection.execute(
        """
        SELECT *
        FROM alerts
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (user["id"],)
    ).fetchall()

    connection.close()

    return jsonify({
        "success": True,
        "alerts": [
            dict(item)
            for item in alerts
        ]
    })


# ============================================================
# PREMIUM ACTIVATION
# ============================================================

@app.route(
    "/admin/activate-premium",
    methods=["POST"]
)
def activate_premium():

    admin_key = request.form.get(
        "admin_key",
        ""
    )

    if admin_key != os.environ.get(
        "ADMIN_KEY",
        "CHANGE_THIS_ADMIN_KEY"
    ):

        return "Unauthorized", 401

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    days = int(
        request.form.get(
            "days",
            "30"
        )
    )

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE lower(email) = lower(?)
        """,
        (email,)
    ).fetchone()

    if not user:

        connection.close()
        return "User not found.", 404

    until = (
        datetime.now(
            timezone.utc
        )
        + timedelta(days=days)
    ).isoformat()

    connection.execute(
        """
        UPDATE users
        SET plan = 'PREMIUM',
            premium_until = ?
        WHERE id = ?
        """,
        (
            until,
            user["id"]
        )
    )

    connection.commit()
    connection.close()

    return (
        f"Premium activated for {email} "
        f"until {until}"
    )


# ============================================================
# SECURITY BADGE
# ============================================================

@app.route(
    "/badge/<scan_id>"
)
def badge(scan_id):

    result = load_scan(
        scan_id
    )

    if not result:

        return (
            "Not found",
            404
        )

    score = result["score"]

    if score >= 85:

        label = (
            f"EthicalGuard · "
            f"Secure {score}/100"
        )

        fill = "#2e9d70"

    elif score >= 70:

        label = (
            f"EthicalGuard · "
            f"Monitor {score}/100"
        )

        fill = "#c49b35"

    else:

        label = (
            f"EthicalGuard · "
            f"Needs Attention {score}/100"
        )

        fill = "#b9434b"

    svg = f"""
    <svg xmlns="http://www.w3.org/2000/svg"
         width="320"
         height="70"
         viewBox="0 0 320 70">

        <rect
            width="320"
            height="70"
            rx="12"
            fill="#0b1118"
            stroke="{fill}"
        />

        <circle
            cx="30"
            cy="35"
            r="16"
            fill="{fill}"
        />

        <text
            x="58"
            y="31"
            fill="#ffffff"
            font-family="Arial"
            font-size="13"
            font-weight="700">
            EthicalGuard
        </text>

        <text
            x="58"
            y="49"
            fill="#b9c4cf"
            font-family="Arial"
            font-size="11">
            {label}
        </text>

    </svg>
    """

    response = make_response(
        svg
    )

    response.headers[
        "Content-Type"
    ] = "image/svg+xml"

    return response


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "product": APP_NAME,
        "version": APP_VERSION,
        "database": "SQLite",
        "features": 23
    })


# ============================================================
# SECURITY HEADERS FOR ETHICALGUARD
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
# START
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
