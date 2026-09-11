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

from werkzeug.security import generate_password_hash, check_password_hash

import requests
import sqlite3
import os
import re
import uuid
import ssl
import socket
import time
import html
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

# =========================================================
# ETHICALGUARD
# Professional Web Security Monitoring Platform
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-in-render"
)

APP_NAME = "EthicalGuard"
APP_VERSION = "7.0"

DATABASE = os.environ.get(
    "DATABASE_PATH",
    "ethicalguard.db"
)

REQUEST_TIMEOUT = 12
PORT_TIMEOUT = 0.8
MAX_HISTORY = 500

CRON_SECRET = os.environ.get(
    "CRON_SECRET",
    "change-this-cron-secret"
)

# =========================================================
# SCAN PROFILES
# =========================================================

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


# =========================================================
# BASIC HELPERS
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(value):
    if not value:
        return ""

    value = value.strip()

    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value

    parsed = urlparse(value)

    if not parsed.netloc:
        return ""

    return value


def hostname_of(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def esc(value):
    return html.escape(str(value if value is not None else ""))


def finding(
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


# =========================================================
# DATABASE
# =========================================================

def db():
    connection = sqlite3.connect(
        DATABASE,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db():

    connection = db()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL UNIQUE,
            user_id INTEGER,
            owner_type TEXT NOT NULL DEFAULT 'guest',
            target TEXT NOT NULL,
            final_url TEXT,
            profile TEXT NOT NULL,
            profile_label TEXT NOT NULL,
            score INTEGER NOT NULL,
            overall TEXT NOT NULL,
            risk TEXT NOT NULL,
            passed INTEGER NOT NULL,
            failed INTEGER NOT NULL,
            warnings INTEGER NOT NULL,
            high INTEGER NOT NULL,
            medium INTEGER NOT NULL,
            low INTEGER NOT NULL,
            info INTEGER NOT NULL,
            response_status INTEGER,
            redirect_count INTEGER,
            duration REAL,
            scan_time TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            data_json TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(site_id) REFERENCES monitored_sites(id)
        )
    """)

    connection.commit()
    connection.close()


init_db()


# =========================================================
# AUTH HELPERS
# =========================================================

def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    connection = db()

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


def login_required():
    return current_user() is not None


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


# =========================================================
# DATABASE USER FUNCTIONS
# =========================================================

def create_user(username, email, password):

    connection = db()

    try:

        connection.execute(
            """
            INSERT INTO users
            (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                email.lower(),
                generate_password_hash(password),
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


def authenticate_user(identifier, password):

    connection = db()

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

    valid = check_password_hash(
        user["password_hash"],
        password
    )

    if not valid:

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


# =========================================================
# AUTH PAGES
# =========================================================

AUTH_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — EthicalGuard</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#070b12;
    color:#edf3f8;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

body:before{
    content:"";
    position:fixed;
    inset:0;
    pointer-events:none;
    background:
        linear-gradient(rgba(255,255,255,.012) 1px,transparent 1px),
        linear-gradient(90deg,rgba(255,255,255,.012) 1px,transparent 1px);
    background-size:38px 38px;
}

.card{
    width:min(460px,92%);
    background:#0a1018;
    border:1px solid #243140;
    border-radius:17px;
    padding:28px;
    position:relative;
    box-shadow:0 30px 90px rgba(0,0,0,.45);
}

.logo{
    width:52px;
    height:52px;
    display:flex;
    align-items:center;
    justify-content:center;
    margin:auto;
    border:1px solid #2e9d70;
    border-radius:14px;
    background:#09150f;
    font-size:24px;
}

h1{
    margin:14px 0 5px;
    text-align:center;
    font-size:25px;
}

.tagline{
    text-align:center;
    color:#718091;
    font-size:10px;
    letter-spacing:2px;
}

.description{
    text-align:center;
    color:#8290a0;
    font-size:11px;
    line-height:1.6;
    margin-top:12px;
}

label{
    display:block;
    margin:18px 0 7px;
    color:#7d8a99;
    text-transform:uppercase;
    letter-spacing:1px;
    font-size:9px;
}

input{
    width:100%;
    background:#080d14;
    border:1px solid #293747;
    border-radius:9px;
    color:#edf3f8;
    padding:13px;
    outline:none;
}

input:focus{
    border-color:#2e9d70;
}

button,
.link{
    width:100%;
    display:block;
    margin-top:12px;
    padding:12px;
    border-radius:9px;
    text-align:center;
    text-decoration:none;
    cursor:pointer;
    font-size:12px;
}

button{
    border:1px solid #2e9d70;
    color:#aff0cb;
    background:#143728;
}

.link{
    border:1px solid #293747;
    color:#d8e0e7;
    background:#0c121a;
}

.error{
    margin-top:13px;
    background:#32171c;
    border:1px solid #54252d;
    color:#ff9da5;
    padding:10px;
    border-radius:8px;
    font-size:11px;
}

.success{
    margin-top:13px;
    background:#0d291c;
    border:1px solid #1d5d3e;
    color:#88e4ae;
    padding:10px;
    border-radius:8px;
    font-size:11px;
}

.small{
    text-align:center;
    color:#657384;
    font-size:10px;
    margin-top:15px;
    line-height:1.6;
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

<div class="tagline">
SCAN • ANALYZE • PROTECT
</div>

<div class="description">
{{ title }} your EthicalGuard account.
</div>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

{% if success %}
<div class="success">{{ success }}</div>
{% endif %}

<form method="POST">

{% if mode == "signup" %}

<label>Username</label>

<input
type="text"
name="username"
placeholder="youname"
required
autocomplete="username"
>

<label>Email</label>

<input
type="email"
name="email"
placeholder="you@example.com"
required
autocomplete="email"
>

<label>Password</label>

<input
type="password"
name="password"
placeholder="Create a password"
required
autocomplete="new-password"
>

{% else %}

<label>Email or Username</label>

<input
type="text"
name="identifier"
placeholder="Email or username"
required
autocomplete="username"
>

<label>Password</label>

<input
type="password"
name="password"
placeholder="Your password"
required
autocomplete="current-password"
>

{% endif %}

<button type="submit">
{{ button_text }}
</button>

</form>

{% if mode == "signup" %}

<a class="link" href="/login">
Already have an account? Login
</a>

{% else %}

<a class="link" href="/signup">
Create an account
</a>

{% endif %}

<a class="link" href="/">
Back to Scanner
</a>

<div class="small">
Your scans are linked to your account and stored locally in the EthicalGuard database.
</div>

</div>

</body>
</html>
"""


# =========================================================
# SIGNUP
# =========================================================

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
                "Username must contain 3–30 letters, "
                "numbers, dots, hyphens or underscores."
            )

        elif not valid_email(email):

            error = "Please enter a valid email address."

        elif len(password) < 8:

            error = "Password must be at least 8 characters."

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

                session["user_id"] = user["id"]

                return redirect(
                    url_for("dashboard")
                )

    return render_template_string(
        AUTH_HTML,
        title="Create your account",
        button_text="Create Account",
        mode="signup",
        error=error,
        success=None
    )


# =========================================================
# LOGIN
# =========================================================

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

        user = authenticate_user(
            identifier,
            password
        )

        if not user:

            error = (
                "Invalid username/email or password."
            )

        else:

            session["user_id"] = user["id"]

            next_url = request.args.get(
                "next"
            )

            if next_url in [
                "history",
                "dashboard",
                "monitoring"
            ]:

                if next_url == "history":
                    return redirect(
                        url_for("history")
                    )

                if next_url == "monitoring":
                    return redirect(
                        url_for("monitoring")
                    )

            return redirect(
                url_for("dashboard")
            )

    return render_template_string(
        AUTH_HTML,
        title="Login to",
        button_text="Login",
        mode="login",
        error=error,
        success=None
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# SCANNER
# =========================================================

def request_target(target):

    return requests.get(
        target,
        headers={
            "User-Agent":
                "EthicalGuard/7.0 "
                "(authorized security assessment)",
            "Accept": "*/*"
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True
    )


# =========================================================
# SECURITY CHECK 1
# =========================================================

def check_https(response):

    if urlparse(response.url).scheme.lower() == "https":

        return finding(
            "HTTPS / SSL",
            "Checks whether the final connection uses HTTPS.",
            "INFO",
            "PASS",
            f"Final URL: {response.url}",
            "Keep HTTPS enabled and redirect HTTP to HTTPS.",
            "CWE-319",
            "Transport Security"
        )

    return finding(
        "HTTPS / SSL",
        "Checks whether the final connection uses HTTPS.",
        "HIGH",
        "FAIL",
        f"Final URL: {response.url}",
        "Install a valid TLS certificate and force HTTPS.",
        "CWE-319",
        "Transport Security"
    )


# =========================================================
# SECURITY CHECKS 2-5
# =========================================================

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
            "Tells browsers to keep using HTTPS.",
            "CWE-319",
            "Add Strict-Transport-Security after HTTPS is configured."
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

        value = response.headers.get(name)

        if value:

            results.append(
                finding(
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
                finding(
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


# =========================================================
# CHECK 6
# =========================================================

def check_server_disclosure(response):

    value = response.headers.get(
        "Server"
    )

    if value:

        return finding(
            "Server Information Disclosure",
            "Checks whether the Server header reveals server details.",
            "LOW",
            "WARNING",
            f"Server: {value}",
            "Hide unnecessary server/version information.",
            "CWE-200",
            "Information Disclosure"
        )

    return finding(
        "Server Information Disclosure",
        "The Server response header was not exposed.",
        "INFO",
        "PASS",
        "Server: Not exposed",
        "Continue hiding unnecessary technology details.",
        "CWE-200",
        "Information Disclosure"
    )


# =========================================================
# CHECK 7 - COOKIE SECURITY
# =========================================================

def get_cookie_headers(response):

    cookies = []

    try:

        raw = response.raw.headers

        if hasattr(raw, "get_all"):

            values = raw.get_all(
                "Set-Cookie"
            )

            if values:
                cookies.extend(values)

    except Exception:
        pass

    if not cookies:

        single = response.headers.get(
            "Set-Cookie"
        )

        if single:
            cookies.append(single)

    return cookies


def parse_cookie(cookie_header):

    parts = [
        x.strip()
        for x in cookie_header.split(";")
        if x.strip()
    ]

    name = (
        parts[0].split("=", 1)[0].strip()
        if parts and "=" in parts[0]
        else "Unknown"
    )

    secure = False
    httponly = False
    samesite = None

    for part in parts[1:]:

        lower = part.lower()

        if lower == "secure":
            secure = True

        elif lower == "httponly":
            httponly = True

        elif lower.startswith("samesite"):

            if "=" in part:

                samesite = (
                    part.split("=", 1)[1]
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


def check_cookie_security(response):

    headers = get_cookie_headers(
        response
    )

    if not headers:

        return finding(
            "Cookie Security",
            "No Set-Cookie header was observed in this response.",
            "INFO",
            "INFO",
            "Set-Cookie: Not Found",
            "Review authenticated/session cookies separately.",
            "CWE-614",
            "Cookie Security"
        )

    results = []

    for header in headers:

        cookie = parse_cookie(
            header
        )

        missing = []

        if not cookie["secure"]:
            missing.append("Secure")

        if not cookie["httponly"]:
            missing.append("HttpOnly")

        same = cookie["samesite"]

        if same is None:
            missing.append("SameSite")

        invalid_none = (
            isinstance(same, str)
            and same.lower() == "none"
            and not cookie["secure"]
        )

        if invalid_none:
            missing.append(
                "Secure required for SameSite=None"
            )

        if invalid_none:

            severity = "MEDIUM"
            status = "FAIL"

        elif len(missing) >= 2:

            severity = "MEDIUM"
            status = "FAIL"

        elif len(missing) == 1:

            severity = "LOW"
            status = "WARNING"

        else:

            severity = "INFO"
            status = "PASS"

        if status == "PASS":

            description = (
                f"Cookie '{cookie['name']}' has "
                "Secure, HttpOnly and SameSite."
            )

        else:

            description = (
                f"Cookie '{cookie['name']}' "
                f"needs: {', '.join(missing)}."
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

    priority = {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4
    }

    highest = "INFO"
    final_status = "PASS"

    for item in results:

        if priority[item["severity"]] > priority[highest]:
            highest = item["severity"]

        if item["status"] == "FAIL":
            final_status = "FAIL"

        elif (
            item["status"] == "WARNING"
            and final_status != "FAIL"
        ):
            final_status = "WARNING"

    return finding(
        "Cookie Security",
        " ".join(
            item["description"]
            for item in results
        ),
        highest,
        final_status,
        " | ".join(
            item["evidence"]
            for item in results
        ),
        (
            "Use Secure and HttpOnly on sensitive cookies. "
            "Use SameSite=Lax or Strict where suitable. "
            "SameSite=None requires Secure."
        ),
        "CWE-614",
        "Cookie Security"
    )


# =========================================================
# CHECK 8
# =========================================================

def check_cors(response):

    value = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    if not value:

        return finding(
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

        return finding(
            "CORS Policy",
            "A wildcard CORS policy was observed.",
            "MEDIUM",
            "WARNING",
            f"Access-Control-Allow-Origin: {value}",
            "Use a trusted origin allow-list for sensitive applications.",
            "CWE-942",
            "CORS"
        )

    return finding(
        "CORS Policy",
        "No permissive wildcard CORS policy was observed.",
        "INFO",
        "PASS",
        f"Access-Control-Allow-Origin: {value}",
        "Keep the origin list restricted.",
        "CWE-942",
        "CORS"
    )


# =========================================================
# CHECK 9
# =========================================================

def check_permissions_policy(response):

    value = response.headers.get(
        "Permissions-Policy"
    )

    if value:

        return finding(
            "Permissions-Policy",
            "Controls access to selected browser features.",
            "INFO",
            "PASS",
            f"Permissions-Policy: {value}",
            "Keep browser permissions restrictive.",
            "CWE-16",
            "Browser Security"
        )

    return finding(
        "Permissions-Policy",
        "Controls access to selected browser features.",
        "LOW",
        "WARNING",
        "Permissions-Policy: Not Found",
        "Consider defining Permissions-Policy.",
        "CWE-16",
        "Browser Security"
    )


# =========================================================
# TLS HELPERS
# =========================================================

def certificate_info(hostname):

    context = ssl.create_default_context()

    with socket.create_connection(
        (hostname, 443),
        timeout=REQUEST_TIMEOUT
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=hostname
        ) as secure_sock:

            return (
                secure_sock.getpeercert(),
                secure_sock.cipher(),
                secure_sock.version()
            )


def tls_probe(
    hostname,
    minimum=None,
    maximum=None
):

    context = ssl.create_default_context()

    if minimum is not None:
        context.minimum_version = minimum

    if maximum is not None:
        context.maximum_version = maximum

    with socket.create_connection(
        (hostname, 443),
        timeout=PORT_TIMEOUT
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=hostname
        ) as secure_sock:

            return (
                secure_sock.version(),
                secure_sock.cipher()
            )


# =========================================================
# CHECK 10
# =========================================================

def check_tls_certificate(response):

    hostname = hostname_of(
        response.url
    )

    if not hostname:

        return finding(
            "TLS Certificate",
            "TLS certificate could not be inspected.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Use a valid HTTPS hostname.",
            "CWE-295",
            "TLS"
        )

    try:

        cert, cipher, version = certificate_info(
            hostname
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

            days_left = (
                expiry - datetime.utcnow()
            ).days

            return finding(
                "TLS Certificate",
                "TLS certificate was successfully inspected.",
                "INFO",
                "PASS",
                (
                    f"TLS={version} | "
                    f"Cipher={cipher[0] if cipher else 'Unknown'} | "
                    f"Expires={expiry.isoformat()} | "
                    f"Days={days_left}"
                ),
                "Keep certificate renewal monitored.",
                "CWE-295",
                "TLS"
            )

        return finding(
            "TLS Certificate",
            "TLS certificate was successfully inspected.",
            "INFO",
            "PASS",
            f"TLS={version}",
            "Continue monitoring TLS configuration.",
            "CWE-295",
            "TLS"
        )

    except ssl.SSLCertVerificationError as exc:

        return finding(
            "TLS Certificate",
            "Certificate validation failed.",
            "HIGH",
            "FAIL",
            str(exc)[:1000],
            "Install a valid trusted certificate and correct the chain.",
            "CWE-295",
            "TLS"
        )

    except Exception as exc:

        return finding(
            "TLS Certificate",
            "TLS certificate details could not be fully inspected.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Review the HTTPS/TLS configuration.",
            "CWE-295",
            "TLS"
        )


# =========================================================
# CHECK 11
# =========================================================

def check_dns(response):

    hostname = hostname_of(
        response.url
    )

    try:

        infos = socket.getaddrinfo(
            hostname,
            None
        )

        addresses = sorted({
            item[4][0]
            for item in infos
            if item and item[4]
        })

        return finding(
            "DNS Information",
            "Shows public host addresses resolved by EthicalGuard.",
            "INFO",
            "INFO",
            f"{hostname}: {', '.join(addresses)}",
            "Keep DNS records accurate.",
            "CWE-706",
            "DNS"
        )

    except Exception as exc:

        return finding(
            "DNS Information",
            "DNS resolution failed.",
            "HIGH",
            "FAIL",
            str(exc)[:1000],
            "Verify the domain DNS configuration.",
            "CWE-706",
            "DNS"
        )


# =========================================================
# CHECK 12
# =========================================================

def check_redirect_chain(response):

    if not response.history:

        return finding(
            "Redirect Chain",
            "Shows redirects followed before reaching the final target.",
            "INFO",
            "INFO",
            f"Final: {response.url}",
            "Keep redirects intentional and minimal.",
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

        return finding(
            "Redirect Chain",
            "A relatively long redirect chain was detected.",
            "MEDIUM",
            "WARNING",
            " -> ".join(chain),
            "Reduce unnecessary redirect hops.",
            "CWE-601",
            "Redirects"
        )

    return finding(
        "Redirect Chain",
        "Shows redirects followed before reaching the final target.",
        "INFO",
        "INFO",
        " -> ".join(chain),
        "Keep redirects intentional.",
        "CWE-601",
        "Redirects"
    )


# =========================================================
# CHECK 13
# =========================================================

def check_x_xss(response):

    value = response.headers.get(
        "X-XSS-Protection"
    )

    if value:

        return finding(
            "X-XSS-Protection",
            "Checks the legacy browser XSS filter header.",
            "INFO",
            "PASS",
            f"X-XSS-Protection: {value}",
            "Prioritize CSP for modern browsers.",
            "CWE-79",
            "Legacy Browser Security"
        )

    return finding(
        "X-XSS-Protection",
        "Checks the legacy browser XSS filter header.",
        "INFO",
        "INFO",
        "X-XSS-Protection: Not Found",
        "Modern browsers should primarily rely on CSP.",
        "CWE-79",
        "Legacy Browser Security"
    )


# =========================================================
# CHECK 14
# =========================================================

def check_referrer_policy(response):

    value = response.headers.get(
        "Referrer-Policy"
    )

    if value:

        return finding(
            "Referrer-Policy",
            "Controls how much referral information is shared with other websites.",
            "INFO",
            "PASS",
            f"Referrer-Policy: {value}",
            "Keep a privacy-conscious policy.",
            "CWE-200",
            "Privacy"
        )

    return finding(
        "Referrer-Policy",
        "Controls referral information shared with other websites.",
        "LOW",
        "WARNING",
        "Referrer-Policy: Not Found",
        "Consider strict-origin-when-cross-origin.",
        "CWE-200",
        "Privacy"
    )


# =========================================================
# CHECK 15
# =========================================================

def check_coop(response):

    value = response.headers.get(
        "Cross-Origin-Opener-Policy"
    )

    if value:

        return finding(
            "Cross-Origin-Opener-Policy (COOP)",
            "Helps isolate the browser context from cross-origin documents.",
            "INFO",
            "PASS",
            f"Cross-Origin-Opener-Policy: {value}",
            "Use a suitable COOP policy where isolation is required.",
            "CWE-693",
            "Cross-Origin Isolation"
        )

    return finding(
        "Cross-Origin-Opener-Policy (COOP)",
        "Helps isolate the browser context from cross-origin documents.",
        "INFO",
        "INFO",
        "COOP: Not Found",
        "Consider COOP where stronger browser isolation is needed.",
        "CWE-693",
        "Cross-Origin Isolation"
    )


# =========================================================
# CHECK 16
# =========================================================

def check_coep(response):

    value = response.headers.get(
        "Cross-Origin-Embedder-Policy"
    )

    if value:

        return finding(
            "Cross-Origin-Embedder-Policy (COEP)",
            "Controls cross-origin resource embedding permissions.",
            "INFO",
            "PASS",
            f"Cross-Origin-Embedder-Policy: {value}",
            "Use COEP where cross-origin isolation is needed.",
            "CWE-693",
            "Cross-Origin Isolation"
        )

    return finding(
        "Cross-Origin-Embedder-Policy (COEP)",
        "Controls cross-origin resource embedding permissions.",
        "INFO",
        "INFO",
        "COEP: Not Found",
        "Consider COEP where required.",
        "CWE-693",
        "Cross-Origin Isolation"
    )


# =========================================================
# CHECK 17
# =========================================================

def check_framework_disclosure(response):

    exposed = []

    for header in [
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version"
    ]:

        value = response.headers.get(
            header
        )

        if value:

            exposed.append(
                f"{header}: {value}"
            )

    if exposed:

        return finding(
            "X-Powered-By / Framework Disclosure",
            "Checks whether backend framework information is exposed.",
            "LOW",
            "WARNING",
            " | ".join(exposed),
            "Remove unnecessary framework/version headers.",
            "CWE-200",
            "Information Disclosure"
        )

    return finding(
        "X-Powered-By / Framework Disclosure",
        "No common backend framework disclosure headers were observed.",
        "INFO",
        "PASS",
        "Framework disclosure headers not observed.",
        "Continue hiding unnecessary framework details.",
        "CWE-200",
        "Information Disclosure"
    )


# =========================================================
# CHECK 18
# =========================================================

def check_tls_protocol(response):

    hostname = hostname_of(
        response.url
    )

    detected = []

    if not hostname:
        return finding(
            "SSL/TLS Protocol Version",
            "Checks whether modern TLS versions are available.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Provide a valid HTTPS hostname.",
            "CWE-327",
            "TLS"
        )

    versions = [
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
    ]

    for version in versions:

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

        except Exception:
            pass

    if detected:

        return finding(
            "SSL/TLS Protocol Version",
            "Checks whether modern TLS protocol versions are available.",
            "INFO",
            "PASS",
            "Tested: " + ", ".join(sorted(set(detected))),
            "Prefer TLS 1.2 and TLS 1.3.",
            "CWE-327",
            "TLS"
        )

    return finding(
        "SSL/TLS Protocol Version",
        "Modern TLS 1.2/1.3 could not be confirmed.",
        "HIGH",
        "WARNING",
        "TLS 1.2 / TLS 1.3 not confirmed.",
        "Enable TLS 1.2 or TLS 1.3.",
        "CWE-327",
        "TLS"
    )


# =========================================================
# CHECK 19
# =========================================================

def check_weak_cipher(response):

    hostname = hostname_of(
        response.url
    )

    if not hostname:

        return finding(
            "Weak Cipher Suites",
            "Checks the negotiated TLS cipher.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Use HTTPS and review TLS configuration.",
            "CWE-327",
            "TLS"
        )

    try:

        version, cipher = tls_probe(
            hostname
        )

        name = (
            cipher[0]
            if cipher
            else "Unknown"
        )

        weak = [
            x for x in [
                "RC4",
                "3DES",
                "DES-CBC",
                "NULL",
                "EXPORT",
                "MD5"
            ]
            if x in name.upper()
        ]

        if weak:

            return finding(
                "Weak Cipher Suites",
                "The negotiated cipher contains a legacy algorithm.",
                "HIGH",
                "FAIL",
                f"{version} | {name}",
                "Disable weak/legacy ciphers and use modern AEAD suites.",
                "CWE-327",
                "TLS"
            )

        return finding(
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

        return finding(
            "Weak Cipher Suites",
            "Cipher information could not be inspected.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Review TLS cipher configuration manually.",
            "CWE-327",
            "TLS"
        )


# =========================================================
# CHECK 20
# =========================================================

def check_certificate_expiry(response):

    hostname = hostname_of(
        response.url
    )

    try:

        cert, _, _ = certificate_info(
            hostname
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

            return finding(
                "SSL Certificate Expiration Alert",
                "Certificate has expired.",
                "HIGH",
                "FAIL",
                f"Expired: {expiry.isoformat()}",
                "Renew the certificate immediately.",
                "CWE-295",
                "TLS"
            )

        if days <= 7:

            return finding(
                "SSL Certificate Expiration Alert",
                f"Certificate expires in approximately {days} days.",
                "HIGH",
                "WARNING",
                f"Expires: {expiry.isoformat()}",
                "Renew immediately.",
                "CWE-295",
                "TLS"
            )

        if days <= 14:

            return finding(
                "SSL Certificate Expiration Alert",
                f"Certificate expires in approximately {days} days.",
                "MEDIUM",
                "WARNING",
                f"Expires: {expiry.isoformat()}",
                "Schedule renewal now.",
                "CWE-295",
                "TLS"
            )

        if days <= 30:

            return finding(
                "SSL Certificate Expiration Alert",
                f"Certificate expires in approximately {days} days.",
                "LOW",
                "WARNING",
                f"Expires: {expiry.isoformat()}",
                "Plan renewal before expiry.",
                "CWE-295",
                "TLS"
            )

        return finding(
            "SSL Certificate Expiration Alert",
            f"Certificate has approximately {days} days remaining.",
            "INFO",
            "PASS",
            f"Expires: {expiry.isoformat()}",
            "Continue monitoring expiry.",
            "CWE-295",
            "TLS"
        )

    except Exception as exc:

        return finding(
            "SSL Certificate Expiration Alert",
            "Certificate expiration could not be checked.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Review the certificate manually.",
            "CWE-295",
            "TLS"
        )


# =========================================================
# CHECK 21
# =========================================================

def check_sri(response):

    if "html" not in response.headers.get(
        "Content-Type",
        ""
    ).lower():

        return finding(
            "Subresource Integrity (SRI)",
            "Checks external scripts for integrity attributes.",
            "INFO",
            "INFO",
            "Response was not identified as HTML.",
            "Review external JavaScript resources where relevant.",
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

            match = re.search(
                r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]",
                tag,
                re.I
            )

            if not match:
                continue

            full = urljoin(
                response.url,
                match.group(1)
            )

            parsed = urlparse(full)

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

            return finding(
                "Subresource Integrity (SRI)",
                f"{len(missing)} external script(s) lack integrity attributes.",
                "LOW",
                "WARNING",
                " | ".join(missing[:10]),
                "Add SRI integrity hashes to suitable third-party scripts.",
                "CWE-829",
                "Frontend Security"
            )

        return finding(
            "Subresource Integrity (SRI)",
            "External scripts were checked for integrity attributes.",
            "INFO",
            "PASS",
            f"External scripts checked: {external}",
            "Continue using SRI where appropriate.",
            "CWE-829",
            "Frontend Security"
        )

    except Exception as exc:

        return finding(
            "Subresource Integrity (SRI)",
            "SRI analysis could not be completed.",
            "LOW",
            "WARNING",
            str(exc)[:1000],
            "Review third-party scripts manually.",
            "CWE-829",
            "Frontend Security"
        )


# =========================================================
# CHECK 22
# =========================================================

def check_open_ports(response):

    hostname = hostname_of(
        response.url
    )

    open_ports = []

    for port, service in COMMON_PORTS.items():

        try:

            with socket.create_connection(
                (hostname, port),
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

        return finding(
            "Open Port Detection",
            "Potentially sensitive service ports responded.",
            "HIGH",
            "WARNING",
            ", ".join(risky),
            "Confirm exposure is intentional and restrict unnecessary services.",
            "CWE-668",
            "Network Exposure"
        )

    return finding(
        "Open Port Detection",
        "Checks a limited set of common TCP service ports.",
        "INFO",
        "INFO",
        (
            "Open ports: "
            + (
                ", ".join(open_ports)
                if open_ports
                else "None detected"
            )
        ),
        "Keep exposed services limited and intentional.",
        "CWE-668",
        "Network Exposure"
    )


# =========================================================
# CHECK 23
# =========================================================

def check_subdomains(response):

    hostname = hostname_of(
        response.url
    )

    if not hostname:

        return finding(
            "Subdomain Enumeration",
            "Checks common subdomain names.",
            "LOW",
            "WARNING",
            "Hostname unavailable.",
            "Provide a valid domain.",
            "CWE-200",
            "DNS Intelligence"
        )

    parts = hostname.split(".")

    if len(parts) >= 2:
        base = ".".join(parts[-2:])
    else:
        base = hostname

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

    return finding(
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
            else "No common candidates resolved."
        ),
        "Review discovered hosts and remove unused subdomains.",
        "CWE-200",
        "DNS Intelligence"
    )


# =========================================================
# SCAN ENGINE
# =========================================================

def audit_website(
    target,
    profile="full"
):

    started = time.time()

    target = normalize_url(
        target
    )

    if not target:
        raise ValueError(
            "Please enter a valid website URL."
        )

    if profile not in SCAN_PROFILES:
        profile = "full"

    response = request_target(
        target
    )

    findings = []

    findings.append(
        check_https(response)
    )

    findings.extend(
        check_required_headers(response)
    )

    findings.append(
        check_server_disclosure(response)
    )

    findings.append(
        check_cookie_security(response)
    )

    findings.append(
        check_cors(response)
    )

    findings.append(
        check_permissions_policy(response)
    )

    findings.append(
        check_tls_certificate(response)
    )

    findings.append(
        check_dns(response)
    )

    findings.append(
        check_redirect_chain(response)
    )

    findings.append(
        check_x_xss(response)
    )

    findings.append(
        check_referrer_policy(response)
    )

    findings.append(
        check_coop(response)
    )

    findings.append(
        check_coep(response)
    )

    findings.append(
        check_framework_disclosure(response)
    )

    findings.append(
        check_tls_protocol(response)
    )

    findings.append(
        check_weak_cipher(response)
    )

    findings.append(
        check_certificate_expiry(response)
    )

    findings.append(
        check_sri(response)
    )

    if SCAN_PROFILES[profile]["ports"]:

        findings.append(
            check_open_ports(response)
        )

    else:

        findings.append(
            finding(
                "Open Port Detection",
                "Checks a limited set of common TCP service ports.",
                "INFO",
                "INFO",
                "Skipped for this scan profile.",
                "Use Full Scan for this check.",
                "CWE-668",
                "Network Exposure"
            )
        )

    if SCAN_PROFILES[profile]["subdomains"]:

        findings.append(
            check_subdomains(response)
        )

    else:

        findings.append(
            finding(
                "Subdomain Enumeration",
                "Checks common subdomain names.",
                "INFO",
                "INFO",
                "Skipped for this scan profile.",
                "Use Full Scan or Passive Intelligence.",
                "CWE-200",
                "DNS Intelligence"
            )
        )

    score = 100

    deduction = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 4,
        "INFO": 0
    }

    for item in findings:

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
        and x["status"] in [
            "FAIL",
            "WARNING"
        ]
    )

    medium = sum(
        1 for x in findings
        if x["severity"] == "MEDIUM"
        and x["status"] in [
            "FAIL",
            "WARNING"
        ]
    )

    low = sum(
        1 for x in findings
        if x["severity"] == "LOW"
        and x["status"] in [
            "FAIL",
            "WARNING"
        ]
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

    return {
        "scan_id": uuid.uuid4().hex[:12],
        "target": target,
        "final_url": response.url,
        "profile": profile,
        "profile_label": SCAN_PROFILES[profile]["label"],
        "score": score,
        "overall": overall,
        "risk": risk,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "response_status": response.status_code,
        "redirect_count": len(response.history),
        "duration": duration,
        "scan_time": now_text(),
        "timestamp": now_iso(),
        "features": findings,
        "feature_count": len(findings),
        "engine": APP_VERSION
    }


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(result, user_id=None):

    connection = db()

    owner_type = (
        "user"
        if user_id
        else "guest"
    )

    connection.execute(
        """
        INSERT INTO scans (
            scan_id,
            user_id,
            owner_type,
            target,
            final_url,
            profile,
            profile_label,
            score,
            overall,
            risk,
            passed,
            failed,
            warnings,
            high,
            medium,
            low,
            info,
            response_status,
            redirect_count,
            duration,
            scan_time,
            timestamp,
            data_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result["scan_id"],
            user_id,
            owner_type,
            result["target"],
            result["final_url"],
            result["profile"],
            result["profile_label"],
            result["score"],
            result["overall"],
            result["risk"],
            result["passed"],
            result["failed"],
            result["warnings"],
            result["high"],
            result["medium"],
            result["low"],
            result["info"],
            result["response_status"],
            result["redirect_count"],
            result["duration"],
            result["scan_time"],
            result["timestamp"],
            __import__("json").dumps(
                result
            )
        )
    )

    connection.commit()
    connection.close()


def load_scan(scan_id):

    connection = db()

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

    return __import__("json").loads(
        row["data_json"]
    )


# =========================================================
# MAIN DASHBOARD
# =========================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>EthicalGuard</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:#070b12;
    color:#eaf0f5;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

body:before{
    content:"";
    position:fixed;
    inset:0;
    pointer-events:none;
    background:
        linear-gradient(rgba(255,255,255,.013) 1px,transparent 1px),
        linear-gradient(90deg,rgba(255,255,255,.013) 1px,transparent 1px);
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
    padding:21px 0;
    border-bottom:1px solid #1d2834;
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
}

.shield{
    width:46px;
    height:46px;
    border:1px solid #2e9d70;
    background:#09150f;
    border-radius:13px;
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
    color:#738192;
    letter-spacing:2px;
    font-size:10px;
}

.actions{
    display:flex;
    gap:8px;
    align-items:center;
}

.btn{
    display:inline-block;
    border:1px solid #293746;
    background:#0c121a;
    color:#e7edf2;
    border-radius:8px;
    padding:10px 13px;
    text-decoration:none;
    cursor:pointer;
    font-size:11px;
}

.btn:hover{
    border-color:#3a4b5d;
}

.btn.primary{
    border-color:#2e9d70;
    background:#143728;
    color:#aef1cb;
}

.profile-pill{
    display:flex;
    align-items:center;
    gap:8px;
    padding:8px 10px;
    border:1px solid #253443;
    border-radius:9px;
    color:#b8c3cd;
}

.avatar{
    width:28px;
    height:28px;
    border-radius:50%;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#123122;
    color:#90e6b4;
    font-size:11px;
    font-weight:800;
}

.hero{
    padding:28px 0 18px;
}

.hero h2{
    margin:0 0 8px;
    font-size:29px;
}

.hero p{
    color:#8190a0;
    line-height:1.6;
    max-width:900px;
    margin:0;
}

.scanbox{
    margin-top:19px;
    padding:17px;
    border:1px solid #202c39;
    background:#0a1018;
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
    background:#080d14;
    border:1px solid #293747;
    color:#edf3f7;
    border-radius:8px;
    padding:12px;
    outline:none;
}

input:focus,
select:focus{
    border-color:#2e9d70;
}

.progress{
    height:4px;
    background:#121b24;
    border-radius:20px;
    margin-top:12px;
    overflow:hidden;
    display:none;
}

.progress-bar{
    width:0;
    height:100%;
    background:#2e9d70;
    transition:.2s;
}

.stats{
    display:grid;
    grid-template-columns:repeat(7,1fr);
    gap:9px;
    margin:17px 0;
}

.stat{
    background:#0a1018;
    border:1px solid #202c39;
    border-radius:12px;
    padding:14px;
}

.stat small{
    color:#718090;
    text-transform:uppercase;
    letter-spacing:1px;
    font-size:9px;
}

.stat strong{
    display:block;
    margin-top:7px;
    font-size:22px;
}

.main-grid{
    display:grid;
    grid-template-columns:minmax(0,1.55fr) minmax(320px,.75fr);
    gap:12px;
}

.card{
    background:#0a1018;
    border:1px solid #202c39;
    border-radius:14px;
    overflow:hidden;
}

.card-head{
    padding:14px 16px;
    border-bottom:1px solid #1d2733;
    display:flex;
    justify-content:space-between;
    align-items:center;
}

.card-head h3{
    margin:0;
    font-size:14px;
}

.muted{
    color:#728192;
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
    padding:12px 13px;
    border-bottom:1px solid #18222d;
    text-align:left;
    font-size:11px;
    vertical-align:top;
}

th{
    color:#6e7c8b;
    font-size:9px;
    text-transform:uppercase;
    letter-spacing:1px;
}

.badge{
    display:inline-block;
    padding:5px 7px;
    border-radius:6px;
    font-size:9px;
    font-weight:800;
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
    color:#718091;
    text-align:center;
    line-height:1.7;
}

.meta{
    display:flex;
    flex-wrap:wrap;
    gap:7px;
    margin:10px 0;
}

.meta span{
    border:1px solid #243140;
    border-radius:6px;
    padding:5px 7px;
    color:#8b99a8;
    font-size:9px;
}

.section{
    margin-top:15px;
}

.section label{
    display:block;
    color:#718090;
    font-size:9px;
    letter-spacing:1px;
    margin-bottom:5px;
}

.section p{
    margin:0;
    color:#c6d0da;
    font-size:11px;
    line-height:1.65;
    word-break:break-word;
}

.footer{
    margin:29px 0 40px;
    padding-top:17px;
    border-top:1px solid #1d2733;
    display:flex;
    justify-content:space-between;
    align-items:center;
    color:#718091;
    font-size:10px;
}

.profile-footer{
    display:flex;
    align-items:center;
    gap:9px;
}

.profile-footer img{
    width:38px;
    height:38px;
    border-radius:50%;
    object-fit:cover;
    border:1px solid #2a3746;
}

@media(max-width:1100px){

    .stats{
        grid-template-columns:repeat(4,1fr);
    }

    .main-grid{
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

    .actions .secondary{
        display:none;
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

<h1>
EthicalGuard
</h1>

<p>
SCAN • ANALYZE • PROTECT
</p>

</div>

</div>


<div class="actions">

{% if user %}

<div class="profile-pill">

<div class="avatar">
{{ user["username"][0]|upper }}
</div>

{{ user["username"] }}

</div>

<a class="btn" href="/history">
History
</a>

<a class="btn" href="/monitoring">
Monitored Sites
</a>

<a class="btn" href="/logout">
Logout
</a>

{% else %}

<a class="btn" href="/login">
Login
</a>

<a class="btn primary" href="/signup">
Sign Up
</a>

{% endif %}

<a class="btn secondary" href="/contact">
Contact Us
</a>

</div>

</div>


<div class="hero">

<h2>
Professional Web Security Assessment
</h2>

<p>
Authorized passive security auditing for transport security,
headers, cookies, CORS, TLS, DNS, frontend integrity,
network exposure and subdomain intelligence.
</p>


<div class="scanbox">

<form
method="POST"
onsubmit="startScan()"
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

<div
class="progress"
id="progress"
>

<div
id="progressBar"
class="progress-bar"
></div>

</div>

</form>

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


<div class="main-grid">

<div class="card">

<div class="card-head">

<h3>
Security Findings
</h3>

<span class="muted">
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

<span class="muted">
Evidence / Remediation
</span>

</div>


<div
id="detailPanel"
class="detail"
>

<div class="detail-empty">
Select a finding to view explanation,
evidence and remediation.
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
Assessment Summary
</h3>

<span class="muted">
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
Owner: {{ result.owner_name }}
</span>

</div>


<div class="section">

<label>
TARGET
</label>

<p>
{{ result.final_url }}
</p>

</div>


<div style="margin-top:14px">

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
Download Report
</a>

</div>

</div>

</div>

{% endif %}


{% if error %}

<div
class="card"
style="margin-top:13px"
>

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
EthicalGuard · Web Security Monitoring Platform
</div>


<div class="profile-footer">

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


<script>

function startScan(){

    const progress =
        document.getElementById("progress");

    const bar =
        document.getElementById("progressBar");

    if(!progress || !bar){
        return;
    }

    progress.style.display =
        "block";

    let value = 0;

    const timer =
        setInterval(function(){

            value +=
                Math.floor(
                    Math.random() * 8
                ) + 4;

            if(value >= 94){

                value = 94;

                clearInterval(timer);

            }

            bar.style.width =
                value + "%";

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

    const panel =
        document.getElementById(
            "detailPanel"
        );

    panel.innerHTML = `

        <h3>
        ${esc(item.name)}
        </h3>

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

            <label>
            WHY IT MATTERS
            </label>

            <p>
            ${esc(item.description)}
            </p>

        </div>

        <div class="section">

            <label>
            EVIDENCE
            </label>

            <p>
            ${esc(item.evidence || "-")}
            </p>

        </div>

        <div class="section">

            <label>
            HOW TO FIX
            </label>

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


# =========================================================
# DASHBOARD ROUTE
# =========================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def dashboard():

    result = None
    error = None
    user = current_user()

    if request.method == "POST":

        target = request.form.get(
            "url",
            ""
        ).strip()

        profile = request.form.get(
            "profile",
            "full"
        )

        try:

            result = audit_website(
                target,
                profile
            )

            user_id = (
                user["id"]
                if user
                else None
            )

            if user:

                result["owner_name"] = (
                    user["username"]
                )

            else:

                result["owner_name"] = "Guest"

            save_scan(
                result,
                user_id
            )

        except requests.exceptions.SSLError as exc:

            error = (
                "SSL/TLS error: "
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
        error=error,
        user=user
    )


# =========================================================
# HISTORY PAGE
# =========================================================

HISTORY_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Scan History — EthicalGuard</title>

<style>

body{
    margin:0;
    background:#070b12;
    color:#edf2f6;
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
    margin-bottom:17px;
}

h1{
    margin:0;
}

.muted{
    color:#718091;
    font-size:11px;
    margin-top:5px;
}

.actions{
    display:flex;
    gap:8px;
}

.btn{
    display:inline-block;
    padding:9px 12px;
    border-radius:8px;
    border:1px solid #293747;
    background:#0c121a;
    color:#e7edf2;
    text-decoration:none;
    font-size:11px;
}

.grid{
    display:grid;
    gap:10px;
}

.scan-card{
    background:#0a1018;
    border:1px solid #202c39;
    border-radius:14px;
    padding:16px;
    transition:.2s;
}

.scan-card:hover{
    border-color:#365064;
}

.row{
    display:flex;
    justify-content:space-between;
    gap:10px;
    align-items:center;
}

.target{
    font-size:14px;
    font-weight:700;
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
    gap:7px;
    margin-top:12px;
}

.meta span{
    color:#8b99a8;
    border:1px solid #263443;
    border-radius:6px;
    padding:5px 7px;
    font-size:9px;
}

.open{
    display:inline-block;
    margin-top:12px;
    color:#79dfa9;
    text-decoration:none;
    font-size:11px;
}

.empty{
    border:1px solid #202c39;
    background:#0a1018;
    border-radius:14px;
    padding:35px;
    text-align:center;
    color:#718091;
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

<div class="muted">
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


<div class="grid">

{% if scans %}

{% for scan in scans %}

<div class="scan-card">

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
{{ scan["profile_label"] }}
</span>

<span>
Risk: {{ scan["risk"] }}
</span>

<span>
{{ scan["overall"] }}
</span>

<span>
High: {{ scan["high"] }}
</span>

<span>
Medium: {{ scan["medium"] }}
</span>

</div>


<a
class="open"
href="/report?id={{ scan["scan_id"] }}"
>
Open Report →
</a>

</div>

{% endfor %}

{% else %}

<div class="empty">

No scan history yet.

<br><br>

Run your first scan from the dashboard.

</div>

{% endif %}

</div>

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
                "login",
                next="history"
            )
        )

    connection = db()

    scans = connection.execute(
        """
        SELECT *
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (
            user["id"],
            MAX_HISTORY
        )
    ).fetchall()

    connection.close()

    return render_template_string(
        HISTORY_HTML,
        scans=scans,
        user=user
    )


# =========================================================
# REPORT
# =========================================================

REPORT_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Security Report — EthicalGuard</title>

<style>

body{
    margin:0;
    background:#081018;
    color:#edf2f6;
    font-family:Arial,Segoe UI,sans-serif;
}

.container{
    width:min(1150px,93%);
    margin:30px auto;
}

.card{
    border:1px solid #223040;
    background:#0c141d;
    border-radius:14px;
    padding:20px;
    margin-bottom:12px;
}

.score{
    font-size:45px;
    font-weight:800;
    margin-top:14px;
}

.muted{
    color:#748394;
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

.back{
    color:#79dfa9;
    text-decoration:none;
    font-size:11px;
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

<div class="container">

<a
class="back"
href="/"
>
← Back to EthicalGuard
</a>


<div class="card"
style="margin-top:14px"
>

<h1>
EthicalGuard Security Report
</h1>

<div class="muted">
SCAN • ANALYZE • PROTECT
</div>

<div style="margin-top:14px">
{{ result["final_url"] }}
</div>

<div class="score">
{{ result["score"] }}/100
</div>

<div class="muted">
{{ result["overall"] }}
 · Risk: {{ result["risk"] }}
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

    scan_id = request.args.get(
        "id",
        ""
    ).strip()

    result = load_scan(
        scan_id
    )

    if not result:
        return "Report not found.", 404

    owner = result.get(
        "owner_id"
    )

    # owner_id is added below when appropriate.
    if owner:

        user = current_user()

        if not user or str(user["id"]) != str(owner):

            return redirect(
                url_for(
                    "login",
                    next="history"
                )
            )

    return render_template_string(
        REPORT_HTML,
        result=result
    )


# =========================================================
# DOWNLOAD REPORT
# =========================================================

@app.route("/download-report")
def download_report():

    scan_id = request.args.get(
        "id",
        ""
    ).strip()

    result = load_scan(
        scan_id
    )

    if not result:
        return "Report not found.", 404

    owner = result.get(
        "owner_id"
    )

    if owner:

        user = current_user()

        if not user or str(user["id"]) != str(owner):

            return redirect(
                url_for(
                    "login",
                    next="history"
                )
            )

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
        f'filename="ethicalguard-{scan_id}.html"'
    )

    return response


# =========================================================
# MONITORED SITES PAGE
# =========================================================

MONITORING_HTML = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Monitored Sites — EthicalGuard</title>

<style>

body{
    margin:0;
    background:#070b12;
    color:#edf2f6;
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
    margin-bottom:15px;
}

.actions{
    display:flex;
    gap:8px;
}

.btn{
    display:inline-block;
    padding:9px 12px;
    border-radius:8px;
    border:1px solid #293747;
    background:#0c121a;
    color:#e7edf2;
    text-decoration:none;
    font-size:11px;
}

.btn.primary{
    background:#143728;
    border-color:#2e9d70;
    color:#adf1cb;
}

.card{
    border:1px solid #202c39;
    background:#0a1018;
    border-radius:14px;
    padding:17px;
    margin-bottom:10px;
}

.form-grid{
    display:grid;
    grid-template-columns:1fr 1fr 150px 130px;
    gap:9px;
}

input,
select{
    width:100%;
    background:#080d14;
    border:1px solid #293747;
    border-radius:8px;
    color:#edf3f7;
    padding:11px;
    outline:none;
}

input:focus,
select:focus{
    border-color:#2e9d70;
}

.site{
    display:flex;
    justify-content:space-between;
    gap:15px;
    align-items:center;
}

.name{
    font-weight:800;
    font-size:14px;
}

.url{
    color:#778595;
    margin-top:5px;
    font-size:11px;
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
    font-size:9px;
    color:#8b99a8;
}

@media(max-width:800px){

    .form-grid{
        grid-template-columns:1fr;
    }

    .top{
        flex-direction:column;
        align-items:flex-start;
    }

    .site{
        flex-direction:column;
        align-items:flex-start;
    }
}

</style>

</head>

<body>

<div class="container">

<div class="top">

<div>

<h1>
Monitored Sites
</h1>

<div style="color:#718091;font-size:11px">
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
Add a monitored website
</h3>

<form
method="POST"
>

<div class="form-grid">

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
style="margin-top:10px"
type="submit"
>
Add Site
</button>

</form>

</div>


{% if sites %}

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
{{ site["frequency"]|upper }}
</span>

<span>
{{ site["profile"] }}
</span>

<span>
{% if site["enabled"] %}
Active
{% else %}
Paused
{% endif %}
</span>

<span>
Last score:
{{ site["last_score"] or "-" }}
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

{% endfor %}

{% else %}

<div class="card">
<span style="color:#718091">
No monitored websites yet.
</span>
</div>

{% endif %}

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
                "login",
                next="monitoring"
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

            connection = db()

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

        return redirect(
            url_for("monitoring")
        )

    connection = db()

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
        sites=sites,
        user=user
    )


# =========================================================
# RUN MONITORED SITE NOW
# =========================================================

@app.route(
    "/monitoring/run/<int:site_id>"
)
def monitoring_run(site_id):

    user = current_user()

    if not user:
        return redirect(
            url_for(
                "login",
                next="monitoring"
            )
        )

    connection = db()

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

        result = audit_website(
            site["url"],
            site["profile"]
        )

        result["owner_name"] = user["username"]
        result["owner_id"] = user["id"]

        save_scan(
            result,
            user["id"]
        )

        connection = db()

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

        connection.commit()
        connection.close()

        return redirect(
            url_for("report", id=result["scan_id"])
        )

    except Exception as exc:

        return (
            "Monitoring scan failed: "
            + esc(exc),
            500
        )


# =========================================================
# TOGGLE MONITORING
# =========================================================

@app.route(
    "/monitoring/toggle/<int:site_id>"
)
def monitoring_toggle(site_id):

    user = current_user()

    if not user:
        return redirect(
            url_for(
                "login",
                next="monitoring"
            )
        )

    connection = db()

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
        url_for("monitoring")
    )


# =========================================================
# CRON ENGINE
# =========================================================

def should_run(site):

    last_run = site["last_run"]

    if not last_run:
        return True

    try:

        last = datetime.strptime(
            last_run,
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:

        return True

    now = datetime.now()

    if site["frequency"] == "weekly":

        return (
            now - last
        ).total_seconds() >= 7 * 86400

    if site["frequency"] == "monthly":

        return (
            now - last
        ).total_seconds() >= 30 * 86400

    return False


@app.route("/cron/run")
def cron_run():

    secret = request.args.get(
        "secret",
        ""
    )

    if not CRON_SECRET or secret != CRON_SECRET:

        return jsonify({
            "success": False,
            "error": "Unauthorized"
        }), 401

    connection = db()

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

        if not should_run(site):
            continue

        try:

            result = audit_website(
                site["url"],
                site["profile"]
            )

            result["owner_id"] = site["user_id"]
            result["owner_name"] = "Monitored Site"

            save_scan(
                result,
                site["user_id"]
            )

            connection = db()

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

            # Alert when score becomes significantly poor.
            if result["score"] < 70:

                connection.execute(
                    """
                    INSERT INTO alerts (
                        user_id,
                        site_id,
                        alert_type,
                        message,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        site["user_id"],
                        site["id"],
                        "SECURITY_RISK",
                        (
                            f"{site['name']} scored "
                            f"{result['score']}/100 "
                            f"with {result['risk']} risk."
                        ),
                        now_text()
                    )
                )

            connection.commit()
            connection.close()

            results.append({
                "site": site["name"],
                "status": "scanned",
                "score": result["score"]
            })

        except Exception as exc:

            results.append({
                "site": site["name"],
                "status": "error",
                "error": str(exc)
            })

    return jsonify({
        "success": True,
        "results": results
    })


# =========================================================
# ALERTS
# =========================================================

@app.route("/alerts")
def alerts():

    user = current_user()

    if not user:
        return redirect(
            url_for(
                "login"
            )
        )

    connection = db()

    rows = connection.execute(
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

    items = [
        dict(row)
        for row in rows
    ]

    return jsonify({
        "success": True,
        "alerts": items
    })


# =========================================================
# CONTACT
# =========================================================

@app.route("/contact")
def contact():

    return """
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <meta name="viewport"
    content="width=device-width,initial-scale=1.0">

    <title>Contact — EthicalGuard</title>

    <style>
    body{
        margin:0;
        min-height:100vh;
        display:flex;
        align-items:center;
        justify-content:center;
        background:#070b12;
        color:#edf2f6;
        font-family:Arial,Segoe UI,sans-serif;
    }

    .card{
        width:min(430px,92%);
        text-align:center;
        padding:30px;
        background:#0a1018;
        border:1px solid #243140;
        border-radius:16px;
    }

    img{
        width:95px;
        height:95px;
        border-radius:50%;
        object-fit:cover;
        border:1px solid #2e9d70;
    }

    .muted{
        color:#718091;
    }

    a{
        display:inline-block;
        margin-top:20px;
        color:#78dfa8;
        text-decoration:none;
    }
    </style>
    </head>

    <body>

    <div class="card">

        <img
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
        sidhuahmed9886@gmail.com
        </p>

        <a href="/">
        ← Back to EthicalGuard
        </a>

    </div>

    </body>
    </html>
    """


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "product": APP_NAME,
        "version": APP_VERSION,
        "features": 23,
        "database": "SQLite"
    })


# =========================================================
# APP SECURITY HEADERS
# =========================================================

@app.after_request
def app_headers(response):

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


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
