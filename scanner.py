from pathlib import Path

code = r'''from flask import (
    Flask, request, render_template_string, redirect,
    url_for, session, jsonify, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash

import sqlite3
import requests
import ssl
import socket
import json
import os
import re
import uuid
import time
import html
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET_KEY")

APP_NAME = "EthicalGuard"
APP_VERSION = "9.0"
FREE_SCAN_LIMIT = 8
DATABASE = os.environ.get("DATABASE_PATH", "ethicalguard.db")
REQUEST_TIMEOUT = 10
PORT_TIMEOUT = 0.5
PREMIUM_EMAIL = "ahmedsidhu97@gmail.com"

PROFILES = {
    "quick": {"label": "Quick Scan", "ports": False, "subdomains": False},
    "full": {"label": "Full Scan — 23 Checks", "ports": True, "subdomains": True},
    "passive": {"label": "Passive Intelligence", "ports": False, "subdomains": True},
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

COMMON_SUBDOMAINS = [
    "www", "api", "app", "admin", "portal", "mail", "dev",
    "test", "staging", "beta", "demo", "shop", "cdn", "static", "m"
]


# --------------------------- DB ---------------------------

def db():
    con = sqlite3.connect(DATABASE, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'FREE',
        free_scans_remaining INTEGER NOT NULL DEFAULT 8,
        created_at TEXT NOT NULL,
        last_login TEXT
    );

    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        user_id INTEGER,
        target TEXT NOT NULL,
        final_url TEXT NOT NULL,
        profile TEXT NOT NULL,
        score INTEGER NOT NULL,
        overall TEXT NOT NULL,
        risk TEXT NOT NULL,
        scan_time TEXT NOT NULL,
        duration REAL NOT NULL,
        data_json TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS monitored_sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        profile TEXT NOT NULL,
        frequency TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run TEXT,
        last_score INTEGER,
        last_risk TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        site_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    con.commit()
    con.close()


init_db()


# --------------------------- Helpers ---------------------------

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(value):
    value = (value or "").strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    try:
        p = urlparse(value)
        if not p.netloc or not p.hostname:
            return ""
        return value
    except Exception:
        return ""


def hostname(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def finding(name, description, severity="INFO", status="PASS",
            evidence="", fix="", cwe="", category="Security"):
    return {
        "name": name, "description": description,
        "severity": severity, "status": status,
        "evidence": evidence, "remediation": fix,
        "cwe": cwe, "category": category
    }


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    con = db()
    user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    return user


def premium(user):
    return bool(user and user["plan"] == "PREMIUM")


def valid_email(email):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


def create_user(username, email, password):
    con = db()
    try:
        cur = con.execute("""
            INSERT INTO users
            (username, email, password_hash, plan, free_scans_remaining, created_at)
            VALUES (?, ?, ?, 'FREE', ?, ?)
        """, (username, email.lower(), generate_password_hash(password),
              FREE_SCAN_LIMIT, now()))
        con.commit()
        user = con.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        return user
    except sqlite3.IntegrityError:
        return None
    finally:
        con.close()


def login_user(identifier, password):
    con = db()
    user = con.execute("""
        SELECT * FROM users
        WHERE lower(email)=lower(?) OR lower(username)=lower(?)
    """, (identifier, identifier)).fetchone()
    if not user:
        con.close()
        return None
    ok = check_password_hash(user["password_hash"], password)
    if not ok:
        con.close()
        return None
    con.execute("UPDATE users SET last_login=? WHERE id=?", (now(), user["id"]))
    con.commit()
    updated = con.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    con.close()
    return updated


def consume_scan(user_id):
    con = db()
    row = con.execute(
        "SELECT free_scans_remaining, plan FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not row:
        con.close()
        return False
    if row["plan"] == "PREMIUM":
        con.close()
        return True
    if row["free_scans_remaining"] <= 0:
        con.close()
        return False
    con.execute(
        "UPDATE users SET free_scans_remaining=free_scans_remaining-1 WHERE id=?",
        (user_id,)
    )
    con.commit()
    con.close()
    return True


def save_scan(result, user_id):
    con = db()
    con.execute("""
        INSERT INTO scans
        (scan_id,user_id,target,final_url,profile,score,overall,risk,scan_time,duration,data_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        result["scan_id"], user_id, result["target"], result["final_url"],
        result["profile"], result["score"], result["overall"], result["risk"],
        result["scan_time"], result["duration"], json.dumps(result, ensure_ascii=False)
    ))
    con.commit()
    con.close()


def owned_scan(scan_id, user_id):
    con = db()
    row = con.execute(
        "SELECT * FROM scans WHERE scan_id=? AND user_id=?", (scan_id, user_id)
    ).fetchone()
    con.close()
    return row


def fetch_target(url):
    return requests.get(
        url,
        headers={"User-Agent": "EthicalGuard/9.0 (authorized security assessment)"},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True
    )


# --------------------------- 23 Checks ---------------------------

def check_https(r):
    ok = urlparse(r.url).scheme.lower() == "https"
    return finding(
        "HTTPS / SSL",
        "Checks whether the final URL uses HTTPS.",
        "INFO" if ok else "HIGH",
        "PASS" if ok else "FAIL",
        f"Final URL: {r.url}",
        "Force HTTPS and use a valid TLS certificate.",
        "CWE-319", "Transport Security"
    )


def header_check(r, name, description, cwe, fix, missing_severity="MEDIUM"):
    v = r.headers.get(name)
    if v:
        return finding(name, description, "INFO", "PASS", f"{name}: {v}", fix, cwe, "Security Headers")
    return finding(name, description, missing_severity, "FAIL", f"{name}: Not Found", fix, cwe, "Security Headers")


def check_server(r):
    v = r.headers.get("Server")
    return finding(
        "Server Information Disclosure",
        "Checks whether server/version information is exposed.",
        "LOW" if v else "INFO",
        "WARNING" if v else "PASS",
        f"Server: {v}" if v else "Server: Not exposed",
        "Hide unnecessary server/version information.",
        "CWE-200", "Information Disclosure"
    )


def cookie_headers(r):
    vals = []
    try:
        raw = getattr(r, "raw", None)
        headers = getattr(raw, "headers", None)
        if headers is not None and hasattr(headers, "get_all"):
            vals = headers.get_all("Set-Cookie") or []
    except Exception:
        pass
    if not vals:
        one = r.headers.get("Set-Cookie")
        if one:
            vals = [one]
    return vals


def check_cookies(r):
    vals = cookie_headers(r)
    if not vals:
        return finding(
            "Cookie Security", "No Set-Cookie header was observed.",
            "INFO", "INFO", "Set-Cookie: Not Found",
            "Review application/session cookies separately.",
            "CWE-614", "Cookie Security"
        )
    worst = 0
    names = []
    levels = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    messages = []
    for raw in vals:
        parts = [x.strip() for x in raw.split(";") if x.strip()]
        cname = parts[0].split("=", 1)[0] if parts and "=" in parts[0] else "Unknown"
        low = [x.lower() for x in parts[1:]]
        secure = "secure" in low
        httponly = "httponly" in low
        samesite = next((x.split("=",1)[1].strip().lower()
                         for x in parts[1:] if x.lower().startswith("samesite=")), None)
        missing = []
        if not secure: missing.append("Secure")
        if not httponly: missing.append("HttpOnly")
        if samesite is None: missing.append("SameSite")
        if samesite == "none" and not secure: missing.append("Secure required for SameSite=None")
        sev = "INFO" if not missing else ("MEDIUM" if len(missing) >= 2 else "LOW")
        status = "PASS" if not missing else ("FAIL" if sev == "MEDIUM" else "WARNING")
        worst = max(worst, levels[sev])
        names.append(cname)
        messages.append(f"{cname}: Secure={secure}, HttpOnly={httponly}, SameSite={samesite or 'Missing'}")
    sev = ["INFO","LOW","MEDIUM","HIGH"][worst]
    status = "PASS" if worst == 0 else ("FAIL" if worst >= 2 else "WARNING")
    return finding(
        "Cookie Security",
        "Checks Secure, HttpOnly and SameSite cookie attributes.",
        sev, status, " | ".join(messages),
        "Use Secure, HttpOnly and an appropriate SameSite policy.",
        "CWE-614", "Cookie Security"
    )


def check_cors(r):
    v = r.headers.get("Access-Control-Allow-Origin")
    if not v:
        return finding("CORS Policy", "No CORS allow-origin header was observed.",
                       "INFO","PASS","Access-Control-Allow-Origin: Not Found",
                       "Keep CORS restricted to trusted origins.","CWE-942","CORS")
    if v.strip() == "*":
        return finding("CORS Policy","Wildcard CORS was observed.","MEDIUM","WARNING",
                       f"Access-Control-Allow-Origin: {v}",
                       "Avoid wildcard CORS for sensitive data.","CWE-942","CORS")
    return finding("CORS Policy","CORS is restricted to a specific origin.",
                   "INFO","PASS",f"Access-Control-Allow-Origin: {v}",
                   "Keep the allow-list narrow.","CWE-942","CORS")


def check_permissions(r):
    v = r.headers.get("Permissions-Policy")
    return finding("Permissions-Policy","Controls access to browser features.",
                   "INFO" if v else "LOW",
                   "PASS" if v else "WARNING",
                   f"Permissions-Policy: {v}" if v else "Header not observed.",
                   "Consider adding a suitable Permissions-Policy.","CWE-16","Browser Security")


def tls_info(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host,443),timeout=REQUEST_TIMEOUT) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            return ss.getpeercert(), ss.cipher(), ss.version()


def tls_probe(host, version):
    ctx = ssl.create_default_context()
    ctx.minimum_version = version
    ctx.maximum_version = version
    with socket.create_connection((host,443),timeout=PORT_TIMEOUT) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            return ss.version(), ss.cipher()


def check_tls_certificate(r):
    if urlparse(r.url).scheme.lower() != "https":
        return finding("TLS Certificate","HTTPS is not in use.","HIGH","FAIL",
                       "Certificate not applicable to HTTP final URL.",
                       "Use HTTPS with a valid certificate.","CWE-295","TLS")
    host = hostname(r.url)
    try:
        cert, cipher, version = tls_info(host)
        exp = cert.get("notAfter","")
        return finding("TLS Certificate","TLS certificate was successfully inspected.",
                       "INFO","PASS",
                       f"TLS={version} | Cipher={cipher[0] if cipher else 'Unknown'} | Expires={exp}",
                       "Keep certificate renewal monitored.","CWE-295","TLS")
    except Exception as e:
        return finding("TLS Certificate","Certificate inspection failed.",
                       "HIGH","FAIL",str(e),
                       "Install a valid trusted certificate.","CWE-295","TLS")


def check_dns(r):
    host = hostname(r.url)
    try:
        infos = socket.getaddrinfo(host,None)
        ips = sorted({x[4][0] for x in infos if x and x[4]})
        return finding("DNS Information","Shows addresses resolved for the host.",
                       "INFO","INFO",f"{host}: {', '.join(ips)}",
                       "Keep DNS records accurate.","CWE-706","DNS")
    except Exception as e:
        return finding("DNS Information","DNS resolution failed.",
                       "HIGH","FAIL",str(e),"Verify DNS records.","CWE-706","DNS")


def check_redirects(r):
    if len(r.history) >= 5:
        chain = " -> ".join([f"{x.status_code}: {x.url}" for x in r.history] + [f"{r.status_code}: {r.url}"])
        return finding("Redirect Chain","A long redirect chain was detected.",
                       "MEDIUM","WARNING",chain,
                       "Reduce unnecessary redirect hops.","CWE-601","Redirects")
    chain = " -> ".join([x.url for x in r.history] + [r.url])
    return finding("Redirect Chain","Shows redirects followed to the final target.",
                   "INFO","INFO",chain,"Keep redirects intentional.","CWE-601","Redirects")


def check_xss(r):
    v = r.headers.get("X-XSS-Protection")
    return finding("X-XSS-Protection","Checks the legacy XSS browser header.",
                   "INFO","PASS" if v else "INFO",v or "Header not observed.",
                   "Use CSP as the primary modern protection.","CWE-79","Legacy Browser Security")


def check_referrer(r):
    v = r.headers.get("Referrer-Policy")
    return finding("Referrer-Policy","Controls referrer information.",
                   "INFO" if v else "LOW","PASS" if v else "WARNING",
                   v or "Header not observed.",
                   "Consider strict-origin-when-cross-origin.","CWE-200","Privacy")


def check_coop(r):
    v = r.headers.get("Cross-Origin-Opener-Policy")
    return finding("Cross-Origin-Opener-Policy (COOP)","Browser context isolation policy.",
                   "INFO","PASS" if v else "INFO",v or "Header not observed.",
                   "Consider COOP where isolation is needed.","CWE-693","Cross-Origin Isolation")


def check_coep(r):
    v = r.headers.get("Cross-Origin-Embedder-Policy")
    return finding("Cross-Origin-Embedder-Policy (COEP)","Cross-origin resource embedding policy.",
                   "INFO","PASS" if v else "INFO",v or "Header not observed.",
                   "Consider COEP where isolation is needed.","CWE-693","Cross-Origin Isolation")


def check_framework(r):
    found = []
    for h in ("X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version"):
        if r.headers.get(h):
            found.append(f"{h}: {r.headers.get(h)}")
    return finding("X-Powered-By / Framework Disclosure",
                   "Checks common technology disclosure headers.",
                   "LOW" if found else "INFO",
                   "WARNING" if found else "PASS",
                   " | ".join(found) if found else "No common framework disclosure.",
                   "Remove unnecessary framework/version headers.","CWE-200","Information Disclosure")


def check_tls_version(r):
    if urlparse(r.url).scheme.lower() != "https":
        return finding("SSL/TLS Protocol Version","HTTPS is not in use.",
                       "HIGH","WARNING","HTTPS unavailable.","Enable HTTPS.","CWE-327","TLS")
    host = hostname(r.url)
    supported = []
    for v in (getattr(ssl.TLSVersion,"TLSv1_2",None), getattr(ssl.TLSVersion,"TLSv1_3",None)):
        if v is None:
            continue
        try:
            actual,_ = tls_probe(host,v)
            if actual: supported.append(actual)
        except Exception:
            pass
    if supported:
        return finding("SSL/TLS Protocol Version","Checks modern TLS support.",
                       "INFO","PASS",", ".join(sorted(set(supported))),
                       "Prefer TLS 1.2 and TLS 1.3.","CWE-327","TLS")
    return finding("SSL/TLS Protocol Version","Modern TLS could not be confirmed.",
                   "HIGH","WARNING","TLS 1.2/1.3 not confirmed.",
                   "Enable TLS 1.2 or TLS 1.3.","CWE-327","TLS")


def check_cipher(r):
    if urlparse(r.url).scheme.lower() != "https":
        return finding("Weak Cipher Suites","HTTPS is not in use.",
                       "HIGH","WARNING","HTTPS unavailable.","Enable HTTPS.","CWE-327","TLS")
    try:
        version,cipher = tls_probe(hostname(r.url), ssl.TLSVersion.MINIMUM_SUPPORTED)
        name = cipher[0] if cipher else "Unknown"
        weak = any(x in name.upper() for x in ("RC4","3DES","DES-CBC","NULL","EXPORT","MD5"))
        return finding("Weak Cipher Suites","Checks the negotiated TLS cipher.",
                       "HIGH" if weak else "INFO",
                       "FAIL" if weak else "PASS",
                       f"{version} | {name}",
                       "Disable legacy ciphers and prefer modern AEAD suites.","CWE-327","TLS")
    except Exception as e:
        return finding("Weak Cipher Suites","Cipher inspection failed.",
                       "LOW","WARNING",str(e),
                       "Review TLS cipher configuration.","CWE-327","TLS")


def check_expiry(r):
    if urlparse(r.url).scheme.lower() != "https":
        return finding("SSL Certificate Expiration Alert","HTTPS is not in use.",
                       "HIGH","WARNING","HTTPS unavailable.","Enable HTTPS.","CWE-295","TLS")
    try:
        cert,_,_ = tls_info(hostname(r.url))
        exp_text = cert.get("notAfter")
        exp = datetime.strptime(exp_text,"%b %d %H:%M:%S %Y %Z")
        days = (exp - datetime.utcnow()).days
        if days < 0:
            sev,status = "HIGH","FAIL"
        elif days <= 7:
            sev,status = "HIGH","WARNING"
        elif days <= 30:
            sev,status = "MEDIUM","WARNING"
        elif days <= 60:
            sev,status = "LOW","WARNING"
        else:
            sev,status = "INFO","PASS"
        return finding("SSL Certificate Expiration Alert",
                       f"Certificate has {days} days remaining.",
                       sev,status,exp.isoformat(),
                       "Renew the certificate before expiry.","CWE-295","TLS")
    except Exception as e:
        return finding("SSL Certificate Expiration Alert","Certificate expiry could not be checked.",
                       "LOW","WARNING",str(e),
                       "Review certificate manually.","CWE-295","TLS")


def check_sri(r):
    if "html" not in r.headers.get("Content-Type","").lower():
        return finding("Subresource Integrity (SRI)","Response was not identified as HTML.",
                       "INFO","INFO","Content-Type does not appear to be HTML.",
                       "Review external scripts where appropriate.","CWE-829","Frontend Security")
    try:
        tags = re.findall(r"<script\b[^>]*>", r.text, re.I)
        external = 0
        missing = []
        for tag in tags:
            m = re.search(r'\bsrc\s*=\s*[\'"]([^\'"]+)',tag,re.I)
            if not m: continue
            full = urljoin(r.url,m.group(1))
            p = urlparse(full)
            if p.hostname and p.hostname != hostname(r.url):
                external += 1
                if not re.search(r"\bintegrity\s*=",tag,re.I):
                    missing.append(full)
        return finding("Subresource Integrity (SRI)",
                       f"{len(missing)} external script(s) lack integrity." if missing else "External scripts were checked.",
                       "LOW" if missing else "INFO",
                       "WARNING" if missing else "PASS",
                       " | ".join(missing[:8]) if missing else f"External scripts checked: {external}",
                       "Add SRI hashes to suitable third-party scripts.","CWE-829","Frontend Security")
    except Exception as e:
        return finding("Subresource Integrity (SRI)","SRI analysis failed.",
                       "LOW","WARNING",str(e),
                       "Review third-party scripts manually.","CWE-829","Frontend Security")


def check_ports(r):
    host = hostname(r.url)
    if not host:
        return finding("Open Port Detection","Host unavailable.","INFO","INFO","Skipped.","","CWE-668","Network Exposure")
    opened = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.create_connection((host,port), timeout=PORT_TIMEOUT):
                opened.append(f"{port}/{service}")
        except Exception:
            pass
    risky = [x for x in opened if x.split("/",1)[1] in {"FTP","Telnet","SMB","MySQL","PostgreSQL","Redis"}]
    return finding("Open Port Detection",
                   "Checks a finite list of common TCP ports.",
                   "HIGH" if risky else "INFO",
                   "WARNING" if risky else "INFO",
                   ", ".join(opened) if opened else "No tested ports responded.",
                   "Confirm exposed services are intentional and restrict unnecessary access.",
                   "CWE-668","Network Exposure")


def check_subdomains(r):
    host = hostname(r.url)
    parts = host.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else host
    found = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f"{prefix}.{base}"
        try:
            socket.gethostbyname(candidate)
            found.append(candidate)
        except Exception:
            pass
    return finding("Subdomain Enumeration",
                   f"{len(found)} common subdomain(s) resolved.",
                   "INFO","INFO",", ".join(found) if found else "None",
                   "Review discovered hosts and remove unused subdomains.",
                   "CWE-200","DNS Intelligence")


def technology_detection(r):
    body = r.text.lower()
    headers = r.headers
    out = []
    signatures = [
        ("WordPress", "wp-content"),
        ("WooCommerce", "woocommerce"),
        ("React", "react"),
        ("Next.js", "__next_data__"),
        ("jQuery", "jquery"),
        ("Bootstrap", "bootstrap"),
    ]
    for name, sig in signatures:
        if sig in body:
            out.append(name)
    server = headers.get("Server","").lower()
    powered = headers.get("X-Powered-By","").lower()
    for name, sig in [("Nginx","nginx"),("Apache","apache"),("PHP","php"),("Express.js","express")]:
        if sig in server or sig in powered:
            out.append(name)
    return list(dict.fromkeys(out))


def rdap(domain):
    try:
        res = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=7,
            headers={"User-Agent":"EthicalGuard/9.0"}
        )
        if res.status_code != 200:
            return {"available":False,"error":f"RDAP {res.status_code}"}
        data = res.json()
        events = {}
        for e in data.get("events",[]):
            if e.get("eventAction"):
                events[e["eventAction"]] = e.get("eventDate")
        return {
            "available": True,
            "handle": data.get("handle"),
            "status": data.get("status",[]),
            "events": events
        }
    except Exception as e:
        return {"available":False,"error":str(e)}


def cve_intelligence(technologies):
    # Informational keyword lookup. Failures are intentionally ignored.
    items = []
    for tech in technologies[:3]:
        try:
            res = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch":tech,"resultsPerPage":2},
                timeout=7,
                headers={"User-Agent":"EthicalGuard/9.0"}
            )
            if res.status_code != 200:
                continue
            for item in res.json().get("vulnerabilities",[])[:2]:
                cve = item.get("cve",{})
                if cve.get("id"):
                    desc = next(
                        (d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"), ""
                    )
                    items.append({"technology":tech,"cve":cve["id"],"description":desc[:300]})
        except Exception:
            pass
    return items[:8]


def latency(url):
    start = time.perf_counter()
    try:
        requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        ms = round((time.perf_counter()-start)*1000)
        return f"{ms} ms"
    except Exception:
        return "Unavailable"


def owasp_map(features):
    areas = []
    for f in features:
        n = f["name"].lower()
        if any(x in n for x in ("cookie","authentication","session")):
            areas.append("A07 Identification & Authentication Failures")
        elif any(x in n for x in ("tls","https","cipher","certificate")):
            areas.append("A02 Cryptographic Failures")
        else:
            areas.append("A05 Security Misconfiguration")
    return list(dict.fromkeys(areas))


# --------------------------- Scan Engine ---------------------------

def perform_scan(target, profile):
    started = time.time()
    target = normalize_url(target)
    if not target:
        raise ValueError("Please enter a valid URL.")
    if profile not in PROFILES:
        profile = "full"

    r = fetch_target(target)

    features = [
        check_https(r),
        header_check(r,"X-Frame-Options",
                     "Protects against clickjacking by controlling framing.",
                     "CWE-1021","Add X-Frame-Options: DENY or SAMEORIGIN."),
        header_check(r,"Content-Security-Policy",
                     "Controls which resources browsers may load.",
                     "CWE-693","Deploy an appropriate Content-Security-Policy."),
        header_check(r,"Strict-Transport-Security",
                     "Tells browsers to keep using HTTPS.",
                     "CWE-319","Add Strict-Transport-Security."),
        header_check(r,"X-Content-Type-Options",
                     "Helps prevent MIME sniffing.",
                     "CWE-16","Add X-Content-Type-Options: nosniff."),
        check_server(r), check_cookies(r), check_cors(r), check_permissions(r),
        check_tls_certificate(r), check_dns(r), check_redirects(r), check_xss(r),
        check_referrer(r), check_coop(r), check_coep(r), check_framework(r),
        check_tls_version(r), check_cipher(r), check_expiry(r), check_sri(r)
    ]

    if PROFILES[profile]["ports"]:
        features.append(check_ports(r))
    else:
        features.append(finding(
            "Open Port Detection","Skipped in this profile.","INFO","INFO","Skipped.",
            "Use Full Scan for common-port testing.","CWE-668","Network Exposure"
        ))

    if PROFILES[profile]["subdomains"]:
        features.append(check_subdomains(r))
    else:
        features.append(finding(
            "Subdomain Enumeration","Skipped in this profile.","INFO","INFO","Skipped.",
            "Use Full or Passive Intelligence.","CWE-200","DNS Intelligence"
        ))

    technologies = technology_detection(r)
    cves = cve_intelligence(technologies)
    domain = hostname(r.url)
    domain_data = rdap(domain)
    latency_ms = latency(r.url)
    owasp = owasp_map(features)

    high = sum(1 for x in features if x["severity"]=="HIGH" and x["status"] in ("FAIL","WARNING"))
    medium = sum(1 for x in features if x["severity"]=="MEDIUM" and x["status"] in ("FAIL","WARNING"))
    low = sum(1 for x in features if x["severity"]=="LOW" and x["status"] in ("FAIL","WARNING"))
    passed = sum(1 for x in features if x["status"]=="PASS")
    failed = sum(1 for x in features if x["status"]=="FAIL")
    warnings = sum(1 for x in features if x["status"]=="WARNING")
    info = sum(1 for x in features if x["status"]=="INFO")

    score = 100 - (high*20 + medium*10 + low*4)
    score = max(0, min(100, score))

    if high >= 2: risk = "CRITICAL"
    elif high == 1: risk = "HIGH"
    elif medium >= 2: risk = "HIGH"
    elif medium == 1: risk = "MEDIUM"
    elif low > 0: risk = "LOW"
    else: risk = "MINIMAL"

    if high > 0:
        overall = "VULNERABLE"
    elif medium > 0 or low > 0:
        overall = "NEEDS ATTENTION"
    elif warnings > 0:
        overall = "SECURE WITH WARNINGS"
    else:
        overall = "SECURE"

    return {
        "scan_id": uuid.uuid4().hex[:12],
        "target": target,
        "final_url": r.url,
        "profile": profile,
        "profile_label": PROFILES[profile]["label"],
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
        "response_status": r.status_code,
        "redirect_count": len(r.history),
        "duration": round(time.time()-started,2),
        "scan_time": now(),
        "features": features,
        "technologies": technologies,
        "cves": cves,
        "rdap": domain_data,
        "latency": latency_ms,
        "owasp": owasp,
        "engine": APP_VERSION
    }


# --------------------------- Templates ---------------------------

BASE_STYLE = """
*{box-sizing:border-box}
body{margin:0;background:#070b12;color:#eaf0f5;font-family:Inter,Segoe UI,Arial,sans-serif}
.wrap{width:min(1200px,94%);margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:18px 0;border-bottom:1px solid #202c39}
.brand{display:flex;align-items:center;gap:11px}
.logo{width:45px;height:45px;border:1px solid #2e9d70;border-radius:12px;display:grid;place-items:center;background:#09150f}
.brand h1{font-size:20px;margin:0}.brand p{font-size:9px;letter-spacing:2px;color:#768597;margin:4px 0 0}
.actions{display:flex;gap:7px;flex-wrap:wrap}.btn{display:inline-block;padding:9px 12px;border:1px solid #2a3949;border-radius:8px;background:#0c121a;color:#e8eef3;text-decoration:none;font-size:10px;cursor:pointer}.primary{background:#143728;border-color:#2e9d70;color:#b0f3cb}
.card{background:#0a1018;border:1px solid #202c39;border-radius:14px;padding:16px;margin-top:12px}
input,select,textarea{width:100%;background:#080d14;color:#edf3f7;border:1px solid #293747;border-radius:8px;padding:11px;outline:none}
h2{font-size:27px;margin:28px 0 8px}.muted{color:#758493}.meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.meta span{font-size:8px;color:#8998a7;border:1px solid #263443;padding:5px 7px;border-radius:6px}
table{width:100%;border-collapse:collapse}th,td{padding:11px;border-bottom:1px solid #202c39;text-align:left;font-size:10px}th{font-size:8px;color:#7c8b99;text-transform:uppercase}
.badge{display:inline-block;padding:4px 6px;border-radius:5px;font-size:8px;font-weight:800}.pass{background:#0c291b;color:#7de2a7}.warning{background:#2d2413;color:#ffd17b}.fail{background:#32161b;color:#ff949d}.info{background:#152439;color:#96bdf0}
.grid{display:grid;grid-template-columns:1.5fr .8fr;gap:12px}.stats{display:grid;grid-template-columns:repeat(7,1fr);gap:8px;margin:12px 0}.stat{background:#0a1018;border:1px solid #202c39;border-radius:11px;padding:12px}.stat small{font-size:8px;color:#768596}.stat strong{display:block;font-size:20px;margin-top:6px}
@media(max-width:950px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(4,1fr)}}@media(max-width:650px){.stats{grid-template-columns:repeat(2,1fr)}.top{align-items:flex-start;flex-direction:column}.formrow{grid-template-columns:1fr!important}}
"""

AUTH = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{title}} — EthicalGuard</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070b12;color:#edf3f7;font-family:Arial}.card{width:min(430px,92%);background:#0a1018;border:1px solid #243241;border-radius:16px;padding:26px}input{width:100%;padding:11px;margin:7px 0 12px;background:#080d14;border:1px solid #293747;border-radius:8px;color:white;box-sizing:border-box}button,a{width:100%;display:block;padding:11px;margin-top:10px;border-radius:8px;text-align:center;text-decoration:none;box-sizing:border-box}button{border:1px solid #2e9d70;background:#143728;color:#aff1ca}a{border:1px solid #293747;background:#0c121a;color:#e7edf2}.err{background:#32161b;color:#ff9ba3;border:1px solid #54242d;padding:9px;border-radius:8px;font-size:11px}
</style></head><body><div class="card"><div style="text-align:center;font-size:26px">🛡️</div><h1 style="text-align:center">EthicalGuard</h1><p style="text-align:center;color:#718091;font-size:9px;letter-spacing:2px">SCAN • ANALYZE • PROTECT</p>{% if error %}<div class="err">{{error}}</div>{% endif %}<form method="post">
{% if signup %}<input name="username" placeholder="e.g. ahmed123" required><input type="email" name="email" placeholder="you@example.com" required>{% else %}<input name="identifier" placeholder="Email or username" required>{% endif %}
<input type="password" name="password" placeholder="{{'Create a password' if signup else 'Your password'}}" required>
<button>{{'Create Account' if signup else 'Login'}}</button></form>
<a href="{{'/login' if signup else '/signup'}}">{{'Already have an account? Login' if signup else 'Create an account'}}</a><a href="/">Back to Scanner</a></div></body></html>
"""

DASHBOARD = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>EthicalGuard</title><style>{{style}}</style></head>
<body><div class="wrap">
<div class="top"><div class="brand"><div class="logo">🛡️</div><div><h1 style="margin:0">EthicalGuard</h1><p>SCAN • ANALYZE • PROTECT</p></div></div>
<div class="actions">
{% if user %}<a class="btn" href="/history">History</a><a class="btn" href="/monitoring">Monitored Sites</a><a class="btn" href="/alerts">Alerts</a><a class="btn" href="/logout">Logout</a>{% else %}<a class="btn" href="/login">Login</a><a class="btn primary" href="/signup">Sign Up</a>{% endif %}
<a class="btn" href="/contact">Contact</a></div></div>

<h2>Professional Web Security Assessment</h2>
<p class="muted">Authorized security auditing with 23 core checks plus technology detection, CVE intelligence, RDAP and OWASP mapping.</p>
<div class="card"><form method="post"><div class="formrow" style="display:grid;grid-template-columns:1fr 180px 150px;gap:8px">
<input name="url" placeholder="https://example.com" required><select name="profile"><option value="quick">Quick Scan</option><option value="full" selected>Full Scan — 23 Checks</option><option value="passive">Passive Intelligence</option></select><button class="btn primary" style="width:100%" type="submit">🔍 Run Assessment</button></div></form>
{% if user %}<div style="margin-top:9px;font-size:10px;color:#718091">{% if user["plan"]=="PREMIUM" %}Premium · Unlimited scans{% else %}Free scans remaining: <strong>{{user["free_scans_remaining"]}}</strong> / 8{% endif %}</div>{% else %}<div style="margin-top:9px;font-size:10px;color:#718091">Guest scan · Sign up for 8 free scans and personal history.</div>{% endif %}</div>

<div class="card"><h3 style="margin-top:0">Raw Header Analyzer</h3><textarea id="raw" rows="6" placeholder="Content-Security-Policy: default-src 'self'&#10;X-Frame-Options: DENY&#10;Strict-Transport-Security: max-age=31536000"></textarea><button class="btn" onclick="analyze()" style="margin-top:8px">Analyze Headers</button><div id="hdr" style="margin-top:8px"></div></div>

{% if result %}
<div class="stats">
{% for label,value in [('Score',result.score),('Passed',result.passed),('Failed',result.failed),('Warnings',result.warnings),('High',result.high),('Medium',result.medium),('Low',result.low)] %}
<div class="stat"><small>{{label}}</small><strong>{{value}}</strong></div>{% endfor %}
</div>
<div class="grid"><div class="card"><h3>Security Findings</h3><table><tr><th>#</th><th>Feature</th><th>Severity</th><th>Status</th></tr>{% for item in result.features %}<tr><td>{{loop.index}}</td><td>{{item.name}}</td><td><span class="badge {{item.severity|lower}}">{{item.severity}}</span></td><td><span class="badge {{item.status|lower}}">{{item.status}}</span></td></tr>{% endfor %}</table></div>
<div class="card"><h3>Security Overview</h3><p><strong>{{result.overall}}</strong></p><div class="meta"><span>Risk: {{result.risk}}</span><span>Score: {{result.score}}/100</span><span>HTTP: {{result.response_status}}</span><span>{{result.duration}}s</span></div><h4>Technologies</h4><p class="muted">{{result.technologies|join(', ') if result.technologies else 'None detected'}}</p><h4>OWASP</h4><p class="muted">{{result.owasp|join(' · ')}}</p><h4>Latency</h4><p class="muted">{{result.latency}}</p>
{% if user %}<a class="btn primary" href="/report?id={{result.scan_id}}">Open Report</a><a class="btn" href="/download-report?id={{result.scan_id}}">Download</a>{% else %}<a class="btn primary" href="/signup">Save this type of scan with an account</a>{% endif %}</div></div>
{% if result.cves %}<div class="card"><h3>CVE Intelligence</h3>{% for c in result.cves %}<div style="padding:8px 0;border-bottom:1px solid #202c39"><strong>{{c.cve}}</strong> · {{c.technology}}<div class="muted" style="font-size:10px;margin-top:5px">{{c.description}}</div></div>{% endfor %}</div>{% endif %}
{% endif %}
{% if error %}<div class="card" style="border-color:#6c2a34;color:#ffadb5"><strong>Scan Error:</strong> {{error}}</div>{% endif %}
<div class="card" style="margin-bottom:30px;color:#718091;font-size:10px">EthicalGuard · Ahmed Sidhu · Security Enthusiast · {{premium_email}}</div>
</div>
<script>
function analyze(){
 const s=document.getElementById('raw').value.toLowerCase();
 const checks=[['content-security-policy','CSP'],['x-frame-options','X-Frame-Options'],['strict-transport-security','HSTS'],['x-content-type-options','X-Content-Type-Options'],['referrer-policy','Referrer-Policy'],['permissions-policy','Permissions-Policy']];
 document.getElementById('hdr').innerHTML=checks.map(x=>s.includes(x[0])?'<div style="color:#7de2a7">PASS · '+x[1]+'</div>':'<div style="color:#ffd17b">MISSING · '+x[1]+'</div>').join('');
}
</script></body></html>
"""

REPORT = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Report — EthicalGuard</title><style>{{style}}.finding{padding:13px 0;border-bottom:1px solid #202c39}.row{display:grid;grid-template-columns:150px 1fr;gap:8px;margin-top:7px}.label{font-size:9px;color:#728294;text-transform:uppercase}@media(max-width:650px){.row{grid-template-columns:1fr}}</style></head>
<body><div class="wrap"><div class="top"><div class="brand"><div class="logo">🛡️</div><div><h1>EthicalGuard</h1><p>SCAN • ANALYZE • PROTECT</p></div></div><div class="actions"><a class="btn" href="/">Scanner</a><a class="btn" href="/history">History</a></div></div>
<div class="card"><h2>Security Report</h2><p>{{result.final_url}}</p><div style="font-size:42px;font-weight:800">{{result.score}}/100</div><p>{{result.overall}} · Risk: {{result.risk}}</p></div>
<div class="card"><div class="meta"><span>Passed {{result.passed}}</span><span>Failed {{result.failed}}</span><span>Warnings {{result.warnings}}</span><span>High {{result.high}}</span><span>Medium {{result.medium}}</span><span>Low {{result.low}}</span></div></div>
<div class="card"><h3>Findings</h3>{% for item in result.features %}<div class="finding"><strong>{{loop.index}}. {{item.name}}</strong><div class="meta"><span>{{item.status}}</span><span>{{item.severity}}</span><span>{{item.cwe or '-'}}</span></div><div class="row"><div class="label">Explanation</div><div>{{item.description}}</div></div><div class="row"><div class="label">Evidence</div><div>{{item.evidence}}</div></div><div class="row"><div class="label">How to Fix</div><div>{{item.remediation}}</div></div></div>{% endfor %}</div>
</div></body></html>
"""

HISTORY = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>History</title><style>{{style}}</style></head>
<body><div class="wrap"><div class="top"><div><h1>Scan History</h1><div class="muted">{{user.email}}</div></div><div class="actions"><a class="btn" href="/">Scanner</a><a class="btn" href="/logout">Logout</a></div></div>
{% for s in scans %}<div class="card"><strong>{{s.target}}</strong><div class="meta"><span>{{s.scan_time}}</span><span>{{s.profile}}</span><span>{{s.score}}/100</span><span>{{s.risk}}</span></div><div style="margin-top:10px"><a class="btn" href="/report?id={{s.scan_id}}">Report</a><a class="btn" href="/compare?id={{s.scan_id}}" style="margin-left:6px">Compare</a></div></div>{% else %}<div class="card">No scan history yet.</div>{% endfor %}
</div></body></html>
"""

MONITORING = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Monitoring</title><style>{{style}}</style></head>
<body><div class="wrap"><div class="top"><div><h1>Monitored Sites</h1><div class="muted">Premium feature</div></div><div class="actions"><a class="btn" href="/">Scanner</a><a class="btn" href="/logout">Logout</a></div></div>
<div class="card"><form method="post"><input name="name" placeholder="Site name" required style="margin-bottom:8px"><input name="url" placeholder="https://example.com" required style="margin-bottom:8px"><select name="frequency" style="margin-bottom:8px"><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select><select name="profile"><option value="full">Full Scan</option><option value="passive">Passive</option><option value="quick">Quick</option></select><button class="btn primary" style="margin-top:8px">Add Site</button></form></div>
{% for s in sites %}<div class="card"><strong>{{s.name}}</strong><div class="muted" style="margin-top:5px">{{s.url}}</div><div class="meta"><span>{{s.frequency}}</span><span>{{s.profile}}</span><span>Score: {{s.last_score or '-'}}</span><span>{{'ACTIVE' if s.enabled else 'PAUSED'}}</span></div><div style="margin-top:9px"><a class="btn" href="/monitoring/run/{{s.id}}">Run Now</a><a class="btn" href="/monitoring/toggle/{{s.id}}">Toggle</a></div></div>{% else %}<div class="card">No monitored sites.</div>{% endfor %}
</div></body></html>
"""


# --------------------------- Routes ---------------------------

@app.route("/", methods=["GET","POST"])
def home():
    user = current_user()
    result = None
    error = None

    if request.method == "POST":
        target = request.form.get("url","")
        profile = request.form.get("profile","full")

        if user and user["plan"] != "PREMIUM" and user["free_scans_remaining"] <= 0:
            return redirect(url_for("premium_page"))

        try:
            result = perform_scan(target, profile)
            if user:
                if not consume_scan(user["id"]):
                    return redirect(url_for("premium_page"))
                save_scan(result, user["id"])
        except requests.exceptions.SSLError as e:
            error = f"SSL/TLS error: {e}"
        except requests.exceptions.Timeout:
            error = "Website request timed out."
        except requests.exceptions.RequestException as e:
            error = f"Website request failed: {e}"
        except Exception as e:
            error = f"Scanner error: {e}"

        user = current_user()

    return render_template_string(
        DASHBOARD, style=BASE_STYLE, user=user, result=result,
        error=error, premium_email=PREMIUM_EMAIL
    )


@app.route("/signup", methods=["GET","POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not re.match(r"^[A-Za-z0-9_.-]{3,30}$", username):
            error = "Username must be 3–30 characters."
        elif not valid_email(email):
            error = "Enter a valid email."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            user = create_user(username,email,password)
            if not user:
                error = "Username or email already exists."
            else:
                session["user_id"] = user["id"]
                return redirect(url_for("home"))
    return render_template_string(AUTH,title="Sign Up",signup=True,error=error)


@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        user = login_user(request.form.get("identifier","").strip(), request.form.get("password",""))
        if not user:
            error = "Invalid username/email or password."
        else:
            session["user_id"] = user["id"]
            return redirect(url_for("home"))
    return render_template_string(AUTH,title="Login",signup=False,error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/history")
def history():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    con = db()
    scans = con.execute("""
        SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 200
    """,(user["id"],)).fetchall()
    con.close()
    return render_template_string(HISTORY,style=BASE_STYLE,user=user,scans=scans)


@app.route("/compare")
def compare():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    scan_id = request.args.get("id","")
    row = owned_scan(scan_id,user["id"])
    if not row:
        return "Scan not found.",404
    con = db()
    previous = con.execute("""
        SELECT * FROM scans
        WHERE user_id=? AND target=? AND id<?
        ORDER BY id DESC LIMIT 1
    """,(user["id"],row["target"],row["id"])).fetchone()
    con.close()
    old = previous["score"] if previous else None
    change = row["score"]-old if old is not None else None
    return render_template_string("""
    <!doctype html><html><head><meta charset="utf-8"><style>{{style}}</style></head><body>
    <div class="wrap"><div class="card"><h1>Historical Comparison</h1><p class="muted">{{row["target"]}}</p>
    {% if old is not none %}<h2>{{row["score"]-old}}</h2><p>Previous: {{old}}/100 · Current: {{row["score"]}}/100</p>
    {% else %}<p>No earlier scan of the same target was found.</p>{% endif %}
    <a class="btn" href="/history">Back</a></div></div></body></html>
    """,style=BASE_STYLE,row=row,old=old,change=change)


@app.route("/report")
def report():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    row = owned_scan(request.args.get("id",""), user["id"])
    if not row:
        return "Report not found.",404
    result = json.loads(row["data_json"])
    return render_template_string(REPORT,style=BASE_STYLE,result=result)


@app.route("/download-report")
def download_report():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    row = owned_scan(request.args.get("id",""), user["id"])
    if not row:
        return "Report not found.",404
    result = json.loads(row["data_json"])
    report = render_template_string(REPORT,style=BASE_STYLE,result=result)
    res = make_response(report)
    res.headers["Content-Disposition"] = f'attachment; filename="ethicalguard-{row["scan_id"]}.html"'
    res.headers["Content-Type"] = "text/html; charset=utf-8"
    return res


@app.route("/premium")
def premium_page():
    return f"""
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{{margin:0;background:#070b12;color:#edf3f7;font-family:Arial;display:grid;place-items:center;min-height:100vh}}.card{{width:min(500px,92%);background:#0a1018;border:1px solid #2e9d70;border-radius:16px;padding:28px}}a{{display:inline-block;padding:11px 14px;border:1px solid #2e9d70;color:#aff1ca;text-decoration:none;border-radius:8px;background:#143728}}</style></head>
    <body><div class="card"><h1>EthicalGuard Premium</h1>
    <p>Unlimited scans, monitoring, alerts, reports and advanced intelligence.</p>
    <p>Upgrade by contacting:</p><strong>{html.escape(PREMIUM_EMAIL)}</strong>
    <p><a href="mailto:{PREMIUM_EMAIL}?subject=EthicalGuard%20Premium%20Upgrade">Contact to Upgrade</a></p>
    <a href="/">Back to Scanner</a></div></body></html>
    """


@app.route("/contact")
def contact():
    return f"""
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{{margin:0;background:#070b12;color:#edf3f7;font-family:Arial;display:grid;place-items:center;min-height:100vh}}.card{{width:min(430px,92%);text-align:center;background:#0a1018;border:1px solid #253443;border-radius:16px;padding:28px}}a{{color:#79dfa9;text-decoration:none}}</style></head>
    <body><div class="card"><h2>Ahmed Sidhu</h2><p style="color:#718091">Security Enthusiast</p><p>{html.escape(PREMIUM_EMAIL)}</p><a href="mailto:{PREMIUM_EMAIL}">Email Ahmed</a><br><br><a href="/">Back</a></div></body></html>
    """


@app.route("/monitoring",methods=["GET","POST"])
def monitoring():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not premium(user):
        return redirect(url_for("premium_page"))

    if request.method == "POST":
        name = request.form.get("name","").strip()
        url = normalize_url(request.form.get("url",""))
        freq = request.form.get("frequency","weekly")
        profile = request.form.get("profile","full")
        if name and url and freq in ("weekly","monthly") and profile in PROFILES:
            con = db()
            con.execute("""
                INSERT INTO monitored_sites
                (user_id,name,url,profile,frequency,enabled)
                VALUES (?,?,?,?,?,1)
            """,(user["id"],name,url,profile,freq))
            con.commit(); con.close()
    con = db()
    sites = con.execute(
        "SELECT * FROM monitored_sites WHERE user_id=? ORDER BY id DESC",(user["id"],)
    ).fetchall()
    con.close()
    return render_template_string(MONITORING,style=BASE_STYLE,sites=sites)


@app.route("/monitoring/toggle/<int:site_id>")
def monitoring_toggle(site_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    con = db()
    row = con.execute("SELECT * FROM monitored_sites WHERE id=? AND user_id=?",(site_id,user["id"])).fetchone()
    if row:
        con.execute("UPDATE monitored_sites SET enabled=? WHERE id=?",(0 if row["enabled"] else 1,site_id))
        con.commit()
    con.close()
    return redirect(url_for("monitoring"))


@app.route("/monitoring/run/<int:site_id>")
def monitoring_run(site_id):
    user = current_user()
    if not user or not premium(user):
        return redirect(url_for("premium_page"))
    con = db()
    site = con.execute("SELECT * FROM monitored_sites WHERE id=? AND user_id=?",(site_id,user["id"])).fetchone()
    con.close()
    if not site:
        return "Site not found.",404
    try:
        result = perform_scan(site["url"],site["profile"])
        save_scan(result,user["id"])
        con = db()
        con.execute("""
            UPDATE monitored_sites SET last_run=?,last_score=?,last_risk=?
            WHERE id=?
        """,(now(),result["score"],result["risk"],site_id))
        if result["risk"] in ("HIGH","CRITICAL"):
            con.execute("INSERT INTO alerts(user_id,site_id,message,created_at) VALUES(?,?,?,?)",
                        (user["id"],site_id,
                         f'{site["name"]}: {result["score"]}/100 · {result["risk"]}',now()))
        con.commit(); con.close()
        return redirect(url_for("report",id=result["scan_id"]))
    except Exception as e:
        return f"Monitoring error: {html.escape(str(e))}",500


@app.route("/alerts")
def alerts():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    con = db()
    rows = con.execute(
        "SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 100",(user["id"],)
    ).fetchall()
    con.close()
    return jsonify({"success":True,"alerts":[dict(r) for r in rows]})


@app.route("/badge/<scan_id>")
def badge(scan_id):
    con = db()
    row = con.execute("SELECT data_json FROM scans WHERE scan_id=?",(scan_id,)).fetchone()
    con.close()
    if not row:
        return "Not found",404
    result = json.loads(row["data_json"])
    score = result["score"]
    if score >= 85:
        color,label = "#2e9d70","Secure"
    elif score >= 70:
        color,label = "#c49b35","Monitor"
    else:
        color,label = "#b9434b","Needs Attention"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="320" height="70">
    <rect width="320" height="70" rx="12" fill="#0b1118" stroke="{color}"/>
    <circle cx="30" cy="35" r="16" fill="{color}"/>
    <text x="58" y="31" fill="#fff" font-family="Arial" font-size="13" font-weight="700">EthicalGuard</text>
    <text x="58" y="49" fill="#b9c4cf" font-family="Arial" font-size="11">{label} · {score}/100</text></svg>"""
    res = make_response(svg)
    res.headers["Content-Type"]="image/svg+xml"
    return res


@app.route("/admin/activate-premium",methods=["POST"])
def activate_premium():
    expected = os.environ.get("ADMIN_KEY","CHANGE_THIS_ADMIN_KEY")
    if request.form.get("admin_key","") != expected:
        return "Unauthorized",401
    email = request.form.get("email","").strip().lower()
    con = db()
    user = con.execute("SELECT * FROM users WHERE lower(email)=?",(email,)).fetchone()
    if not user:
        con.close(); return "User not found.",404
    con.execute("UPDATE users SET plan='PREMIUM', free_scans_remaining=8 WHERE id=?",(user["id"],))
    con.commit(); con.close()
    return f"Premium activated for {html.escape(email)}"


@app.route("/health")
def health():
    return jsonify({
        "status":"ok","product":APP_NAME,"version":APP_VERSION,
        "database":"SQLite","checks":23
    })


@app.after_request
def hardening(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
'''

path = Path("/mnt/data/scanner.py")
path.write_text(code, encoding="utf-8")

req = Path("/mnt/data/requirements.txt")
req.write_text(
    "Flask==3.1.2\nrequests==2.32.5\ngunicorn==23.0.0\nWerkzeug==3.1.3\n",
    encoding="utf-8"
)

print(f"Created {path} and {req}")
