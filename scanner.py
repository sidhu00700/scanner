from flask import (
    Flask,
    request,
    render_template_string,
    jsonify,
    make_response,
)
import requests
from urllib.parse import urlparse
from datetime import datetime
import json
import os
import re


app = Flask(__name__)

# =========================================================
# FILES
# =========================================================

HISTORY_FILE = "scan_history.json"
FEEDBACK_FILE = "feedback.json"

# =========================================================
# SECURITY CHECK DEFINITIONS
# =========================================================

SECURITY_HEADERS = [
    {
        "name": "X-Frame-Options",
        "title": "Clickjacking Protection",
        "severity": "MEDIUM",
        "description": (
            "Checks whether the website has protection against "
            "being embedded inside another website."
        ),
        "why": (
            "Without this protection, attackers may try to place "
            "the page inside a malicious frame and trick users "
            "into clicking something."
        ),
        "fix": (
            "Add: X-Frame-Options: SAMEORIGIN or DENY."
        ),
    },
    {
        "name": "Content-Security-Policy",
        "title": "Content Security Policy",
        "severity": "MEDIUM",
        "description": (
            "Controls which scripts, styles and other resources "
            "a browser is allowed to load."
        ),
        "why": (
            "A strong CSP can reduce the impact of various "
            "cross-site scripting and content-injection attacks."
        ),
        "fix": (
            "Create an appropriate Content-Security-Policy for "
            "your application."
        ),
    },
    {
        "name": "Strict-Transport-Security",
        "title": "HTTP Strict Transport Security",
        "severity": "MEDIUM",
        "description": (
            "Tells the browser to continue using HTTPS when "
            "connecting to the website."
        ),
        "why": (
            "HSTS helps protect users from insecure HTTP "
            "connections and some downgrade scenarios."
        ),
        "fix": (
            "For HTTPS websites, configure an appropriate HSTS "
            "header such as max-age=31536000."
        ),
    },
    {
        "name": "X-Content-Type-Options",
        "title": "MIME Type Protection",
        "severity": "LOW",
        "description": (
            "Helps prevent browsers from guessing the content "
            "type of a response."
        ),
        "why": (
            "This can reduce certain content-type confusion "
            "and browser-side attack scenarios."
        ),
        "fix": (
            "Add: X-Content-Type-Options: nosniff"
        ),
    },
]

KNOWN_SERVER_SOFTWARE = [
    "apache/",
    "nginx/",
    "iis/",
    "php/",
    "openresty/",
    "tomcat/",
    "lighttpd/",
]


# =========================================================
# JSON HELPERS
# =========================================================

def load_json(filename, default):
    if not os.path.exists(filename):
        return default

    try:
        with open(filename, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return default


def save_json(filename, data):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


# =========================================================
# URL VALIDATION
# =========================================================

def normalize_url(url):
    url = url.strip()

    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        return None

    return url


# =========================================================
# COOKIE ANALYSIS
# =========================================================

def analyze_cookies(response):

    cookies = response.headers.get("Set-Cookie")

    if not cookies:
        return {
            "name": "Cookie Security",
            "title": "Cookie Security",
            "severity": "INFO",
            "status": "INFO",
            "description": "No Set-Cookie header was observed.",
            "why": (
                "No cookie attributes could be reviewed from "
                "the response."
            ),
            "evidence": "Set-Cookie: Not observed",
            "fix": (
                "Review authentication and session cookies if "
                "the application uses them."
            ),
        }

    lowered = cookies.lower()

    has_secure = "secure" in lowered
    has_httponly = "httponly" in lowered
    has_samesite = "samesite" in lowered

    missing = []

    if not has_secure:
        missing.append("Secure")

    if not has_httponly:
        missing.append("HttpOnly")

    if not has_samesite:
        missing.append("SameSite")

    # IMPORTANT:
    # We call this a configuration warning rather than claiming
    # a confirmed exploitable vulnerability.
    if len(missing) >= 2:
        status = "FAIL"
        severity = "MEDIUM"
    elif len(missing) == 1:
        status = "WARNING"
        severity = "LOW"
    else:
        status = "PASS"
        severity = "INFO"

    if missing:
        description = (
            "One or more recommended cookie security settings "
            "could not be confirmed."
        )

        why = (
            "Cookie protections help reduce exposure to certain "
            "session and cross-site request risks."
        )

        fix = (
            "Review session cookies and use Secure, HttpOnly and "
            "an appropriate SameSite value where applicable."
        )

    else:
        description = (
            "The observed Set-Cookie response contains the "
            "main recommended security attributes."
        )

        why = (
            "Secure, HttpOnly and SameSite provide useful "
            "browser-side protections for cookies."
        )

        fix = (
            "Keep these attributes enabled for appropriate "
            "authentication and session cookies."
        )

    return {
        "name": "Cookie Security",
        "title": "Cookie Security",
        "severity": severity,
        "status": status,
        "description": description,
        "why": why,
        "evidence": (
            f"Secure={has_secure}, "
            f"HttpOnly={has_httponly}, "
            f"SameSite={has_samesite}"
        ),
        "fix": fix,
    }


# =========================================================
# CORS ANALYSIS
# =========================================================

def analyze_cors(response):

    cors = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    if not cors:

        return {
            "name": "CORS Policy",
            "title": "Cross-Origin Resource Sharing",
            "severity": "INFO",
            "status": "PASS",
            "description": (
                "No permissive Access-Control-Allow-Origin "
                "header was observed."
            ),
            "why": (
                "Restrictive CORS policies help control which "
                "web origins can access resources."
            ),
            "evidence": (
                "Access-Control-Allow-Origin: Not observed"
            ),
            "fix": (
                "No action required based on this check."
            ),
        }

    if cors.strip() == "*":

        return {
            "name": "CORS Policy",
            "title": "Cross-Origin Resource Sharing",
            "severity": "MEDIUM",
            "status": "WARNING",
            "description": (
                "The Access-Control-Allow-Origin header uses "
                "a wildcard (*)."
            ),
            "why": (
                "A wildcard CORS policy can be too permissive "
                "for applications handling sensitive data."
            ),
            "evidence": (
                "Access-Control-Allow-Origin: *"
            ),
            "fix": (
                "Allow only trusted origins where sensitive "
                "resources require restricted cross-origin access."
            ),
        }

    return {
        "name": "CORS Policy",
        "title": "Cross-Origin Resource Sharing",
        "severity": "INFO",
        "status": "PASS",
        "description": (
            "A specific CORS origin was observed instead of "
            "a wildcard."
        ),
        "why": (
            "Explicit origin controls are generally easier to "
            "restrict than wildcard access."
        ),
        "evidence": (
            f"Access-Control-Allow-Origin: {cors}"
        ),
        "fix": (
            "Review allowed origins and keep them limited to "
            "trusted domains."
        ),
    }


# =========================================================
# SERVER DISCLOSURE
# =========================================================

def analyze_server(server_value):

    if not server_value:

        return {
            "name": "Server Information Disclosure",
            "title": "Server Header",
            "severity": "INFO",
            "status": "PASS",
            "leak": False,
            "description": (
                "The Server response header was not exposed."
            ),
            "why": (
                "Reducing unnecessary server information can "
                "limit technology fingerprinting."
            ),
            "evidence": "Server: Not exposed",
            "fix": (
                "No action required based on this check."
            ),
        }

    lowered = server_value.lower()

    software_match = any(
        item in lowered
        for item in KNOWN_SERVER_SOFTWARE
    )

    version_match = re.search(
        r"(apache|nginx|iis|php|tomcat|lighttpd|openresty)"
        r"[/\s-]*\d",
        lowered,
    )

    leak = bool(
        software_match or version_match
    )

    if leak:

        return {
            "name": "Server Information Disclosure",
            "title": "Server Header",
            "severity": "LOW",
            "status": "WARNING",
            "leak": True,
            "description": (
                "The Server header appears to reveal "
                "recognizable software or version information."
            ),
            "why": (
                "Technology fingerprinting can provide useful "
                "information about the server stack."
            ),
            "evidence": (
                f"Server: {server_value}"
            ),
            "fix": (
                "Minimize unnecessary software and version "
                "disclosure in response headers."
            ),
        }

    return {
        "name": "Server Information Disclosure",
        "title": "Server Header",
        "severity": "INFO",
        "status": "PASS",
        "leak": False,
        "description": (
            "A Server header is present, but obvious version "
            "disclosure was not detected."
        ),
        "why": (
            "Generic server information is generally less "
            "informative than detailed version disclosure."
        ),
        "evidence": (
            f"Server: {server_value}"
        ),
        "fix": (
            "Review whether the header needs to expose "
            "implementation details."
        ),
    }


# =========================================================
# MAIN SECURITY AUDIT
# =========================================================

def audit_website(url):

    normalized = normalize_url(url)

    if not normalized:
        return {
            "error": (
                "Invalid URL. Please enter a valid website address."
            )
        }

    try:

        start_time = datetime.now()

        response = requests.get(
            normalized,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "AhmedSidhu-SecurityAuditor/2.0"
                )
            },
        )

        headers = response.headers

        findings = []

        # -------------------------------------------------
        # HTTPS
        # -------------------------------------------------

        https_ok = (
            response.url.lower().startswith("https://")
        )

        findings.append({
            "id": "https",
            "name": "HTTPS / SSL",
            "title": "Encrypted Connection",
            "severity": "HIGH" if not https_ok else "INFO",
            "status": "PASS" if https_ok else "FAIL",
            "description": (
                "Checks whether the final connection uses HTTPS."
            ),
            "why": (
                "HTTPS encrypts communication between the "
                "browser and the web server."
            ),
            "evidence": (
                f"Final URL: {response.url}"
            ),
            "fix": (
                "Enable HTTPS and redirect HTTP traffic to HTTPS."
            ),
        })

        # -------------------------------------------------
        # SECURITY HEADERS
        # -------------------------------------------------

        for item in SECURITY_HEADERS:

            present = item["name"] in headers

            findings.append({
                "id": item["name"].lower().replace("-", "_"),
                "name": item["name"],
                "title": item["title"],
                "severity": (
                    "INFO"
                    if present
                    else item["severity"]
                ),
                "status": (
                    "PASS"
                    if present
                    else "FAIL"
                ),
                "description": item["description"],
                "why": item["why"],
                "evidence": (
                    f"{item['name']}: "
                    f"{headers.get(item['name'], 'Not present')}"
                ),
                "fix": item["fix"],
            })

        # -------------------------------------------------
        # SERVER
        # -------------------------------------------------

        server_finding = analyze_server(
            headers.get("Server")
        )

        findings.append({
            "id": "server",
            **server_finding,
        })

        # -------------------------------------------------
        # COOKIES
        # -------------------------------------------------

        findings.append({
            "id": "cookies",
            **analyze_cookies(response),
        })

        # -------------------------------------------------
        # CORS
        # -------------------------------------------------

        findings.append({
            "id": "cors",
            **analyze_cors(response),
        })

        # -------------------------------------------------
        # FULL-SCAN ADDITIONAL HEADERS
        # -------------------------------------------------

        # These are useful informational checks.
        # They do not turn the entire website into a vulnerability
        # simply because they are absent.

        referrer_policy = headers.get(
            "Referrer-Policy"
        )

        if referrer_policy:

            findings.append({
                "id": "referrer_policy",
                "name": "Referrer-Policy",
                "title": "Referrer Policy",
                "severity": "INFO",
                "status": "PASS",
                "description": (
                    "Controls how much referrer information is "
                    "shared with other origins."
                ),
                "why": (
                    "A suitable Referrer-Policy can reduce "
                    "unnecessary URL information leakage."
                ),
                "evidence": (
                    f"Referrer-Policy: {referrer_policy}"
                ),
                "fix": (
                    "Review the policy and choose the least "
                    "permissive behavior required by the site."
                ),
            })

        permissions_policy = headers.get(
            "Permissions-Policy"
        )

        if permissions_policy:

            findings.append({
                "id": "permissions_policy",
                "name": "Permissions-Policy",
                "title": "Browser Feature Policy",
                "severity": "INFO",
                "status": "PASS",
                "description": (
                    "Controls access to selected browser features."
                ),
                "why": (
                    "Restricting unnecessary browser capabilities "
                    "can reduce the attack surface."
                ),
                "evidence": (
                    f"Permissions-Policy: {permissions_policy}"
                ),
                "fix": (
                    "Keep only the browser capabilities your "
                    "application actually needs."
                ),
            })

        # -------------------------------------------------
        # COUNTERS
        # -------------------------------------------------

        high_count = 0
        medium_count = 0
        low_count = 0

        passed_count = 0
        failed_count = 0

        for finding in findings:

            if finding["status"] == "PASS":
                passed_count += 1
            elif finding["status"] in (
                "FAIL",
                "WARNING"
            ):
                failed_count += 1

            if finding["status"] in (
                "FAIL",
                "WARNING"
            ):

                if finding["severity"] == "HIGH":
                    high_count += 1

                elif finding["severity"] == "MEDIUM":
                    medium_count += 1

                elif finding["severity"] == "LOW":
                    low_count += 1

        total = len(findings)

        score = round(
            (passed_count / total) * 100
        ) if total else 0

        # -------------------------------------------------
        # RISK LEVEL
        # -------------------------------------------------

        if high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 0:
            risk_level = "MEDIUM"
        elif low_count > 0:
            risk_level = "LOW"
        else:
            risk_level = "LOW"

        overall = (
            "SECURE"
            if failed_count == 0
            else "VULNERABLE"
        )

        # -------------------------------------------------
        # RESULT
        # -------------------------------------------------

        results = {
            "target": normalized,
            "final_url": response.url,
            "scan_time": start_time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "duration": round(
                (
                    datetime.now() - start_time
                ).total_seconds(),
                2,
            ),
            "status_code": response.status_code,
            "overall": overall,
            "risk_level": risk_level,
            "score": score,
            "total": total,
            "passed": passed_count,
            "failed": failed_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "findings": findings,
        }

        # -------------------------------------------------
        # HISTORY
        # -------------------------------------------------

        history = load_json(
            HISTORY_FILE,
            []
        )

        history.insert(
            0,
            {
                "target": response.url,
                "time": results["scan_time"],
                "score": score,
                "status": overall,
                "risk": risk_level,
            },
        )

        save_json(
            HISTORY_FILE,
            history[:50]
        )

        return results

    except requests.exceptions.SSLError:

        return {
            "error": (
                "SSL certificate verification failed."
            )
        }

    except requests.exceptions.Timeout:

        return {
            "error": (
                "Connection timed out. The target took too long "
                "to respond."
            )
        }

    except requests.exceptions.ConnectionError:

        return {
            "error": (
                "Unable to connect to the target website."
            )
        }

    except requests.exceptions.RequestException as error:

        return {
            "error": f"Request failed: {error}"
        }

    except Exception as error:

        return {
            "error": f"Unexpected error: {error}"
        }


# =========================================================
# MAIN DASHBOARD
# =========================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0"
>

<title>Security Audit Console</title>

<style>

:root{

    --bg:#050b16;
    --panel:#0b1424;
    --panel2:#0e192b;
    --border:#193452;
    --blue:#1677f8;
    --cyan:#3db8ff;
    --text:#eef7ff;
    --muted:#8497af;
    --green:#14d99a;
    --red:#ff5872;
    --yellow:#f5bd49;
}

*{
    box-sizing:border-box;
}

body{

    margin:0;

    min-height:100vh;

    background:
    radial-gradient(
        circle at 85% 0%,
        rgba(24,119,248,.12),
        transparent 30%
    ),
    radial-gradient(
        circle at 10% 100%,
        rgba(61,184,255,.05),
        transparent 28%
    ),
    var(--bg);

    color:var(--text);

    font-family:
    Inter,
    Segoe UI,
    Arial,
    sans-serif;
}

button,
input{

    font:inherit;
}

.topbar{

    height:72px;

    display:flex;

    align-items:center;

    justify-content:space-between;

    padding:0 30px;

    border-bottom:1px solid #142943;

    background:#07101d;
}

.brand{

    display:flex;

    align-items:center;

    gap:12px;
}

.brand-icon{

    width:40px;
    height:40px;

    display:grid;
    place-items:center;

    background:#10264a;

    border:1px solid #1f5db5;

    border-radius:10px;

    color:#6bc7ff;

    font-size:18px;
}

.brand-title{

    font-size:16px;

    font-weight:900;
}

.brand-sub{

    color:#627a95;

    font-size:9px;

    letter-spacing:1px;

    margin-top:3px;
}

.top-actions{

    display:flex;

    align-items:center;

    gap:15px;
}

.ready{

    color:#42dc9d;

    font-size:10px;

    font-weight:900;

    white-space:nowrap;
}

.contact-btn{

    height:35px;

    padding:0 14px;

    border-radius:7px;

    background:#0d1e33;

    border:1px solid #29557f;

    color:#cbe8ff;

    font-size:10px;

    font-weight:800;

    cursor:pointer;
}

.contact-btn:hover{

    background:#12345a;

    border-color:#3f98da;
}

.wrap{

    max-width:1380px;

    margin:auto;

    padding:30px 22px 45px;
}

.hero{

    margin-bottom:20px;
}

.hero h1{

    margin:0 0 7px;

    font-size:31px;

    letter-spacing:-.5px;
}

.hero p{

    margin:0;

    color:var(--muted);

    font-size:13px;
}

.search{

    display:flex;

    gap:10px;

    padding:18px;

    background:var(--panel);

    border:1px solid var(--border);

    border-radius:13px;

    margin-bottom:16px;
}

.search input{

    flex:1;

    height:48px;

    padding:0 15px;

    color:white;

    background:#040b14;

    border:1px solid #29445f;

    border-radius:8px;

    outline:none;

    font-size:13px;
}

.search input:focus{

    border-color:#3196ff;

    box-shadow:0 0 0 3px rgba(22,119,248,.12);
}

.scan-btn{

    height:48px;

    padding:0 22px;

    border:0;

    border-radius:8px;

    background:#1677f8;

    color:white;

    font-size:12px;

    font-weight:900;

    cursor:pointer;
}

.scan-btn:hover{

    background:#0b67dc;
}

.scan-btn:disabled{

    opacity:.65;

    cursor:not-allowed;
}

.error{

    padding:14px;

    margin-bottom:18px;

    border-radius:9px;

    background:#2d1119;

    border:1px solid #7f1d35;

    color:#ffadb9;

    font-size:12px;
}

.progress-box{

    display:none;

    margin-bottom:16px;

    padding:18px;

    background:var(--panel);

    border:1px solid var(--border);

    border-radius:12px;
}

.progress-top{

    display:flex;

    justify-content:space-between;

    margin-bottom:9px;

    color:#b8cce0;

    font-size:11px;

    font-weight:700;
}

.progress-track{

    height:7px;

    background:#07101c;

    border-radius:99px;

    overflow:hidden;
}

.progress-bar{

    width:0%;

    height:100%;

    background:
    linear-gradient(
        90deg,
        #1573ff,
        #35c2ff
    );

    transition:width .5s ease;
}

.progress-text{

    margin-top:9px;

    color:#7890aa;

    font-size:10px;
}

.live-feed{

    margin-top:12px;

    padding:10px;

    background:#040a12;

    border:1px solid #152b44;

    border-radius:8px;

    color:#6fd3ff;

    font-family:Consolas,monospace;

    font-size:10px;

    line-height:1.8;

    min-height:70px;
}

.stats{

    display:grid;

    grid-template-columns:
    1.4fr
    .8fr
    .8fr
    .8fr
    .8fr;

    gap:11px;

    margin-bottom:18px;
}

.card{

    background:var(--panel);

    border:1px solid var(--border);

    border-radius:12px;

    padding:17px;
}

.label{

    margin-bottom:8px;

    color:#6e829b;

    text-transform:uppercase;

    letter-spacing:1px;

    font-size:9px;
}

.target{

    color:#cae7ff;

    font-size:12px;

    word-break:break-all;
}

.big{

    font-size:25px;

    font-weight:900;
}

.green{
    color:var(--green);
}

.red{
    color:var(--red);
}

.yellow{
    color:var(--yellow);
}

.small{

    color:#71859d;

    font-size:10px;

    margin-top:4px;
}

.dashboard{

    display:grid;

    grid-template-columns:
    minmax(0,2fr)
    minmax(340px,1fr);

    gap:15px;

    align-items:start;
}

.findings-card{

    background:var(--panel);

    border:1px solid var(--border);

    border-radius:12px;

    padding:18px;
}

.title-row{

    display:flex;

    align-items:center;

    justify-content:space-between;

    gap:10px;

    margin-bottom:13px;
}

.title-row h2{

    margin:0;

    font-size:16px;
}

.search-findings{

    width:220px;

    height:34px;

    background:#040b14;

    border:1px solid #29435f;

    border-radius:7px;

    color:white;

    padding:0 10px;

    font-size:10px;

    outline:none;
}

.filters{

    display:flex;

    flex-wrap:wrap;

    gap:6px;

    margin-bottom:12px;
}

.filter{

    padding:7px 10px;

    border-radius:7px;

    border:1px solid #284c72;

    background:#081523;

    color:#90a8c0;

    font-size:10px;

    font-weight:700;

    cursor:pointer;
}

.filter.active{

    background:#146fe2;

    border-color:#2d91ff;

    color:white;
}

.table{

    overflow:hidden;

    border:1px solid #1b3653;

    border-radius:8px;
}

.finding{

    display:grid;

    grid-template-columns:
    28px
    minmax(170px,1fr)
    80px
    75px
    102px;

    align-items:center;

    gap:10px;

    padding:13px;

    border-bottom:1px solid #162f49;
}

.finding:last-child{

    border-bottom:0;
}

.number{

    color:#5e7893;

    font-size:10px;
}

.finding-name{

    font-size:11px;

    font-weight:800;
}

.finding-desc{

    margin-top:3px;

    color:#7389a1;

    font-size:9px;

    line-height:1.4;
}

.badge{

    display:inline-block;

    width:max-content;

    padding:4px 7px;

    border-radius:5px;

    font-size:8px;

    font-weight:900;

    letter-spacing:.4px;
}

.medium{

    background:#392d0d;

    color:#f4c456;
}

.high{

    background:#41101b;

    color:#ff7188;
}

.low{

    background:#0d2940;

    color:#78caff;
}

.pass{

    background:#06382c;

    color:#56e1b2;
}

.fail{

    background:#41131f;

    color:#ff7890;
}

.info{

    background:#252f3f;

    color:#b7c5d8;
}

.details-btn{

    padding:7px 8px;

    border-radius:6px;

    border:1px solid #2b5784;

    background:#0a1b2e;

    color:#b8dcff;

    cursor:pointer;

    font-size:9px;

    font-weight:800;
}

.details-btn:hover{

    background:#10365c;
}

.detail-panel{

    position:sticky;

    top:15px;

    min-height:455px;

    padding:18px;

    background:var(--panel);

    border:1px solid var(--border);

    border-radius:12px;
}

.detail-empty{

    min-height:410px;

    display:grid;

    place-items:center;

    text-align:center;

    color:#70869e;

    font-size:11px;

    line-height:1.8;
}

.detail-title{

    font-size:19px;

    font-weight:900;

    margin-bottom:6px;
}

.detail-sub{

    color:#8da1b8;

    font-size:10px;

    line-height:1.7;

    margin-bottom:14px;
}

.detail-section{

    padding:12px 0;

    border-top:1px solid #1a3550;
}

.detail-section strong{

    display:block;

    margin-bottom:6px;

    font-size:10px;

    color:#ecf6ff;
}

.detail-section p{

    margin:0;

    color:#93a7bd;

    font-size:10px;

    line-height:1.75;
}

.code{

    padding:9px;

    border-radius:6px;

    background:#040a12;

    border:1px solid #17304d;

    color:#a4d5ff;

    font-family:Consolas,monospace;

    font-size:9px;

    line-height:1.6;

    word-break:break-word;
}

.actions{

    display:flex;

    flex-wrap:wrap;

    gap:8px;

    margin-top:16px;
}

.action{

    display:inline-flex;

    align-items:center;

    justify-content:center;

    min-height:39px;

    padding:0 13px;

    border-radius:7px;

    border:1px solid #284d74;

    background:#091729;

    color:#b9dcfb;

    text-decoration:none;

    font-size:10px;

    font-weight:800;

    cursor:pointer;
}

.action.primary{

    background:#1677f8;

    border-color:#2b93ff;

    color:white;
}

.action:hover{

    filter:brightness(1.1);
}

.feedback{

    margin-top:17px;

    padding:16px;

    background:var(--panel);

    border:1px solid var(--border);

    border-radius:12px;
}

.feedback h3{

    margin:0 0 5px;

    font-size:13px;
}

.feedback p{

    margin:0 0 11px;

    color:#71869e;

    font-size:10px;
}

.feedback-row{

    display:flex;

    gap:7px;
}

.feedback input{

    flex:1;

    height:35px;

    background:#040b14;

    border:1px solid #29435f;

    border-radius:7px;

    color:white;

    padding:0 10px;

    outline:none;

    font-size:10px;
}

.feedback button{

    height:35px;

    padding:0 11px;

    border-radius:7px;

    border:1px solid #2b5d92;

    background:#0d3965;

    color:#d2ecff;

    font-size:9px;

    font-weight:800;

    cursor:pointer;
}

.footer{

    display:flex;

    justify-content:space-between;

    align-items:center;

    gap:12px;

    margin-top:29px;

    padding-top:17px;

    border-top:1px solid #132943;

    color:#607891;

    font-size:9px;
}

.author{

    display:flex;

    align-items:center;

    gap:9px;

    color:#b4c5d7;
}

.avatar-photo{

    width:36px;

    height:36px;

    border-radius:50%;

    object-fit:cover;

    border:2px solid #35aaff;

    box-shadow:0 0 16px rgba(53,170,255,.18);
}

.modal{

    display:none;

    position:fixed;

    inset:0;

    z-index:9999;

    align-items:center;

    justify-content:center;

    background:rgba(0,7,16,.80);

    backdrop-filter:blur(8px);
}

.modal-box{

    width:min(390px,90%);

    position:relative;

    text-align:center;

    padding:31px;

    background:
    linear-gradient(
        145deg,
        #0d1a2c,
        #07111f
    );

    border:1px solid #285174;

    border-radius:19px;

    box-shadow:
    0 30px 90px rgba(0,0,0,.55);
}

.modal-close{

    position:absolute;

    top:11px;

    right:14px;

    width:30px;

    height:30px;

    border:0;

    background:transparent;

    color:#8096ad;

    font-size:25px;

    line-height:1;

    cursor:pointer;
}

.contact-photo{

    width:98px;

    height:98px;

    border-radius:50%;

    object-fit:cover;

    border:3px solid #39aeff;

    box-shadow:
    0 0 25px rgba(57,174,255,.25);

    margin-bottom:15px;
}

.modal-box h2{

    margin:0;

    font-size:22px;
}

.contact-role{

    margin:5px 0 14px;

    color:#42b9ff;

    font-size:10px;

    font-weight:900;

    letter-spacing:.8px;

    text-transform:uppercase;
}

.contact-text{

    color:#8ea2b8;

    font-size:10px;

    line-height:1.8;
}

.email-button{

    display:inline-flex;

    align-items:center;

    justify-content:center;

    margin-top:16px;

    padding:11px 17px;

    border-radius:8px;

    color:white;

    background:#1677f8;

    text-decoration:none;

    font-size:10px;

    font-weight:900;
}

.email-button:hover{

    background:#0d68df;
}

.email-address{

    margin-top:10px;

    color:#607a94;

    font-size:9px;
}

@media(max-width:1150px){

    .stats{

        grid-template-columns:
        1fr 1fr 1fr;
    }

    .dashboard{

        grid-template-columns:1fr;
    }

    .detail-panel{

        position:static;
    }
}

@media(max-width:850px){

    .finding{

        grid-template-columns:
        25px
        1fr
        75px;
    }

    .finding > :nth-child(4){

        display:none;
    }

    .finding > :nth-child(5){

        justify-self:end;
    }
}

@media(max-width:650px){

    .topbar{

        padding:0 14px;
    }

    .top-actions{

        gap:8px;
    }

    .ready{

        display:none;
    }

    .wrap{

        padding:20px 12px 35px;
    }

    .search{

        flex-direction:column;
    }

    .stats{

        grid-template-columns:1fr;
    }

    .title-row{

        align-items:stretch;

        flex-direction:column;
    }

    .search-findings{

        width:100%;
    }

    .feedback-row{

        flex-direction:column;
    }

    .footer{

        flex-direction:column;

        align-items:flex-start;
    }
}

</style>

</head>

<body>


<!-- =====================================================
     TOP BAR
====================================================== -->

<header class="topbar">

<div class="brand">

<div class="brand-icon">
🛡️
</div>

<div>

<div class="brand-title">
Security Audit Console
</div>

<div class="brand-sub">
SCAN • ANALYZE • PROTECT
</div>

</div>

</div>


<div class="top-actions">

<div class="ready">
● SCANNER READY
</div>

<button
    class="contact-btn"
    onclick="openContact()"
>
Contact Us
</button>

</div>

</header>


<main class="wrap">


<!-- =====================================================
     HERO
====================================================== -->

<section class="hero">

<h1>
Web Security Assessment
</h1>

<p>
Review common HTTPS, security-header, cookie and
server-configuration issues.
</p>

</section>


<!-- =====================================================
     SEARCH
====================================================== -->

<form
    method="POST"
    class="search"
    onsubmit="startScan()"
>

<input
    type="text"
    name="url"
    value="{{ url }}"
    placeholder="https://example.com"
    required
>

<button
    type="submit"
    class="scan-btn"
    id="scanButton"
>
🔍 Run Assessment
</button>

</form>


<!-- =====================================================
     PROGRESS
====================================================== -->

<div
    class="progress-box"
    id="progressBox"
>

<div class="progress-top">

<span id="progressStatus">
Preparing assessment...
</span>

<span id="progressPercent">
0%
</span>

</div>

<div class="progress-track">

<div
    class="progress-bar"
    id="progressBar"
></div>

</div>

<div
    class="progress-text"
    id="progressText"
>
Initializing...
</div>

<div
    class="live-feed"
    id="liveFeed"
>
[+] Initializing security assessment...
</div>

</div>


<!-- =====================================================
     ERROR
====================================================== -->

{% if error %}

<div class="error">
{{ error }}
</div>

{% endif %}


{% if results %}


<!-- =====================================================
     STATS
====================================================== -->

<section class="stats">


<div class="card">

<div class="label">
Target
</div>

<div class="target">
{{ results.final_url }}
</div>

</div>


<div class="card">

<div class="label">
Security Score
</div>

<div class="big
{% if results.score >= 80 %}
green
{% elif results.score >= 60 %}
yellow
{% else %}
red
{% endif %}
">

{{ results.score }}/100

</div>

<div class="small">
{{ results.passed }} passed / {{ results.failed }} findings
</div>

</div>


<div class="card">

<div class="label">
High Risk
</div>

<div class="big red">
{{ results.high }}
</div>

</div>


<div class="card">

<div class="label">
Medium Risk
</div>

<div class="big yellow">
{{ results.medium }}
</div>

</div>


<div class="card">

<div class="label">
Low Risk
</div>

<div class="big green">
{{ results.low }}
</div>

</div>


</section>


<!-- =====================================================
     MAIN DASHBOARD
====================================================== -->

<section class="dashboard">


<div>


<!-- FINDINGS -->

<div class="findings-card">

<div class="title-row">

<h2>
Security Findings ({{ results.total }})
</h2>

<input
    type="text"
    id="findingSearch"
    class="search-findings"
    placeholder="Search findings..."
    onkeyup="filterFindings()"
>

</div>


<!-- FILTERS -->

<div class="filters">

<button
    class="filter active"
    onclick="filterStatus('ALL', this)"
>
All
</button>

<button
    class="filter"
    onclick="filterStatus('FAIL', this)"
>
Failed
</button>

<button
    class="filter"
    onclick="filterStatus('WARNING', this)"
>
Warnings
</button>

<button
    class="filter"
    onclick="filterStatus('PASS', this)"
>
Passed
</button>

<button
    class="filter"
    onclick="filterStatus('HIGH', this)"
>
High
</button>

<button
    class="filter"
    onclick="filterStatus('MEDIUM', this)"
>
Medium
</button>

<button
    class="filter"
    onclick="filterStatus('LOW', this)"
>
Low
</button>

</div>


<div class="table">


{% for finding in results.findings %}

<div
    class="finding"
    data-status="{{ finding.status }}"
    data-severity="{{ finding.severity }}"
    data-name="{{ finding.name|lower }}"
>


<div class="number">
{{ loop.index }}
</div>


<div>

<div class="finding-name">
{{ finding.name }}
</div>

<div class="finding-desc">
{{ finding.description }}
</div>

</div>


<div>

<span class="badge
{% if finding.severity == 'HIGH' %}
high
{% elif finding.severity == 'MEDIUM' %}
medium
{% elif finding.severity == 'LOW' %}
low
{% else %}
info
{% endif %}
">

{{ finding.severity }}

</span>

</div>


<div>

<span class="badge
{% if finding.status == 'PASS' or finding.status == 'INFO' %}
pass
{% else %}
fail
{% endif %}
">

{{ finding.status }}

</span>

</div>


<div>

<button
    type="button"
    class="details-btn"
    onclick='showDetails({{ finding|tojson }})'
>
View Details →
</button>

</div>


</div>

{% endfor %}


</div>

</div>


<!-- ACTIONS -->

<div class="actions">

<a
    class="action primary"
    href="/report?target={{ results.final_url|urlencode }}"
    target="_blank"
>
View Full Report
</a>

<a
    class="action"
    href="/download-report?target={{ results.final_url|urlencode }}"
>
Download Report
</a>

<a
    class="action"
    href="/"
>
New Scan
</a>

<button
    type="button"
    class="action"
    onclick="copyCurrentURL()"
>
Copy Link
</button>

</div>


<!-- FEEDBACK -->

<div class="feedback">

<h3>
Was this assessment helpful?
</h3>

<p>
Your feedback helps improve this security tool.
</p>

<div class="feedback-row">

<input
    type="text"
    id="feedbackText"
    placeholder="Tell us what could be better..."
>

<button
    type="button"
    onclick="sendFeedback('helpful')"
>
Helpful
</button>

<button
    type="button"
    onclick="sendFeedback('not_helpful')"
>
Not Helpful
</button>

</div>

</div>


</div>


<!-- =====================================================
     DETAILS PANEL
====================================================== -->

<aside
    class="detail-panel"
    id="detailPanel"
>

<div
    class="detail-empty"
    id="detailEmpty"
>

<div>

<div
    style="
        font-size:30px;
        margin-bottom:12px;
    "
>
🔍
</div>

<strong
    style="color:#dbeeff;"
>
Select View Details
</strong>

<p>
You will see:
<br>
What is it?
<br>
Why does it matter?
<br>
What was detected?
<br>
How do you fix it?
</p>

</div>

</div>


<div
    id="detailContent"
    style="display:none;"
>


<div
    class="detail-title"
    id="detailName"
>
</div>


<div
    class="detail-sub"
    id="detailDescription"
>
</div>


<div class="detail-section">

<strong>
STATUS
</strong>

<div id="detailStatus">
</div>

</div>


<div class="detail-section">

<strong>
WHY IT MATTERS
</strong>

<p
    id="detailWhy"
>
</p>

</div>


<div class="detail-section">

<strong>
EVIDENCE
</strong>

<div
    class="code"
    id="detailEvidence"
>
</div>

</div>


<div class="detail-section">

<strong>
HOW TO FIX
</strong>

<p
    id="detailFix"
>
</p>

</div>


</div>

</aside>


</section>


{% endif %}


<!-- =====================================================
     FOOTER
====================================================== -->

<footer class="footer">

<div>
Security Audit Console • Authorized testing only
</div>


<div class="author">

<img
    src="/static/ahmed.jpg"
    class="avatar-photo"
    alt="Ahmed Sidhu"
    onerror="this.style.display='none';"
>

<div>

<strong>
Ahmed Sidhu
</strong>

<br>

Security Enthusiast

</div>

</div>

</footer>


</main>


<!-- =====================================================
     CONTACT MODAL
====================================================== -->

<div
    class="modal"
    id="contactModal"
>

<div class="modal-box">


<button
    class="modal-close"
    onclick="closeContact()"
>
×
</button>


<img
    src="/static/ahmed.jpg"
    class="contact-photo"
    alt="Ahmed Sidhu"
    onerror="
        this.src='';
        this.style.display='none';
    "
>


<h2>
Ahmed Sidhu
</h2>


<div class="contact-role">
Security Enthusiast
</div>


<div class="contact-text">

Have a question, suggestion, or feedback?

<br>

Feel free to get in touch.

</div>


<a
    href="mailto:sidhuahmed9886@gmail.com"
    class="email-button"
>
Contact via Email
</a>


<div class="email-address">
sidhuahmed9886@gmail.com
</div>


</div>

</div>


<script>

/* =====================================================
   PROGRESS ANIMATION
====================================================== */

function startScan(){

    const button =
        document.getElementById(
            "scanButton"
        );

    const box =
        document.getElementById(
            "progressBox"
        );

    const bar =
        document.getElementById(
            "progressBar"
        );

    const percent =
        document.getElementById(
            "progressPercent"
        );

    const status =
        document.getElementById(
            "progressStatus"
        );

    const text =
        document.getElementById(
            "progressText"
        );

    const feed =
        document.getElementById(
            "liveFeed"
        );

    if(!button || !box){
        return;
    }

    button.innerText =
        "Scanning...";

    button.disabled = true;

    box.style.display =
        "block";

    const steps = [

        [
            15,
            "Connecting to target...",
            "[+] Connecting to target..."
        ],

        [
            30,
            "Checking HTTPS / SSL...",
            "[+] HTTPS / SSL check running..."
        ],

        [
            45,
            "Checking security headers...",
            "[+] Testing security headers..."
        ],

        [
            60,
            "Reviewing cookie security...",
            "[+] Reviewing cookie attributes..."
        ],

        [
            75,
            "Checking CORS policy...",
            "[+] Checking CORS configuration..."
        ],

        [
            90,
            "Analyzing server information...",
            "[+] Checking server disclosure..."
        ],

        [
            100,
            "Finalizing assessment...",
            "[+] Finalizing security assessment..."
        ]

    ];

    let index = 0;

    const interval =
        setInterval(() => {

            const step =
                steps[index];

            bar.style.width =
                step[0] + "%";

            percent.innerText =
                step[0] + "%";

            status.innerText =
                step[1];

            text.innerText =
                step[1];

            feed.innerHTML +=
                "<br>" +
                step[2];

            index++;

            if(index >= steps.length){

                clearInterval(interval);

            }

        }, 420);

}


/* =====================================================
   DETAILS
====================================================== */

function showDetails(item){

    document.getElementById(
        "detailEmpty"
    ).style.display = "none";

    document.getElementById(
        "detailContent"
    ).style.display = "block";


    document.getElementById(
        "detailName"
    ).innerText = item.name;


    document.getElementById(
        "detailDescription"
    ).innerText =
        item.description;


    document.getElementById(
        "detailWhy"
    ).innerText =
        item.why;


    document.getElementById(
        "detailEvidence"
    ).innerText =
        item.evidence;


    document.getElementById(
        "detailFix"
    ).innerText =
        item.fix;


    const status =
        document.getElementById(
            "detailStatus"
        );


    status.innerText =
        item.status +
        " • " +
        item.severity;


    if(
        item.status === "PASS" ||
        item.status === "INFO"
    ){

        status.className =
            "badge pass";

    }else{

        status.className =
            "badge fail";

    }

}


/* =====================================================
   FILTERS
====================================================== */

let activeStatus = "ALL";


function filterStatus(
    status,
    button
){

    activeStatus =
        status;


    document
        .querySelectorAll(".filter")
        .forEach(
            element =>
                element.classList.remove(
                    "active"
                )
        );


    button.classList.add(
        "active"
    );


    applyFilters();

}


function filterFindings(){

    applyFilters();

}


function applyFilters(){

    const search =
        document
        .getElementById(
            "findingSearch"
        )
        .value
        .toLowerCase();


    document
        .querySelectorAll(
            ".finding"
        )
        .forEach(
            row => {

                const status =
                    row.dataset.status;

                const severity =
                    row.dataset.severity;

                const name =
                    row.dataset.name;


                let statusMatch =
                    activeStatus === "ALL"
                    ||
                    activeStatus === status
                    ||
                    activeStatus === severity;


                const searchMatch =
                    name.includes(
                        search
                    );


                row.style.display =
                    statusMatch &&
                    searchMatch
                    ? "grid"
                    : "none";

            }
        );

}


/* =====================================================
   COPY URL
====================================================== */

function copyCurrentURL(){

    navigator.clipboard
        .writeText(
            window.location.href
        )
        .then(
            () =>
                alert(
                    "Scan URL copied."
                )
        )
        .catch(
            () =>
                alert(
                    "Could not copy the URL."
                )
        );

}


/* =====================================================
   FEEDBACK
====================================================== */

function sendFeedback(type){

    const input =
        document.getElementById(
            "feedbackText"
        );


    const message =
        input.value.trim();


    fetch(
        "/feedback",
        {

            method:"POST",

            headers:{
                "Content-Type":
                    "application/json"
            },

            body:JSON.stringify({

                type:type,

                message:message

            })

        }
    )

    .then(
        response =>
            response.json()
    )

    .then(
        data => {

            alert(
                data.message
            );

            input.value = "";

        }
    )

    .catch(
        () => {

            alert(
                "Could not submit feedback."
            );

        }
    );

}


/* =====================================================
   CONTACT POPUP
====================================================== */

function openContact(){

    document.getElementById(
        "contactModal"
    ).style.display =
        "flex";

}


function closeContact(){

    document.getElementById(
        "contactModal"
    ).style.display =
        "none";

}


window.addEventListener(
    "click",
    function(event){

        const modal =
            document.getElementById(
                "contactModal"
            );

        if(
            event.target === modal
        ){

            closeContact();

        }

    }
);

</script>


</body>

</html>
"""


# =========================================================
# REPORT HTML
# =========================================================

REPORT_HTML = r"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0"
>

<title>
Security Assessment Report
</title>

<style>

body{

    margin:0;

    background:#edf3f8;

    color:#112235;

    font-family:
    Arial,
    Segoe UI,
    sans-serif;
}

.report{

    max-width:1000px;

    margin:35px auto;

    background:white;

    border-radius:14px;

    padding:35px;

    box-shadow:
    0 15px 50px rgba(12,29,50,.10);
}

button{

    border:0;

    padding:10px 15px;

    border-radius:7px;

    background:#1677f8;

    color:white;

    font-size:11px;

    font-weight:800;

    cursor:pointer;

    margin-bottom:20px;
}

.header{

    border-bottom:2px solid #e6edf4;

    padding-bottom:20px;

    margin-bottom:20px;
}

.header h1{

    margin:0 0 6px;

    font-size:28px;
}

.muted{

    color:#73869a;

    font-size:11px;
}

.summary{

    display:grid;

    grid-template-columns:
    2fr
    1fr
    1fr
    1fr;

    gap:11px;

    margin-bottom:22px;
}

.box{

    padding:16px;

    border:1px solid #dae5ee;

    border-radius:10px;
}

.label{

    margin-bottom:7px;

    color:#8294a8;

    text-transform:uppercase;

    letter-spacing:1px;

    font-size:8px;
}

.big{

    font-size:23px;

    font-weight:900;
}

.green{
    color:#078c68;
}

.red{
    color:#db3954;
}

.yellow{
    color:#b97b00;
}

.finding{

    margin-bottom:12px;

    border:1px solid #dce6ef;

    border-radius:10px;

    padding:17px;
}

.finding-head{

    display:flex;

    align-items:center;

    justify-content:space-between;

    gap:10px;

    margin-bottom:9px;
}

.finding-head strong{

    font-size:14px;
}

.badge{

    padding:4px 7px;

    border-radius:5px;

    font-size:8px;

    font-weight:900;
}

.pass{

    background:#dcfce7;

    color:#15803d;
}

.fail{

    background:#fee2e2;

    color:#b91c1c;
}

.desc{

    color:#61758a;

    font-size:10px;

    line-height:1.7;
}

.section{

    margin-top:10px;

    padding-top:10px;

    border-top:1px solid #e6edf3;
}

.section strong{

    display:block;

    margin-bottom:4px;

    color:#16283b;

    font-size:9px;
}

.section p{

    margin:0;

    color:#65798e;

    font-size:9px;

    line-height:1.7;
}

.evidence{

    padding:9px;

    margin-top:6px;

    background:#f3f7fa;

    border-radius:6px;

    font-family:Consolas,monospace;

    font-size:9px;

    word-break:break-word;
}

@media(max-width:700px){

    .report{

        margin:10px;

        padding:20px;
    }

    .summary{

        grid-template-columns:1fr;
    }

}

@media print{

    button{
        display:none;
    }

    body{
        background:white;
    }

    .report{
        margin:0;
        max-width:none;
        box-shadow:none;
    }

}

</style>

</head>

<body>


<div class="report">


<button onclick="window.print()">
Print / Save as PDF
</button>


<div class="header">

<h1>
Web Security Assessment Report
</h1>

<div class="muted">
Security Audit Console • Ahmed Sidhu
</div>

</div>


<div class="summary">


<div class="box">

<div class="label">
Target
</div>

<div
    style="
        font-size:11px;
        word-break:break-all;
    "
>
{{ results.final_url }}
</div>

</div>


<div class="box">

<div class="label">
Security Score
</div>

<div class="big">

{{ results.score }}/100

</div>

</div>


<div class="box">

<div class="label">
Risk Level
</div>

<div class="big
{% if results.risk_level == 'HIGH' %}
red
{% elif results.risk_level == 'MEDIUM' %}
yellow
{% else %}
green
{% endif %}
">

{{ results.risk_level }}

</div>

</div>


<div class="box">

<div class="label">
Status
</div>

<div class="big
{% if results.overall == 'SECURE' %}
green
{% else %}
red
{% endif %}
">

{{ results.overall }}

</div>

</div>


</div>


{% for finding in results.findings %}

<div class="finding">


<div class="finding-head">

<strong>
{{ finding.name }}
</strong>


<span
    class="badge
    {% if finding.status == 'PASS' or finding.status == 'INFO' %}
        pass
    {% else %}
        fail
    {% endif %}
    "
>

{{ finding.status }}

</span>

</div>


<div class="desc">
{{ finding.description }}
</div>


<div class="section">

<strong>
WHY IT MATTERS
</strong>

<p>
{{ finding.why }}
</p>

</div>


<div class="section">

<strong>
EVIDENCE
</strong>

<div class="evidence">
{{ finding.evidence }}
</div>

</div>


<div class="section">

<strong>
HOW TO FIX
</strong>

<p>
{{ finding.fix }}
</p>

</div>


</div>

{% endfor %}


<div
    style="
        margin-top:25px;
        padding-top:15px;
        border-top:1px solid #e1e8ef;
        color:#7c8ea1;
        text-align:center;
        font-size:9px;
    "
>
Generated by Security Audit Console
•
Ahmed Sidhu • Security Enthusiast
</div>


</div>

</body>

</html>
"""


# =========================================================
# ROUTES
# =========================================================

@app.route("/", methods=["GET", "POST"])
def index():

    results = None
    error = None
    url = ""

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        if not url:

            error = (
                "Please enter a website URL."
            )

        else:

            results = audit_website(url)

            if "error" in results:

                error = results["error"]
                results = None

    return render_template_string(
        DASHBOARD_HTML,
        results=results,
        error=error,
        url=url,
    )


@app.route("/report")
def report():

    target = request.args.get(
        "target",
        ""
    ).strip()

    if not target:
        return (
            "No target website was provided.",
            400
        )

    results = audit_website(target)

    if "error" in results:
        return results["error"], 400

    return render_template_string(
        REPORT_HTML,
        results=results,
    )


@app.route("/download-report")
def download_report():

    target = request.args.get(
        "target",
        ""
    ).strip()

    if not target:
        return (
            "No target website was provided.",
            400
        )

    results = audit_website(target)

    if "error" in results:
        return results["error"], 400

    html = render_template_string(
        REPORT_HTML,
        results=results,
    )

    response = make_response(html)

    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; "
        "filename=security-audit-report.html"
    )

    response.headers[
        "Content-Type"
    ] = "text/html; charset=utf-8"

    return response


@app.route(
    "/feedback",
    methods=["POST"]
)
def feedback():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    feedback = load_json(
        FEEDBACK_FILE,
        []
    )

    feedback.insert(
        0,
        {
            "type": data.get(
                "type",
                "unknown"
            ),
            "message": data.get(
                "message",
                ""
            ),
            "time": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        },
    )

    save_json(
        FEEDBACK_FILE,
        feedback[:100]
    )

    return jsonify(
        {
            "success": True,
            "message": (
                "Thanks! Your feedback was saved."
            ),
        }
    )


@app.route("/history")
def history():

    return jsonify(
        load_json(
            HISTORY_FILE,
            []
        )
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )