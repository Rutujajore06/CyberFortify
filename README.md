# CyberFortify: Automated Red Team Simulation, Blue Team Defense Evaluation & Live Authorized Website Security Testing Platform

**CyberFortify** is a cybersecurity engineering platform developed as a BTech Final Year Project. It combines:
1. **Controlled Red Team vs. Blue Team Simulation & SIEM Evaluation** against the built-in **Fortress Bank Demo** portal.
2. **Live Authorized Website Security Testing** with strict target authorization, SSRF/DNS-rebinding defenses, real passive HTTPS/TLS & HTTP security header inspection, owner remediation tracking, before-and-after retesting, downloadable reports, and session-based **Admin / Website Owner / Viewer RBAC**.

---

## 🛡️ Architecture Overview

```
+-----------------------------------------------------------------------------------------+
|                                    CYBERFORTIFY PLATFORM                                |
+-----------------------------------------------------------------------------------------+
|  [1] FORTRESS BANK DEMO & RED vs BLUE SIEM LAB                                          |
|      Red Team Engine  --->  Fortress Banking Portal (/target, /api/target/*)            |
|      (Brute Force, RBAC,    (Toggleable Defenses: Rate Limit, RBAC, SQLi, XSS)          |
|       SQLi, XSS, Benign)               | Structured Audit Telemetry (SQLite)            |
|                                        v                                                |
|      Evaluation Engine <--- Blue Team Detection / SIEM (TP, FP, FN, TN, Recall, F1)     |
+-----------------------------------------------------------------------------------------+
|  [2] LIVE AUTHORIZED WEBSITE SECURITY TESTING & REMEDIATION                             |
|      Auth & RBAC Layer (/login, /api/auth/*)                                            |
|       - Admin / Website Owner / Viewer | scrypt Hashing | CSRF | IDOR | Rate Limiting   |
|                                        |                                                |
|      Target Registration & Approval (/live-targets, /api/live/targets/*)                |
|       - Explicit Consent | Unique Token | Signed Attestation / HTTP / Meta | Auto-Expiry|
|                                        |                                                |
|      Safe Passive Scanner & Target Security (/live-assessment, /api/live/assessments/*) |
|       - DNS Timeout & Validation | Private/NAT64/Metadata IP Block | IP-Pinned TLS/HTTP |
|       - Per-Hop Redirect Revalidation | Real TLS, HSTS, CSP, Cookies, Server Checks     |
|                                        |                                                |
|      Remediation, Retesting & Reports (/live-remediation, /api/live/remediations/*)     |
|       - Open / In Progress / Fixed / Verified (Retest-Enforced) | Before/After Scores   |
|       - Downloadable HTML, Markdown & JSON Reports (Verification Tokens Redacted)       |
+-----------------------------------------------------------------------------------------+
```

---

## 🚀 Key Modules

1. **Red Team Console (`/simulations`) & Fortress Bank Demo (`/target`)**
   - Safe, controlled simulation scenarios against the local Fortress Banking Portal: Brute Force, Broken Access Control, SQL Injection, Input Validation/XSS, and Benign Baseline traffic.
2. **Blue Team SIEM Alerts (`/alerts`), Audit Logs (`/logs`) & Demo Remediation (`/defenses`)**
   - Rule-based IDS correlation (`RULE_BRUTE_FORCE_01`, `RULE_UNAUTHORIZED_ACCESS_01`, `RULE_SQLI_DETECTED_01`, `RULE_XSS_INPUT_01`), detection latency tracking, confusion matrix metrics (Recall, Precision, F1-score), CSV log export, toggleable defenses, before-and-after retesting, and printable Academic Evaluation Report (`/report`).
3. **Confined Demo Security Assessment (`/assessment`)**
   - Strictly restricted server-side to the local Fortress Bank demo (`http://127.0.0.1:5000` / `localhost:5000`).
4. **Live Target Registration & Authorization (`/live-targets`)**
   - Registers authorized external HTTPS/HTTP websites with explicit owner consent, approved paths, safe HTTP methods (`GET`, `HEAD`, `OPTIONS`), validity window (`start_date` → `expiry_date`), max request rate, cryptographic verification token, ownership verification / signed attestation (clearly noting self-attestation does not claim independent DNS/HTTP ownership proof), administrator Approve/Reject queue, and automatic expiration.
5. **Live Website Security Assessment (`/live-assessment`)**
   - Executes real passive HTTP & TLS inspections (no hardcoded results, no intrusive attacks) on approved active targets: HTTPS availability, TLS certificate validity & expiry (`certifi`-verified), HTTP→HTTPS redirection, HTTP security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`), cookie security flags (`Secure`, `HttpOnly`, `SameSite`), server information exposure, `Permissions-Policy`, and CORS checks.
   - Server-side protections: blocks localhost, private/link-local/metadata/NAT64-private/obfuscated IPs, prevents SSRF & DNS rebinding via IP-pinned sockets, enforces DNS/connect/read timeouts, revalidates every redirect hop, strips cookies/credentials, enforces per-target rate limits, and records detailed SQLite audit logs.
6. **Live Vulnerability Remediation & Retesting (`/live-remediation`)**
   - Tracks detected findings with severity, evidence, affected headers, remediation instructions, owner notes, and retest-enforced statuses (`Open`, `In Progress`, `Fixed`, `Verified`). Never modifies external websites automatically and strictly blocks marking findings `Fixed`/`Verified` without a passing live retest.
   - Compares previous vs. latest assessments (before-and-after security scores, fixed vs. remaining vs. regressed findings) and exports downloadable **HTML**, **Markdown**, and **JSON** reports with verification tokens redacted.
7. **Admin Authentication & Role-Based Access Control (`/login`)**
   - Session authentication with `scrypt` password hashing, `HttpOnly`/`SameSite=Lax`/`Secure` cookies, CSRF protection, login/registration rate limiting, atomic one-time Admin bootstrap (`BEGIN IMMEDIATE`), IDOR prevention, and three roles: **Admin**, **Website Owner**, and **Viewer**.

---

## 🛠️ Technology Stack

- **Backend:** Python 3.12+, Flask 3.x, Gunicorn, Werkzeug (`scrypt`, `ProxyFix`), Requests/Certifi
- **Database:** SQLite (15 relational tables, zero external DB dependencies)
- **Frontend:** HTML5, Vanilla CSS (Responsive dark cybersecurity theme), Vanilla JavaScript, Chart.js
- **Testing:** Python `unittest` suite (**57 automated unit & integration tests**)

---

## 💻 Local Windows Startup Instructions

1. **Open PowerShell in the project folder:**
   ```powershell
   cd C:\Users\RUTUJA\OneDrive\Desktop\CyberFortify
   ```
2. **Ensure dependencies are installed in the virtual environment:**
   - If using the existing project virtual environment (`.venv`):
     ```powershell
     .\.venv\bin\python.exe -m pip install -r requirements.txt
     ```
   - Or if creating a fresh standard Windows venv:
     ```powershell
     py -m venv .venv
     .\.venv\Scripts\python.exe -m pip install -r requirements.txt
     ```
3. **Run the complete 57-test regression suite:**
   ```powershell
   .\.venv\bin\python.exe -m unittest discover tests -v
   ```
4. **Start CyberFortify locally (Local Demo Mode):**
   ```powershell
   .\.venv\bin\python.exe run.py
   ```
   *(To test strict mandatory login locally, run `$env:REQUIRE_AUTH="true"; .\.venv\bin\python.exe run.py`.)*
5. **Open in your browser (`http://127.0.0.1:5000`):**
   - Executive Dashboard: `http://127.0.0.1:5000/`
   - Authentication & RBAC: `http://127.0.0.1:5000/login`
   - Live Target Registration & Approvals: `http://127.0.0.1:5000/live-targets`
   - Live Website Assessment: `http://127.0.0.1:5000/live-assessment`
   - Live Remediation & Retesting: `http://127.0.0.1:5000/live-remediation`
   - Fortress Bank Demo Portal: `http://127.0.0.1:5000/target`
   - Confined Demo Assessment: `http://127.0.0.1:5000/assessment`
   - Red Team Console / Blue Team Alerts / Audit Logs / Demo Remediation / Evaluation Report: `/simulations`, `/alerts`, `/logs`, `/defenses`, `/report`

---

## ☁️ Production Deployment Instructions (Render)

1. **Create a Render Web Service** connected to your GitHub repository:
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:**
     ```bash
     gunicorn --workers 1 --threads 4 --bind 0.0.0.0:$PORT --timeout 60 run:app
     ```
     *(Use `--workers 1` with SQLite so in-memory rate limiters and SQLite writes remain consistent.)*
2. **Attach a Persistent Disk** (e.g., mount path `/var/data`) so SQLite data, users, assessment history, and audit logs survive redeploys.
3. **Configure Required Environment Variables in Render Dashboard** (never commit secrets to Git):
   - `FLASK_ENV=production`
   - `HOST=0.0.0.0`
   - `SECRET_KEY=<64-char random hex>` *(generate locally via `python -c "import secrets; print(secrets.token_hex(32))"`)*
   - `STRICT_PRODUCTION_CONFIG=true`
   - `REQUIRE_AUTH=true`
   - `LOCAL_DEMO_MODE=false`
   - `TRUST_PROXY=true`
   - `SESSION_COOKIE_SECURE=true`
   - `DATABASE_PATH=/var/data/cyberfortify.db`
   - `CYBERFORTIFY_ADMIN_USERNAME=<your_admin_username>`
   - `CYBERFORTIFY_ADMIN_EMAIL=<your_admin_email>`
   - `CYBERFORTIFY_ADMIN_PASSWORD=<strong_admin_password>`
   - *(Optional)* `CYBERFORTIFY_BOOTSTRAP_TOKEN=<random_secret>` if using `/api/auth/setup-admin` instead of `CYBERFORTIFY_ADMIN_*`.
4. **Online SQLite Backup Command:**
   ```bash
   python -c "import sqlite3, datetime; src=sqlite3.connect('/var/data/cyberfortify.db'); dst=sqlite3.connect(f'/var/data/backup-{datetime.date.today()}.db'); src.backup(dst); dst.close(); src.close(); print('Backup complete')"
   ```

---

## 🔒 Security & Ethical Testing Notice

- **Fortress Bank Demo simulations** execute strictly against the local mock target endpoints (`/api/target/*`).
- **Live Website Security Testing** executes **passive, non-invasive configuration checks only** (TLS, redirects, HTTP headers, cookies, server banners) against explicitly registered, verified, approved, and unexpired domains with strict SSRF, DNS-rebinding, private-IP, and rate-limit enforcement. No destructive testing, brute force, exploitation, or unauthorized crawling is performed against external websites.
