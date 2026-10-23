# CyberFortify: Automated Red Team Simulation & Blue Team Defense Evaluation Platform

**CyberFortify** is an enterprise-grade cybersecurity engineering platform designed to simulate controlled adversary tactics (Red Team) against a dedicated target application and rigorously evaluate detection capabilities and defensive controls (Blue Team).

Developed as a BTech Cybersecurity Final Year Project.

---

## 🛡️ Project Overview & Architecture

CyberFortify unites offensive simulation and defensive evaluation within a unified telemetry and metrics pipeline:

```
+-----------------------------------------------------------------------------------------+
|                                    CYBERFORTIFY PLATFORM                                |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   +-----------------------+     Controlled Probes     +-----------------------------+   |
|   |   RED TEAM ENGINE     | ------------------------> |     TARGET DEMO APP         |   |
|   |  - Brute Force        |                           |  - Fortress Banking Portal  |   |
|   |  - Broken Access Ctrl |                           |  - Toggleable Defenses:     |   |
|   |  - SQL Injection      |                           |    * Rate Limiting          |   |
|   |  - Input Valid. / XSS |                           |    * RBAC Token Guard       |   |
|   |  - Benign Baseline    |                           |    * Parameterized Queries  |   |
|   +-----------------------+                           |    * Input Sanitizer        |   |
|                                                       +-----------------------------+   |
|                                                                      |                  |
|                                                              Structured Audit Logs      |
|                                                                      v                  |
|   +-----------------------+     Evaluation & Recall   +-----------------------------+   |
|   |   EVALUATION ENGINE   | <------------------------ |   BLUE TEAM DETECTION / SIEM|   |
|   |  - Confusion Matrix   |     (TP, FP, FN, TN)      |  - Signature Matching       |   |
|   |  - Recall & Precision |                           |  - Rolling Time-Window IDS  |   |
|   |  - Detection Latency  |                           |  - Latency Telemetry        |   |
|   |  - Before vs After    |                           |  - Alert Severity Triage    |   |
|   +-----------------------+                           +-----------------------------+   |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   |                   EXECUTIVE DASHBOARD & REPORTING SYSTEM                        |   |
|   |  - Dark Navy & Cyan Cyber UI | Real-time Charts | CSV Export | Audit Logs       |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

---

## 🚀 Key Modules & Scenarios

1. **Offensive Scenarios (Red Team)**:
   - **Scenario 1 — Brute Force Authentication**: Rapid credential guessing against authentication endpoints.
   - **Scenario 2 — Broken Access Control**: Unauthorized attempts to access administrative vaults and secrets without authorization tokens.
   - **Scenario 3 — Harmless SQL Injection**: Tautology probes (`' OR 1=1 --`), union inspection, and quote balance testing.
   - **Scenario 4 — Input Validation & Cross-Site Scripting (XSS)**: Safe script injection tags and event handler probe vectors.
   - **Scenario 5 — Benign Baseline Traffic**: Legitimate user searches, valid logins, and customer feedback to measure False Positive Rates.

2. **Defensive Detection & SIEM (Blue Team)**:
   - Multi-stage rule matching (`RULE_BRUTE_FORCE_01`, `RULE_UNAUTHORIZED_ACCESS_01`, `RULE_SQLI_DETECTED_01`, `RULE_XSS_INPUT_01`).
   - Real-time detection latency measurement ($T_{alert} - T_{event}$).
   - Automated ground-truth comparison calculating:
     - **True Positives (TP)**, **False Positives (FP)**, **False Negatives (FN)**, **True Negatives (TN)**
     - **Detection Rate (Sensitivity/Recall)**: $\frac{TP}{TP + FN} \times 100\%$
     - **Precision**: $\frac{TP}{TP + FP} \times 100\%$
     - **F1-Score**: $2 \times \frac{Precision \times Recall}{Precision + Recall}$

3. **Remediation & Retesting Engine**:
   - Toggleable defensive controls on the target application:
     - Authentication rate limiter with automated IP lockout.
     - Strict Role-Based Access Control (RBAC) token verifier.
     - Prepared statements / Parameterized SQL queries.
     - Context-aware input sanitization and HTML entity escaping.
   - **Before vs After Retesting**: Runs baseline vs fortified tests side-by-side to verify vulnerability mitigation.

4. **Website Security Assessment Engine**:
   - **Confined Demo Scope**: Strictly restricted server-side to the local built-in Fortress Bank demo application (`http://127.0.0.1:5000` / `localhost:5000`).
   - **Server-Side Scope Validation**: Rejects unexpected hosts (external websites), unexpected ports, credentials in URLs, unsupported schemes, and path traversal.
   - **Safe & Non-Intrusive Checks**: No arbitrary server requests, brute force, or exploitation. Evaluates defensive control states in SQLite, response headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`), audit telemetry count, and runtime environment.
   - **Persistent SQLite Audit Trail**: Stores overall status (`FORTIFIED`, `PARTIALLY_FORTIFIED`, `VULNERABLE`), check counts, observed evidence, and remediation advice.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.12+, Flask, Requests
- **Database**: SQLite (Zero external dependencies, isolated schema)
- **Frontend**: HTML5, Vanilla CSS (Dark navy and glowing cyan design system), JavaScript, Chart.js
- **Testing**: Python `unittest` suite

---

## 📦 Setup & Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Rutujajore06/CyberFortify.git
   cd CyberFortify
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Windows
   py -m venv .venv
   .\.venv\Scripts\activate

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run automated test suite**:
   ```bash
   python -m unittest discover tests
   # Or run only the security assessment tests:
   python -m unittest tests.test_assessment
   ```

5. **Start CyberFortify server**:
   ```bash
   python run.py
   ```
   Open your browser at:
   - Dashboard: `http://127.0.0.1:5000/`
   - Website Security Assessment: `http://127.0.0.1:5000/assessment`
   - Red Team Simulation: `http://127.0.0.1:5000/simulations`
   - Blue Team Alerts: `http://127.0.0.1:5000/alerts`
   - Remediation Lab: `http://127.0.0.1:5000/defenses`
   - Evaluation Report: `http://127.0.0.1:5000/report`

---

## 🔒 Security & Safe Practice Notice

All simulations execute **strictly against our internal local target demo endpoints** (`/api/target/*`). No destructive commands, arbitrary shell execution, or external network requests are made.
