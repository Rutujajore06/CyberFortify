import sqlite3
import datetime
from app.config import Config

def get_db_connection():
    """Returns a SQLite database connection with Row factory enabled."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes all CyberFortify database tables and seeds initial configuration."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Audit Security Events Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_uuid TEXT UNIQUE,
        timestamp TEXT NOT NULL,
        ip_address TEXT,
        endpoint TEXT NOT NULL,
        http_method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        user_identifier TEXT,
        payload_data TEXT,
        is_attack INTEGER DEFAULT 0,
        attack_scenario TEXT,
        expected_rule TEXT,
        simulation_run_id TEXT
    )
    ''')

    # 2. Blue Team Alerts Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_uuid TEXT UNIQUE,
        timestamp TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        trigger_event_id INTEGER,
        detection_latency_ms REAL DEFAULT 0.0,
        simulation_run_id TEXT,
        status TEXT DEFAULT 'NEW',
        FOREIGN KEY (trigger_event_id) REFERENCES events(id)
    )
    ''')

    # 3. Red Team Simulation Runs Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS simulation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_uuid TEXT UNIQUE NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        scenario_name TEXT NOT NULL,
        total_requests INTEGER DEFAULT 0,
        attack_requests INTEGER DEFAULT 0,
        benign_requests INTEGER DEFAULT 0,
        blocked_by_defense INTEGER DEFAULT 0,
        defense_config_snapshot TEXT,
        notes TEXT
    )
    ''')

    # 4. Blue Team Evaluations Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS evaluations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        simulation_run_id TEXT,
        evaluated_at TEXT NOT NULL,
        true_positives INTEGER DEFAULT 0,
        false_positives INTEGER DEFAULT 0,
        false_negatives INTEGER DEFAULT 0,
        true_negatives INTEGER DEFAULT 0,
        detection_rate REAL DEFAULT 0.0,
        precision_rate REAL DEFAULT 0.0,
        f1_score REAL DEFAULT 0.0,
        avg_latency_ms REAL DEFAULT 0.0,
        summary_json TEXT
    )
    ''')

    # 5. Defensive Controls Table (Toggleable defenses for Target App)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS defense_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        defense_key TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        is_enabled INTEGER DEFAULT 0,
        remediation_guidance TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    ''')

    # 6. Target Demo App Users (Mock Banking Accounts)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS target_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        account_number TEXT,
        balance REAL DEFAULT 0.0
    )
    ''')

    # 7. Target Demo App Feedback / Records
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS target_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT,
        content TEXT,
        submitted_at TEXT NOT NULL
    )
    ''')

    conn.commit()

    # Seed Default Defenses if not present
    seed_defenses(cursor)

    # Seed Target Demo App Users if not present
    seed_target_data(cursor)

    conn.commit()
    conn.close()

def seed_defenses(cursor):
    """Seeds the 4 core defensive controls corresponding to our test scenarios."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    defenses = [
        (
            'rate_limiting',
            'Authentication Rate Limiting & Account Lockout',
            'Enforces maximum 3 consecutive failed login attempts within 60s per username/IP before enforcing HTTP 429 lockouts.',
            0,
            'Implement rate-limiting middleware (e.g., token bucket or sliding window) and progressive delays or account lockout after repeated failed attempts.',
            now
        ),
        (
            'rbac_enforcement',
            'Role-Based Access Control & Strict Token Validation',
            'Restricts access to administrative resources by validating cryptographic session tokens and ensuring the user holds the ADMIN role.',
            0,
            'Enforce authorization checks on all server-side endpoints rather than relying on UI hiding. Validate session tokens and enforce strict RBAC roles.',
            now
        ),
        (
            'parameterized_queries',
            'Prepared Statements & SQL Injection Prevention',
            'Uses parameterized queries (?) for search and authentication inputs to treat user data as literals rather than executable SQL code.',
            0,
            'Always use parameterized SQL queries or an ORM. Never concatenate unvalidated user inputs directly into raw database query strings.',
            now
        ),
        (
            'input_sanitization',
            'Input Validation & HTML Output Encoding',
            'Applies strict character whitelisting and HTML entity encoding to user feedback and form submissions to prevent Cross-Site Scripting (XSS).',
            0,
            'Implement strict input validation schemas (length, type, allowed characters) and context-aware output encoding (HTML entities) before rendering inputs in views.',
            now
        )
    ]

    for d in defenses:
        cursor.execute('''
        INSERT OR IGNORE INTO defense_settings 
        (defense_key, name, description, is_enabled, remediation_guidance, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', d)

def seed_target_data(cursor):
    """Seeds the demo target app with initial mock users and accounts."""
    users = [
        ('admin', 'AdminPass2026!', 'ADMIN', 'ACC-990001', 54200.50),
        ('alice', 'AliceSecure123#', 'CUSTOMER', 'ACC-100234', 12450.00),
        ('bob', 'BobPassword789$', 'CUSTOMER', 'ACC-100567', 3200.75),
        ('charlie', 'CharlieKey456%', 'CUSTOMER', 'ACC-100890', 890.20)
    ]

    for u in users:
        cursor.execute('''
        INSERT OR IGNORE INTO target_users (username, password, role, account_number, balance)
        VALUES (?, ?, ?, ?, ?)
        ''', u)

    # Seed some initial feedback
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('''
    INSERT OR IGNORE INTO target_feedback (id, author, content, submitted_at)
    VALUES (1, 'alice', 'Loving the new banking portal interface! Smooth experience.', ?)
    ''', (now,))
