import re
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import get_db_connection

ROLE_ADMIN = 'ADMIN'
ROLE_OWNER = 'WEBSITE_OWNER'
ROLE_VIEWER = 'VIEWER'

VALID_ROLES = {ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER}

ROLE_LABELS = {
    ROLE_ADMIN: 'Admin',
    ROLE_OWNER: 'Website Owner',
    ROLE_VIEWER: 'Viewer'
}

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.-]{3,40}$')


def _utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sanitize_user(row):
    """Converts a platform_users SQLite row to a safe dict, NEVER exposing password_hash."""
    if not row:
        return None
    d = dict(row)
    d.pop('password_hash', None)
    d['is_active'] = bool(d.get('is_active', 1))
    d['role_label'] = ROLE_LABELS.get(d.get('role'), d.get('role'))
    return d


def has_admin_user():
    """Returns True if at least one active Admin account exists in SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) as c FROM platform_users WHERE role = 'ADMIN' AND is_active = 1")
    count = cursor.fetchone()['c']
    conn.close()
    return count > 0


def create_user(username, email, password, role=ROLE_VIEWER):
    """
    Creates a new platform user with a salted memory-hard scrypt password hash.
    Returns (user_dict | None, error_message | None).
    """
    uname = (username or '').strip()
    mail = (email or '').strip().lower()
    role_norm = (role or '').strip().upper()

    if not _USERNAME_RE.match(uname):
        return None, "Username must be 3-40 characters (letters, numbers, _, ., -)."
    if not _EMAIL_RE.match(mail):
        return None, "A valid email address is required."
    if not password or not isinstance(password, str) or len(password) < 8:
        return None, "Password must be at least 8 characters long."
    if role_norm not in VALID_ROLES:
        return None, f"Invalid role '{role}'. Must be one of: {', '.join(sorted(VALID_ROLES))}."

    user_uuid = f"usr-{uuid.uuid4().hex[:12]}"
    pw_hash = generate_password_hash(password, method='scrypt')
    now = _utc_now_iso()

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO platform_users (
                user_uuid, username, email, password_hash, role, is_active, created_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?)
        ''', (user_uuid, uname, mail, pw_hash, role_norm, now))
        conn.commit()
    except Exception as e:
        conn.close()
        err_str = str(e).lower()
        if 'unique' in err_str:
            return None, "A user with that username or email already exists."
        return None, f"Could not create user: {str(e)}"

    cursor.execute('SELECT * FROM platform_users WHERE user_uuid = ?', (user_uuid,))
    row = cursor.fetchone()
    conn.close()
    return sanitize_user(row), None


def create_initial_admin_atomic(username, email, password):
    """
    Atomically creates the first Administrator account using a SQLite BEGIN IMMEDIATE
    write-lock transaction so concurrent /api/auth/setup-admin requests cannot race
    to create multiple Admin accounts.
    Returns (user_dict | None, error_code | None, error_message | None).
    """
    uname = (username or '').strip()
    mail = (email or '').strip().lower()

    if not _USERNAME_RE.match(uname):
        return None, 'VALIDATION_ERROR', "Username must be 3-40 characters (letters, numbers, _, ., -)."
    if not _EMAIL_RE.match(mail):
        return None, 'VALIDATION_ERROR', "A valid email address is required."
    if not password or not isinstance(password, str) or len(password) < 8:
        return None, 'VALIDATION_ERROR', "Password must be at least 8 characters long."

    user_uuid = f"usr-{uuid.uuid4().hex[:12]}"
    pw_hash = generate_password_hash(password, method='scrypt')
    now = _utc_now_iso()

    conn = get_db_connection()
    conn.isolation_level = None  # Explicit transaction control
    cursor = conn.cursor()
    try:
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute("SELECT count(*) as c FROM platform_users WHERE role = 'ADMIN' AND is_active = 1")
        if cursor.fetchone()['c'] > 0:
            cursor.execute('ROLLBACK')
            conn.close()
            return None, 'ADMIN_ALREADY_EXISTS', (
                "An administrator account already exists. Ask an existing Admin to create additional accounts."
            )

        cursor.execute('''
            INSERT INTO platform_users (
                user_uuid, username, email, password_hash, role, is_active, created_at
            )
            VALUES (?, ?, ?, ?, 'ADMIN', 1, ?)
        ''', (user_uuid, uname, mail, pw_hash, now))
        cursor.execute('COMMIT')
    except Exception as e:
        try:
            cursor.execute('ROLLBACK')
        except Exception:
            pass
        conn.close()
        err_str = str(e).lower()
        if 'unique' in err_str:
            return None, 'VALIDATION_ERROR', "A user with that username or email already exists."
        return None, 'SETUP_ERROR', "Could not initialize administrator account."

    cursor.execute('SELECT * FROM platform_users WHERE user_uuid = ?', (user_uuid,))
    row = cursor.fetchone()
    conn.close()
    return sanitize_user(row), None, None


def authenticate_user(identifier, password):
    """
    Verifies username or email + password using constant-time Werkzeug hash verification.
    Returns sanitized user dict on success, or None on failure.
    """
    ident = (identifier or '').strip()
    if not ident or not password:
        return None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM platform_users
        WHERE (lower(username) = lower(?) OR lower(email) = lower(?)) AND is_active = 1
        LIMIT 1
    ''', (ident, ident))
    row = cursor.fetchone()

    if not row or not check_password_hash(row['password_hash'], password):
        conn.close()
        return None

    now = _utc_now_iso()
    cursor.execute('UPDATE platform_users SET last_login_at = ? WHERE id = ?', (now, row['id']))
    conn.commit()
    cursor.execute('SELECT * FROM platform_users WHERE id = ?', (row['id'],))
    updated = cursor.fetchone()
    conn.close()
    return sanitize_user(updated)


def get_user_by_uuid(user_uuid):
    """Fetches a sanitized active user by UUID."""
    if not user_uuid:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM platform_users WHERE user_uuid = ? AND is_active = 1', (user_uuid,))
    row = cursor.fetchone()
    conn.close()
    return sanitize_user(row)


def list_users():
    """Returns all platform users with password hashes strictly stripped."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM platform_users ORDER BY id ASC')
    rows = [sanitize_user(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def bootstrap_admin_from_env(app_config):
    """
    Provisions an Admin account ONLY if explicitly supplied via environment variables
    (CYBERFORTIFY_ADMIN_USERNAME, CYBERFORTIFY_ADMIN_EMAIL, CYBERFORTIFY_ADMIN_PASSWORD)
    and no Admin account exists yet. Never hardcodes default credentials.
    """
    if has_admin_user():
        return None
    uname = app_config.get('CYBERFORTIFY_ADMIN_USERNAME')
    email = app_config.get('CYBERFORTIFY_ADMIN_EMAIL')
    pwd = app_config.get('CYBERFORTIFY_ADMIN_PASSWORD')
    if uname and email and pwd:
        user, _ = create_user(uname, email, pwd, role=ROLE_ADMIN)
        return user
    return None
