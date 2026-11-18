import os
import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class Config:
    DEFAULT_DEV_SECRET_KEY = 'cyberfortify-secret-key-btech-2026'
    IS_RENDER = bool(os.environ.get('RENDER'))
    IS_VERCEL = bool(os.environ.get('VERCEL'))
    SECRET_KEY = os.environ.get('SECRET_KEY', DEFAULT_DEV_SECRET_KEY)
    # PostgreSQL connection string (Neon / Vercel Postgres / Render Postgres).
    # When set, CyberFortify uses PostgreSQL automatically; otherwise uses local SQLite.
    DATABASE_URL = os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL')
    # Vercel serverless filesystem is read-only outside /tmp; default to /tmp/cyberfortify.db on Vercel if no DATABASE_URL
    DATABASE_PATH = os.environ.get(
        'DATABASE_PATH',
        '/tmp/cyberfortify.db' if IS_VERCEL else os.path.join(BASE_DIR, 'cyberfortify.db')
    )
    TARGET_APP_NAME = "Fortress Demo Banking Portal"
    # Port on which CyberFortify runs (binds to hosting platform PORT or defaults to 5000)
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '127.0.0.1')
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development').lower()
    TRUST_PROXY = os.environ.get(
        'TRUST_PROXY',
        'true' if (IS_RENDER or IS_VERCEL or FLASK_ENV == 'production') else 'false'
    ).lower() in ('1', 'true', 'yes')
    STRICT_PRODUCTION_CONFIG = os.environ.get('STRICT_PRODUCTION_CONFIG', 'false').lower() in ('1', 'true', 'yes')
    # Disable Flask debug mode in production; enable via FLASK_DEBUG or DEBUG env var in development
    DEBUG = os.environ.get('FLASK_DEBUG', os.environ.get('DEBUG', 'false')).lower() in ('1', 'true', 'yes')

    # Configured Demo Scope for Website Security Assessment (Fortress Bank Demo)
    # The internal Fortress Bank demo port is decoupled from the dynamic hosting platform web-service PORT (e.g. Render PORT=10000)
    DEMO_PORT = int(os.environ.get('DEMO_PORT', 5000))
    DEMO_HOST = os.environ.get('DEMO_HOST', '127.0.0.1')
    DEMO_ALLOWED_HOSTS = {'127.0.0.1', 'localhost'}
    DEMO_ALLOWED_SCHEMES = {'http'}
    # Allowed ports for demo assessment: allows configured internal demo port as well as web service PORT if distinct
    DEMO_ALLOWED_PORT = DEMO_PORT
    DEMO_ALLOWED_PORTS = {DEMO_PORT, PORT}
    DEMO_ORIGIN = f"http://{DEMO_HOST}:{DEMO_PORT}"
    REQUIRE_AUTH = os.environ.get('REQUIRE_AUTH', 'false').lower() in ('1', 'true', 'yes')
    LOCAL_DEMO_MODE = os.environ.get('LOCAL_DEMO_MODE', 'true').lower() in ('1', 'true', 'yes')

    # Secure Session, Cookie & CSRF Configuration
    SESSION_COOKIE_NAME = 'cyberfortify_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get(
        'SESSION_COOKIE_SECURE',
        'true' if (IS_RENDER or IS_VERCEL or FLASK_ENV == 'production') else 'false'
    ).lower() in ('1', 'true', 'yes')
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(hours=4)
    CSRF_ENABLED = True

    # Optional environment-only initial admin provisioning (never hardcoded in source)
    CYBERFORTIFY_ADMIN_USERNAME = os.environ.get('CYBERFORTIFY_ADMIN_USERNAME')
    CYBERFORTIFY_ADMIN_EMAIL = os.environ.get('CYBERFORTIFY_ADMIN_EMAIL')
    CYBERFORTIFY_ADMIN_PASSWORD = os.environ.get('CYBERFORTIFY_ADMIN_PASSWORD')
    CYBERFORTIFY_BOOTSTRAP_TOKEN = os.environ.get('CYBERFORTIFY_BOOTSTRAP_TOKEN')

    # Authentication rate-limiting defaults
    AUTH_LOGIN_MAX_ATTEMPTS = int(os.environ.get('AUTH_LOGIN_MAX_ATTEMPTS', 10))
    AUTH_LOGIN_WINDOW_SECONDS = int(os.environ.get('AUTH_LOGIN_WINDOW_SECONDS', 300))
    AUTH_REGISTER_MAX_ATTEMPTS = int(os.environ.get('AUTH_REGISTER_MAX_ATTEMPTS', 5))
    AUTH_REGISTER_WINDOW_SECONDS = int(os.environ.get('AUTH_REGISTER_WINDOW_SECONDS', 600))

    # Live Authorized Website Security Testing Configuration
    LIVE_ALLOWED_SCHEMES = {'http', 'https'}
    LIVE_ALLOWED_PORTS = {80, 443}
    LIVE_ALLOWED_METHODS = {'GET', 'HEAD', 'OPTIONS'}
    LIVE_REQUEST_TIMEOUT = float(os.environ.get('LIVE_REQUEST_TIMEOUT', 10.0))
    LIVE_DNS_TIMEOUT = float(os.environ.get('LIVE_DNS_TIMEOUT', 3.0))
    LIVE_CONNECT_TIMEOUT = float(os.environ.get('LIVE_CONNECT_TIMEOUT', LIVE_REQUEST_TIMEOUT))
    LIVE_READ_TIMEOUT = float(os.environ.get('LIVE_READ_TIMEOUT', LIVE_REQUEST_TIMEOUT))
    LIVE_MAX_REDIRECTS = int(os.environ.get('LIVE_MAX_REDIRECTS', 5))
    LIVE_MAX_RATE_LIMIT = int(os.environ.get('LIVE_MAX_RATE_LIMIT', 60))
    LIVE_MAX_RESPONSE_BYTES = int(os.environ.get('LIVE_MAX_RESPONSE_BYTES', 524288))  # 512 KB cap
    LIVE_ADMIN_TOKEN = os.environ.get('LIVE_ADMIN_TOKEN', SECRET_KEY)
