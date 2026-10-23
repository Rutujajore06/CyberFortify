import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyberfortify-secret-key-btech-2026')
    DATABASE_PATH = os.path.join(BASE_DIR, 'cyberfortify.db')
    TARGET_APP_NAME = "Fortress Demo Banking Portal"
    # Port on which CyberFortify runs (binds to hosting platform PORT or defaults to 5000)
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '127.0.0.1')
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
