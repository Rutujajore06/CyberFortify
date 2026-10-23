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
    DEMO_ALLOWED_HOSTS = {'127.0.0.1', 'localhost'}
    DEMO_ALLOWED_SCHEMES = {'http'}
    DEMO_ALLOWED_PORT = PORT
    DEMO_ORIGIN = f"http://{HOST}:{PORT}"
    REQUIRE_AUTH = os.environ.get('REQUIRE_AUTH', 'false').lower() in ('1', 'true', 'yes')
