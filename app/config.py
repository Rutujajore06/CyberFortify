import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyberfortify-secret-key-btech-2026')
    DATABASE_PATH = os.path.join(BASE_DIR, 'cyberfortify.db')
    TARGET_APP_NAME = "Fortress Demo Banking Portal"
    # Port on which CyberFortify runs locally
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '127.0.0.1')
    DEBUG = True
