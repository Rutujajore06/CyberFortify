from flask import Flask
from app.config import Config
from app.database import init_db

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite database and tables
    with app.app_context():
        init_db()

    # Register Target App Blueprint
    from app.target_app import target_bp
    app.register_blueprint(target_bp)

    return app
