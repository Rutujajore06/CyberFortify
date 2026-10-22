from flask import Blueprint

target_bp = Blueprint('target_bp', __name__, url_prefix='/api/target')

from app.target_app import routes
