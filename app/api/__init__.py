from flask import Blueprint

api_bp = Blueprint('api_bp', __name__, url_prefix='/api')

from app.api import defense_routes
from app.api import simulation_routes
from app.api import alert_routes
from app.api import event_routes
from app.api import evaluation_routes
from app.api import assessment_routes
