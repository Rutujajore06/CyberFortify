from flask import Flask, render_template
from app.config import Config
from app.database import init_db

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite database and tables
    with app.app_context():
        init_db()

    # Register Target App Blueprint (/api/target/*)
    from app.target_app import target_bp
    app.register_blueprint(target_bp)

    # Register Platform API Blueprint (/api/*)
    from app.api import api_bp
    app.register_blueprint(api_bp)

    # Web Dashboard UI Routes
    @app.route('/')
    def dashboard_view():
        return render_template('dashboard.html', active_page='dashboard')

    @app.route('/assessment')
    def assessment_view():
        return render_template('assessment.html', active_page='assessment')

    @app.route('/simulations')
    def simulations_view():
        return render_template('simulations.html', active_page='simulations')

    @app.route('/alerts')
    def alerts_view():
        return render_template('alerts.html', active_page='alerts')

    @app.route('/logs')
    def logs_view():
        return render_template('logs.html', active_page='logs')

    @app.route('/defenses')
    def defenses_view():
        return render_template('defenses.html', active_page='defenses')

    @app.route('/report')
    def report_view():
        return render_template('report.html', active_page='report')

    return app
