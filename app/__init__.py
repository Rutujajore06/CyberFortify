from flask import Flask, render_template
from app.config import Config
from app.database import init_db

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite database and tables
    with app.app_context():
        init_db()
        from app.models.user_model import bootstrap_admin_from_env
        bootstrap_admin_from_env(app.config)

    # Register Authentication & RBAC Blueprint (/api/auth/*)
    from app.auth.routes import auth_bp
    app.register_blueprint(auth_bp)

    # Register Target App Blueprint (/api/target/*)
    from app.target_app import target_bp
    app.register_blueprint(target_bp)

    # Register Platform API Blueprint (/api/*)
    from app.api import api_bp
    app.register_blueprint(api_bp)

    # Inject current_user, CSRF token, and auth state into all Jinja templates
    @app.context_processor
    def inject_auth_context():
        from app.auth.security import get_current_user, get_or_create_csrf_token, is_auth_enforced, is_public_deployment
        return {
            'current_user': get_current_user(),
            'csrf_token': get_or_create_csrf_token(),
            'auth_enforced': is_auth_enforced(),
            'public_deployment': is_public_deployment()
        }

    # Authentication & Access Control UI Route
    @app.route('/login')
    def login_view():
        return render_template('login.html', active_page='login')

    # Web Dashboard UI Routes
    @app.route('/')
    def dashboard_view():
        return render_template('dashboard.html', active_page='dashboard')

    @app.route('/assessment')
    def assessment_view():
        return render_template('assessment.html', active_page='assessment')

    @app.route('/live-targets')
    def live_targets_view():
        return render_template('live_targets.html', active_page='live_targets')

    @app.route('/live-assessment')
    def live_assessment_view():
        return render_template('live_assessment.html', active_page='live_assessment')

    @app.route('/live-remediation')
    def live_remediation_view():
        return render_template('live_remediation.html', active_page='live_remediation')

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

    @app.route('/target')
    @app.route('/target/')
    @app.route('/bank')
    @app.route('/demo')
    def target_portal_view():
        return render_template('target.html', active_page='target')

    return app
