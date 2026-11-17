import secrets
from flask import Flask, render_template, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix
from app.config import Config
from app.database import init_db

_WEAK_SECRET_KEYS = {
    '',
    'cyberfortify-secret-key-btech-2026',
    'cyberfortify-change-me-in-production-demo-key',
    'replace-with-strong-random-secret-key'
}


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Production / Public Deployment Hardening
    with app.app_context():
        from app.auth.security import is_public_deployment
        public_mode = is_public_deployment()

    if public_mode:
        # Never allow DEBUG mode in public deployments
        app.config['DEBUG'] = False
        # Live Website Testing & Admin RBAC authentication cannot be disabled on public deployments
        app.config['LIVE_AUTH_ENFORCED'] = True
        # Ensure Secure session cookie flag behind HTTPS reverse proxy
        app.config['SESSION_COOKIE_SECURE'] = True

        # Reject or rotate hardcoded / weak SECRET_KEY in public deployments
        raw_secret = str(app.config.get('SECRET_KEY') or '').strip()
        if raw_secret in _WEAK_SECRET_KEYS or len(raw_secret) < 32:
            if app.config.get('STRICT_PRODUCTION_CONFIG', False):
                raise RuntimeError(
                    "Production startup blocked: set a strong random SECRET_KEY (>= 32 characters) in the environment."
                )
            app.logger.warning(
                "SECURITY WARNING: Default or weak SECRET_KEY detected in public deployment; "
                "generated ephemeral runtime SECRET_KEY. Set a persistent SECRET_KEY env var."
            )
            app.config['SECRET_KEY'] = secrets.token_hex(32)

    # Trust reverse proxy headers (X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host) when deployed behind Render/Nginx
    if public_mode or app.config.get('TRUST_PROXY', False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

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

    # Sanitized global error handlers (never expose internal stack traces or secrets)
    @app.errorhandler(404)
    def handle_404(err):
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'error_type': 'NOT_FOUND', 'message': 'Requested resource not found.'}), 404
        return "404 Not Found", 404

    @app.errorhandler(405)
    def handle_405(err):
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'error_type': 'METHOD_NOT_ALLOWED', 'message': 'HTTP method not allowed.'}), 405
        return "405 Method Not Allowed", 405

    @app.errorhandler(500)
    def handle_500(err):
        app.logger.exception("Unhandled internal server error on %s", request.path)
        if request.path.startswith('/api/'):
            return jsonify({
                'status': 'error',
                'error_type': 'INTERNAL_ERROR',
                'message': 'An internal server error occurred. Please check server logs.'
            }), 500
        return "500 Internal Server Error", 500

    return app
