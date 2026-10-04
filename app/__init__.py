from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_login import LoginManager, current_user
from flask import Flask, flash, redirect, request, url_for
from .config import Config


# ==========================================================
# FLASK EXTENSIONS
# ==========================================================

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
login_manager = LoginManager()

# Flask-Login session protection
login_manager.session_protection = "strong"


# ==========================================================
# USER LOADER
# ==========================================================

@login_manager.user_loader
def load_user(user_id):
    from .models import User

    try:
        return db.session.get(User, int(user_id))

    except (TypeError, ValueError):
        return None


# ==========================================================
# APPLICATION FACTORY
# ==========================================================

def create_app():
    app = Flask(
        __name__,
        instance_relative_config=True,
    )

    # ------------------------------------------------------
    # Configuration
    # ------------------------------------------------------

    app.config.from_object(Config)

    # ------------------------------------------------------
    # Initialize extensions
    # ------------------------------------------------------

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    # ------------------------------------------------------
    # Flask-Login configuration
    # ------------------------------------------------------

    login_manager.login_view = "auth.login"

    login_manager.login_message = (
        "Veuillez vous connecter pour accéder à cette page."
    )

    login_manager.login_message_category = "warning"

    # ======================================================
    # UNAUTHENTICATED ACCESS LOGGING
    # ======================================================
    #
    # This handler is called when @login_required blocks
    # an unauthenticated user.
    #
    # Example:
    #
    # Anonymous user
    #      ↓
    # /admin/users
    #      ↓
    # @login_required
    #      ↓
    # UNAUTHORIZED_ACCESS
    #
    # ======================================================

    @login_manager.unauthorized_handler
    def handle_unauthorized():
        from app.security.audit import log_security_event
        from app.security.audit_events import UNAUTHORIZED_ACCESS

        log_security_event(
            UNAUTHORIZED_ACCESS,
            user_id=None,
            status="DENIED",
            details={
                "reason": "authentication_required",
                "requested_endpoint": request.endpoint,
                "requested_path": request.path,
                "method": request.method,
            },
        )
        flash(
            "Veuillez vous connecter pour accéder à cette page.",
            "warning",
        )
        return (
            "Veuillez vous connecter pour accéder à cette page.",
            401,
        )

    # ======================================================
    # CSRF ERROR LOGGING
    # ======================================================
    #
    # Any invalid/missing CSRF token is recorded.
    #
    # IMPORTANT:
    # Never log the CSRF token itself.
    #
    # ======================================================

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        from app.security.audit import log_security_event
        from app.security.audit_events import CSRF_REJECTED

        log_security_event(
            CSRF_REJECTED,
            user_id=(
                current_user.id
                if current_user.is_authenticated
                else None
            ),
            status="DENIED",
            details={
                "reason": "csrf_validation_failed",
                "requested_endpoint": request.endpoint,
                "requested_path": request.path,
                "method": request.method,
            },
        )

        return (
            "Requête rejetée : protection CSRF invalide.",
            400,
        )

    # ======================================================
    # BLUEPRINTS
    # ======================================================

    from .admin import admin_bp
    from .auth import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # ======================================================
    # HOME
    # ======================================================

    @app.route("/")
    def home():
        return "Secure Digital Contract Platform - OK"

    return app