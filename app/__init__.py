import os

from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_login import LoginManager, current_user
from flask import Flask, flash, redirect, request, url_for,render_template
from .config import Config
from .extensions import db, migrate, csrf, login_manager, socketio

talisman = Talisman()

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

    # CSP avec autorisations Google Fonts + iframes internes
    csp = {
        'default-src': "'self'",
        'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
        'script-src': "'self'",
        'img-src': "'self' data:",
        'font-src': "'self' data: https://fonts.gstatic.com",
        'connect-src': "'self'",
        'frame-src': "'self'",
        'frame-ancestors': "'self'",
        'object-src': "'self'",
        'base-uri': "'self'",
        'form-action': "'self'",
        'script-src': "'self' https://cdn.socket.io",
        'connect-src': "'self' wss://127.0.0.1:5000 ws://127.0.0.1:5000",
    }

    talisman.init_app(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=["script-src"],
        force_https=app.config.get("SESSION_COOKIE_SECURE", False),
        strict_transport_security=True,
        session_cookie_secure=app.config.get("SESSION_COOKIE_SECURE", False),
        frame_options="SAMEORIGIN",
        x_content_type_options=True,
    )
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
    login_manager.login_message = "Veuillez vous connecter pour acceder a cette page."
    login_manager.login_message_category = "warning"

    # --- SocketIO (temps réel) ---
    socketio.init_app(
        app,
        async_mode="threading",
        cors_allowed_origins=None,
        logger=False,
        engineio_logger=False,
    )

    # --- Imports différés (dans la factory) ---

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
    from .routes import client, employee
    from .routes import public
    from .routes import notifications
    from .routes import chat as chat_routes
    from .routes import amendments as amend_routes

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(employee.bp)
    app.register_blueprint(client.bp)
    app.register_blueprint(public.bp)
    app.register_blueprint(notifications.bp)
    app.register_blueprint(chat_routes.bp)
    app.register_blueprint(amend_routes.bp)

    # --- Enregistrer les événements WebSocket ---
    from .routes import socket_events
    socket_events.init_socket_events(socketio)

    # --- Route racine ---
    # ======================================================
    # HOME
    # ======================================================

    @app.route("/")
    def home():
        return render_template("public/landing.html")

    return app