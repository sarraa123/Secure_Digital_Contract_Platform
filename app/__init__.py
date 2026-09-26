import os

from flask import Flask, render_template
from flask_talisman import Talisman

from .config import Config
from .extensions import db, migrate, csrf, login_manager

talisman = Talisman()


@login_manager.user_loader
def load_user(user_id):
    from .models import User

    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def create_app():
    app = Flask(__name__, instance_relative_config=True)
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
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Veuillez vous connecter pour acceder a cette page."
    login_manager.login_message_category = "warning"

    # Imports differes (a l'interieur de la factory) pour eviter les
    # imports circulaires : les blueprints importent des modeles qui
    # eux-memes importent `db` depuis ce module.
    from .admin import admin_bp
    from .auth import auth_bp
    from .routes import client, employee

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(employee.bp)
    app.register_blueprint(client.bp)

    @app.route("/")
    def home():
        return render_template("public/landing.html")

    return app