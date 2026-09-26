from flask import Flask

from .config import Config
from .extensions import db, migrate, csrf, login_manager


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
        return "Secure Digital Contract Platform - OK"

    return app
