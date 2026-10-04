"""
Extensions Flask partagees.

Ce module ne depend d'AUCUN autre module du projet -> pas de cycle.
Tous les autres modules importent db/migrate/csrf/login_manager d'ICI.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_socketio import SocketIO  
db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.session_protection = "strong"
# SocketIO : temps réel pour le chat
# async_mode='threading' : le plus simple pour du dev local
socketio = SocketIO()       