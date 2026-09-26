from functools import wraps

from flask import abort, current_app
from flask_login import current_user, login_required


def role_required(*roles):
    """Décorateur pour une seule route : exige un utilisateur connecté
    dont le rôle figure parmi ceux fournis."""
    def decorator(view_function):
        @wraps(view_function)
        @login_required
        def wrapped_view(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return view_function(*args, **kwargs)
        return wrapped_view
    return decorator


def require_role(*roles):
    """A utiliser dans un @bp.before_request pour protéger tout un
    blueprint (ex : tout /client ou tout /employee) en une seule fois.

    Renvoie une redirection vers la page de login si l'utilisateur n'est
    pas authentifié, ou une 403 si son rôle ne correspond pas.
    """
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()
    if current_user.role not in roles:
        abort(403)
    return None


# Conservé pour compatibilité : @admin_required continue de fonctionner
# exactement comme avant sur les routes de app/admin/routes.py.
admin_required = role_required("ADMIN")
