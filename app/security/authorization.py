from functools import wraps

from flask import abort, current_app
from flask_login import current_user, login_required

from app.security.audit import log_security_event
from app.security.audit_events import UNAUTHORIZED_ACCESS


# ==========================================================
# ROLE-BASED DECORATOR (pour une seule route)
# ==========================================================

def role_required(*roles):
    """Décorateur pour une seule route : exige un utilisateur connecté
    dont le rôle figure parmi ceux fournis."""

    def decorator(view_function):

        @wraps(view_function)
        @login_required
        def wrapped_view(*args, **kwargs):

            if current_user.role not in roles:

                log_security_event(
                    UNAUTHORIZED_ACCESS,
                    user_id=current_user.id,
                    status="DENIED",
                    details={
                        "reason": "role_required",
                        "required_roles": list(roles),
                        "actual_role": current_user.role,
                        "action": view_function.__name__,
                    },
                )

                abort(403)

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator


# ==========================================================
# BLUEPRINT-LEVEL GUARD (pour @bp.before_request)
# ==========================================================

def require_role(*roles):
    """A utiliser dans un @bp.before_request pour protéger tout un
    blueprint (ex : tout /client ou tout /employee) en une seule fois.

    Renvoie une redirection vers la page de login si l'utilisateur n'est
    pas authentifié, ou une 403 si son rôle ne correspond pas.
    """

    if not current_user.is_authenticated:

        return current_app.login_manager.unauthorized()

    if current_user.role not in roles:

        log_security_event(
            UNAUTHORIZED_ACCESS,
            user_id=current_user.id,
            status="DENIED",
            details={
                "reason": "role_required",
                "required_roles": list(roles),
                "actual_role": current_user.role,
            },
        )

        abort(403)

    return None


# ==========================================================
# ADMIN-ONLY DECORATOR (compatibilité + sécurité)
# ==========================================================

def admin_required(view_function):
    """
    Restrict access to authenticated ADMIN users.

    Security logging:
    - UNAUTHORIZED_ACCESS when an authenticated user
      without ADMIN role tries to access an admin endpoint.
    """

    @wraps(view_function)
    @login_required
    def wrapped_view(*args, **kwargs):

        # ==================================================
        # AUTHENTICATED USER BUT NOT ADMIN
        # ==================================================

        if current_user.role != "ADMIN":

            log_security_event(
                UNAUTHORIZED_ACCESS,
                user_id=current_user.id,
                status="DENIED",
                details={
                    "reason": "admin_role_required",
                    "required_role": "ADMIN",
                    "actual_role": current_user.role,
                    "action": view_function.__name__,
                },
            )

            abort(403)

        # ==================================================
        # ADMIN AUTHORIZED
        # ==================================================

        return view_function(*args, **kwargs)

    return wrapped_view