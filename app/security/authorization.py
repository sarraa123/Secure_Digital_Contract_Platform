from functools import wraps

from flask import abort
from flask_login import current_user, login_required

from app.security.audit import log_security_event
from app.security.audit_events import UNAUTHORIZED_ACCESS


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