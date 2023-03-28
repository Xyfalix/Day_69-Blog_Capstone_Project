from functools import wraps
from flask import abort
from flask_login import current_user

def admin_only(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            # If the user is not authenticated or their ID doesn't match the admin ID (in this case, ID 1), abort with a 403 error.
            abort(403)
        # Otherwise, proceed with the view function.
        return func(*args, **kwargs)
    return decorated_view