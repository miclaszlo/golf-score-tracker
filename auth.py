"""
Authentication and authorization utilities
"""
from functools import wraps
from flask import session, redirect, url_for, flash, request
from models import User, AuditLog, db

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or not user.is_admin():
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get the currently logged-in user"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def log_action(action, resource=None, details=None):
    """Log user actions for audit trail"""
    user_id = session.get('user_id')
    ip_address = request.remote_addr

    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        details=details
    )
    db.session.add(log_entry)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging action: {e}")

def validate_password_strength(password):
    """
    Basic password strength validation (SECURITY GAP: too weak)
    TODO: Implement stronger password requirements
    """
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"

    # SECURITY GAP: Should check for:
    # - Uppercase and lowercase letters
    # - Numbers
    # - Special characters
    # - Common passwords

    return True, "Password accepted"

def validate_score(strokes, par):
    """
    Basic score validation (SECURITY GAP: insufficient)
    TODO: Add more rigorous validation and integrity checks
    """
    if strokes < 1:
        return False, "Strokes must be at least 1"

    # SECURITY GAP: Should have upper limits, check for realistic scores
    if strokes > 20:
        return False, "Score seems unrealistic"

    return True, "Score accepted"
