from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from ..models.database import get_db
from functools import wraps

user_bp = Blueprint('user', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@user_bp.route('/profile')
@login_required
def profile():
    username = session.get('username')
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    sessions = conn.execute(
        'SELECT session_id, created_at FROM sessions WHERE username = ? ORDER BY created_at DESC',
        (username,)
    ).fetchall()
    conn.close()
    
    return render_template('profile.html', user=user, sessions=sessions)

@user_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        username = session.get('username')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            return render_template('settings.html', error='Passwords do not match')
        
        if len(new_password) < 6:
            return render_template('settings.html', error='Password must be at least 6 characters')
        
        conn = get_db()
        conn.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
        conn.commit()
        conn.close()
        
        return render_template('settings.html', success='Password updated successfully')
    
    return render_template('settings.html')

@user_bp.route('/sessions')
@login_required
def sessions_list():
    username = session.get('username')
    
    conn = get_db()
    sessions = conn.execute(
        'SELECT session_id, created_at FROM sessions WHERE username = ? ORDER BY created_at DESC',
        (username,)
    ).fetchall()
    conn.close()
    
    return render_template('sessions.html', sessions=sessions)

@user_bp.route('/sessions/revoke/<session_id>', methods=['POST'])
@login_required
def revoke_session(session_id):
    username = session.get('username')
    
    conn = get_db()
    conn.execute('DELETE FROM sessions WHERE session_id = ? AND username = ?', (session_id, username))
    conn.commit()
    conn.close()
    
    return redirect(url_for('user.sessions_list'))
