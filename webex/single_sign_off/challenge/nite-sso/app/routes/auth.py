from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from ..models.database import get_db
from ..utils.validators import validate_username, validate_password
import uuid

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    if 'username' in session:
        username = session.get('username')
        return render_template('home.html', username=username)
    else:
        return redirect(url_for('auth.login'))

@auth_bp.route('/doLogin', methods=['GET'])
def doLoginGet():
    redirect_url = request.args.get('redirect_url')
    username = request.args.get('username')
    password = request.args.get('password')

    if username and password:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        
        if user:
            conn.execute("DELETE FROM sessions WHERE created_at <= datetime('now', '-1 hour')")
            
            conn.execute('DELETE FROM sessions WHERE username = ?', (username,))
            
            sessionId = str(uuid.uuid4())
            conn.execute('INSERT INTO sessions (session_id, username) VALUES (?, ?)', (sessionId, username))
            conn.commit()
            conn.close()
            
            session['username'] = username
            session['session_id'] = sessionId
            
            if redirect_url and redirect_url.strip():
                redirectUrlFinal = redirect_url + "?sessionId=" + sessionId
                return redirect(redirectUrlFinal)
            else:
                return redirect('/')
        conn.close()

    if 'username' in session and redirect_url:
        sessionId = session.get('session_id')
        if sessionId:
            conn = get_db()
            db_session = conn.execute('SELECT 1 FROM sessions WHERE session_id = ?', (sessionId,)).fetchone()
            conn.close()
            
            if db_session:
                redirectUrlFinal = redirect_url + "?sessionId=" + sessionId
                return redirect(redirectUrlFinal)
            else:
                session.clear()

    if redirect_url:
         return redirect(url_for('auth.login', redirect_url=redirect_url))
    return redirect(url_for('auth.login'))

@auth_bp.route('/doLogin', methods=['POST'])
def doLoginPost():
    username = request.form.get('username')
    password = request.form.get('password')

    if not validate_username(username):
        redirect_url = request.form.get('redirect_url')
        return render_template('login.html', error='Invalid username format', redirect_url=redirect_url)
    
    if not validate_password(password):
        redirect_url = request.form.get('redirect_url')
        return render_template('login.html', error='Invalid password format', redirect_url=redirect_url)

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
    
    if user:

        conn.execute("DELETE FROM sessions WHERE created_at <= datetime('now', '-1 hour')")

        conn.execute('DELETE FROM sessions WHERE username = ?', (username,))
        
        sessionId = str(uuid.uuid4())
        conn.execute('INSERT INTO sessions (session_id, username) VALUES (?, ?)', (sessionId, username))
        conn.commit()
        conn.close()
        
        session['username'] = username
        session['session_id'] = sessionId
        
        redirect_url = request.form.get('redirect_url')
        if redirect_url and redirect_url.strip():
            redirectUrlFinal = redirect_url + "?sessionId=" + sessionId
            return redirect(redirectUrlFinal)
        else:
            return redirect('/')
    
    conn.close()
    redirect_url = request.form.get('redirect_url')
    return render_template('login.html', error='Invalid username or password', redirect_url=redirect_url)

@auth_bp.route('/doRegister', methods=['POST'])
def doRegister():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not validate_username(username):
        return render_template('register.html', error='Username must be 3-20 characters, alphanumeric')
    
    if not validate_password(password):
        return render_template('register.html', error='Password must be at least 6 characters')
        
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        return redirect(url_for('auth.login', success='Registration successful'))
    except Exception:
        conn.close()
        return render_template('register.html', error='Username already exists')

@auth_bp.route('/login')
def login():
    if 'username' in session:
        return redirect('/')
    
    redirect_url = request.args.get('redirect_url', '')
    success = request.args.get('success')
    error = request.args.get('errorMsg')
    return render_template('login.html', redirect_url=redirect_url, success=success, error=error)

@auth_bp.route('/register')
def register():
    if 'username' in session:
        return redirect('/')
    
    return render_template('register.html')

@auth_bp.route('/logout')
def logout():
    session_id = session.get('session_id')

    if session_id:
        conn = get_db()
        conn.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()

    session.clear()
    
    redirect_url = request.args.get('redirect_url')
    if redirect_url:
        return redirect(url_for('auth.login', redirect_url=redirect_url))
    return redirect(url_for('auth.login'))
