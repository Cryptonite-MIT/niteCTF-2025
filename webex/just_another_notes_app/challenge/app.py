from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, Response
from models import db, User, Note, InviteCode
from datetime import datetime, timedelta
import threading
import time
import urllib.parse
import random
import os
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['SECRET_KEY'] = 'duf1Qe2ACkRF7FDzRplPVHiPggfLVgscKFjBv31gyarvg8oQoy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ctf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ADMIN_PASS = os.environ.get('ADMIN_PASS', 'ubdgj5loTe5KKyiN5Eebvqcd51XAJ0rh2hIm82Q23ErR9Z3HDy')
MODERATER_PASS = os.environ.get('MODERATER_PASS', 'kfokDyaskri1RDRaxHd67POtn8ENSTAQQhF7R3lQdD0uayphSd')
FLAG = os.environ.get('FLAG', 'nite{r3qu3575_d0n7_n33d_70_4lw4y5_c0mpl373}')

db.init_app(app)

def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(username='admin', is_admin=True)
        admin.set_password(ADMIN_PASS)
        db.session.add(admin)
        moderator = User(username='moderator', is_admin=False)
        moderator.set_password(MODERATER_PASS)
        db.session.add(moderator)
        db.session.commit()
        print("Database initialized at", datetime.utcnow())

try:
    init_db()
except Exception as e:
    print(f"⚠️  Database initialization: {e}")

TOKEN = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') for _ in range(12))

def auto_reset():
    while True:
        time.sleep(30 * 60)
        init_db()

reset_thread = threading.Thread(target=auto_reset, daemon=True)
reset_thread.start()

def _clear_invalid_session_and_redirect():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    try:
        resp.delete_cookie(app.session_cookie_name)
    except Exception:
        pass
    return resp

@app.after_request
def set_cookie(response):
    response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'self';"
    return response

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('notes'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('register.html', error='Username and password required')
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('notes'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('notes'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            note = Note(user_id=session['user_id'], content=content)
            db.session.add(note)
            db.session.commit()
            return redirect(url_for('notes'))
    user = User.query.get(session['user_id'])
    if not user:
        return _clear_invalid_session_and_redirect()
    notes_list = Note.query.filter_by(user_id=user.id).order_by(Note.created_at.desc()).all()
    return render_template('notes.html', notes=notes_list, username=user.username)

@app.route('/notes/<note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    note = Note.query.get_or_404(note_id)
    
    # Allow admin users to view all notes; other users can only view their own notes
    user = User.query.get(session['user_id'])
    if note.user_id != session['user_id']:
        if not user or not getattr(user, 'is_admin', False):
            return "Access denied. You can only view your own notes.", 403


    response = make_response(render_template('view_note.html', note=note))
    return response

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user:
        return _clear_invalid_session_and_redirect()
    if not getattr(user, 'is_admin', False):
        return "Access denied. Admin privileges required.", 403
    invites = InviteCode.query.filter_by(created_by=user.id).order_by(InviteCode.created_at.desc()).limit(10).all()
    response = make_response(render_template('admin.html', invites=invites))
    if 'flag' not in request.cookies:
        response.set_cookie('flag', FLAG, httponly=True, samesite='Lax')
    return response

@app.route('/admin/generate_invite', methods=['POST'])
def generate_invite():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    user = User.query.get(session['user_id'])
    if not user:
        return _clear_invalid_session_and_redirect()
    if not getattr(user, 'is_admin', False):
        return jsonify({'error': 'Admin only'}), 403
    code = InviteCode.generate_code()
    invite = InviteCode(
        code=code,
        target_user='moderator',
        created_by=user.id,
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    db.session.add(invite)
    db.session.commit()
    share_url = url_for('getToken', _external=True)
    return jsonify({'success': True, 'url': share_url})


@app.route('/getToken', methods=['GET'])
def getToken():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    print(request)
    token_param = request.args.get("token")
    if token_param:
        invite = InviteCode.query.filter_by(code=token_param, used=False).first()
        if invite and not invite.is_expired():
            return redirect(url_for('accept_invite', token=token_param))
        return redirect("/")
    
    invite = InviteCode.query.filter_by(used=False).order_by(InviteCode.created_at.desc()).first()
    if not invite or invite.is_expired():
        return redirect("/")
    
    token_value = invite.code
    query_params = {"token": token_value}
    new_query = urllib.parse.urlencode(query_params)
    new_url = f"{url_for('getToken', _external=True)}?{new_query}"

    resp = make_response(redirect(new_url))
    resp.set_cookie('FinalToken', TOKEN, max_age=60 * 60 * 24 * 7, httponly=True)
    print(resp.status_code, resp.headers)
    return resp


@app.route('/accept_invite', methods=['GET', 'POST'])
def accept_invite():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        token = request.form.get('token')
        if not token:
            return render_template('accept_invite.html', error='Token required')
        invite = InviteCode.query.filter_by(code=token, used=False).first()
        if not invite:
            return render_template('accept_invite.html', error='Invalid or expired invite code')
        if invite.is_expired():
            return render_template('accept_invite.html', error='Invite code has expired')
        user = User.query.get(session['user_id'])
        if not user:
            return _clear_invalid_session_and_redirect()
        user.is_admin = True
        invite.used = True
        invite.used_by = user.id
        db.session.commit()
        return redirect(url_for('admin'))
    token = request.args.get('token')
    return render_template('accept_invite.html', token=token)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

