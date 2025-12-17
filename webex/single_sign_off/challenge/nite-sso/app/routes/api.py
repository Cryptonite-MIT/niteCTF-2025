from flask import Blueprint, request, jsonify
from ..models.database import get_db

api_bp = Blueprint('api', __name__)

@api_bp.route('/app/logincheck')
def login_check():
    session_id = request.args.get('sessionId')
    if not session_id:
        return jsonify({'code': 500, 'msg': 'Session ID required'})
        
    conn = get_db()
    session = conn.execute(
        "SELECT * FROM sessions WHERE session_id = ? AND created_at > datetime('now', '-1 hour')", 
        (session_id,)
    ).fetchone()
    conn.close()
    
    if session:
        return jsonify({'code': 200, 'msg': 'Success', 'username': session['username']})
    else:
        return jsonify({'code': 500, 'msg': 'Invalid session'})
