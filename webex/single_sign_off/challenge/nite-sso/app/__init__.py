from flask import Flask
import secrets
import os

def create_app():
    app = Flask(__name__, template_folder='../templates')
    app.secret_key = secrets.token_hex(32)
    
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600  
    
    from .models.database import init_db
    init_db()
    
    from .routes.auth import auth_bp
    from .routes.api import api_bp
    from .routes.user import user_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(user_bp)

    @app.context_processor
    def inject_portal_url():
        DOMAIN = os.environ.get('DOMAIN', 'localhost')
        PORTAL_URL = os.environ.get('PORTAL_EXTERNAL_URL', f'http://document-portal.{DOMAIN}')
        return dict(PORTAL_URL=PORTAL_URL)
    
    return app
