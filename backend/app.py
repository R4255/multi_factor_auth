from flask import Flask, config,jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import os
from datetime import timedelta

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()

limiter = Limiter(key_func = get_remote_address)
redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))

def create_app(config_name = 'development'):
    app = Flask(__name__)
    if config_name == 'production':
        app.config.from_object('config.ProductionConfig')
    else:
        app.config.from_object('config.DevelopmentConfig')
        
    CORS(app)
    db.init_app(app)
    migrate.init_app(app, db)
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    jwt.init_app(app)
    
    limiter.init_app(app)
    
    from routes.auth import auth_bp
    from routes.oauth import oauth_bp
    from routes.users import users_bp   
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(oauth_bp, url_prefix='/oauth')
    app.register_blueprint(users_bp, url_prefix='/users')
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify(error=str(e)), 404
    
    @app.errorhandler(500)
    def server_error(e):
        return jsonify(error=str(e)), 500
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug = True, host = '0.0.0.0')
    