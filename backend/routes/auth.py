from re import L
from flask import Blueprint, config, request, jsonify, current_app
from sqlalchemy import Identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from models.user import User
from services.auth import verify_mfa
from services.token import add_token_to_blocklist

import uuid
from backend import db, limiter, redis_client

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    if not all(k in data for k in ('email', 'username', 'password')):
        return jsonify({'message': 'Missing required fields'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 409
    
    if User.query.filter_by(username = data['username']).first():
        return jsonify({'message': 'Username already taken'}), 409
    
    user = User(
        email = data['email'],
        username = data['username'],
        first_name = data['first_name',''],
        last_name = data['last_name',''],
    )
    user.password = data['password']
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    if not all(k in data for k in ('email', 'password')):
        return jsonify({'message': 'Missing required fields'}), 400
    
    user = User.query.filter(
        (User.username == data['username']) | (User.email == data['username'])
    ).first()
    
    
    
    if not user or not user.verify_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'message': 'Account is inactive'}), 403
    
    if user.mfa_enabled:
        if 'mfa_code' not in data:
            return jsonify({
                "message": "MFA required",
                "requires_mfa": True,
                # Provide a temporary token for MFA verification
                "mfa_token": create_access_token(
                    identity=user.id,
                    additional_claims={"mfa_required": True},
                    expires_delta=current_app.config.get("MFA_TOKEN_EXPIRES", 300)  # 5 min
                )
            }), 200
            
        if not verify_mfa(user, data['mfa_code']):
            return jsonify({'message': 'Invalid MFA code'}), 401
        
        
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'roles': [role.name for role in user.roles]},
    )
    
    refresh_token = create_refresh_token(
        identity=user.id,
    )
    
    token_id = str(uuid.uuid4())
    redis_client.hset(
        f"user:{user.id}:tokens",
        token_id,
        {
            "refresh_token" : refresh_token,
            "user_agent" : request.headers.get("User-Agent", ""),
            "ip": request.remote_addr
        }
    )
    
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict(),
    }), 200
    
    
@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh = True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity = identity)
    return jsonify({"access_token": access_token}), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    add_token_to_blocklist(jti)
    return jsonify({"message": "Successfully logged out"}), 200

