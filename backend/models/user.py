from backend import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

#Creating a Many to Many relationship
user_roles = db.Table('user_roles',
    db.Column('user_id', db.String(36), db.ForeignKey('users.id'),primary_key=True),
    db.Column('role_id', db.String(36), db.ForeignKey('roles.id'),primary_key=True)                     
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key = True, default = lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique = True, nullable = False)
    username = db.Column(db.String(80), unique = True, nullable = False)
    password_hash = db.Column(db.String(200), nullable = False)
    first_name = db.Column(db.String(80), nullable = False)
    last_name = db.Column(db.String(80), nullable = False)
    is_active = db.Column(db.Boolean, default = True)
    email_verified = db.Column(db.Boolean, default = False)
    mfa_enabled = db.Column(db.Boolean, default = False)
    mfa_secret = db.Column(db.String(80), nullable = True)
    created_at = db.Column(db.DateTime, default = datetime.utcnow)
    updated_at = db.Column(db.DateTime, default = datetime.utcnow, onupdate = datetime.utcnow)
    
    roles = db.relationship('Role', secondary = user_roles, backref = db.backref('users', lazy = 'dynamic'))
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission_name):
        for role in self.roles:
            for permission in role.permissions:
                if permission.name == permission_name:
                    return True
            
        return False
    
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'email_verified': self.email_verified,
            'mfa_enabled': self.mfa_enabled,
            'roles': [role.name for role in self.roles],
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }