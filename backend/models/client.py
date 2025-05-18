from backend import db
from datetime import datetime
import uuid
import secrets
import json

class Client(db.Model):
    """
    OAuth Client model representing third-party applications
    that can request access to user resources
    """
    __tablename__ = 'oauth_clients'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(80), unique=True, nullable=False, default = lambda: str(uuid.uuid4()))
    client_secret = db.Column(db.String(120), nullable=False, default = lambda: secrets.token_urlsafe(32))
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text)
    _redirect_uri = db.Column(db.String(255), nullable=False)
    
    