from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    mfa_secret = db.Column(db.String(32))
    is_mfa_enabled = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<User {self.username}>'