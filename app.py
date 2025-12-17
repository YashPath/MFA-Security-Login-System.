import os
import io
import re
import base64
import pyotp
import qrcode
import bcrypt
from flask import Flask, render_template, request, redirect, url_for
from models import db, User
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError

load_dotenv()

app = Flask(__name__)

# Basic Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Database creation
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # NLP/Regex based Password Validation
        if len(password) < 8 or not re.search("[0-9]", password) or not re.search("[A-Z]", password):
            return "<h2>Weak Password</h2><p>Use 8+ chars, 1 number, 1 uppercase.</p><a href='/signup'>Try Again</a>"

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        mfa_secret = pyotp.random_base32()
        new_user = User(username=username, password=hashed_pw, mfa_secret=mfa_secret)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name="SecureAuth")
            img = qrcode.make(totp_uri)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            
            return f"<h2>Registration Successful!</h2><img src='data:image/png;base64,{qr_base64}'><br><p>Secret Key: {mfa_secret}</p><a href='/login'>Proceed to Login</a>"
        except IntegrityError:
            db.session.rollback()
            return "<h2>Username Already Exists</h2><a href='/signup'>Try Again</a>"
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')
        
        user = User.query.filter_by(username=username).first()
        
        # Identity Verification Logic
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(otp):
                # UI/UX Improvement: Rendering a proper dashboard template
                return render_template('dashboard.html', username=username)
            else:
                return "<h2>Invalid MFA Token</h2><a href='/login'>Try Again</a>"
        
        return "<h2>Invalid Credentials</h2><a href='/login'>Try Again</a>"
        
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)