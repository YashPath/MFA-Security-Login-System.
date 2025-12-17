import os
import io
import re
import base64
import pyotp
import qrcode
import bcrypt
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
from models import db, User
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError

load_dotenv()

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Database
db.init_app(app)

with app.app_context():
    db.create_all()
    print("Security System Initialized...")

# Audit Logging Function
def log_event(message):
    with open("security_audit.log", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Security: Password Strength Validation
        if len(password) < 8 or not re.search("[0-9]", password) or not re.search("[A-Z]", password):
            log_event(f"Failed registration attempt (Weak Password): {username}")
            return "<h2>Registration Failed</h2><p>Password must be 8+ characters, include a number and an uppercase letter.</p><a href='/signup'>Try again</a>"

        # Security: Password Hashing
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Security: MFA Secret Generation
        mfa_secret = pyotp.random_base32()
        new_user = User(username=username, password=hashed_pw, mfa_secret=mfa_secret)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            log_event(f"New user registered: {username}")
            
            # Generate QR Code for Setup
            totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name="SecureAuthSystem")
            img = qrcode.make(totp_uri)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            
            return f"""
                <body style="background-color: #121212; color: white; text-align: center; font-family: sans-serif; padding-top: 50px;">
                    <h2>Registration Successful!</h2>
                    <p>Scan this QR Code in <b>Google Authenticator</b>:</p>
                    <div style="background: white; display: inline-block; padding: 10px; border-radius: 10px;">
                        <img src="data:image/png;base64,{qr_base64}">
                    </div>
                    <br><br>
                    <p>Secret Key: <b>{mfa_secret}</b></p>
                    <p style="color: #ff4444;"><b>Security Warning:</b> This code is shown only once. Save it now.</p>
                    <a href="/login" style="color: #00d4ff;">Proceed to Secure Login</a>
                </body>
            """
        except IntegrityError:
            db.session.rollback()
            return "<h2>Error</h2><p>Username already exists.</p><a href='/signup'>Try again</a>"
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Security: Account Lockout Check
            if user.failed_attempts >= 3:
                log_event(f"Blocked login attempt on locked account: {username}")
                return "<h2>Account Locked</h2><p>Too many failed attempts. Please contact security admin.</p>"

            # Step 1: Password Verification
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                
                # Step 2: MFA Token Verification
                totp = pyotp.totp.TOTP(user.mfa_secret)
                if totp.verify(otp):
                    user.failed_attempts = 0 # Reset attempts on success
                    db.session.commit()
                    log_event(f"Successful MFA login: {username}")
                    return f"<h1>Access Granted!</h1><p>Welcome back, {username}.</p>"
                else:
                    user.failed_attempts += 1
                    db.session.commit()
                    log_event(f"Invalid MFA Token attempt: {username}")
                    return f"<h2>Invalid MFA Token</h2><p>Attempts: {user.failed_attempts}/3</p><a href='/login'>Try again</a>"
            else:
                user.failed_attempts += 1
                db.session.commit()
                log_event(f"Incorrect password attempt: {username}")
                return f"<h2>Incorrect Password</h2><p>Attempts: {user.failed_attempts}/3</p><a href='/login'>Try again</a>"
        
        return "<h2>User Not Found</h2><a href='/signup'>Register here</a>"
        
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)