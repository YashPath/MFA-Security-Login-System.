# 🛡️ Multi-Factor Authentication (MFA) Security System

This is a comprehensive security project developed for a University Security Audit. It demonstrates a robust authentication flow using Python, Flask, and Industry-standard security protocols.

## 👥 Team Roles (4-Man Team)
* **Lead Developer:** Backend architecture & API routing.
* **Security Engineer:** MFA logic (TOTP) & Password Hashing.
* **UI/UX Designer:** Front-end dashboard & QR integration.
* **Security Auditor:** Penetration testing & Audit logging.

## 🚀 Key Security Features
1. **Adaptive Password Hashing:** Uses `Bcrypt` to protect against Rainbow Table attacks.
2. **Multi-Factor Authentication:** Time-based One-Time Passwords (TOTP) compatible with Google Authenticator.
3. **Brute Force Protection:** Automatic account lockout after 3 failed login attempts.
4. **Credential Entropy:** Enforced password complexity (Uppercase, Numbers, 8+ characters).
5. **Audit Logging:** Real-time tracking of security events in `security_audit.log`.

## 🛠️ Installation & Setup
1. **Clone the repo:**
   `git clone https://github.com/YOUR_USERNAME/MFA-Security-System.git`
2. **Install dependencies:**
   `pip install -r requirements.txt`
3. **Setup Environment:**
   Create a `.env` file and add:
   `SECRET_KEY=your_random_secret`
   `DATABASE_URL=sqlite:///database.db`
4. **Run Application:**
   `python app.py`