from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import secrets
import string
from functools import wraps
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "gibd.lab@gmail.com"
SENDER_PASSWORD = "jkrp shng hzsv uzow"
SUPPORT_EMAIL = "ali6011201@gmail.com"

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        country TEXT,
        phone_number TEXT,
        occupation TEXT,
        role TEXT DEFAULT 'user',
        is_admin INTEGER DEFAULT 0,
        is_verified INTEGER DEFAULT 0,
        verification_token TEXT,
        password_reset_token TEXT,
        password_reset_expires TIMESTAMP,
        remaining_credit REAL DEFAULT 50.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # API Keys table
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        llm_model TEXT NOT NULL,
        used_tokens INTEGER NOT NULL,
        cost REAL DEFAULT 0.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS support_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        reply TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        replied_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Create default admin if not exists
    c.execute("SELECT * FROM users WHERE email = 'admin@gibd.com'")
    if not c.fetchone():
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute('''INSERT INTO users (email, password, first_name, last_name, role, is_admin, is_verified)
                     VALUES (?, ?, ?, ?, ?, 1, 1)''',
                  ('admin@gibd.com', admin_password, 'Admin', 'User', 'admin'))
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN remaining_credit REAL DEFAULT 50.0")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN occupation TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN password_reset_token TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN password_reset_expires TIMESTAMP")
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        conn = get_db()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def send_verification_email(email, token, first_name):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Verify Your Email - GIBD Services"
    msg["From"] = f"GIBD Services <{SENDER_EMAIL}>"
    msg["To"] = email
    
    verification_link = f"http://localhost:5000/verify/{token}"
    
    text = f"""\
Hello {first_name},

Thank you for registering with GIBD Services!

Please verify your email address by clicking the link below:
{verification_link}

This link will expire in 24 hours.

If you did not create this account, please ignore this email.

Best regards,
GIBD Services Team
"""
    
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
      <h2 style="color: #4CAF50;">Welcome to GIBD Services!</h2>
      <p>Hello <strong>{first_name}</strong>,</p>
      <p>Thank you for registering with GIBD Services. We're excited to have you on board!</p>
      <p>Please verify your email address by clicking the button below:</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="{verification_link}" 
           style="background-color: #4CAF50; color: white; padding: 12px 30px; 
                  text-decoration: none; border-radius: 5px; display: inline-block;">
          Verify Email Address
        </a>
      </div>
      <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
      <p style="color: #666; font-size: 12px; word-break: break-all;">{verification_link}</p>
      <p style="color: #999; font-size: 12px; margin-top: 30px;">
        This link will expire in 24 hours. If you did not create this account, please ignore this email.
      </p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
      <p style="color: #999; font-size: 12px;">
        This is an automated message, please do not reply to this email.
      </p>
    </div>
  </body>
</html>
"""
    
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, email, msg.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_password_reset_email(email, token, first_name):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Reset Your Password - GIBD Services"
    msg["From"] = f"GIBD Services <{SENDER_EMAIL}>"
    msg["To"] = email
    
    reset_link = f"http://localhost:5000/reset-password/{token}"
    
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
      <h2 style="color: #667eea;">Password Reset Request</h2>
      <p>Hello <strong>{first_name}</strong>,</p>
      <p>We received a request to reset your password for your GIBD Services account.</p>
      <p>Click the button below to reset your password:</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="{reset_link}" 
           style="background-color: #667eea; color: white; padding: 12px 30px; 
                  text-decoration: none; border-radius: 5px; display: inline-block;">
          Reset Password
        </a>
      </div>
      <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
      <p style="color: #666; font-size: 12px; word-break: break-all;">{reset_link}</p>
      <p style="color: #999; font-size: 12px; margin-top: 30px;">
        This link will expire in 1 hour. If you did not request a password reset, please ignore this email.
      </p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
      <p style="color: #999; font-size: 12px;">
        This is an automated message, please do not reply to this email.
      </p>
    </div>
  </body>
</html>
"""
    
    msg.attach(MIMEText(html, "html"))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, email, msg.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_support_notification(user_email, user_name, message):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "New Support Message - GIBD Authenticator"
    msg["From"] = f"GIBD Services <{SENDER_EMAIL}>"
    msg["To"] = SUPPORT_EMAIL
    
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
      <h2 style="color: #667eea;">New Support Message from GIBD Authenticator</h2>
      <p><strong>From:</strong> {user_name} ({user_email})</p>
      <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p style="margin: 0;"><strong>Message:</strong></p>
        <p style="margin: 10px 0 0 0;">{message}</p>
      </div>
      <p style="color: #666; font-size: 14px;">Please log in to the admin dashboard to reply to this message.</p>
    </div>
  </body>
</html>
"""
    
    msg.attach(MIMEText(html, "html"))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, SUPPORT_EMAIL, msg.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_reply_notification(email, first_name):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "New Reply to Your Support Message - GIBD Services"
    msg["From"] = f"GIBD Services <{SENDER_EMAIL}>"
    msg["To"] = email
    
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
      <h2 style="color: #4CAF50;">You Have a New Message!</h2>
      <p>Hello <strong>{first_name}</strong>,</p>
      <p>You have received a new reply to your support message from the GIBD Services team.</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="http://localhost:5000/login" 
           style="background-color: #4CAF50; color: white; padding: 12px 30px; 
                  text-decoration: none; border-radius: 5px; display: inline-block;">
          View Message
        </a>
      </div>
      <p style="color: #666; font-size: 14px;">Please log in to your account to view the full message.</p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
      <p style="color: #999; font-size: 12px;">
        This is an automated message from no-reply@gibd.lab. Please do not reply to this email.
      </p>
    </div>
  </body>
</html>
"""
    
    msg.attach(MIMEText(html, "html"))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, email, msg.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def generate_api_key():
    chars = string.ascii_letters + string.digits
    random_part = ''.join(secrets.choice(chars) for _ in range(12))
    return f"gibd-services-{random_part}"

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        country = request.form.get('country', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        occupation = request.form.get('occupation', '').strip()
        
        # Validation
        if not all([email, password, first_name, last_name]):
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html', 
                                 email=email, first_name=first_name, last_name=last_name,
                                 country=country, phone_number=phone_number, occupation=occupation)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html', 
                                 email=email, first_name=first_name, last_name=last_name,
                                 country=country, phone_number=phone_number, occupation=occupation)
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html', 
                                 email=email, first_name=first_name, last_name=last_name,
                                 country=country, phone_number=phone_number, occupation=occupation)
        
        conn = get_db()
        
        # Check if email already exists
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            conn.close()
            flash('Email already exists.', 'error')
            return render_template('register.html', 
                                 email=email, first_name=first_name, last_name=last_name,
                                 country=country, phone_number=phone_number, occupation=occupation)
        
        # Hash password and generate verification token
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        verification_token = secrets.token_urlsafe(32)
        
        try:
            # Insert user
            conn.execute('''INSERT INTO users 
                           (email, password, first_name, last_name, country, phone_number, occupation, verification_token)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                        (email, hashed_password, first_name, last_name, country, phone_number, occupation, verification_token))
            conn.commit()
            
            # Send verification email
            if send_verification_email(email, verification_token, first_name):
                flash('Registration successful! Please check your email to verify your account.', 'success')
                conn.close()
                return redirect(url_for('login'))
            else:
                flash('Registration successful, but we could not send the verification email. Please contact support.', 'warning')
                conn.close()
                return redirect(url_for('login'))
        except Exception as e:
            conn.close()
            flash(f'An error occurred during registration: {str(e)}', 'error')
            return render_template('register.html', 
                                 email=email, first_name=first_name, last_name=last_name,
                                 country=country, phone_number=phone_number, occupation=occupation)
    
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE verification_token = ?', (token,)).fetchone()
    
    if not user:
        conn.close()
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('login'))
    
    if user['is_verified']:
        conn.close()
        flash('Email already verified. Please log in.', 'info')
        return redirect(url_for('login'))
    
    # Verify the user
    conn.execute('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?', (user['id'],))
    conn.commit()
    conn.close()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('login.html')
        
        conn = get_db()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND password = ?', 
                           (email, hashed_password)).fetchone()
        conn.close()
        
        if not user:
            flash('Invalid email or password.', 'error')
            return render_template('login.html')
        
        if not user['is_verified']:
            flash('Please verify your email address before logging in.', 'warning')
            return render_template('login.html')
        
        # Set session
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['is_admin'] = user['is_admin']
        session.permanent = True
        
        flash(f'Welcome back, {user["first_name"]}!', 'success')
        
        # Redirect to admin dashboard if admin
        if user['is_admin']:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            expires = datetime.now() + timedelta(hours=1)
            
            conn.execute('UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?',
                        (reset_token, expires, user['id']))
            conn.commit()
            
            # Send reset email
            send_password_reset_email(email, reset_token, user['first_name'])
        
        conn.close()
        
        # Always show success message to prevent email enumeration
        flash('If that email exists in our system, you will receive a password reset link shortly.', 'success')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE password_reset_token = ?', (token,)).fetchone()
    
    if not user or not user['password_reset_expires']:
        conn.close()
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('login'))
    
    # Check if token is expired
    expires = datetime.strptime(user['password_reset_expires'], '%Y-%m-%d %H:%M:%S.%f')
    if datetime.now() > expires:
        conn.close()
        flash('This reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        conn.execute('UPDATE users SET password = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?',
                    (hashed_password, user['id']))
        conn.commit()
        conn.close()
        
        flash('Password reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    api_keys = conn.execute('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC', 
                           (session['user_id'],)).fetchall()
    
    # Get total tokens used
    total_tokens = conn.execute('''
        SELECT SUM(used_tokens) as total FROM usage WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()['total'] or 0
    
    usage_stats = conn.execute('''
        SELECT llm_model, 
               SUM(used_tokens) as total_tokens, 
               SUM(cost) as total_cost,
               COUNT(*) as request_count
        FROM usage 
        WHERE user_id = ? 
        GROUP BY llm_model
        ORDER BY total_tokens DESC
    ''', (session['user_id'],)).fetchall()
    
    total_spent = conn.execute('''
        SELECT SUM(cost) as total FROM usage WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()['total'] or 0.0
    
    # Get usage data for chart (last 30 days)
    usage_chart_data = conn.execute('''
        SELECT DATE(created_at) as date, SUM(used_tokens) as tokens
        FROM usage
        WHERE user_id = ? AND created_at >= date('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    ''', (session['user_id'],)).fetchall()
    
    # Get support messages
    support_messages = conn.execute('''
        SELECT * FROM support_messages 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, api_keys=api_keys, 
                         usage_stats=usage_stats, total_spent=total_spent,
                         total_tokens=total_tokens, usage_chart_data=usage_chart_data,
                         support_messages=support_messages)

@app.route('/generate-key', methods=['POST'])
@login_required
def generate_key():
    conn = get_db()
    
    # Check if user is verified
    user = conn.execute('SELECT is_verified FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user['is_verified']:
        conn.close()
        return jsonify({'success': False, 'message': 'Please verify your email address before generating API keys.'}), 403
    
    # Check if user already has an API key
    existing_key = conn.execute('SELECT * FROM api_keys WHERE user_id = ?', (session['user_id'],)).fetchone()
    
    # If user has existing key, delete it
    if existing_key:
        conn.execute('DELETE FROM api_keys WHERE user_id = ?', (session['user_id'],))
    
    # Generate unique API key
    max_attempts = 10
    for _ in range(max_attempts):
        api_key = generate_api_key()
        existing = conn.execute('SELECT * FROM api_keys WHERE api_key = ?', (api_key,)).fetchone()
        if not existing:
            break
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to generate unique API key. Please try again.'}), 500
    
    # Insert API key
    try:
        conn.execute('INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)', 
                    (session['user_id'], api_key))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'API key generated successfully!', 'api_key': api_key}), 200
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Error generating API key: {str(e)}'}), 500

@app.route('/send-support-message', methods=['POST'])
@login_required
def send_support_message():
    message = request.form.get('message', '').strip()
    
    if not message:
        flash('Please enter a message.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Insert support message
    conn.execute('''INSERT INTO support_messages (user_id, message)
                   VALUES (?, ?)''', (session['user_id'], message))
    conn.commit()
    conn.close()
    
    # Send notification email
    user_name = f"{user['first_name']} {user['last_name']}"
    send_support_notification(user['email'], user_name, message)
    
    flash('Your message has been sent to support. We will respond shortly.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    
    # Get all users with their API key counts
    users = conn.execute('''
        SELECT u.*, 
               COUNT(DISTINCT a.id) as api_key_count
        FROM users u
        LEFT JOIN api_keys a ON u.id = a.user_id
        WHERE u.is_admin = 0
        GROUP BY u.id
        ORDER BY u.created_at DESC
    ''').fetchall()
    
    # Get statistics
    total_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_admin = 0').fetchone()['count']
    verified_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_admin = 0 AND is_verified = 1').fetchone()['count']
    total_api_keys = conn.execute('SELECT COUNT(*) as count FROM api_keys').fetchone()['count']
    
    # Get pending support messages
    support_messages = conn.execute('''
        SELECT sm.*, u.first_name, u.last_name, u.email
        FROM support_messages sm
        JOIN users u ON sm.user_id = u.id
        ORDER BY sm.created_at DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         total_users=total_users,
                         verified_users=verified_users,
                         total_api_keys=total_api_keys,
                         support_messages=support_messages)

@app.route('/admin/reply-support/<int:message_id>', methods=['POST'])
@admin_required
def reply_support(message_id):
    reply = request.form.get('reply', '').strip()
    
    if not reply:
        flash('Please enter a reply.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db()
    
    # Get message and user info
    message = conn.execute('''
        SELECT sm.*, u.email, u.first_name
        FROM support_messages sm
        JOIN users u ON sm.user_id = u.id
        WHERE sm.id = ?
    ''', (message_id,)).fetchone()
    
    if not message:
        conn.close()
        flash('Message not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Update message with reply
    conn.execute('''UPDATE support_messages 
                   SET reply = ?, status = 'replied', replied_at = CURRENT_TIMESTAMP
                   WHERE id = ?''', (reply, message_id))
    conn.commit()
    conn.close()
    
    # Send notification email to user
    send_reply_notification(message['email'], message['first_name'])
    
    flash('Reply sent successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>')
@admin_required
def view_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    api_keys = conn.execute('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC', 
                           (user_id,)).fetchall()
    
    # Get usage data for chart
    usage_chart_data = conn.execute('''
        SELECT DATE(created_at) as date, SUM(used_tokens) as tokens
        FROM usage
        WHERE user_id = ? AND created_at >= date('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    ''', (user_id,)).fetchall()
    
    conn.close()
    
    return render_template('view_user.html', user=user, api_keys=api_keys, usage_chart_data=usage_chart_data)

@app.route('/admin/update-role/<int:user_id>', methods=['POST'])
@admin_required
def update_user_role(user_id):
    is_developer = request.form.get('is_developer') == 'on'
    
    conn = get_db()
    role = 'developer' if is_developer else 'user'
    conn.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    conn.commit()
    conn.close()
    
    flash('User role updated successfully!', 'success')
    return redirect(url_for('view_user', user_id=user_id))

# API endpoint to update token usage
@app.route('/api/update-usage', methods=['POST'])
def api_update_usage():
    """
    API endpoint to update user token usage
    Expected JSON payload:
    {
        "api_key": "gibd-services-xxxxxxxxxxxx",
        "tokens": 10,
        "llm_model": "OpenAI-GPT-4o",
        "cost": 0.05  (optional)
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        api_key = data.get('api_key')
        tokens = data.get('tokens')
        llm_model = data.get('llm_model')
        cost = data.get('cost', 0.0)
        
        # Validate required fields
        if not api_key or tokens is None or not llm_model:
            return jsonify({"error": "Missing required fields: api_key, tokens, llm_model"}), 400
        
        # Validate tokens is a positive number
        try:
            tokens = int(tokens)
            if tokens <= 0:
                return jsonify({"error": "Tokens must be a positive number"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid tokens value"}), 400
        
        # Validate cost is a number
        try:
            cost = float(cost)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid cost value"}), 400
        
        conn = get_db()
        
        # Find user by API key
        api_key_record = conn.execute('SELECT user_id FROM api_keys WHERE api_key = ?', (api_key,)).fetchone()
        
        if not api_key_record:
            conn.close()
            return jsonify({"error": "Invalid API key"}), 401
        
        user_id = api_key_record['user_id']
        
        # Insert usage record with timestamp
        conn.execute('''INSERT INTO usage (user_id, llm_model, used_tokens, cost, created_at)
                       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                    (user_id, llm_model, tokens, cost))
        
        # Update remaining credit
        conn.execute('UPDATE users SET remaining_credit = remaining_credit - ? WHERE id = ?',
                    (cost, user_id))
        
        conn.commit()
        
        # Get updated credit
        user = conn.execute('SELECT remaining_credit FROM users WHERE id = ?', (user_id,)).fetchone()
        remaining_credit = user['remaining_credit']
        
        # Get cumulative tokens for this model
        cumulative = conn.execute('''SELECT SUM(used_tokens) as total FROM usage 
                                    WHERE user_id = ? AND llm_model = ?''',
                                 (user_id, llm_model)).fetchone()
        cumulative_tokens = cumulative['total'] or 0
        
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Usage updated successfully",
            "remaining_credit": round(remaining_credit, 2),
            "cumulative_tokens": cumulative_tokens,
            "llm_model": llm_model
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# API endpoint to check user credit
@app.route('/api/check-credit', methods=['POST'])
def api_check_credit():
    """
    API endpoint to check if user is authorized and has credit
    Expected JSON payload:
    {
        "api_key": "gibd-services-xxxxxxxxxxxx"
    }
    Response:
    {
        "user_authorized": "Yes" or "No",
        "credit": "Yes" or "No",
        "remaining_credit": 45.50 (if authorized)
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        api_key = data.get('api_key')
        
        if not api_key:
            return jsonify({
                "user_authorized": "No",
                "credit": "No"
            }), 200
        
        conn = get_db()
        
        # Find user by API key
        result = conn.execute('''
            SELECT u.id, u.remaining_credit, u.is_verified
            FROM users u
            JOIN api_keys a ON u.id = a.user_id
            WHERE a.api_key = ?
        ''', (api_key,)).fetchone()
        
        conn.close()
        
        if not result:
            return jsonify({
                "user_authorized": "No",
                "credit": "No"
            }), 200
        
        # Check if user is verified
        if not result['is_verified']:
            return jsonify({
                "user_authorized": "No",
                "credit": "No",
                "message": "Email not verified"
            }), 200
        
        # Check if user has credit
        has_credit = result['remaining_credit'] > 0
        
        return jsonify({
            "user_authorized": "Yes",
            "credit": "Yes" if has_credit else "No",
            "remaining_credit": round(result['remaining_credit'], 2)
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
