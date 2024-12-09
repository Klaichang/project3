from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from datetime import datetime, timedelta
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import uuid
from argon2 import PasswordHasher

app = Flask(__name__)
db_file = 'totally_not_my_privateKeys.db'
ph = PasswordHasher()

# Rate limiting setup
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per day", "25 per hour"], headers_enabled=True)
auth_limit = "10 per second"

# Secret key for JWT encoding
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'default_secret_key')

# AES encryption key
NOT_MY_KEY = os.getenv('NOT_MY_KEY', None)
if NOT_MY_KEY is None:
    raise ValueError("Environment variable NOT_MY_KEY is not set.")

# Initialize the database schema
def init_db():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        success INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

# JWT Functions
def generate_jwt_token(user_id):
    """Generate JWT token for a user ID."""
    expiration = datetime.utcnow() + timedelta(hours=1)
    payload = {
        'user_id': user_id,
        'exp': expiration
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Log authentication attempts
def log_auth_request(request_ip, user_id, success):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('INSERT INTO auth_logs (request_ip, user_id, success) VALUES (?, ?, ?)', (request_ip, user_id, success))
    conn.commit()
    conn.close()

# Flask Endpoints
@app.route('/auth', methods=['POST'])
@limiter.limit(auth_limit)
def auth():
    """Authenticate a user and return a JWT token."""
    try:
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password are required."}), 400

        username = data['username']
        password = data['password']
        client_ip = request.remote_addr

        # Fetch user details from the database
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user is None:
            log_auth_request(client_ip, None, success=0)
            return jsonify({"error": "Invalid username."}), 401

        # Verify the password
        try:
            if not ph.verify(user[1], password):
                log_auth_request(client_ip, user[0], success=0)
                return jsonify({"error": "Invalid password."}), 401
        except Exception:
            log_auth_request(client_ip, user[0], success=0)
            return jsonify({"error": "Password verification failed."}), 200

        user_id = user[0]

        # Generate the JWT token
        token = generate_jwt_token(user_id)

        # Log the successful authentication
        log_auth_request(client_ip, user_id, success=1)

        return jsonify({'token': token}), 200
    except Exception as e:
        print(f"Error in /auth endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 200

@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({"error": "Username and email are required."}), 400

    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', (username, password_hash, email))
        conn.commit()
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists."}), 409
    finally:
        conn.close()

# Initialize the database
init_db()

if __name__ == '__main__':
    app.run(debug=True, port=8080)
