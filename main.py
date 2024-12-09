
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib.parse import urlparse
from argon2 import PasswordHasher
from uuid import uuid4
import sqlite3
import base64
import json
import jwt
import datetime
import os
import time

hostName = "localhost"
serverPort = 8080

NOT_MY_KEY = os.getenv('NOT_MY_KEY', 'default_key')  # Replace 'default_key' in production
ph = PasswordHasher()

# Database setup
db = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
cursor = db.cursor()

# Create necessary tables
cursor.execute('''
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_name TEXT UNIQUE NOT NULL,
    encrypted_key TEXT NOT NULL,
    iv TEXT NOT NULL
)
''')

db.commit()

# AES Helper Functions
def pad_key(key, length=32):
    if len(key) > length:
        return key[:length]
    return key.ljust(length, '0')

def aes_encrypt(key, plaintext):
    key = pad_key(key, 32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

def aes_decrypt(key, iv, ciphertext):
    key = pad_key(key, 32)
    iv = base64.b64decode(iv)
    ciphertext = base64.b64decode(ciphertext)
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Encrypt and store the private key during initialization
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
iv, encrypted_key = aes_encrypt(NOT_MY_KEY, private_key_pem.decode())

print("Inserting private key into the database...")
cursor.execute('''
    INSERT INTO keys (key_name, encrypted_key, iv)
    VALUES (?, ?, ?)
    ON CONFLICT(key_name) DO UPDATE SET
        encrypted_key=excluded.encrypted_key,
        iv=excluded.iv
''', ("default", encrypted_key, iv))
db.commit()

# Validate the insertion by checking the `id` column
cursor.execute('SELECT id, key_name FROM keys WHERE key_name=?', ("default",))
result = cursor.fetchone()
if not result or not result[0]:
    raise ValueError("Key ID is missing or not properly inserted.")
else:
    print(f"Key successfully stored with ID: {result[0]} and Key Name: {result[1]}")

# Rate limiting setup
request_counters = {}

def rate_limit(client_ip, max_requests=10, window_seconds=1):
    current_time = time.time()
    if client_ip not in request_counters:
        request_counters[client_ip] = []
    request_counters[client_ip] = [
        t for t in request_counters[client_ip] if t > current_time - window_seconds
    ]
    if len(request_counters[client_ip]) >= max_requests:
        return False
    request_counters[client_ip].append(current_time)
    return True

# HTTP Server
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = json.loads(post_data)

        if parsed_path.path == "/register":
            self.handle_register(data)
        elif parsed_path.path == "/auth":
            self.handle_auth(data)
        else:
            self.send_response(405)
            self.end_headers()

    def handle_register(self, data):
        try:
            username = data["username"]
            email = data["email"]
            password = str(uuid4())  # Generate random password
            password_hash = ph.hash(password)  # Hash the password

            cursor.execute('''
                INSERT INTO users (username, password_hash, email)
                VALUES (?, ?, ?)
            ''', (username, password_hash, email))
            db.commit()

            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"password": password}).encode())
        except sqlite3.IntegrityError:
            self.send_response(409)  # Conflict
            self.end_headers()
        except Exception:
            self.send_response(500)  # Internal Server Error
            self.end_headers()

    def handle_auth(self, data):
        try:
            client_ip = self.client_address[0]
            if not rate_limit(client_ip):
                self.send_response(429)  # Too Many Requests
                self.end_headers()
                return

            username = data["username"]
            password = data["password"]

            cursor.execute('''
                SELECT id, password_hash FROM users WHERE username=?
            ''', (username,))
            user = cursor.fetchone()

            if user and ph.verify(user[1], password):
                token_payload = {
                    "user": username,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }
                token = jwt.encode(token_payload, NOT_MY_KEY, algorithm="HS256")
                
                cursor.execute('''
                    INSERT INTO auth_logs (request_ip, user_id)
                    VALUES (?, ?)
                ''', (client_ip, user[0]))
                db.commit()

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"token": token}).encode())
            else:
                self.send_response(401)  # Unauthorized
                self.end_headers()
        except Exception:
            self.send_response(500)
            self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        db.close()
        webServer.server_close()
