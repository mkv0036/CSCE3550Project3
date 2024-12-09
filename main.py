"""Module for handling JWT authentication and key management."""
import os
import base64
import json
import datetime
import sqlite3
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from time import time
from collections import defaultdict
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import jwt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from database import create_tables
from argon2 import PasswordHasher

HOST_NAME = "localhost"
SERVER_PORT = 8080

ph = PasswordHasher()

# Create users table and auth_logs table
create_tables()

# Get encryption key from environment variable
encryption_key = os.environ.get("NOT_MY_KEY")

# Validate key presence
if not encryption_key:
    raise ValueError("Environment variable NOT_MY_KEY not set")\

# Connection to SQLite database
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

# Drop the table if it exists
cursor.execute('DROP TABLE IF EXISTS keys')

# Create table with correct data types
cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
''')
# Function to encrypt data using AES with padding
def encrypt(data, key):
    iv = os.urandom(16) # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')

# Function to decrypt data using AES with padding
def decrypt_data(data, key):
    decoded_data = base64.urlsafe_b64decode(data)
    iv = decoded_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_plain_text = decryptor.update(decoded_data[16:]) + decryptor.finalize()
    plain_text = unpadder.update(padded_plain_text) + decryptor.finalize()
    return plain_text

# Generate private keys
def generate_private_key(encryption_key):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Encrypt the private key with AES
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_key = encrypt(private_key_bytes, encryption_key)
    return encrypted_key

# Generate and encrypt private keys
expired_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
encrypted_private_key = generate_private_key(encryption_key.encode('utf-8'))
encrypted_expired_private_key = generate_private_key(encryption_key.encode('utf-8'))

# Set expiration times
current_time = datetime.datetime.now(datetime.timezone.utc)
one_hour_later = current_time + datetime.timedelta(hours=1)

# Insert keys into database with expiration times
try:
    cursor.execute(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        (encrypted_expired_private_key, int(current_time.timestamp()))  # Expired
    )
    cursor.execute(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        (encrypted_private_key, int(one_hour_later.timestamp()))  # Valid
    )
except Exception as e:
    pass

# Commit changes and close connection
conn.commit()
conn.close()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    """HTTP Server for handling authentication requests."""
    # Rate limiter settings
    rate_limit = 10 # Max requests per second
    request_counts = defaultdict(list)

    # Function to log authentication request
    def log_auth_request(cursor, request_ip, request_timestamp, user_id, success):
        cursor.execute(
            'INSERT INTO auth_logs (request_ip, request_timestamp, user_id, success) VALUES (?, ?, ?, ?)',
            (request_ip, request_timestamp, user_id, success)
        )

    # Function to check the rate limit
    def check_rate_limit(self, client_ip):
        current_time = time()
        self.request_counts[client_ip] = [timestamp for timestamp in self.request_counts[client_ip] if current_time - timestamp < 1]

        if len(self.request_counts[client_ip]) >= self.rate_limit:
            return False

        self.request_counts[client_ip].append(current_time)
        return True

    def do_PUT(self):
        """Handles PUT requests."""
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        """Handles PATCH requests."""
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        """Handles DELETE requests."""
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        """Handles HEAD requests."""
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        """Handles POST requests."""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        current_time = datetime.datetime.now(datetime.timezone.utc)

        client_ip = self.client_address[0]

        if parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_details = json.loads(post_data)

            username = user_details.get('username')
            email = user_details.get('email')

            if not username or not email:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid input"}).encode('utf-8'))
                return

            # Generate a secure password
            password = str(uuid.uuid4())

            # Hash the password using Argon2
            hashed_password = ph.hash(password)

            # Store user details in the database
            try:
                with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                        (username, email, hashed_password)
                    )
                    conn.commit()
            except sqlite3.IntegrityError as e:
                self.send_response(409)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "User with this username or email already exists"}).encode('utf-8'))
                return

            # Return the password to the user
            self.send_response(201)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"password": password}).encode('utf-8'))

        elif parsed_path.path == "/auth":
            if not self.check_rate_limit(client_ip):
                self.send_response(429)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Rate limit exceeded"}).encode('utf-8'))
                return
            # Connect to the database
            try:
                with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
                    cursor = conn.cursor()
                    # Fetch the correct key based on expiration status
                    if 'expired' in params:
                        cursor.execute(
                            'SELECT key FROM keys WHERE exp <= ? ORDER BY exp LIMIT 1',
                            (int(current_time.timestamp()),)
                        )
                    else:
                        cursor.execute(
                            'SELECT key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1',
                            (int(current_time.timestamp()),)
                        )
                    key_row = cursor.fetchone()
                    if key_row:
                        key_pem = key_row[0]
                        try:
                            key = serialization.load_pem_private_key(key_pem, password=None)
                        except (ValueError, TypeError):
                            self.send_response(500)
                            self.send_header("Content-type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "No valid key found"}')
                            return
                        headers = {
                            "kid": "goodKID"
                        }
                        token_payload = {
                            "user": "username",
                            "exp": int((current_time + datetime.timedelta(hours=1)).timestamp())
                        }
                        if 'expired' in params:
                            headers["kid"] = "expiredKID"
                            token_payload["exp"] = int(
                                (current_time - datetime.timedelta(hours=1)).timestamp())

                        try:
                            encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)
                        except Exception as e:
                            self.send_response(500)
                            self.send_header("Content-type", "application/json")
                            self.end_headers()
                            self.wfile.write(json.dumps({"error": f"JWT encoding failed: {str(e)}"}).encode('utf-8'))
                            return
                        # Log the successful request
                        self.log_auth_request(cursor, self.client_address[0], current_time, user_id=None, success=True)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(bytes(json.dumps({'token': encoded_jwt}), "utf-8"))
                    else:
                        self.send_response(500)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "No valid key found"}).encode('utf-8'))
            except sqlite3.OperationalError as e:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Database connection failed: {str(e)}"}).encode('utf-8'))
        else:
            self.send_response(405)
            self.end_headers()


    def do_GET(self):
        """Handles GET requests"""
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return
        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
