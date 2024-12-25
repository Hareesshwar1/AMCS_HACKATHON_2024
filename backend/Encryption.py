from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS for handling cross-origin requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS to allow requests from the frontend

# Generate RSA keys
private_key = RSA.generate(2048)  # Private key used for decryption
public_key = private_key.publickey()  # Public key used for encryption

# Function to encrypt data using RSA public key
def encrypt_the_mysteries(data):
    """
    Encrypts plaintext data using RSA public key.
    The function wraps the data in a shroud of mathematical secrecy.
    """
    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(data.encode())).decode()

# Function to decrypt data using RSA private key
def decrypt_the_enigma(encrypted_data):
    """
    Decrypts encrypted data using RSA private key.
    This function deciphers the once-hidden truth of the data.
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(encrypted_data)).decode()

# Endpoint for encrypting data
@app.route('/encrypt', methods=['POST'])
def handle_secret_wrapping():
    """
    Handles incoming requests to encrypt data.
    Transforms plaintext into an encoded enigma and returns it.
    """
    try:
        data = request.json['data']  # Extract 'data' field from the JSON request
        encrypted = encrypt_the_mysteries(data)  # Encrypt the data
        return jsonify({'encrypted_data': encrypted})  # Return encrypted data
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Endpoint for decrypting data
@app.route('/decrypt', methods=['POST'])
def handle_truth_unveiling():
    """
    Handles incoming requests to decrypt data.
    Transforms an encrypted enigma back into readable plaintext.
    """
    try:
        encrypted_data = request.json['encrypted_data']  # Extract 'encrypted_data' field
        decrypted = decrypt_the_enigma(encrypted_data)  # Decrypt the data
        return jsonify({'decrypted_data': decrypted})  # Return decrypted data
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
