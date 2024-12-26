from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import pymysql
import logging

# Initializing Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate RSA keys
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# connecting to DB
db = pymysql.connect(
    host="localhost",
    user="root",
    password="root",
    database="vault_db",
    cursorclass=pymysql.cursors.DictCursor
)


def encrypt_binary_data(data):
    """
    Encrypts binary data using RSA public key.
    """
    try:
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher.encrypt(data)
        return base64.b64encode(encrypted_data).decode()  # Return as base64 encoded string
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise

# Decrypt function for binary data
def decrypt_binary_data(encrypted_data):
    """
    Decrypts encrypted binary data using RSA private key.
    """
    try:
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
        return decrypted_data
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

# Encrypt and save to database
@app.route('/encrypt', methods=['POST'])
def encrypt_and_save():
    """
    Encrypts file data and saves it to the database.
    """
    try:
        if 'file' not in request.files or 'category' not in request.form:
            return jsonify({'error': 'Invalid request. File and category are required.'}), 400

        uploaded_file = request.files['file']
        category = request.form['category']
        file_name = uploaded_file.filename

        # Read file data as binary
        file_data = uploaded_file.read()

        # Encrypt file data
        encrypted_data = encrypt_binary_data(file_data)

        # Saving to database
        with db.cursor() as cursor:
            query = """
            INSERT INTO files (name, category, encrypted_data) 
            VALUES (%s, %s, %s)
            """
            cursor.execute(query, (file_name, category, encrypted_data))
            db.commit()

        logging.info(f"File '{file_name}' encrypted and saved under category '{category}'.")
        return jsonify({'message': 'File encrypted and saved successfully!'})

    except Exception as e:
        logging.error(f"Error encrypting file: {e}")
        return jsonify({'error': 'Failed to encrypt and save file.', 'details': str(e)}), 500

# Decrypt and retrieve from database
@app.route('/decrypt', methods=['POST'])
def decrypt_and_retrieve():
    """
    Decrypts file data from the database.
    """
    try:
        file_id = request.json.get('file_id')
        if not file_id:
            return jsonify({'error': 'Invalid request. File ID is required.'}), 400

        # Retrieve encrypted data from the database
        with db.cursor() as cursor:
            query = "SELECT name, encrypted_data FROM files WHERE id = %s"
            cursor.execute(query, (file_id,))
            result = cursor.fetchone()

            if not result:
                return jsonify({'error': 'File not found.'}), 404

            file_name = result['name']
            encrypted_data = result['encrypted_data']

            # Decrypt the file data
            decrypted_data = decrypt_binary_data(encrypted_data)

        # Return the decrypted file data as a response
        response = jsonify({'file_name': file_name, 'decrypted_data': base64.b64encode(decrypted_data).decode()})
        response.headers['Content-Disposition'] = f'attachment; filename={file_name}'
        return response

    except Exception as e:
        logging.error(f"Error decrypting file: {e}")
        return jsonify({'error': 'Failed to decrypt file.', 'details': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
