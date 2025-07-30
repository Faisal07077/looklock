import os
import cv2
import face_recognition
import pickle
import numpy as np
from flask import Flask, render_template, request, jsonify, session, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import base64
import hashlib
from datetime import datetime
import json
import io   
from flask import Flask, render_template, request, jsonify, session, send_file, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here' 
app.config['UPLOAD_FOLDER'] = 'vault'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

os.makedirs('face_data', exist_ok=True)
os.makedirs('vault', exist_ok=True)
os.makedirs('templates', exist_ok=True)

class SecureFileVault:
    def __init__(self):
        self.face_data_dir = 'face_data'
        self.vault_dir = 'vault'
        self.users_file = 'users.json'
        self.load_users()
    
    def load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}
    
    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def generate_key_from_face(self, face_encoding):
        face_bytes = face_encoding.tobytes()
        hash_object = hashlib.sha256(face_bytes)
        key = base64.urlsafe_b64encode(hash_object.digest())
        return key
    
    def register_user(self, username, face_encoding):
        if username in self.users:
            return False, "User already exists"
        
        face_file = os.path.join(self.face_data_dir, f'{username}.pkl')
        with open(face_file, 'wb') as f:
            pickle.dump(face_encoding, f)
        
        encryption_key = self.generate_key_from_face(face_encoding)
        
        self.users[username] = {
            'face_file': face_file,
            'encryption_key': encryption_key.decode(),
            'created_at': datetime.now().isoformat(),
            'files': []
        }
        
        self.save_users()
        return True, "User registered successfully"
    
    def authenticate_user(self, face_encoding, tolerance=0.6):
        for username, user_data in self.users.items():
            if os.path.exists(user_data['face_file']):
                with open(user_data['face_file'], 'rb') as f:
                    stored_encoding = pickle.load(f)
                
                match = face_recognition.compare_faces([stored_encoding], face_encoding, tolerance=tolerance)
                if match[0]:
                    return True, username
        
        return False, None
    
    def encrypt_file(self, username, file_data, filename):
        if username not in self.users:
            return False, "User not found"
        
        key = self.users[username]['encryption_key'].encode()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(file_data)
        
        encrypted_filename = f"{username}_{secure_filename(filename)}"
        file_path = os.path.join(self.vault_dir, encrypted_filename)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        file_info = {
            'original_name': filename,
            'encrypted_name': encrypted_filename,
            'upload_date': datetime.now().isoformat(),
            'size': len(file_data)
        }
        
        self.users[username]['files'].append(file_info)
        self.save_users()
        
        return True, "File encrypted and saved successfully"
    
    def decrypt_file(self, username, encrypted_filename):
        if username not in self.users:
            return False, None, "User not found"
        
        user_files = [f['encrypted_name'] for f in self.users[username]['files']]
        if encrypted_filename not in user_files:
            return False, None, "File not found or access denied"
        
        key = self.users[username]['encryption_key'].encode()
        fernet = Fernet(key)
        
        file_path = os.path.join(self.vault_dir, encrypted_filename)
        if not os.path.exists(file_path):
            return False, None, "File not found"
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            return True, decrypted_data, "File decrypted successfully"
        except Exception as e:
            return False, None, f"Decryption failed: {str(e)}"
    
    def get_user_files(self, username):
        if username not in self.users:
            return []
        return self.users[username]['files']

vault = SecureFileVault()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user_files = vault.get_user_files(username)
    return render_template('dashboard.html', username=username, files=user_files)

@app.route('/confirm_delete')
def confirm_delete():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))
    return render_template('confirm_delete.html')

@app.route('/capture_face', methods=['POST'])
def capture_face():
    try:
        cap = cv2.VideoCapture(0)
        
        if not cap.isOpened():
            return jsonify({'success': False, 'message': 'Cannot access webcam'})
        
        ret, frame = cap.read()
        cap.release()
        
        if not ret:
            return jsonify({'success': False, 'message': 'Failed to capture image'})
        
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        face_locations = face_recognition.face_locations(rgb_frame)
        
        if len(face_locations) == 0:
            return jsonify({'success': False, 'message': 'No face detected'})
        
        if len(face_locations) > 1:
            return jsonify({'success': False, 'message': 'Multiple faces detected. Please ensure only one face is visible'})
        
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        face_encoding = face_encodings[0]
        
        return jsonify({
            'success': True, 
            'face_encoding': face_encoding.tolist(),
            'message': 'Register successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/register_user', methods=['POST'])
def register_user():
    try:
        data = request.json
        username = data.get('username')
        face_encoding = np.array(data.get('face_encoding'))
        
        if not username or len(face_encoding) == 0:
            return jsonify({'success': False, 'message': 'Invalid data'})
        
        success, message = vault.register_user(username, face_encoding)
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    try:
        data = request.json
        username = data.get('username')
        face_encoding = np.array(data.get('face_encoding'))

        if not username or face_encoding is None or len(face_encoding) == 0:
            return jsonify({'success': False, 'message': 'Username or face data missing'}), 400

        if username not in vault.users:
            return jsonify({'success': False, 'message': 'Username Invalid'}), 401

        face_file = vault.users[username]['face_file']
        if not os.path.exists(face_file):
            return jsonify({'success': False, 'message': 'Face does not match'}), 500

        with open(face_file, 'rb') as f:
            stored_encoding = pickle.load(f)

        match = face_recognition.compare_faces([stored_encoding], face_encoding, tolerance=0.6)

        if match[0]:
            session['username'] = username
            return jsonify({'success': True, 'message': f'Welcome back, {username}!'})
        else:
            return jsonify({'success': False, 'message': 'Face and username do not match'}), 403

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file selected'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        file_data = file.read()
        username = session['username']
        
        success, message = vault.encrypt_file(username, file_data, file.filename)
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/delete_file', methods=['POST'])
def delete_file():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    try:
        data = request.json
        encrypted_filename = data.get('filename')
        username = session['username']

        if not encrypted_filename:
            return jsonify({'success': False, 'message': 'No file specified'})

        user_files = vault.users.get(username, {}).get('files', [])
        updated_files = [f for f in user_files if f['encrypted_name'] != encrypted_filename]

        if len(updated_files) == len(user_files):
            return jsonify({'success': False, 'message': 'File not found or unauthorized'})

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        vault.users[username]['files'] = updated_files
        vault.save_users()

        return jsonify({'success': True, 'message': 'File deleted successfully'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/download_file/<encrypted_filename>')
def download_file(encrypted_filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        username = session['username']
        success, decrypted_data, message = vault.decrypt_file(username, encrypted_filename)
        
        if not success:
            return f"Error: {message}", 400
        
        user_files = vault.get_user_files(username)
        original_filename = None
        for file_info in user_files:
            if file_info['encrypted_name'] == encrypted_filename:
                original_filename = file_info['original_name']
                break
        
        if not original_filename:
            return "File not found", 404
        
        file_obj = io.BytesIO(decrypted_data)
        file_obj.seek(0)
        
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=original_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    
    try:
        face_file = vault.users[username]['face_file']
        if os.path.exists(face_file):
            os.remove(face_file)
        
        for file_info in vault.users[username].get('files', []):
            encrypted_file = file_info['encrypted_name']
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_file)
            if os.path.exists(file_path):
                os.remove(file_path)

        del vault.users[username]
        vault.save_users()
        
        session.pop('username', None)
        
        return redirect(url_for('index'))
    
    except Exception as e:
        return f"Error deleting account: {str(e)}", 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)