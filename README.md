# 🔐 LookLock

LookLock is a secure file storage system that uses **face recognition authentication** and **file encryption** to protect your personal data. It ensures privacy by storing all data locally without any centralized database.

---

## 🚀 Features

- 👤 **Face Recognition Login** — Secure access using your face
- 🔒 **File Encryption** — Every file is encrypted with your unique key
- 🗂️ **Local Storage** — No database used; all data is saved locally
- 📁 **File Management** — Upload, view, and download files securely

---

## 🛠️ Tech Stack

- **Frontend**: HTML, CSS (Bootstrap)
- **Backend**: Python (Flask)
- **Face Recognition**: OpenCV, face-recognition
- **Encryption**: Python `cryptography` library
- **Storage**: Local filesystem

---

## 🧠 How It Works

1. **User registers** with a face image and password.
2. **Face encoding** is stored locally.
3. On login, user's face is compared with stored encodings.
4. Once authenticated, user can **upload, encrypt, view, and download files**.

---

## 📦 Setup Instructions

1. Clone the repo:
   ```bash
   git clone https://github.com/your-username/looklock.git
   cd looklock
2.python -m venv venv
venv\Scripts\activate  # Windows
3.pip install -r requirements.txt
4.python app.py
5.http://127.0.0.1:5000/

