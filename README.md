# 🔐 Secure Password Manager

A secure web-based password manager built using **Flask**, **PostgreSQL**, and **modern cryptography**.  
The application encrypts all stored credentials using a **master password–derived key**, ensuring that **no passwords are ever stored in plaintext**, not even in the database.

---

## 📌 Features

### 🔑 Master Password–Based Security
- A single **master password** unlocks the entire vault.
- If the master password is lost, the encrypted data becomes **permanently inaccessible**.
- The server and database **cannot read stored passwords**.

### 🔒 Strong Encryption
- **Argon2id** is used to derive a 256-bit encryption key from the master password.
- The vault is encrypted using **AES-256-GCM** (authenticated encryption).
- Each encryption uses a **unique nonce** to ensure security.

### 🗂 Password Vault
- Securely store credentials (site → username → password).
- Full **CRUD operations**:
  - Add password
  - View password
  - Update password
  - Delete password

### 🔐 Password Generator
- Generate strong random passwords.
- Uses:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Symbols
- Passwords are generated using a **cryptographically secure RNG**.

### 📋 Clipboard Integration
- Passwords are automatically copied to the clipboard.
- Clipboard content is **cleared after ~10 seconds** to prevent leaks.

### 🖥 Clean Web Interface
- Responsive UI built with **Bootstrap 5**.
- Password visibility toggle (eye icon).
- Flash notifications for actions and clipboard events.

---

## 🧱 Tech Stack

- **Backend:** Python, Flask
- **Database:** PostgreSQL
- **ORM:** SQLAlchemy
- **Cryptography:**
  - Argon2id (key derivation)
  - AES-256-GCM (encryption)
- **Frontend:** HTML, CSS, Bootstrap 5, JavaScript

---

## 🛡 Security Design Overview

1. **Key Derivation**
   - The master password is never stored.
   - A key is derived using Argon2id with a unique per-user salt.

2. **Vault Encryption**
   - Entire vault is serialized as JSON.
   - Encrypted using AES-256-GCM.
   - Stored in the database as `(nonce + ciphertext)`.

3. **Runtime Decryption**
   - Vault is decrypted **only after successful login**.
   - Decrypted data exists only in memory (session).

4. **Database Safety**
   - Database administrators cannot read passwords.
   - Encrypted data is useless without the master password.

---

## 📁 Project Structure

.

├── main.py # Flask app, routes, encryption logic

├── init_db.py # Database initialization script

├── templates/

│ ├── signin.html

│ ├── signup.html

│ ├── password_vault.html

│ ├── add_password.html

│ ├── update_password.html

│ └── view_password.html

└── README.md


**Important Notes

This is a single-user learning project, not a commercial password manager.

Losing the master password means permanent data loss.

No password recovery mechanism exists by design.


**Learning Outcomes

Practical use of modern cryptography

Secure password handling principles

Flask session management

Full-stack CRUD application design

Defense against plaintext data leaks
