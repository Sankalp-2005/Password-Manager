# Argon2 low-level API for deriving cryptographic keys securely from passwords
from argon2.low_level import hash_secret_raw, Type

# AES-GCM authenticated encryption (confidentiality + integrity)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Exception raised when AES-GCM authentication fails (wrong key / tampered data)
from cryptography.exceptions import InvalidTag

# secrets: cryptographically secure random generator
# string: predefined character sets
# os: OS-level randomness and environment interaction
# json: serialization/deserialization of Python objects
import secrets, string, os, json

# Flask core components
from flask import Flask, render_template, request, jsonify, flash, session, redirect, url_for

# ORM for database interaction
from flask_sqlalchemy import SQLAlchemy

# Used to preserve function metadata in decorators
from functools import wraps


# ===================== UTILITIES =====================

# Character pool used for generating strong random passwords
ALL_CHARS = (
    string.ascii_lowercase +
    string.ascii_uppercase +
    string.digits +
    "!@#$%^&*()-_=+[]{};:,.<>/?"
)

# Generates a 16-character cryptographically secure random password
def generate_password():
    return "".join(secrets.choice(ALL_CHARS) for _ in range(16))


# Encrypts and saves the entire vault back into the database
def save_vault_to_db(user_id, vault, master_password):
    # Fetch the user record from the database
    user = User.query.get(user_id)

    # Generate a fresh 12-byte nonce for AES-GCM
    nonce = os.urandom(12)

    # Derive a 256-bit encryption key from the master password using Argon2id
    key = hash_secret_raw(
        salt=user.salt,              # User-specific salt stored in DB
        secret=master_password,      # Master password provided during login
        time_cost=2,                 # Argon2 time cost (iterations)
        hash_len=32,                 # Output key length (32 bytes = 256 bits)
        memory_cost=1024,            # Memory cost in KiB
        type=Type.ID,                # Argon2id variant (recommended)
        parallelism=2                # Number of parallel threads
    )

    # Initialize AES-GCM with the derived key
    aesgcm = AESGCM(key)

    # Encrypt the serialized vault (JSON → bytes)
    ciphertext = aesgcm.encrypt(
        nonce,
        json.dumps(vault).encode(),
        None
    )

    # Store nonce + ciphertext together in the database
    user.encrypted_blob = nonce + ciphertext
    db.session.commit()

    # Explicitly delete key from memory
    del key


# ===================== APP SETUP =====================

# Create Flask application instance
app = Flask(__name__)

# Secret key for session signing (random each restart)
app.secret_key = os.urandom(32)

# PostgreSQL(With Render) database connection URI

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:7893@localhost:5432/test"
)


# Disable SQLAlchemy event notifications (performance)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize SQLAlchemy with Flask app
db = SQLAlchemy(app)


# ===================== MODELS =====================

# User table definition
class User(db.Model):
    __tablename__ = "users"

    # Primary key
    user_id = db.Column(db.Integer, primary_key=True)

    # Unique username
    user_name = db.Column(db.String(200), nullable=False, unique=True)

    # Random salt used for Argon2 key derivation
    salt = db.Column(db.LargeBinary, nullable=False)

    # Encrypted vault data (nonce + ciphertext)
    encrypted_blob = db.Column(db.LargeBinary, nullable=False)


# ===================== AUTH =====================

# Decorator to protect routes that require authentication
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # If user is not logged in
        if "user_id" not in session:
            flash("Please log in to continue", "danger")
            return redirect(url_for("sign_in"))
        return view(*args, **kwargs)
    return wrapped


# ===================== ROUTES =====================

# Redirect root URL to sign-in page
@app.route("/")
def home():
    return redirect(url_for("sign_in"))


# ---------- SIGN IN ----------
@app.route("/sign-in", methods=["GET", "POST"])
def sign_in():
    if request.method == "POST":
        # Read credentials from form
        username = request.form["username"]
        password = request.form["password"].encode()

        # Look up user by username
        user = User.query.filter_by(user_name=username).first()
        if not user:
            flash("Invalid username", "danger")
            return redirect(url_for("sign_in"))

        try:
            # Derive key from provided password
            key = hash_secret_raw(
                salt=user.salt,
                secret=password,
                time_cost=2,
                hash_len=32,
                memory_cost=1024,
                type=Type.ID,
                parallelism=2
            )

            # Attempt to decrypt stored vault
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(
                user.encrypted_blob[:12],     # Extract nonce
                user.encrypted_blob[12:],     # Extract ciphertext
                None
            )

            # Deserialize vault JSON
            vault = json.loads(plaintext.decode())

        # Raised when password is incorrect or data is tampered
        except InvalidTag:
            flash("Incorrect password", "danger")
            return redirect(url_for("sign_in"))

        # Store authenticated session data
        session["user_id"] = user.user_id
        session["vault"] = vault
        session["master_password"] = password

        # Remove key from memory
        del key

        return redirect(url_for("password_vault"))

    return render_template("signin.html")


# ---------- SIGN UP ----------
@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        # Prevent duplicate usernames
        if User.query.filter_by(user_name=username).first():
            flash("User already exists", "danger")
            return redirect(url_for("sign_up"))

        # Generate salt and nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # Derive encryption key
        key = hash_secret_raw(
            salt=salt,
            secret=password,
            time_cost=2,
            hash_len=32,
            memory_cost=1024,
            type=Type.ID,
            parallelism=2
        )

        # Encrypt an empty vault
        aesgcm = AESGCM(key)
        encrypted_blob = nonce + aesgcm.encrypt(
            nonce,
            json.dumps({}).encode(),
            None
        )

        # Create and store user
        user = User(
            user_name=username,
            salt=salt,
            encrypted_blob=encrypted_blob
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please sign in.", "success")
        flash("Password Copied to clipboard(expires in 10 seconds)", "success")

        return redirect(url_for("sign_in"))

    return render_template("signup.html")


# ---------- VAULT ----------
@app.route("/password-vault")
@login_required
def password_vault():
    # Render vault using session-stored decrypted data
    return render_template(
        "password_vault.html",
        vault=session.get("vault", {})
    )


# ---------- ADD PASSWORD ----------
@app.route("/add-password", methods=["GET", "POST"])
@login_required
def add_password():
    if request.method == "POST":
        site = request.form["site"]
        username = request.form["username"]
        password = request.form["password"]

        # Update vault in session
        vault = session.get("vault", {})
        vault[site] = {
            "username": username,
            "password": password
        }
        session["vault"] = vault

        # Persist encrypted vault
        save_vault_to_db(
            session["user_id"],
            vault,
            session["master_password"]
        )

        flash("Password added, copied to clipboard (expires in 10 seconds)", "copy")
        return redirect(url_for("password_vault"))

    return render_template("add_password.html")


# ---------- UPDATE PASSWORD ----------
@app.route("/update-password/<site>", methods=["GET", "POST"])
@login_required
def update_password(site):
    vault = session.get("vault", {})

    # Ensure entry exists
    if site not in vault:
        flash("Entry not found", "danger")
        return redirect(url_for("password_vault"))

    if request.method == "POST":
        # Update stored credentials
        vault[site]["username"] = request.form["username"]
        vault[site]["password"] = request.form["password"]
        session["vault"] = vault

        # Save encrypted changes
        save_vault_to_db(
            session["user_id"],
            vault,
            session["master_password"]
        )

        flash("Password updated, copied to clipboard (expires in 10 seconds)", "copy")
        return redirect(url_for("password_vault"))

    return render_template(
        "update_password.html",
        site=site,
        data=vault[site]
    )


# ---------- VIEW PASSWORD ----------
@app.route("/view-password/<site>")
@login_required
def view_password(site):
    vault = session.get("vault", {})

    if site not in vault:
        flash("Entry not found", "danger")
        return redirect(url_for("password_vault"))

    return render_template(
        "view_password.html",
        site=site,
        data=vault[site]
    )


# ---------- DELETE PASSWORD ----------
@app.route("/delete-password/<site>", methods=["POST"])
@login_required
def delete_password(site):
    vault = session.get("vault", {})

    if site not in vault:
        flash("Entry not found", "danger")
        return redirect(url_for("password_vault"))

    # Remove entry
    del vault[site]
    session["vault"] = vault

    # Save encrypted vault
    save_vault_to_db(
        session["user_id"],
        vault,
        session["master_password"]
    )

    flash("Password deleted successfully", "success")
    return redirect(url_for("password_vault"))


# ---------- GENERATE PASSWORD ----------
@app.route("/generate-password")
def generate_password_api():
    # API endpoint for frontend password generation
    return jsonify({"password": generate_password()})


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    # Clear session data
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("sign_in"))


# Run Flask development server
if __name__ == "__main__":
    app.run(debug=False)
