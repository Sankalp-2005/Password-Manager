from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import secrets
import string
from IPython.core.formatters import _safe_repr
from sqlalchemy.sql._typing import Nullable
import os,json
from flask.helpers import url_for
from flask.helpers import redirect
from flask import Flask, render_template, request,jsonify,flash,session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps


ALL_CHARS = string.ascii_lowercase+string.ascii_uppercase+string.digits+"!@#$%^&*()-_=+[]{};:,.<>/?"

def generate_password():
    return "".join(secrets.choice(ALL_CHARS) for _ in range(16))
def save_vault_to_db(user_id,vault,master_password):
    user = User.query.get(user_id)

    nonce = os.urandom(12)

    key = hash_secret_raw(
        salt=user.salt,
        secret=master_password,
        time_cost=2,
        hash_len=32,
        memory_cost=1024,
        type=Type.ID,
        parallelism=2
    )

    aesgcm = AESGCM(key)
    plaintext = json.dumps(vault).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    user.encrypted_blob = nonce + ciphertext
    db.session.commit()

    del key

#FLask App Creating
app = Flask(__name__)
app.secret_key = os.urandom(32)

#Data base configuration
app.config["SQLALCHEMY_DATABASE_URI"]="postgresql://postgres:7893@localhost:5432/test"
# user = os.environ.get("DB_USER","postgres")
# password = os.environ.get("DB_PASSWORD","7893")
# host = os.environ.get("DB_HOST","localhost")
# dbname=os.environ.get("DB_NAME","test")
# app.config["SQLALCHEMY_DATABASE_URI"]=f"postgresql+psycopg2://{user}:{password}@{host}/{dbname}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db=SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    user_id=db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(200), nullable=False, unique=True)
    salt=db.Column(db.LargeBinary,nullable=False)
    encrypted_blob=db.Column(db.LargeBinary, nullable=False)

    def __repr__(self):
        return f"{self.user_id}:{self.user_name}"
    
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue", "danger")
            return redirect(url_for("sign_in"))
        return view(*args, **kwargs)
    return wrapped_view

@app.route("/")
def home():
    return redirect(url_for("sign_in"))

@app.route("/sign-in",methods = ["GET","POST"])
def sign_in():
    if request.method=="POST":
        username = request.form["username"]
        password = request.form["password"].encode()
        user = User.query.filter_by(user_name=username).first()
        if user is None:
            flash("Invalid Username", "danger")
            return redirect(url_for("sign_in"))
        else:
            salt=user.salt
            nonce=user.encrypted_blob[:12]
            ciphertext=user.encrypted_blob[12:]
            key=hash_secret_raw(
                salt=salt,
                secret=password,
                time_cost=2,
                hash_len=32,
                memory_cost=1024,
                type=Type.ID,
                parallelism=2
            )
            aesgcm=AESGCM(key)
            try:
                plaintext=aesgcm.decrypt(nonce,ciphertext,None)
                vault = json.loads(plaintext.decode())
            except InvalidTag:
                flash("Incorrect Password", "danger")
                return redirect(url_for("sign_in"))
            del key
            del password
            session["user_id"] = user.user_id
            session["vault"]= vault
            session["master_password"] = request.form["password"].encode()
            return redirect(url_for("password_vault"))
    return render_template("signin.html")

@app.route("/sign-up",methods=["GET","POST"])
def sign_up():
    if request.method=="POST":
        username=request.form["username"]
        existing_user = User.query.filter_by(user_name=username).first()
        if existing_user:
            flash("User already exists", "danger")
            return redirect(url_for("sign_up"))
        password=request.form["password"].encode()
        salt=os.urandom(16)
        nonce = os.urandom(12)
        key=hash_secret_raw(
            salt=salt,
            secret=password,
            time_cost=2,
            hash_len=32,
            memory_cost=1024,
            type=Type.ID,
            parallelism=2
        )
        aesgcm=AESGCM(key)
        vault={}
        plaintext=json.dumps(vault).encode()
        ciphertext=aesgcm.encrypt(nonce,plaintext,None)
        encrypted_blob=nonce+ciphertext
        user=User(
            user_name=username,
            salt=salt,
            encrypted_blob=encrypted_blob
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please sign in.", "success")
        flash("Password Copied to Clipboard, Expires in 10 seconds!", "success")
        return redirect(url_for("sign_in"))
    return render_template("signup.html")

@app.route("/password-vault",methods=["GET","POST"])
@login_required
def password_vault():
    vault = session.get("vault", {})
    if request.method=="POST":
        return redirect(url_for("add_password"))
    return render_template("password_vault.html", vault=vault)

@app.route("/add-password",methods=["GET","POST"])
@login_required
def add_password():
    if request.method=="POST":
        site = request.form["site"]
        username = request.form["username"]
        password=request.form["password"]
        vault = session.get("vault",{})
        vault[site]={
            "username":username,
            "password":password
        }
        session["vault"]=vault
        save_vault_to_db(
            session["user_id"],
            vault,
            session["master_password"]
        )
        flash("Password Added Successfully","success")
        return redirect(url_for("password_vault"))
    return render_template("add_password.html")

@app.route("/update-password/<site>",methods=["GET","POST"])
@login_required
def update_password(site):
    vault = session.get("vault",{})
    if site not in vault:
        flash("Entery not found","danger")
        return redirect(url_for("password_vault"))
    if request.method=="POST":
        vault[site]["username"]=request.form["username"]
        vault[site]["password"]=request.form["password"]
        session["vault"]=vault
        save_vault_to_db(
            session["user_id"],
            vault,
            session["master_password"]
        )
        flash("Password Updated Successfully","success")
        flash(f"__COPY__{request.form['password']}", "copy")
        return redirect(url_for("password_vault"))
    
    return render_template("update_password.html",site=site,data=vault[site])

@app.route("/view-password/<site>")
@login_required
def view_password(site):
    vault=session.get("vault",{})
    if site not in vault:
        flash("Entry not found", "danger")
        return redirect(url_for("password_vault"))
    return render_template("view_password.html",site=site,data=vault[site])

@app.route("/delete-password/<site>", methods=["POST"])
@login_required
def delete_password(site):
    vault = session.get("vault", {})

    if site not in vault:
        flash("Entry not found", "danger")
        return redirect(url_for("password_vault"))

    del vault[site]
    session["vault"] = vault
    save_vault_to_db(
        session["user_id"],
        vault,
        session["master_password"]
    )
    flash("Password deleted successfully", "success")
    return redirect(url_for("password_vault"))

@app.route("/generate-password")
def generate_password_api():
    password = generate_password()
    return jsonify({"password": password})

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("sign_in"))

if __name__ == "__main__":
    app.run(debug=True)

    

