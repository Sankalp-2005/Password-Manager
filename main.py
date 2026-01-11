# from argon2 import PasswordHasher

# password_hasher = PasswordHasher()
# master_password = input("Enter Master Password")
# hash1 = password_hasher.hash(master_password)
# print(hash1)
# print(password_hasher.verify(hash1,"sdfg"))

from IPython.core.formatters import _safe_repr
from sqlalchemy.sql._typing import Nullable
import os
from flask.helpers import url_for
from flask.helpers import redirect
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

#FLask App Creating
app = Flask(__name__)

#Data base configuration
# app.config["SQLALCHEMY_DATABASE_URI"]="postgresql://postgres:7893@localhost:5432/test"
user = os.environ.get("DB_USER","postgres")
password = os.environ.get("DB_PASSWORD","7893")
host = os.environ.get("DB_HOST","localhost")
dbname=os.environ.get("DB_NAME","test")
app.config["SQLALCHEMY_DATABASE_URI"]=f"postgresql+psycopg2://{user}:{password}@{host}/{dbname}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db=SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    user_id=db.Column(db.Integer, primary_key=True)
    user_name=db.Column(db.String(200), nullable=False)
    encryption_parameters=db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"{self.user_id}:{self.user_name}"

@app.route("/")
def home():
    return redirect(url_for("sign_in"))

@app.route("/Sign-In")
def sign_in():
    return render_template("signin.html")

@app.route("/Sign-Up")
def sign_up():
    return render_template("signup.html")

@app.route("/Password-Vault")
def password_vault():
    return render_template("password_vault.html")

@app.route("/Add-Password")
def add_password():
    return render_template("add_password.html")

@app.route("/Update-Password")
def update_password():
    return render_template("update_password.html")

@app.route("/View-Password")
def view_password():
    return render_template("view_password.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)