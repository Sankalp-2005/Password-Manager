# from argon2 import PasswordHasher

# password_hasher = PasswordHasher()
# master_password = input("Enter Master Password")
# hash1 = password_hasher.hash(master_password)
# print(hash1)
# print(password_hasher.verify(hash1,"sdfg"))
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQL-ALCHEMY-URI"]=
@app.route("/Sign In")
def sign_in():
    return render_template("signin.html")

@app.route("/Sign Up")
def sign_up():
    return render_template("signup.html")

@app.route("/Password Vault")
def password_vault():
    return render_template("password_vault.html")

@app.route("/Add Password")
def add_password():
    return render_template("add_password.html")

@app.route("/Update Password")
def update_password():
    return render_template("update_password.html")

@app.route("/View Password")
def view_password():
    return render_template("view_password.html")

if __name__ == '__main__':
    app.run(debug=True)