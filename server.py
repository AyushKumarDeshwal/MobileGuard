from flask import Flask, request, render_template, redirect, session, flash
from flask_wtf import FlaskForm, CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired
import bcrypt, json, os
from ai_agent.agent import analyze_log

app = Flask(__name__)
app.secret_key = 'supersecretkey'

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app)

USERS_FILE = 'auth/users.json'

# Login form definition
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with open(USERS_FILE) as f:
            users = json.load(f)
        user = form.username.data
        pwd = form.password.data
        print("Trying login for:", user)

        if user in users:
            print("User exists.")
            if bcrypt.checkpw(pwd.encode(), users[user]['password'].encode()):
                print("Password match!")
                session['username'] = user
                return redirect('/dashboard')
            else:
                print("Password mismatch.")
                flash("Invalid username or password")
        else:
            print("User not found.")
            flash("Invalid username or password")

    return render_template("login.html", form=form)

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect('/login')

    log_path = f"logs/{username}/log.json"
    alerts = analyze_log(log_path)
    with open(log_path) as f:
        logs = json.load(f)

    keyword = request.args.get('keyword', '')
    level = request.args.get('level', '')

    return render_template("dashboard.html", logs=logs, alerts=alerts, keyword=keyword, level=level)

if __name__ == '__main__':
    app.run(debug=True)
