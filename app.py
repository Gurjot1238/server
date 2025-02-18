from flask import Flask, flash, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://admin:6PClz29NxSYaswnnFz3utkW7TRgGuKzL@dpg-cuqb3oan91rc73asbui0-a.singapore-postgres.render.com/meetx_db_hhbn"
app.config["SECRET_KEY"] = "My Super Secret Key"

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)

def is_logged_in():
    return 'user_id' in session

def requires_login(f):
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    logged_in = is_logged_in()
    if logged_in:
        curr_user = User.query.get(session.get('user_id'))
        return render_template("index.html", logged_in=True, curr_user=curr_user)
    else:
        return render_template("index.html", logged_in=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect('/')
        else:
            flash('Invalid email or password', 'danger')
            return redirect('/login')

    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect('/register')

        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect('/register')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email', 'danger')
            return redirect('/register')

        existing_user = User.query.filter((User .username == username) | (User .email == email)).first()

        if existing_user:
            flash('Username or email already exists', 'danger')
        else:
            hashed_password = generate_password_hash(password)

            new_user = User(username=username, email=email, password=hashed_password)

            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))

    return render_template('auth/register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

@app.route('/meeting')
def meeting():
    curr_user = User.query.get(session['user_id'])
    return render_template('meeting.html', curr_user=curr_user)
    

@app.route('/join', methods=['GET', 'POST'])
def join_meeting():
    if request.method == 'POST':
        meeting_id = request.form.get('meeting_id')  # Corrected form field name
        if meeting_id:
            return redirect(url_for('meeting', roomID=meeting_id))
        else:
            flash('Please enter a meeting ID', 'danger')
    return render_template("join_meeting.html")

if __name__ == '__main__':
    app.run(debug=True)