from flask import Flask, render_template, redirect, url_for, request, flash, g, session, send_from_directory
import os
import sqlite3
from werkzeug.utils import secure_filename
from datetime import datetime
import random
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from flask_talisman import Talisman
import shutil
import zipfile
from flask_dance.contrib.github import make_github_blueprint


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'd61234cf10c04506e329525a2a1eeba200b3a83f7ee3e42bba96a248d62acf40'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'site.db'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SSL_CERTIFICATE'] = '/path/to/your/ssl/certificate.crt'
app.config['SSL_KEY'] = '/path/to/your/ssl/private.key'
db = SQLAlchemy(app)
Session(app)
talisman = Talisman(app, content_security_policy=None)

UPLOAD_FOLDER = 'your_upload_folder_path'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

google_bp = make_google_blueprint(
    client_id='825490061392-12imjl8v9c1o4ndfavk1vugett3qioae.apps.googleusercontent.com',
    client_secret='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',
    redirect_to='google_login'
)
app.register_blueprint(google_bp, url_prefix='/google_login')

github_blueprint = make_github_blueprint(
    client_id="b69c9b7d89f8e733c660",
    client_secret="f97f11a79dd81864cd967729b5f716f88a9a8680",
    scope="user:email"
)
app.register_blueprint(github_blueprint, url_prefix='/github_login')

# Define the User model using SQLAlchemy
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))  # Add a password field for local login
    phone_number = db.Column(db.String(20))


def init_db():
    with app.app_context():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                phone_number TEXT
            )
        ''')
        conn.commit()
        conn.close()

# Function to get a database connection
def get_db_connection():
    conn = getattr(g, '_database', None)
    if conn is None:
        conn = g._database = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
    return conn

def get_user_data_from_db(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
    user_data = cursor.fetchone()
    conn.close()
    return user_data

def user_authenticated(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def is_user_authenticated():
    return 'username' in session

def get_user_folder(username):
    return os.path.join(app.config['UPLOAD_FOLDER'], username)

@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get('/plus/v1/people/me')
    assert resp.ok, resp.text
    google_user_data = resp.json()
    google_user_email = google_user_data['emails'][0]['value']

    # Check if the Google user is already registered in your database
    existing_user = get_user_data_from_db(google_user_email)

    if existing_user:
        # User is already registered, log them in
        session['username'] = existing_user['username']
        flash('Login successful!', 'success')
    else:
        # User is not registered, create a new account
        # Use the Google email as the username
        username = google_user_email
        phone_number = None  # You may want to add phone number handling here

        # Create a new user in your database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO user (username, email, password, phone_number) VALUES (?, ?, ?, ?)',
                       (username, google_user_email, '', phone_number))  # Insert an empty password
        conn.commit()

        # Fetch the newly inserted user's data from the database
        cursor.execute('SELECT * FROM user WHERE email = ?', (google_user_email,))
        new_user = cursor.fetchone()
        conn.close()

        # Log in the newly created user
        session['username'] = new_user['username']
        flash('Registration and login successful!', 'success')

    return redirect(url_for('cloud_storage'))



@app.route('/github_login')
def github_login():
    if not github_blueprint.authorized:
        return redirect(url_for("github.login"))

    resp = github_blueprint.get("/user")
    if resp.ok:
        github_user_data = resp.json()
        github_user_email = github_user_data.get("email")

        if github_user_email:
            existing_user = User.query.filter_by(email=github_user_email).first()

            if existing_user:
                session['username'] = existing_user.username
                flash('Login successful!', 'success')
            else:
                new_user = User(username=github_user_data['login'], email=github_user_email)
                db.session.add(new_user)
                db.session.commit()
                session['username'] = new_user.username
                flash('Registration and login successful!', 'success')

    return redirect('cloud_storage.html')

@app.route('/create_folder', methods=['POST'])
def create_folder():
    if not is_user_authenticated():
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    folder_name = request.form.get('folder_name')

    if folder_name:
        # Get the user's folder path
        user_folder = get_user_folder(session['username'])

        # Create the full path for the new folder
        new_folder_path = os.path.join(user_folder, folder_name)

        # Check if the folder already exists
        if not os.path.exists(new_folder_path):
            os.makedirs(new_folder_path)  # Create the folder if it doesn't exist

            flash(f'Folder "{folder_name}" created successfully', 'success')
        else:
            flash(f'Folder "{folder_name}" already exists', 'danger')
    else:
        flash('Folder name cannot be empty', 'danger')

    return redirect(url_for('cloud_storage'))

@app.route('/folder/<folder_name>')
def folder(folder_name):
    if not is_user_authenticated():
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    username = session['username']
    user_folder = get_user_folder(username)

    # Check if the user's folder exists
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)  # Create the user's folder if it doesn't exist

    folder_path = os.path.join(user_folder, folder_name)

    # List and display files in the selected folder
    uploaded_files = os.listdir(folder_path)

    return render_template('folder.html', uploaded_files=uploaded_files, current_folder=folder_name)

deleted_folders = {}

@app.route('/delete_folder', methods=['POST'])
def delete_folder():
    folder_name = request.form.get('folder_name')

    username = session['username']
    if username not in deleted_folders:
        deleted_folders[username] = []
    deleted_folders[username].append(folder_name)

    flash(f'Folder "{folder_name}" deleted successfully', 'success')

    return redirect(url_for('cloud_storage'))

@app.route('/upload_folder', methods=['POST'])
def upload_folder():
    if not is_user_authenticated():
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    # Get the user's folder path
    user_folder = get_user_folder(session['username'])

    # Check if the POST request has a file part
    if 'folder_zip' not in request.files:
        flash('No ZIP file part', 'danger')
        return redirect(url_for('cloud_storage'))

    zip_file = request.files['folder_zip']

    # If the user submits an empty file input, zip_file.filename will be an empty string
    if zip_file.filename == '':
        flash('No selected ZIP file', 'danger')
        return redirect(url_for('cloud_storage'))

    if zip_file:
        # Ensure the filename is secure to prevent any potential security issues
        filename = secure_filename(zip_file.filename)

        # Create the full path for the uploaded ZIP file
        zip_path = os.path.join(user_folder, filename)

        # Save the uploaded ZIP file
        zip_file.save(zip_path)

        # Extract the contents of the ZIP file to a folder with the same name
        extracted_folder = os.path.join(user_folder, filename.split('.')[0])
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extracted_folder)

        flash(f'Folder "{filename}" uploaded and extracted successfully', 'success')

    return redirect(url_for('cloud_storage'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        username = request.form['username']

    if not is_user_authenticated():
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    current_folder = request.args.get('folder_name')
    user_folder = get_user_folder(session['username'])
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, current_folder, filename)
        file.save(file_path)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO files (filename) VALUES (?)', (filename,))
        conn.commit()
        conn.close()

        flash('File uploaded successfully', 'success')

        return redirect(url_for('folder', folder_name=current_folder))

@app.route('/download/<folder_name>/<filename>')
def download_file(folder_name, filename):
    user_folder = get_user_folder(session['username'])
    folder_path = os.path.join(user_folder, folder_name)
    file_path = os.path.join(folder_path, filename)

    if os.path.isfile(file_path):
        return send_from_directory(folder_path, filename)
    else:
        flash('File not found', 'danger')
        return redirect(url_for('folder', folder_name=folder_name))

@app.route('/delete/<folder_name>', methods=['POST'])
def delete_file(folder_name):
    if not is_user_authenticated():
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    file_to_delete = request.form.get('fileToDelete')

    if file_to_delete:
        user_folder = get_user_folder(session['username'])
        folder_path = os.path.join(user_folder, folder_name)
        file_path = os.path.join(folder_path, file_to_delete)

        if os.path.exists(file_path):
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM files WHERE filename = ?', (file_to_delete,))
            conn.commit()
            os.remove(file_path)
            flash(f'File {file_to_delete} deleted successfully', 'success')
        else:
            flash(f'File {file_to_delete} does not exist.', 'danger')

    return redirect(url_for('folder', folder_name=folder_name))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'danger')
        else:
            cursor.execute('INSERT INTO user (username, email, password, phone_number) VALUES (?, ?, ?, ?)',
                           (username, email, password, phone_number))
            conn.commit()
            conn.close()

            flash('Registration successful! You can now log in.', 'success')
            return redirect('/login')

    return render_template('register.html')

# Implement the function to retrieve user folder path
def get_user_folder(username):
    return os.path.join(app.config['UPLOAD_FOLDER'], username)

# Modify the login route to handle user authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Add your logic for user authentication here (e.g., check against the database)
        if user_authenticated(username, password):
            flash('Login successful!', 'success')
            session['username'] = username
            flash("You are successfully logged into the Flask Application")

            # Redirect to the appropriate route after login (e.g., cloud_storage)
            return redirect(url_for('cloud_storage'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return render_template('login.html')

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/cloud_storage')
def cloud_storage():
    username = session.get('username')

    if not username:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user_folder = get_user_folder(username)

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    uploaded_files = os.listdir(user_folder)

    user_folders = [f for f in os.listdir(user_folder) if os.path.isdir(os.path.join(user_folder, f))]

    if username in deleted_folders:
        user_folders = [folder for folder in user_folders if folder not in deleted_folders[username]]

    return render_template('cloud_storage.html', uploaded_files=uploaded_files, user_folders=user_folders)



if __name__ == '__main__':
    app.run(debug=True)
