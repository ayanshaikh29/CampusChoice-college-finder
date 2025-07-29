from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pandas as pd
import secrets
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# =============================
# SQLite Setup & Reusable DB
# =============================
DB_PATH = 'campuschoice.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_csrf_token():
    return secrets.token_hex(16)

# =========================
# ROUTES START
# =========================

@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'), csrf_token=generate_csrf_token())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password or not email:
            flash('Please fill out the form!', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only letters and numbers!', 'danger')
            return redirect(url_for('register'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        account = cursor.fetchone()

        if account:
            flash('Account with that username or email already exists!', 'danger')
            return redirect(url_for('register'))

        try:
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
            flash('Registered successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {e}', 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html', csrf_token=generate_csrf_token())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', csrf_token=generate_csrf_token())

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/skip_login', methods=['POST'])
def skip_login():
    session['username'] = 'Guest'
    flash('You have skipped login.', 'success')
    return redirect(url_for('index'))

@app.route('/result', methods=['POST'])
def result():
    try:
        marks = int(request.form['marks'])
        city = request.form['city'].strip()
        stream = request.form['stream'].strip()

        csv_path = os.path.join(os.path.dirname(__file__), 'data', 'colleges.csv')
        df = pd.read_csv(csv_path)

        if df.empty:
            flash('College data is empty.', 'warning')
            return redirect(url_for('index'))

        filtered_df = df[
            (df['City'].str.lower() == city.lower()) &
            (df['Stream'].str.lower() == stream.lower()) &
            (df['Cutoff'] <= marks)
        ]

        colleges = filtered_df.to_dict(orient='records')
        return render_template('result.html', colleges=colleges, csrf_token=generate_csrf_token())

    except ValueError:
        flash('Please enter valid marks.', 'danger')
        return redirect(url_for('index'))
    except FileNotFoundError:
        flash('College data file not found.', 'danger')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error processing request: {e}', 'danger')
        return redirect(url_for('index'))

# =========================
# Run
# =========================
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=10000)
