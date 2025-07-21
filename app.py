from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import pandas as pd
import secrets
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Secure random secret key

# Connect to MySQL
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Ayan@2615f",
        database="campuschoice"
    )
    cursor = db.cursor()
except mysql.connector.Error as err:
    print(f"Database connection failed: {err}")
    exit(1)

def generate_csrf_token():
    return secrets.token_hex(16)

@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'), csrf_token=generate_csrf_token())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not username or not password or not email:
            flash('Please fill out the form!', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only letters and numbers!', 'danger')
            return redirect(url_for('register'))

        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        account = cursor.fetchone()
        if account:
            flash('Account with that username or email already exists!', 'danger')
            return redirect(url_for('register'))

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, password))
            db.commit()
            flash('Registered successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', csrf_token=generate_csrf_token())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        if user:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', csrf_token=generate_csrf_token())

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

        # Load and filter college data
        df = pd.read_csv('data/colleges.csv')

        if df.empty:
            flash('College data is empty.', 'warning')
            return redirect(url_for('index'))

        filtered_df = df[
            (df['City'].str.lower() == city.lower()) &
            (df['Stream'].str.lower() == stream.lower()) &
            (df['Cutoff'] <= marks)
        ]

        # Convert to list of dicts for rendering
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

if __name__ == '__main__':
    app.run(debug=True)
