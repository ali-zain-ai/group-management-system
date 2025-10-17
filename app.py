from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Change this later!

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Simple student table (we’ll expand later)
    c.execute('''CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reg_no TEXT UNIQUE NOT NULL,
                    name TEXT,
                    password TEXT,
                    role TEXT DEFAULT 'student'
                )''')
    conn.commit()
    conn.close()

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
