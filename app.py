from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super_secret_key"

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Student table
    c.execute('''CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reg_no TEXT UNIQUE NOT NULL,
                    name TEXT,
                    password TEXT,
                    role TEXT DEFAULT 'student'
                )''')
    conn.commit()
    conn.close()

# ---------- UTILS ----------
def get_user_by_reg(reg_no):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM students WHERE reg_no = ?", (reg_no,))
    user = c.fetchone()
    conn.close()
    return user

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        reg_no = request.form['reg_no']
        name = request.form['name']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO students (reg_no, name, password) VALUES (?, ?, ?)", 
                      (reg_no, name, hashed_pw))
            conn.commit()
            flash("Account created! You can now log in.", "success")
        except:
            flash("Registration number already exists!", "danger")
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        reg_no = request.form['reg_no']
        password = request.form['password']

        user = get_user_by_reg(reg_no)
        if user and check_password_hash(user[3], password):
            session['user'] = {'id': user[0], 'reg_no': user[1], 'name': user[2], 'role': user[4]}
            flash("Login successful!", "success")
            if user[4] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin.html', user=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# ---------- MAIN ----------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
