import sqlite3
from werkzeug.security import generate_password_hash

# Apni marzi ka admin registration number aur password likho:
reg_no = "admin001"
name = "System Admin"
password = "admin123"  # tum apni marzi se rakh sakte ho
hashed_pw = generate_password_hash(password)

conn = sqlite3.connect('database.db')
c = conn.cursor()

# Insert admin if not exists
c.execute("SELECT * FROM students WHERE reg_no = ?", (reg_no,))
if c.fetchone() is None:
    c.execute("INSERT INTO students (reg_no, name, password, role) VALUES (?, ?, ?, 'admin')",
              (reg_no, name, hashed_pw))
    conn.commit()
    print("✅ Admin created successfully!")
else:
    print("⚠️ Admin already exists!")

conn.close()
