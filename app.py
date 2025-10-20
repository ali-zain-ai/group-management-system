from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import secrets

app = Flask(__name__)
app.secret_key = "super_secret_key"


@app.before_request
def ensure_csrf():
    # ensure a CSRF token exists in session for forms
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)


def validate_csrf(token):
    return token and session.get('csrf_token') and token == session.get('csrf_token')


# ---------- DATABASE SETUP ----------
def get_db_connection():
    """ Helper function to connect to database """
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # ---------- Students table ----------
    c.execute('''CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reg_no TEXT UNIQUE NOT NULL,
                    name TEXT,
                    password TEXT,
                    role TEXT DEFAULT 'student',
                    group_id INTEGER,
                    FOREIGN KEY (group_id) REFERENCES groups(id)
                )''')

    # ---------- Groups table ----------
    c.execute('''CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    purpose TEXT,
                    leader_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (leader_id) REFERENCES students(id)
                )''')

    # ---------- Group Members table ----------
    c.execute('''CREATE TABLE IF NOT EXISTS group_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER,
                    student_id INTEGER,
                    FOREIGN KEY (group_id) REFERENCES groups(id),
                    FOREIGN KEY (student_id) REFERENCES students(id)
                )''')

    # ---------- Group Requests table ----------
    c.execute('''CREATE TABLE IF NOT EXISTS group_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER,
                    receiver_id INTEGER,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY (sender_id) REFERENCES students(id),
                    FOREIGN KEY (receiver_id) REFERENCES students(id)
                )''')

    # ---------- Admin Settings table ----------
    c.execute('''CREATE TABLE IF NOT EXISTS admin_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    allow_group_creation INTEGER DEFAULT 1,
                    max_group_members INTEGER DEFAULT 5
                )''')

    # ---------- Insert default settings if none exist ----------
    c.execute('SELECT COUNT(*) FROM admin_settings')
    count = c.fetchone()[0]
    if count == 0:
        c.execute('INSERT INTO admin_settings (allow_group_creation, max_group_members) VALUES (1, 5)')

    conn.commit()
    conn.close()



# ---------- UTILS ----------
def get_user_by_reg(reg_no):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM students WHERE reg_no = ?", (reg_no,)).fetchone()
    conn.close()
    return user


def get_admin_settings():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT allow_group_creation, max_group_members FROM admin_settings LIMIT 1")
    settings = c.fetchone()
    conn.close()
    return {'allow_group_creation': settings[0], 'max_group_members': settings[1]}


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

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO students (reg_no, name, password) VALUES (?, ?, ?)",
                         (reg_no, name, hashed_pw))
            conn.commit()
            flash("Account created! You can now log in.", "success")
        except:
            flash("Registration number already exists!", "danger")
        conn.close()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/send_request/<int:receiver_id>', methods=['POST'])
def send_request(receiver_id):
    if 'user' not in session:
        flash("Please login to send requests.", "warning")
        return redirect(url_for('login'))

    sender_id = session['user']['id']

    if sender_id == receiver_id:
        flash("You cannot send a request to yourself.", "warning")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    c = conn.cursor()

    # verify receiver exists
    c.execute('SELECT * FROM students WHERE id = ?', (receiver_id,))
    receiver = c.fetchone()
    if not receiver:
        conn.close()
        flash("Student not found.", "danger")
        return redirect(url_for('dashboard'))

    # check duplicate pending request
    c.execute('SELECT * FROM group_requests WHERE sender_id = ? AND receiver_id = ? AND status = "pending"',
              (sender_id, receiver_id))
    if c.fetchone():
        conn.close()
        flash("You already sent a request to this student.", "info")
        return redirect(url_for('dashboard'))

    # insert request
    c.execute('INSERT INTO group_requests (sender_id, receiver_id, status) VALUES (?, ?, ?)',
              (sender_id, receiver_id, 'pending'))
    conn.commit()
    conn.close()

    flash("Request sent successfully.", "success")
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        reg_no = request.form['reg_no']
        password = request.form['password']

        user = get_user_by_reg(reg_no)
        if user and check_password_hash(user['password'], password):
            # ✅ Fixed session keys: we’ll use user['id'], not user_id
            session['user'] = {
                'id': user['id'],
                'reg_no': user['reg_no'],
                'name': user['name'],
                'role': user['role']
            }
            flash("Login successful!", "success")
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    conn = get_db_connection()

    # Fetch the group where the student is a member
    group = conn.execute('''
        SELECT g.* FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.student_id = ?
    ''', (user['id'],)).fetchone()

    # Fetch groups created by this user (leader)
    created_rows = conn.execute('''
        SELECT g.id, g.name, g.purpose, g.leader_id, g.created_at,
               (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
        FROM groups g
        WHERE g.leader_id = ?
        ORDER BY g.created_at DESC
    ''', (user['id'],)).fetchall()

    # Fetch groups the student has joined but did not create
    joined_rows = conn.execute('''
        SELECT g.id, g.name, g.purpose, g.leader_id, g.created_at,
               (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.student_id = ? AND g.leader_id != ?
        ORDER BY g.created_at DESC
    ''', (user['id'], user['id'])).fetchall()

    def fmt_row(r):
        d = dict(r)
        raw = d.get('created_at')
        if raw:
            try:
                dt = datetime.datetime.strptime(raw, '%Y-%m-%d %H:%M:%S')
                d['created_at'] = dt.strftime('%b %d, %Y')
            except Exception:
                # leave as-is if parsing fails
                pass
        else:
            d['created_at'] = ''
        return d

    created_groups = [fmt_row(r) for r in created_rows]
    joined_groups = [fmt_row(r) for r in joined_rows]

    # Fetch ungrouped students (students not in any group)
    if user.get('role') == 'admin':
        # admin can see all ungrouped students
        ungrouped_students = conn.execute('''
            SELECT s.* FROM students s
            LEFT JOIN group_members gm ON s.id = gm.student_id
            WHERE gm.group_id IS NULL AND s.id != ?
        ''', (user['id'],)).fetchall()
    else:
        # non-admins should not see admin accounts in lists
        ungrouped_students = conn.execute('''
            SELECT s.* FROM students s
            LEFT JOIN group_members gm ON s.id = gm.student_id
            WHERE gm.group_id IS NULL AND s.id != ? AND s.role != 'admin'
        ''', (user['id'],)).fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        user=user,
        group=group,
        ungrouped_students=ungrouped_students
    )


@app.route('/requests')
def requests_view():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    conn = get_db_connection()
    incoming = conn.execute('SELECT gr.id, gr.sender_id, s.reg_no, s.name FROM group_requests gr JOIN students s ON gr.sender_id = s.id WHERE gr.receiver_id = ? AND gr.status = "pending"', (user_id,)).fetchall()
    conn.close()
    return render_template('requests.html', incoming=incoming)


@app.route('/accept_request/<int:request_id>', methods=['POST'])
def accept_request(request_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    conn = get_db_connection()
    c = conn.cursor()

    # fetch request
    c.execute('SELECT * FROM group_requests WHERE id = ? AND receiver_id = ? AND status = "pending"', (request_id, user_id))
    req = c.fetchone()
    if not req:
        conn.close()
        flash('Request not found or already handled.', 'warning')
        return redirect(url_for('dashboard'))

    sender_id = req['sender_id']

    # create a new group with both students if neither is in a group
    # check if sender or receiver already in group
    c.execute('SELECT * FROM group_members WHERE student_id = ?', (sender_id,))
    s_in = c.fetchone()
    c.execute('SELECT * FROM group_members WHERE student_id = ?', (user_id,))
    r_in = c.fetchone()

    if s_in or r_in:
        # cannot accept if either already in a group
        c.execute('UPDATE group_requests SET status = ? WHERE id = ?', ('rejected', request_id))
        conn.commit()
        conn.close()
        flash('One of the students is already in a group. Request rejected.', 'warning')
        return redirect(url_for('dashboard'))

    # create group
    settings = get_admin_settings()
    maxm = settings.get('max_group_members', 5)
    if maxm < 2:
        conn.close()
        flash('Admin settings do not allow creating groups of this size.', 'warning')
        return redirect(url_for('dashboard'))

    group_name = f"Group_{sender_id}_{user_id}"
    c.execute('INSERT INTO groups (name, purpose, leader_id) VALUES (?, ?, ?)', (group_name, 'Created via request', sender_id))
    group_id = c.lastrowid
    # add members
    c.execute('INSERT INTO group_members (group_id, student_id) VALUES (?, ?)', (group_id, sender_id))
    c.execute('INSERT INTO group_members (group_id, student_id) VALUES (?, ?)', (group_id, user_id))
    # update students.group_id for both
    c.execute('UPDATE students SET group_id = ? WHERE id = ?', (group_id, sender_id))
    c.execute('UPDATE students SET group_id = ? WHERE id = ?', (group_id, user_id))

    c.execute('UPDATE group_requests SET status = ? WHERE id = ?', ('accepted', request_id))
    conn.commit()
    conn.close()
    flash('Request accepted — group created.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/api/accept_request/<int:request_id>', methods=['POST'])
def api_accept_request(request_id):
    if 'user' not in session:
        return {'status': 'error', 'message': 'login_required'}, 401

    user_id = session['user']['id']
    conn = get_db_connection()
    c = conn.cursor()

    c.execute('SELECT * FROM group_requests WHERE id = ? AND receiver_id = ? AND status = "pending"', (request_id, user_id))
    req = c.fetchone()
    if not req:
        conn.close()
        return {'status': 'error', 'message': 'not_found_or_handled'}, 404

    sender_id = req['sender_id']
    # check if either already in a group
    c.execute('SELECT * FROM group_members WHERE student_id = ?', (sender_id,))
    s_in = c.fetchone()
    c.execute('SELECT * FROM group_members WHERE student_id = ?', (user_id,))
    r_in = c.fetchone()
    if s_in or r_in:
        c.execute('UPDATE group_requests SET status = ? WHERE id = ?', ('rejected', request_id))
        conn.commit()
        conn.close()
        return {'status': 'error', 'message': 'one_already_in_group'}, 409

    # create group and add members
    settings = get_admin_settings()
    maxm = settings.get('max_group_members', 5)
    if maxm < 2:
        conn.close()
        return {'status': 'error', 'message': 'max_group_size_too_small'}, 400

    group_name = f"Group_{sender_id}_{user_id}"
    c.execute('INSERT INTO groups (name, purpose, leader_id) VALUES (?, ?, ?)', (group_name, 'Created via request', sender_id))
    group_id = c.lastrowid
    c.execute('INSERT INTO group_members (group_id, student_id) VALUES (?, ?)', (group_id, sender_id))
    c.execute('INSERT INTO group_members (group_id, student_id) VALUES (?, ?)', (group_id, user_id))
    c.execute('UPDATE students SET group_id = ? WHERE id = ?', (group_id, sender_id))
    c.execute('UPDATE students SET group_id = ? WHERE id = ?', (group_id, user_id))
    c.execute('UPDATE group_requests SET status = ? WHERE id = ?', ('accepted', request_id))
    conn.commit()
    conn.close()
    return {'status': 'ok', 'message': 'accepted', 'group_id': group_id}


@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM group_requests WHERE id = ? AND receiver_id = ? AND status = "pending"', (request_id, user_id))
    req = c.fetchone()
    if not req:
        conn.close()
        flash('Request not found or already handled.', 'warning')
        return redirect(url_for('dashboard'))

    c.execute('UPDATE group_requests SET status = ? WHERE id = ?', ('rejected', request_id))
    conn.commit()
    conn.close()
    flash('Request rejected.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/api/reject_request/<int:request_id>', methods=['POST'])
def api_reject_request(request_id):
    if 'user' not in session:
        return {'status': 'error', 'message': 'login_required'}, 401
    user_id = session['user']['id']
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM group_requests WHERE id = ? AND receiver_id = ? AND status = "pending"', (request_id, user_id))
    req = c.fetchone()
    if not req:
        conn.close()
        return {'status': 'error', 'message': 'not_found_or_handled'}, 404

    c.execute('UPDATE group_requests SET status = ? WHERE id = ?', ('rejected', request_id))
    conn.commit()
    conn.close()
    return {'status': 'ok', 'message': 'rejected'}



@app.route('/admin/change_password', methods=['GET', 'POST'])
def change_admin_password():
    # Ensure user is logged in and is admin
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    c = conn.cursor()

    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # fetch current (hashed) password for this admin
        c.execute("SELECT password FROM students WHERE id = ?", (session['user']['id'],))
        row = c.fetchone()

        if not row or not check_password_hash(row['password'], old_password):
            conn.close()
            return render_template('change_password.html', error="❌ Old password is incorrect")

        if new_password != confirm_password:
            conn.close()
            return render_template('change_password.html', error="❌ New passwords do not match")

        # store hashed new password
        hashed_new = generate_password_hash(new_password)
        c.execute("UPDATE students SET password = ? WHERE id = ?", (hashed_new, session['user']['id']))
        conn.commit()
        conn.close()
        return render_template('change_password.html', success="✅ Password updated successfully!")

    conn.close()
    return render_template('change_password.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


# ---------- GROUP SYSTEM ----------
@app.route('/groups')
def groups():
    if 'user' not in session:
        return redirect('/login')

    conn = get_db_connection()
    groups = conn.execute('SELECT * FROM groups').fetchall()
    conn.close()
    return render_template('groups.html', groups=groups)


@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user' not in session:
        return redirect('/login')
    
    settings = get_admin_settings()

    # Prevent group creation if admin disabled it
    if settings['allow_group_creation'] == 0:
        return "Group creation is currently disabled by admin."

    if request.method == 'POST':
        name = request.form['name']
        purpose = request.form['purpose']
        leader_reg = request.form.get('leader_reg', '').strip()
        leader_name = request.form.get('leader_name', '').strip()

        conn = get_db_connection()
        c = conn.cursor()

        # Determine group leader
        if leader_reg:
            c.execute('SELECT * FROM students WHERE reg_no = ?', (leader_reg,))
            student = c.fetchone()
            if student:
                leader_id = student['id']
            else:
                hashed_pw = generate_password_hash('changeme')
                c.execute('INSERT INTO students (reg_no, name, password) VALUES (?, ?, ?)',
                          (leader_reg, leader_name or leader_reg, hashed_pw))
                leader_id = c.lastrowid
        else:
            leader_id = session['user']['id']

        # Create group and assign leader
        c.execute('INSERT INTO groups (name, purpose, leader_id) VALUES (?, ?, ?)',
                  (name, purpose, leader_id))
        group_id = c.lastrowid

        # Add leader to group_members
        c.execute('INSERT INTO group_members (group_id, student_id) VALUES (?, ?)',
                  (group_id, leader_id))

        # Update student's group_id in students table
        c.execute('UPDATE students SET group_id = ? WHERE id = ?', (group_id, leader_id))

        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))

    # GET request → show the group creation form
    return render_template('create_group.html')

@app.route('/join_group/<int:group_id>')
def join_group(group_id):
    if 'user' not in session:
        return redirect('/login')

    student_id = session['user']['id']
    conn = get_db_connection()

    # Check if already in any group
    in_group = conn.execute('SELECT * FROM group_members WHERE student_id = ?', (student_id,)).fetchone()
    if in_group:
        conn.close()
        return "You are already in a group."

    # enforce max members
    settings = get_admin_settings()
    maxm = settings.get('max_group_members', 5)
    count = conn.execute('SELECT COUNT(*) as cnt FROM group_members WHERE group_id = ?', (group_id,)).fetchone()['cnt']
    if count >= maxm:
        conn.close()
        return "This group is full."

    conn.execute('INSERT INTO group_members (group_id, student_id) VALUES (?, ?)',
                 (group_id, student_id))
    conn.commit()
    # update students.group_id for quick lookup
    conn.execute('UPDATE students SET group_id = ? WHERE id = ?', (group_id, student_id))
    conn.commit()
    conn.close()
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/leave_group/<int:group_id>')
def leave_group(group_id):
    if 'user' not in session:
        return redirect('/login')

    student_id = session['user']['id']
    conn = get_db_connection()
    conn.execute('DELETE FROM group_members WHERE group_id = ? AND student_id = ?',
                 (group_id, student_id))
    conn.commit()
    # clear students.group_id
    conn.execute('UPDATE students SET group_id = NULL WHERE id = ?', (student_id,))
    conn.commit()
    conn.close()
    return redirect('/groups')


@app.route('/group/<int:group_id>')
def group_detail(group_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    group = conn.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    members = conn.execute('SELECT s.id, s.reg_no, s.name FROM students s JOIN group_members gm ON s.id = gm.student_id WHERE gm.group_id = ?', (group_id,)).fetchall()
    conn.close()
    return render_template('group.html', group=group, members=members, user=session.get('user'))


@app.route('/group/<int:group_id>/edit', methods=['GET', 'POST'])
def edit_group(group_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    c = conn.cursor()
    # permission: only leader or admin
    g = c.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    if not g:
        conn.close()
        flash('Group not found.', 'danger')
        return redirect(url_for('dashboard'))
    user = session['user']
    if user.get('role') != 'admin' and g['leader_id'] != user['id']:
        conn.close()
        flash('Only group leader or admin can edit this group.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))
    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not validate_csrf(token):
            conn.close()
            flash('Invalid CSRF token.', 'danger')
            return redirect(url_for('group_detail', group_id=group_id))

        name = request.form.get('name')
        purpose = request.form.get('purpose')
        c.execute('UPDATE groups SET name = ?, purpose = ? WHERE id = ?', (name, purpose, group_id))
        conn.commit()
        conn.close()
        flash('Group updated successfully.', 'success')
        return redirect(url_for('group_detail', group_id=group_id))

    group = conn.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    conn.close()
    return render_template('edit_group.html', group=group)


@app.route('/group/<int:group_id>/add_member', methods=['POST'])
def add_member(group_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    # only leader or admin can add
    user = session['user']
    conn = get_db_connection()
    c = conn.cursor()
    group = c.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    if not group:
        conn.close()
        flash('Group not found.', 'danger')
        return redirect(url_for('dashboard'))

    if user.get('role') != 'admin' and group['leader_id'] != user['id']:
        conn.close()
        flash('Only group leader or admin can add members.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))
    # CSRF check
    token = request.form.get('csrf_token')
    if not validate_csrf(token):
        conn.close()
        flash('Invalid CSRF token.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id))

    # enforce max members
    settings = get_admin_settings()
    maxm = settings.get('max_group_members', 5)
    current_count = c.execute('SELECT COUNT(*) as cnt FROM group_members WHERE group_id = ?', (group_id,)).fetchone()['cnt']
    if current_count >= maxm:
        conn.close()
        flash('Group is full. Cannot add more members.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))

    reg_no = request.form.get('reg_no')
    student = c.execute('SELECT * FROM students WHERE reg_no = ?', (reg_no,)).fetchone()
    if not student:
        conn.close()
        flash('Student not found.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id))

    # check if already in a group
    in_group = c.execute('SELECT * FROM group_members WHERE student_id = ?', (student['id'],)).fetchone()
    if in_group:
        conn.close()
        flash('Student already in a group.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))

    c.execute('INSERT INTO group_members (group_id, student_id) VALUES (?, ?)', (group_id, student['id']))
    # update students.group_id
    c.execute('UPDATE students SET group_id = ? WHERE id = ?', (group_id, student['id']))
    conn.commit()
    conn.close()
    flash('Student added to group.', 'success')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/group/<int:group_id>/remove_member/<int:student_id>', methods=['POST'])
def remove_member(group_id, student_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    conn = get_db_connection()
    c = conn.cursor()
    group = c.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    if user.get('role') != 'admin' and group['leader_id'] != user['id']:
        conn.close()
        flash('Only group leader or admin can remove members.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))
    # CSRF check
    token = request.form.get('csrf_token')
    if not validate_csrf(token):
        conn.close()
        flash('Invalid CSRF token.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id))

    c.execute('DELETE FROM group_members WHERE group_id = ? AND student_id = ?', (group_id, student_id))
    # clear students.group_id
    c.execute('UPDATE students SET group_id = NULL WHERE id = ?', (student_id,))
    conn.commit()
    conn.close()
    flash('Member removed from group.', 'info')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/group/<int:group_id>/delete', methods=['POST'])
def delete_group(group_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    conn = get_db_connection()
    c = conn.cursor()
    group = c.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    if not group:
        conn.close()
        flash('Group not found.', 'danger')
        return redirect(url_for('dashboard'))

    # CSRF token
    token = request.form.get('csrf_token')
    if not validate_csrf(token):
        conn.close()
        flash('Invalid CSRF token.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id))

    if user.get('role') != 'admin' and group['leader_id'] != user['id']:
        conn.close()
        flash('Only group leader or admin can delete this group.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))

    # clear students.group_id for members
    c.execute('SELECT student_id FROM group_members WHERE group_id = ?', (group_id,))
    members = c.fetchall()
    for m in members:
        c.execute('UPDATE students SET group_id = NULL WHERE id = ?', (m['student_id'],))

    c.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
    c.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    conn.commit()
    conn.close()
    flash('Group deleted.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/api/send_request/<int:receiver_id>', methods=['POST'])
def api_send_request(receiver_id):
    # JSON API endpoint to send request (used by AJAX)
    if 'user' not in session:
        return {'status': 'error', 'message': 'login_required'}, 401
    # require CSRF header for AJAX
    token = request.headers.get('X-CSRF-Token')
    if not token or not validate_csrf(token):
        return {'status': 'error', 'message': 'invalid_csrf'}, 403
    sender_id = session['user']['id']
    if sender_id == receiver_id:
        return {'status': 'error', 'message': 'cannot_send_to_self'}, 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM students WHERE id = ?', (receiver_id,))
    if not c.fetchone():
        conn.close()
        return {'status': 'error', 'message': 'recipient_not_found'}, 404

    c.execute('SELECT * FROM group_requests WHERE sender_id = ? AND receiver_id = ? AND status = "pending"', (sender_id, receiver_id))
    if c.fetchone():
        conn.close()
        return {'status': 'error', 'message': 'already_sent'}, 409

    c.execute('INSERT INTO group_requests (sender_id, receiver_id, status) VALUES (?, ?, ?)', (sender_id, receiver_id, 'pending'))
    conn.commit()
    conn.close()
    return {'status': 'ok', 'message': 'request_sent'}


@app.route('/_find_student_by_reg')
def _find_student_by_reg():
    reg = request.args.get('reg')
    if not reg:
        return {'error': 'missing_reg'}, 400
    conn = get_db_connection()
    s = conn.execute('SELECT id, reg_no, name FROM students WHERE reg_no = ?', (reg,)).fetchone()
    conn.close()
    if not s:
        return {'error': 'not_found'}, 404
    return {'id': s['id'], 'reg_no': s['reg_no'], 'name': s['name']}


@app.route('/api/find_students')
def api_find_students():
    q = request.args.get('q', '').strip()
    if not q:
        return {'results': []}
    like = f"%{q}%"
    conn = get_db_connection()
    rows = conn.execute("SELECT id, reg_no, name FROM students WHERE name LIKE ? OR reg_no LIKE ? LIMIT 20", (like, like)).fetchall()
    conn.close()
    results = [{'id': r['id'], 'reg_no': r['reg_no'], 'name': r['name']} for r in rows]
    return {'results': results}


# ----------------- ADMIN DASHBOARD -----------------

@app.route('/admin/dashboard')
def admin_dashboard_panel():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM groups')
    groups = c.fetchall()

    c.execute('SELECT * FROM students')
    students = c.fetchall()

    settings = get_admin_settings()
    conn.close()

    return render_template('admin_dashboard.html', groups=groups, students=students, settings=settings, user=session['user'])



@app.route('/admin/delete_group/<int:group_id>')
def admin_delete_group(group_id):
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # clear students.group_id for members first
    c.execute('SELECT student_id FROM group_members WHERE group_id = ?', (group_id,))
    members = c.fetchall()
    for m in members:
        c.execute('UPDATE students SET group_id = NULL WHERE id = ?', (m[0],))
    c.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
    c.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    conn.commit()
    conn.close()
    return redirect('/admin/dashboard')


@app.route('/admin/update_settings', methods=['POST'])
def admin_update_settings():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect('/login')

    allow = int(request.form.get('allow_group_creation', 0))
    max_members = int(request.form.get('max_group_members', 5))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE admin_settings SET allow_group_creation=?, max_group_members=? WHERE id=1',
              (allow, max_members))
    conn.commit()
    conn.close()
    return redirect('/admin/dashboard')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080)

