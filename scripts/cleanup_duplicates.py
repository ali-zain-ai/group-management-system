import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()

# find duplicates
dup_ids = [r[0] for r in c.execute('SELECT student_id FROM group_members GROUP BY student_id HAVING COUNT(*)>1').fetchall()]
fixed = []
for sid in dup_ids:
    max_gid = c.execute('SELECT MAX(group_id) FROM group_members WHERE student_id=?', (sid,)).fetchone()[0]
    # delete other memberships
    c.execute('DELETE FROM group_members WHERE student_id=? AND group_id!=?', (sid, max_gid))
    fixed.append((sid, max_gid))

conn.commit()

# resync students.group_id
c.execute("UPDATE students SET group_id = (SELECT gm.group_id FROM group_members gm WHERE gm.student_id = students.id LIMIT 1)")
c.execute("UPDATE students SET group_id = NULL WHERE id NOT IN (SELECT student_id FROM group_members)")
conn.commit()

# create unique index
try:
    c.execute('CREATE UNIQUE INDEX IF NOT EXISTS ux_group_members_student ON group_members(student_id)')
    conn.commit()
except Exception as e:
    print('INDEX ERROR', e)

# print results
print('DUPLICATES_FIXED:', fixed)
print('\nSTUDENTS:')
for r in c.execute('SELECT id,reg_no,name,role,group_id FROM students'):
    print(r)
print('\nGROUP_MEMBERS:')
for r in c.execute('SELECT group_id,student_id FROM group_members'):
    print(r)
print('\nGROUPS:')
for r in c.execute('SELECT id,name,leader_id FROM groups'):
    print(r)
print('\nGROUP_REQUESTS:')
for r in c.execute('SELECT id,sender_id,receiver_id,status FROM group_requests'):
    print(r)

conn.close()
