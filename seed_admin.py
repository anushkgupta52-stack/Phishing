"""
seed_admin.py — run ONCE after schema.sql to set real password hashes.

Usage:
    python seed_admin.py
"""
import MySQLdb
from werkzeug.security import generate_password_hash

DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = 'your_mysql_password'   # ← change
DB_NAME = 'phishshield'

ACCOUNTS = [
    ('admin', 'Admin@1234'),
    ('demo',  'User@1234'),
]

conn = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASS, db=DB_NAME)
cur  = conn.cursor()
for username, password in ACCOUNTS:
    h = generate_password_hash(password)
    cur.execute("UPDATE users SET password=%s WHERE username=%s", (h, username))
    print(f'✓ Password set for  {username}')
conn.commit()
cur.close()
conn.close()
print('\nDone. You can now log in at http://localhost:5000')
