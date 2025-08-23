# app.py
from flask import Flask, request, render_template, redirect, url_for, flash
import sqlite3
import os
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB_NAME = "database.db"

def init_db():
    """Initialize the database and insert sample data"""
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT
        )
    ''')
    # Insert sample user (vulnerable: plaintext password)
    cur.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", "password123"))
    # Insert sample products
    sample_products = [
        ("Laptop", "High-performance laptop"),
        ("Phone", "Latest smartphone"),
        ("Tablet", "Portable tablet device")
    ]
    cur.executemany("INSERT OR IGNORE INTO products (name, description) VALUES (?, ?)", sample_products)
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

# ❌ VULNERABLE Login (SQLi-prone)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        # 🔥 VULNERABLE: Direct string formatting (SQLi possible)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print("Executing:", query)  # For logs/detection

        try:
            cur.execute(query)
            user = cur.fetchone()
            conn.close()

            if user:
                flash("Login successful!", "success")
                return redirect(url_for('index'))
            else:
                flash("Invalid credentials.", "error")
        except Exception as e:
            flash(f"Database error: {str(e)}", "error")
            print("SQL Error:", str(e))  # For detection

    return render_template('login.html')

# ❌ VULNERABLE Search (SQLi-prone)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []

    if query:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        # 🔥 VULNERABLE: Unsanitized input
        sql = f"SELECT name, description FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
        print("Search query:", sql)

        try:
            cur.execute(sql)
            results = cur.fetchall()
        except Exception as e:
            print("Search error:", str(e))
        conn.close()

    return render_template('search.html', results=results, query=query)

# ✅ SECURE Login Demo (Parameterized)
@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        # ✅ SAFE: Parameterized query
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cur.fetchone()
        conn.close()

        if user:
            flash("✅ Secure login successful!", "success")
        else:
            flash("❌ Invalid credentials.", "error")

    return render_template('secure_demo.html')

if __name__ == '__main__':
    if not os.path.exists(DB_NAME):
        init_db()
    app.run(debug=True, port=5000)