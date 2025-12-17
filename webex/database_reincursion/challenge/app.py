from flask import Flask, request, render_template, redirect, jsonify, url_for, session
import sqlite3, os

app = Flask(__name__)
app.config["SECRET_KEY"] = "b6ff48e4beb1b197a389062fa701e65bef43702505352c8cc7ed42b1df20de4e289fa6f68de9f1962e957476f3e7f3cfe25ccf3972e114679ea12a97738de267"

DB_PATH = os.path.join(os.path.dirname(__file__), 'ctf.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
        
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        print(f"[DEBUG] Login attempt: {username=} {password=}")

        blacklist = ["--","OR"]
        for bad in blacklist:
            if bad.lower() in username.lower() or bad.lower() in password.lower():
                return jsonify({"msg": "Citadel SysSec: Input rejected by security filter."}), 400

        if len(username) > 60 or len(password) > 60:
            return jsonify({"msg": "Citadel SysSec: Username/Password exceeds max length"}), 400

        conn = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"[DEBUG] Executing SQL: {query}")

        user = None
        try:
            user = conn.execute(query).fetchone()
        except Exception as e:
            print(f"[DEBUG] SQL Error: {e}")
        finally:
            conn.close()

        if user:
            session['logged_in'] = True
            session['username'] = user["username"] if "username" in user.keys() else "player"
            return jsonify({"success": True, "redirect": "/search"}), 200
        else:
            return jsonify({"msg": "Invalid username or password"}), 401

    return render_template("login.html")

@app.route("/search", methods=["GET", "POST"])
def search():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    results = []
    message = None
    conn = get_db()

    if request.method == "POST":
        term = request.form.get("term", "").strip()
        passcode = request.form.get("passcode", "").strip()

        if passcode == "ecSKsN7SES":
            session['username'] = "admin"
            conn.close()
            return jsonify({"success": True, "redirect": "/admin"}), 200
        elif passcode:
            message = "Invalid passcode"

        if term and not passcode:

            if "sqlite_master" in term.lower() or "sqlite_" in term.lower():
                 return render_template("search.html", results=[], message="Access denied: System tables blocked")

            if len(term) > 60:
                return render_template("search.html", results=[], message="Citadel SysSec: Query max length exceeded")
            
            blacklist = ["or","--"]
            for bad in blacklist:
                if bad in term.lower():
                    print(f"[DEBUG] Stage 2 blacklist triggered: {bad}")
                    conn.close()
                    return render_template("search.html", results=[], message="Citadel SysSec: Query blocked by input filter")

            query = (
                "SELECT id, name, department, email, notes "
                f"FROM employees WHERE name = '{term}' ORDER BY id LIMIT 4"
            )

            try:
                results = conn.execute(query).fetchall()
                results = results[:4]
            except Exception as e:
                message = f"SQL error: {e}"
    else:
        results = conn.execute(
            "SELECT id, name, department, email, notes FROM employees LIMIT 4"
        ).fetchall()

    conn.close()
    return render_template("search.html", results=results, message=message)


@app.route("/admin-login", methods=["POST"])
def admin_login():
    if not session.get('logged_in'):
        return jsonify({"msg": "Unauthorized"}), 401
        
    passcode = request.form.get("passcode", "").strip()
    if passcode == "ecSKsN7SES":
        session['username'] = "admin"
        return jsonify({"success": True, "redirect": "/admin"}), 200
    else:
        return jsonify({"msg": "Invalid passcode"}), 401

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('username') != 'admin':
        return redirect(url_for('search'))
        
    conn = get_db()
    metadata = conn.execute(
        "SELECT table_name, description, columns FROM metadata"
    ).fetchall()

    results = []
    message = None
    username = session.get('username', 'guest')

    if request.method == "POST":
        q = request.form.get("query", "").strip()

        if len(q) > 60:
            conn.close()
            return render_template(
                "admin.html",
                user=username,
                metadata=metadata,
                results=[],
                message="Citadel SysSec: Query max length exceeded"
            )
        if q:
            try:
                query = f"SELECT id, quarter, note, revenue FROM reports WHERE quarter LIKE '{q}'"
                print(f"[DEBUG] Admin executing: {query}")
                results = conn.execute(query).fetchall()
            except Exception as e:
                message = f"SQL error: {e}"
    else:
        results = conn.execute(
            "SELECT id, quarter, note, revenue FROM reports"
        ).fetchall()

    conn.close()
    return render_template("admin.html", user=username, metadata=metadata, results=results, message=message)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        conn.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS employees;
        DROP TABLE IF EXISTS secrets;
        DROP TABLE IF EXISTS reports;
        DROP TABLE IF EXISTS CITADEL_ARCHIVE_2077;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        );
                           
        INSERT INTO users (username, password) VALUES
        ('kwA9gKGmXKYFi1MbB2WGwcNdwTstr7XM', 'PcnqmffOwMyV9D14N8HXzvAxlV6VuYZ9');

        CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            department TEXT,
            position TEXT,
            email TEXT,
            notes TEXT
        );

        INSERT INTO employees (name, department, position, email, notes) VALUES
        
        ('Drake', 'Sushi Line', 'Sushi Packer', 'drake@citadel.com', 'I heard Kiwi from Management has the passcode'),
        ('Josh', 'Sushi Line', 'Sushi Packer', 'josh@citadel.com', 'No special access'),
        ('Lewis', 'IT', 'Sysadmin', 'bluexephos@citadel.com', 'No special access'),                   
        ('Simon', 'IT', 'Sysadmin', 'honeydew@citadel.com', 'No special access'),
        ('Duncan', 'IT', 'Sysadmin', 'lividcoffee@citadel.com', 'No special access'),
        ('David', 'Management', 'Assistant Manager', 'Davide@citadel.com', 'Talk to Kiwi, she has the passcode.'),
        ('Lucy', 'Management', 'Assistant Manager', 'Lucy@citadel.com', 'No special access'),
        ('Rebecca', 'Management', 'Assistant Manager', 'Becky@citadel.com', 'No special access'),
        ('Maine', 'Management', 'Assistant Manager', 'Maine@citadel.com', 'No special access'),
        ('Kiwi', 'Finances', 'CFO', 'KiwiF@citadel.com', 'No special access'),
        ('Kiwi', 'IT', 'CTO', 'KiwiT@citadel.com', 'No special access'),
        ('Kiwi', 'Operations', 'COO', 'KiwiO@citadel.com', 'No special access'),
        ('Kiwi', 'Marketing', 'CBO', 'KiwiM@citadel.com', 'No special access'),
        ('Kiwi', 'Management', 'CEO', 'Kiwi@citadel.com', 'Passcode: ecSKsN7SES');
                           
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quarter TEXT,
            note TEXT,
            revenue TEXT 
        );
        
        INSERT INTO reports (quarter, note, revenue) VALUES
                           
        ('Q1','profit', '$1,200,000'),
        ('Q2','loss', '$980,000'),
        ('Q3','profit', '$1,300,000'),
        ('Q4','profit', '$1,100,000');
                           
        CREATE TABLE metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT,
            description TEXT,
            columns TEXT
        );
                           
        INSERT INTO metadata (table_name, description,columns) VALUES
        ('reports', 'Quarterly revenue data for executives','quarter, note, revenue'),
        ('users', 'Stores usernames and passwords','username, password'),
        ('employees', 'Directory of employees and their notes','name, department, email, position, notes'),
        ('metadata', 'Lists tables in this system','table_name, description, columns'),
        ('CITADEL_ARCHIVE_2077', 'Restricted info (to be redacted by intern)','secrets');

        CREATE TABLE CITADEL_ARCHIVE_2077 (
            secrets TEXT
        );
                           
        INSERT INTO CITADEL_ARCHIVE_2077 (secrets) VALUES
        ('nite{neVeR_9Onn4_57OP_WonDER1N9_1f_175_5ql_oR_5EKWeL}');
        """)

        conn.commit()
        conn.close()
    app.run(host="127.0.0.1", port=5000, debug=False)

