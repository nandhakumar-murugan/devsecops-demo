# Student: NANDHAKUMAR M (Reg No: 711724UCY129)
# EX.NO: 08 - OPEN ENDED EXPERIMENT: SECURE STUDENT PORTAL WITH SECURITY AUDITING

from flask import Flask, request, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get("PORTAL_SECRET", "nandhakumar_secure_key_711724UCY129")

curr_dir = os.path.dirname(os.path.abspath(__file__))
log_file_path = os.path.join(curr_dir, "audit.log")

# Registered Demo Users
users = {
    "nandhakumar": {
        "password": generate_password_hash("Nandha@123"),
        "role": "student"
    },
    "student1": {
        "password": generate_password_hash("Student@123"),
        "role": "student"
    },
    "admin1": {
        "password": generate_password_hash("Admin@123"),
        "role": "admin"
    }
}

marks = {
    "nandhakumar": 98,
    "student1": 85
}

def audit(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file_path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] - {message}\n")
    print(f"[AUDIT] {message}")

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

def login_required(role=None):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            username = session.get("username")
            if not username or username not in users:
                audit(f"Unauthorized access attempt to {request.path}")
                return "Please login first", 401
            if role and users[username]["role"] != role:
                audit(f"Access denied for user '{username}' (Requires role: '{role}')")
                return "Forbidden: insufficient permissions", 403
            return function(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/")
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Secure Student Portal</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>KGiSL Institute of Technology - Secure Student Portal</h2>
        <p><b>Course:</b> 24UCY511 Secure Software Systems | <b>Student:</b> NANDHAKUMAR M (711724UCY129)</p>
        <div style="border: 1px solid #ccc; padding: 20px; width: 350px; border-radius: 6px;">
            <h3>Login</h3>
            <form method="post" action="/login">
                Username: <br><input name="username" style="width: 100%; margin-bottom: 10px;" required><br>
                Password: <br><input type="password" name="password" style="width: 100%; margin-bottom: 15px;" required><br>
                <button type="submit" style="padding: 8px 16px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer;">Login</button>
            </form>
            <p style="font-size: 12px; color: #666; margin-top: 15px;">
                Demo Credentials:<br>
                Student: <code>nandhakumar</code> / <code>Nandha@123</code><br>
                Admin: <code>admin1</code> / <code>Admin@123</code>
            </p>
        </div>
    </body>
    </html>
    '''

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
        audit("Rejected invalid username syntax")
        return "Invalid input syntax for username", 400

    user = users.get(username)
    if user and check_password_hash(user["password"], password):
        session.clear()
        session["username"] = username
        audit(f"Login successful for user: {username}")
        return redirect("/dashboard")

    audit(f"Login failed for username: {username}")
    return "Invalid username or password", 401

@app.route("/dashboard")
@login_required()
def dashboard():
    username = session["username"]
    role = users[username]["role"]
    if role == "admin":
        return f'''
        <div style="font-family: Arial; margin: 40px;">
            <h2>Admin Dashboard</h2>
            <p>Welcome, Administrator ({username})</p>
            <p><a href="/admin">Manage Marks</a> | <a href="/logout">Logout</a></p>
        </div>
        '''
    return f'''
    <div style="font-family: Arial; margin: 40px;">
        <h2>Student Dashboard</h2>
        <p>Welcome, <b>{username}</b></p>
        <p><a href="/marks">View My Marks</a> | <a href="/logout">Logout</a></p>
    </div>
    '''

@app.route("/marks")
@login_required()
def view_marks():
    username = session["username"]
    student_mark = marks.get(username, "Not available")
    return f'''
    <div style="font-family: Arial; margin: 40px;">
        <h2>Academic Performance</h2>
        <p>Student Username: <b>{username}</b></p>
        <p>Marks Awarded: <b>{student_mark} / 100</b></p>
        <p><a href="/dashboard">Back to Dashboard</a> | <a href="/logout">Logout</a></p>
    </div>
    '''

@app.route("/admin", methods=["GET", "POST"])
@login_required("admin")
def admin():
    if request.method == "POST":
        student = request.form.get("student", "").strip()
        score = request.form.get("score", "").strip()
        if student not in marks or not score.isdigit():
            return "Invalid student or marks", 400
        val = int(score)
        if not 0 <= val <= 100:
            return "Marks must be between 0 and 100", 400

        marks[student] = val
        audit(f"Admin updated marks for {student} to {val}")
        return f'''
        <div style="font-family: Arial; margin: 40px;">
            <p style="color: green;">Marks updated successfully for {student}!</p>
            <p><a href="/admin">Back</a> | <a href="/dashboard">Dashboard</a></p>
        </div>
        '''

    return '''
    <div style="font-family: Arial; margin: 40px;">
        <h2>Admin: Update Student Marks</h2>
        <form method="post">
            Student Username: <br><input name="student" required><br><br>
            Marks (0-100): <br><input name="score" type="number" min="0" max="100" required><br><br>
            <button type="submit">Update Marks</button>
        </form>
        <p><a href="/dashboard">Back to Dashboard</a></p>
    </div>
    '''

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    audit(f"Logout successful for user: {username}")
    return redirect("/")

if __name__ == "__main__":
    print(f"Secure Student Portal running at http://127.0.0.1:5000")
    print(f"Audit log saved to: {log_file_path}")
    app.run(host="127.0.0.1", port=5000, debug=False)
