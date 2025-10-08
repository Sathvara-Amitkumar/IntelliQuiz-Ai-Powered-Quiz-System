# app.py - Final Version with Admin Panel Logic

import os
import sqlite3
import json
import functools
import random
import time
import string
import sys
import csv
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from flask import request, jsonify, send_file
import google.oauth2.id_token
import google.auth.transport.requests


# Add the project root directory to Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.append(project_root)

from flask import (
    Flask, render_template, request, jsonify, session, redirect, url_for, g,
    Blueprint, flash, current_app
)
from dotenv import load_dotenv
from utils.session_store import SessionStore
from werkzeug.exceptions import HTTPException
from flask import make_response

load_dotenv()

# --- Database Functions ---
def get_db():
    if 'db' not in g:
        try:
            g.db = sqlite3.connect(
                os.path.join(current_app.instance_path, 'quiz_database.db'),
                detect_types=sqlite3.PARSE_DECLTYPES,
                timeout=30.0,  # 30 second timeout for locks
                isolation_level='IMMEDIATE',  # Use immediate transaction mode
                check_same_thread=False
            )
            g.db.row_factory = sqlite3.Row
            
            # Enable WAL mode and set pragmas for better concurrency
            g.db.execute('PRAGMA journal_mode=WAL')
            g.db.execute('PRAGMA busy_timeout=30000')  # 30 second busy timeout
            g.db.execute('PRAGMA synchronous=NORMAL')  # Better performance with acceptable safety
            
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            raise
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        try:
            db.commit()  # Commit any pending transactions
        except sqlite3.Error:
            db.rollback()  # Rollback if commit fails
        finally:
            db.close()

def init_db():
    db = get_db()
    try:
        # First check if we can connect to the database
        db.execute('SELECT 1').fetchone()
        # If we get here, the database exists and we can connect
        # Check if tables exist by querying the sqlite_master table
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        if len(tables) > 0:  # Tables exist, skip initialization
            return
    except sqlite3.Error:
        # If we can't connect, the database might be corrupted
        db_path = os.path.join(current_app.instance_path, 'quiz_database.db')
        if os.path.exists(db_path):
            # Create a backup before removing
            backup_path = f"{db_path}.bak"
            try:
                os.rename(db_path, backup_path)
            except OSError as e:
                print(f"Warning: Could not create backup: {e}")
            os.remove(db_path) if os.path.exists(db_path) else None
    
    # Apply schema only if tables don't exist
    try:
        with current_app.open_resource('database.sql') as f:
            db.executescript(f.read().decode('utf8'))
        db.commit()
        print("Database initialized successfully.")
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to initialize database: {e}")

def init_app_commands(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db_path = os.path.join(app.instance_path, 'quiz_database.db')
        
        # Ensure instance folder exists
        os.makedirs(app.instance_path, exist_ok=True)
        
        try:
            # Try to initialize/update schema
            init_db()
            print("Database schema ensured.")
            
            # Verify critical tables exist
            db = get_db()
            tables = ['users', 'quizzes', 'questions', 'results', 'student_answers', 'activity_log']
            for table in tables:
                try:
                    db.execute(f'SELECT 1 FROM {table} LIMIT 1')
                except sqlite3.OperationalError:
                    raise Exception(f"Critical table '{table}' is missing")
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            if os.path.exists(db_path):
                print("Attempting to fix corrupt database...")
                backup_path = f"{db_path}.{int(time.time())}.bak"
                try:
                    os.rename(db_path, backup_path)
                    print(f"Created backup at {backup_path}")
                except OSError as e:
                    print(f"Warning: Could not create backup: {e}")
                
                try:
                    os.remove(db_path) if os.path.exists(db_path) else None
                    init_db()
                    print("Database reinitialized successfully.")
                except Exception as e:
                    print(f"Fatal error: Could not reinitialize database: {e}")
                    raise

# --- Email Functions ---
def send_email(to_email, subject, html_content):
    # Get email configuration from .env
    smtp_server = os.getenv("MAIL_SERVER")
    smtp_port = int(os.getenv("MAIL_PORT"))
    sender_email = os.getenv("MAIL_USERNAME")
    sender_password = os.getenv("MAIL_PASSWORD")

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = f'"IntelliQuiz" <{sender_email}>'
    message["To"] = to_email

    part = MIMEText(html_content, "html")
    message.attach(part)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, message.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False

def send_student_email(to_email, username, password):
    subject = "Your IntelliQuiz Account details"
    html = f"""
    <html>
        <body>
            <p>Hello {username},</p>
            <p>Your IntelliQuiz account has been created.</p>
            <p>You can log in with the following credentials:</p>
            <ul>
                <li><b>Username:</b> {to_email}</li>
                <li><b>Password:</b> {password}</li>
            </ul>
            <p>Please keep these credentials secure.</p>
        </body>
    </html>
    """
    return send_email(to_email, subject, html)

# --- Blueprints & Auth ---
bp_main = Blueprint('main', __name__, url_prefix='/')
bp_auth = Blueprint('auth', __name__, url_prefix='/auth')
bp_teacher = Blueprint('teacher', __name__, url_prefix='/teacher')
bp_student = Blueprint('student', __name__, url_prefix='/student')
bp_admin = Blueprint('admin', __name__, url_prefix='/admin')


# --- FIXED LOGIN DECORATOR ---
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            # For API requests, return a JSON error instead of redirecting
            if request.path.startswith('/api/') or request.path.startswith('/teacher/api/') or request.path.startswith('/student/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            # For regular pages, redirect to the main page
            return redirect(url_for('main.index'))
        return view(**kwargs)
    return wrapped_view

# --- NEW: ADMIN REQUIRED DECORATOR ---
def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Permission denied. Admin access is required.', 'error')
            return redirect(url_for('main.index'))
        return view(**kwargs)
    return wrapped_view

# --- NEW: DECORATOR FOR TEACHER OR ADMIN ACCESS ---
def teacher_or_admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session or (session.get('role') != 'teacher' and session.get('role') != 'admin'):
            flash('Permission denied. Admin or Teacher access is required.', 'error')
            return redirect(url_for('main.index'))
        return view(**kwargs)
    return wrapped_view


@bp_main.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'teacher' or role == 'student':
            return redirect(url_for(f"{role}.dashboard"))
        elif role == 'admin':
            return redirect(url_for("admin.dashboard"))
    return render_template('index.html')

# ------------------------------------------------------------------------
# google log-in
@bp_auth.route('auth/google-login/<role>', methods=['POST'])
def google_login(role):
    data = request.get_json()
    token = data.get('credential')
    try:
        # Verify the token
        idinfo = google.oauth2.id_token.verify_oauth2_token(
            token,
            google.auth.transport.requests.Request(),
            os.getenv("GOOGLE_CLIENT_ID")
        )

        google_email = idinfo['email']
        google_name = idinfo.get('name', google_email.split('@')[0]) # Use email prefix if name not available

        db = get_db()
        user = db.execute('SELECT id, username, email, role FROM users WHERE email = ?', (google_email,)).fetchone()

        if user is None:
            # User does not exist, create a new one
            # For Google sign-in, password can be a placeholder or randomly generated
            # We'll use the google_name as username, but it can be null in the schema
            cursor = db.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (google_name, google_email, "google_auth_placeholder", role)
            )
            db.commit()
            user_id = cursor.lastrowid
            username = google_name
        else:
            # User exists, log them in
            user_id = user['id']
            username = user['username'] # Use existing username

        session.clear()
        session['user_id'] = user_id
        session['role'] = role
        session['username'] = username

        print("Received token:", token)
        print(f"User {username} ({google_email}) logged in with role {role}.")
        return jsonify(success=True, redirect_url=url_for(f"{role}.dashboard"))

    except Exception as e:
        print("Google sign-in error:", e)
        return jsonify(success=False, message=f"Google sign-in failed: {str(e)}"), 400
# -------------------------------------------------------------------------

# --- Authentication Routes ---
# @bp_auth.route('/login/<role>', methods=('GET', 'POST'))
# def login(role):
#     if role not in ['teacher', 'student', 'admin']:
#         return redirect(url_for('main.index'))
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         remember_me = request.form.get('remember_me', False)
#         db = get_db()
#         user = db.execute('SELECT * FROM users WHERE username = ? AND password = ? AND role = ?', (username, password, role)).fetchone()
        
#         if user:
#             ip = request.remote_addr
            
#             try:
#                 db.execute('BEGIN IMMEDIATE')
#                 recent_login = db.execute('SELECT ip FROM activity_log WHERE student_id = ? AND action = "login" ORDER BY timestamp DESC LIMIT 1', (user['id'],)).fetchone()
                
#                 if session.get('user_id') == user['id']:
#                     flash('Duplicate login detected. You are already logged in elsewhere.')
#                     db.rollback() 
#                     return redirect(url_for('main.index'))
#                 if recent_login and recent_login['ip'] != ip:
#                     db.execute('INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
#                                (user['id'], None, 'multi_login_ip', ip, int(time.time())))
                
#                 db.execute('INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
#                            (user['id'], None, 'login', ip, int(time.time())))
#                 db.commit()
#             except sqlite3.OperationalError as e:
#                 db.rollback()
#                 print(f"Warning: Failed to log login attempt due to locked database: {e}")
            
#             session_store = SessionStore(current_app.instance_path)
#             session_store.store_user_session(user['id'], user['username'], user['role'], password)
            
#             session.clear()
#             session.permanent = remember_me
#             session['user_id'] = user['id']
#             session['role'] = user['role']
#             session['username'] = user['username']
            
#             return redirect(url_for(f"{role}.dashboard"))
            
#         else:
#             ip = request.remote_addr
#             try:
#                 db.execute('INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
#                     (None, None, 'failed_login', ip, int(time.time())))
#                 db.commit()
#             except sqlite3.OperationalError as e:
#                 db.rollback()
#                 print(f"Warning: Failed to log failed login attempt due to locked database: {e}")
            
#             flash('Invalid credentials or incorrect role.')
#             return render_template('login.html', role=role)
    
#     return render_template('login.html', role=role)

@bp_auth.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    role = request.form.get('role')

    if not role:
        flash('Please select a role to log in.', 'error')
        return redirect(url_for('main.index'))

    db = get_db()
    user = None

    # Handle hardcoded admin login
    if role == 'admin':
        admin_user_env = os.getenv('ADMIN_USERNAME')
        admin_pass_env = os.getenv('ADMIN_PASSWORD')
        if username == admin_user_env and password == admin_pass_env:
            user = db.execute('SELECT * FROM users WHERE username = ? AND role = "admin"', (username,)).fetchone()
    # Handle student and teacher login from the database
    else:
        user = db.execute('SELECT * FROM users WHERE email = ? AND password = ? AND role = ?', (username, password, role)).fetchone()

    # If login is successful, create the session
    if user:
        session.clear()
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['username'] = user['username']
        # Redirect to the correct dashboard
        return redirect(url_for(f"{role}.dashboard"))
    else:
        # If login fails
        flash('Invalid credentials or incorrect role.', 'danger')
        return redirect(url_for('main.index'))

@bp_auth.route('/signup/<role>', methods=('GET', 'POST'))
def signup(role):
    if role not in ['teacher', 'student', 'admin']:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login', role=role))
        except sqlite3.IntegrityError:
            flash(f"User '{username}' is already registered.", 'error')
    return render_template('signup.html', role=role)

@bp_auth.route('/logout')
def logout():
    if 'user_id' in session:
        # Clear stored credentials
        session_store = SessionStore(current_app.instance_path)
        session_store.clear_user_session(session['user_id'])
    session.clear()
    return redirect(url_for('main.index'))

# --- Teacher Routes ---
@bp_teacher.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    quizzes_raw = db.execute(
        'SELECT q.*, COUNT(qu.id) as question_count FROM quizzes q LEFT JOIN questions qu ON q.id = qu.quiz_id WHERE q.teacher_id = ? GROUP BY q.id ORDER BY q.created_at DESC',
        (session['user_id'],)
    ).fetchall()
    quiz_count = db.execute('SELECT COUNT(*) FROM quizzes WHERE teacher_id = ?', (session['user_id'],)).fetchone()[0]
    student_count = db.execute('SELECT COUNT(*) FROM users WHERE role = "student"').fetchone()[0]
    recent_activity = []
    # Example: last 5 quizzes created
    recent_quizzes = db.execute('SELECT title, created_at FROM quizzes WHERE teacher_id = ? ORDER BY created_at DESC LIMIT 5', (session['user_id'],)).fetchall()
    for q in recent_quizzes:
        recent_activity.append(f"Created quiz '{q['title']}' on {q['created_at']}")
    students = db.execute('SELECT id, username FROM users WHERE role = "student"').fetchall()
    # Suspicious activity log for teacher
    suspicious_logs = db.execute('SELECT a.student_id, u.username, a.quiz_id, q.title, a.action, a.timestamp FROM activity_log a JOIN users u ON a.student_id = u.id JOIN quizzes q ON a.quiz_id = q.id WHERE a.action IN ("plagiarism_detected", "tab_switch", "unusual_pattern") ORDER BY a.timestamp DESC LIMIT 20').fetchall()
    # Student performance analytics
    student_performance = []
    for student in students:
        avg_score = db.execute('SELECT AVG(score) FROM results WHERE student_id = ?', (student['id'],)).fetchone()[0]
        last_quiz = db.execute('SELECT MAX(quiz_id) FROM results WHERE student_id = ?', (student['id'],)).fetchone()[0]
        
        # Convert average score to float or None
        if avg_score is not None:
            try:
                avg_score = float(avg_score)
                avg_score = round(avg_score, 2)
            except (ValueError, TypeError):
                avg_score = None
        
        student_performance.append({
            'id': student['id'],
            'username': student['username'],
            'avg_score': avg_score,  # Now it's either a float or None
            'last_quiz': last_quiz if last_quiz is not None else None
        })

    # Quiz management actions (edit, delete, duplicate)
    # Pass quizzes_raw as quizzes, each quiz will have id, title, etc.
    return render_template(
        'teacher_dashboard_new.html',
        quizzes=quizzes_raw,
        username=session.get('username'),
        quiz_count=quiz_count,
        student_count=student_count,
        recent_activity=recent_activity,
        students=students,
        student_performance=student_performance,
        suspicious_logs=suspicious_logs
    )

# Sending Mails
def send_quiz_invitation_email(to_email, quiz_title, room_code):
    """Helper function to format and send the quiz invitation email."""
    subject = f"Invitation to take quiz: {quiz_title}"
    html_content = f"""
    <html>
        <body>
            <p>Hello Student,</p>
            <p>You have been invited to take the quiz titled "<h3 style="color:black;">{quiz_title}</h3>".</p>
            <p>Please use the following room code to access the quiz:</p>
            <h2 style="color:#7367F0;">{room_code}</h2>
            <p>Good luck!</p>
        </body>
    </html>
    """
    # This assumes you have a generic send_email function like the one we built for the admin panel
    return send_email(to_email, subject, html_content)


@bp_teacher.route('/send_quiz_invite', methods=['POST'])
@login_required
def send_quiz_invite():
    if session.get('role') != 'teacher':
        return redirect(url_for('main.index'))

    quiz_id = request.form.get('quiz_id')
    if not quiz_id:
        flash('Please select a quiz to send invites for.', 'danger')
        return redirect(url_for('teacher.dashboard'))

    db = get_db()
    
    # Get the selected quiz's details
    quiz = db.execute('SELECT title, room_code FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    if not quiz or not quiz['room_code']:
        flash('Selected quiz does not exist or has no room code.', 'danger')
        return redirect(url_for('teacher.dashboard'))
        
    # Get all student emails
    students = db.execute("SELECT email FROM users WHERE role = 'student'").fetchall()
    student_emails = [student['email'] for student in students]
    
    if not student_emails:
        flash('There are no students to send invitations to.', 'warning')
        return redirect(url_for('teacher.dashboard'))
        
    # Send the email to every student
    success_count = 0
    for email in student_emails:
        if send_quiz_invitation_email(email, quiz['title'], quiz['room_code']):
            success_count += 1
            
    flash(f'Successfully sent quiz invitation to {success_count} student(s).', 'success')
    return redirect(url_for('teacher.dashboard'))

# Clear logs funcctionality
@bp_teacher.route('/clear_logs', methods=['POST'])
@login_required
def clear_suspicious_logs():
    # Ensure the user is a teacher
    if session.get('role') != 'teacher':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.index'))

    teacher_id = session.get('user_id')
    db = get_db()

    # Security check: Get all quiz IDs that belong to the current teacher
    teacher_quizzes = db.execute('SELECT id FROM quizzes WHERE teacher_id = ?', (teacher_id,)).fetchall()
    
    if not teacher_quizzes:
        flash('You have no quizzes to clear logs for.', 'info')
        return redirect(url_for('teacher.dashboard'))

    # Create a tuple of quiz IDs to safely use in the SQL query
    quiz_ids_tuple = tuple([q['id'] for q in teacher_quizzes])

    try:
        # Delete only the logs associated with this teacher's quizzes
        cursor = db.execute(
            f'DELETE FROM activity_log WHERE quiz_id IN ({",".join("?" * len(quiz_ids_tuple))})',
            quiz_ids_tuple
        )
        db.commit()
        
        if cursor.rowcount > 0:
            flash(f'Successfully cleared {cursor.rowcount} suspicious activity logs.', 'success')
        else:
            flash('No suspicious activity logs were found to clear.', 'info')

    except sqlite3.Error as e:
        db.rollback()
        flash(f'An error occurred: {e}', 'danger')
        
    return redirect(url_for('teacher.dashboard'))


# --- Teacher: Create Quiz (GET) ---
@bp_teacher.route('/create')
@teacher_or_admin_required # NEW: Use the new decorator
def create_quiz():
    return render_template('create_quiz.html')

# --- Teacher: Preview Generated Questions (POST) ---
@bp_teacher.route('/preview', methods=['POST'])
@teacher_or_admin_required # NEW: Use the new decorator
def preview_generated_questions():
    data = request.form
    if not data:
        return render_template('generated_questions.html',
                            questions=[],
                            error="No form data provided",
                            saved_files=[],
                            viva=False)
    
    viva_mode = data.get('mode', 'mcq') == 'viva'
    
    try:
        num_questions = int(data.get('num_questions', 5))
        if num_questions <= 0 or num_questions > 50:
            return render_template('generated_questions.html',
                                questions=[],
                                error="Number of questions must be between 1 and 50",
                                saved_files=[],
                                viva=viva_mode)
    except ValueError:
        return render_template('generated_questions.html',
                            questions=[],
                            error="Invalid number of questions",
                            saved_files=[],
                            viva=viva_mode)
    
    # Initialize variables
    manual_questions_raw = data.get('manual_questions', '').strip()
    manual_questions = []
    has_manual_input = bool(manual_questions_raw)
    has_file_upload = bool(request.files.getlist('question_files'))
    prompt = data.get('prompt', '').strip()
    
    # First try to process manual questions and files
    if not has_manual_input and not has_file_upload and not prompt:
        return render_template('generated_questions.html',
                            questions=[],
                            error="Please either enter manual questions, upload a file, or provide an AI prompt",
                            saved_files=[],
                            viva=viva_mode)
    
    # Only set up AI if we need it (no manual input and no files, but has prompt)
    if not has_manual_input and not has_file_upload and prompt:
        client = None
        groq_api_key = os.getenv('GROQ_API_KEY', '').strip()
        
        # Validate API key format only if using AI generation
        if not groq_api_key or not groq_api_key.startswith('gsk_'):
            error_msg = "Invalid or missing Groq API key. Please check your .env file."
            return render_template('generated_questions.html', 
                                questions=[], 
                                error=error_msg,
                                saved_files=[],
                                viva=viva_mode)
    
    # Process manual questions first
    if has_manual_input:
        for line in manual_questions_raw.splitlines():
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 1:
                continue
            if viva_mode:
                manual_questions.append({ 'text': parts[0], 'type': 'viva' })
            else:
                if len(parts) < 3:
                    continue
                question_text = parts[0]
                try:
                    if parts[-1].isdigit():
                        correct_index = int(parts[-1])
                        options = parts[1:-1]
                    else:
                        options = parts[1:]
                        correct_index = 0
                    if options and 0 <= correct_index < len(options):
                        manual_questions.append({ 'text': question_text, 'options': options, 'correct_answer': correct_index, 'type': 'mcq' })
                except (ValueError, IndexError):
                    continue
        if manual_questions:
            return render_template('generated_questions.html', questions=manual_questions, error=None, saved_files=[], viva=viva_mode)

    # Handle file uploads in a try-except block
    saved_files = []
    try:
        uploaded_files = request.files.getlist('question_files')
        if uploaded_files:
            upload_folder = os.path.join(current_app.root_path, 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            
            for file in uploaded_files:
                if file and file.filename:
                    # Only accept txt files
                    if not file.filename.lower().endswith('.txt'):
                        continue
                        
                    filename = file.filename
                    save_path = os.path.join(upload_folder, filename)
                    file.save(save_path)
                    saved_files.append(filename)
                    
                    # Read questions from the file
                    try:
                        with open(save_path, 'r', encoding='utf-8') as f:
                            file_content = f.read().strip()
                            if file_content:
                                for line in file_content.splitlines():
                                    parts = [p.strip() for p in line.split('|')]
                                    if len(parts) < 1:
                                        continue
                                    if viva_mode:
                                        manual_questions.append({ 'text': parts[0], 'type': 'viva' })
                                    else:
                                        if len(parts) < 3:
                                            continue
                                        try:
                                            if parts[-1].isdigit():
                                                correct_index = int(parts[-1])
                                                options = parts[1:-1]
                                            else:
                                                options = parts[1:]
                                                correct_index = 0
                                            if options and 0 <= correct_index < len(options):
                                                manual_questions.append({ 'text': parts[0], 'options': options, 'correct_answer': correct_index, 'type': 'mcq' })
                                        except (ValueError, IndexError):
                                            continue
                    except Exception as e:
                        print(f"Error reading file {filename}: {e}")
                        
        # If we have questions from files, return them
        if manual_questions:
            return render_template('generated_questions.html',
                                questions=manual_questions,
                                error=None,
                                saved_files=saved_files,
                                viva=viva_mode)
                                
    except Exception as e:
        print(f"Error handling file uploads: {e}")
        # Continue execution even if file uploads fail
        
    # If we still have no questions after processing everything, show error
    if not manual_questions and not prompt:
        return render_template('generated_questions.html',
                            questions=[],
                            error="No valid questions found. Please check your input format.",
                            saved_files=saved_files,
                            viva=viva_mode)
                            
    # If we have manual questions, no need to proceed with AI generation
    if manual_questions:
        return render_template('generated_questions.html',
                            questions=manual_questions,
                            error=None,
                            saved_files=saved_files,
                            viva=viva_mode)

    if manual_questions_raw:
        for line in manual_questions_raw.splitlines():
            parts = line.split('|')
            if len(parts) >= 2:
                if viva_mode:
                    manual_questions.append({'text': parts[0]})
                else:
                    # MCQ: Question|Option1|Option2|Option3|CorrectOptionIndex
                    opts = parts[1:-1]
                    try:
                        correct = int(parts[-1])
                    except:
                        correct = 0
                    manual_questions.append({'text': parts[0], 'options': opts, 'answer': opts[correct] if 0 <= correct < len(opts) else None})
    if viva_mode:
        if not client:
            error_msg = "Groq API key not found or Groq SDK not installed. AI question generation is disabled."
            questions = manual_questions
            return render_template('generated_questions.html', questions=questions, viva=True, error=error_msg, saved_files=saved_files)
        system_prompt = "You are an expert examiner. Generate open-ended viva questions in a strict JSON format. The root of the JSON should be a list of question objects. Each object must have a 'question' (string)."
        user_prompt = f"Generate {num_questions} open-ended viva questions about: {prompt}."
        questions = []
        if manual_questions:
            questions.extend(manual_questions)
        try:
            completion = client.chat.completions.create(
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                model="llama3-8b-8192", response_format={"type": "json_object"}
            )
            response_content = completion.choices[0].message.content
            data = json.loads(response_content)
            if isinstance(data, list):
                questions.extend([{'text': q['question']} for q in data])
            elif isinstance(data, dict):
                key = next(iter(data))
                questions.extend([{'text': q['question']} for q in data[key]])
            else:
                raise ValueError("Unexpected JSON format for viva questions.")
        except Exception as e:
            return render_template('generated_questions.html', questions=None, error=f"Failed to generate viva questions: {e}", saved_files=saved_files)
        return render_template('generated_questions.html', questions=questions, viva=True, saved_files=saved_files)
    else:
        if not client:
            error_msg = "Groq API key not found or Groq SDK not installed. AI question generation is disabled."
            display_questions = manual_questions
            return render_template('generated_questions.html', questions=display_questions, viva=False, error=error_msg, saved_files=saved_files)
        # MCQ mode
        system_prompt = "You are an expert quiz creator. Generate multiple-choice questions in a strict JSON format. The root of the JSON should be a list of question objects. Each object must have three keys: 'question' (a string), 'options' (a list of strings), and 'correct_answer' (a 0-indexed integer)."
        user_prompt = f"Generate {num_questions} multiple-choice questions about: {prompt}."
        display_questions = []
        if manual_questions:
            display_questions.extend(manual_questions)
        try:
            # Test API key with a simple request first
            try:
                completion = client.chat.completions.create(
                    messages=[{"role": "system", "content": "Test"}, {"role": "user", "content": "Test"}],
                    model="llama3-8b-8192"
                )
            except Exception as api_error:
                if "invalid_api_key" in str(api_error):
                    error_msg = "Invalid Groq API key. Please check your API key in the .env file."
                else:
                    error_msg = f"Groq API error: {str(api_error)}"
                return render_template('generated_questions.html',
                                    questions=manual_questions,
                                    error=error_msg,
                                    saved_files=saved_files,
                                    viva=viva_mode)

            # If API key is valid, proceed with question generation
            completion = client.chat.completions.create(
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                model="llama3-8b-8192", response_format={"type": "json_object"}
            )
            response_content = completion.choices[0].message.content
            data = json.loads(response_content)
            for q in data:
                display_questions.append({
                    'text': q['question'],
                    'options': q['options'],
                    'answer': q['options'][q['correct_answer']] if 'correct_answer' in q and isinstance(q['correct_answer'], int) and 0 <= q['correct_answer'] < len(q['options']) else None
                })
        except Exception as e:
            error_msg = "Error generating questions. Falling back to manual questions."
            if manual_questions:
                return render_template('generated_questions.html',
                                    questions=manual_questions,
                                    error=error_msg,
                                    saved_files=saved_files,
                                    viva=viva_mode)
            else:
                return render_template('generated_questions.html',
                                    questions=None,
                                    error=f"{error_msg} Please add manual questions or check API configuration.",
                                    saved_files=saved_files,
                                    viva=viva_mode)
        return render_template('generated_questions.html', questions=display_questions, viva=False, saved_files=saved_files)

@bp_teacher.route('/quiz/<int:quiz_id>')
@login_required
def quiz_details(quiz_id):
    db = get_db()
    quiz = db.execute(
        'SELECT q.*, COUNT(qu.id) as question_count FROM quizzes q LEFT JOIN questions qu ON q.id = qu.quiz_id WHERE q.id = ? AND q.teacher_id = ? GROUP BY q.id ORDER BY q.created_at DESC',
        (quiz_id, session['user_id'],)
    ).fetchone()
    
    if not quiz:
        return redirect(url_for('teacher.dashboard'))
    
    results = db.execute(
        'SELECT r.score, u.username FROM results r JOIN users u ON r.student_id = u.id WHERE r.quiz_id = ?', (quiz_id,)
    ).fetchall()
    return render_template('quiz_details.html', quiz=quiz, results=results)

# --- Teacher: View Quiz Answers ---
@bp_teacher.route('/quiz/<int:quiz_id>/answers')
@login_required
def quiz_answers(quiz_id):
    db = get_db()
    quiz = db.execute('SELECT * FROM quizzes WHERE id = ? AND teacher_id = ?', (quiz_id, session['user_id'])).fetchone()
    if not quiz:
        return redirect(url_for('teacher.dashboard'))
    questions = db.execute('SELECT question_text, options, correct_answer FROM questions WHERE quiz_id = ?', (quiz_id,)).fetchall()
    question_list = []
    for q in questions:
        opts = json.loads(q['options'])
        question_list.append({
            'question': q['question_text'],
            'options': opts,
            'correct': q['correct_answer']
        })
    return render_template('quiz_answers.html', quiz=quiz, questions=question_list)

# --- Student Routes ---
@bp_student.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user_id = session.get('user_id')
    # Quizzes taken
    quizzes_taken = db.execute('SELECT COUNT(*) FROM results WHERE student_id = ?', (user_id,)).fetchone()[0]
    # Average score
    avg_score = db.execute('SELECT AVG(score) FROM results WHERE student_id = ?', (user_id,)).fetchone()[0]
    avg_score = round(avg_score, 2) if avg_score is not None else 'N/A'
    # Recent activity (last 5 quizzes)
    recent_results = db.execute('SELECT r.score, q.title, r.submitted_at FROM results r JOIN quizzes q ON r.quiz_id = q.id WHERE r.student_id = ? ORDER BY r.submitted_at DESC LIMIT 5', (user_id,)).fetchall()
    recent_activity = [f"Scored {r['score']} on '{r['title']}' at {r['submitted_at']}" for r in recent_results]
    # Past quiz history (all quizzes)
    past_quizzes = db.execute('SELECT q.title, r.submitted_at, r.score, r.quiz_id FROM results r JOIN quizzes q ON r.quiz_id = q.id WHERE r.student_id = ? ORDER BY r.submitted_at DESC', (user_id,)).fetchall()
    return render_template('student_dashboard.html', username=session.get('username'), quizzes_taken=quizzes_taken, avg_score=avg_score, recent_activity=recent_activity, past_quizzes=past_quizzes)

@bp_student.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    db = get_db()
    # Get quiz with anti-cheating features
    quiz = db.execute('SELECT q.*, q.time_limit, COALESCE(q.anti_cheating_features, "{}") as anti_cheating_features FROM quizzes q WHERE q.id = ?', (quiz_id,)).fetchone()
    if quiz:
        print(f"[DEBUG take_quiz] user_id={session.get('user_id')}, quiz_id={quiz_id}, quiz_id={quiz['id']}, quiz_title={quiz['title']}")
    else:
        print(f"[DEBUG take_quiz] user_id={session.get('user_id')}, quiz_id={quiz_id}, quiz=None")
    if not quiz:
        flash('Quiz not found.')
        return redirect(url_for('student.dashboard'))
    # Prevent retake: check if result exists
    result = db.execute('SELECT id FROM results WHERE quiz_id = ? AND student_id = ?', (quiz_id, session['user_id'])).fetchone()
    if result:
        flash('You have already taken this quiz.')
        return redirect(url_for('student.quiz_result', result_id=result['id']))

    # Get questions with options
    questions_raw = db.execute('SELECT id, question_text, options FROM questions WHERE quiz_id = ?', (quiz_id,)).fetchall()
    questions = []
    for q in questions_raw:
        question_data = {
            'id': q['id'],
            'question_text': q['question_text']
        }
        # Only process options if they exist (for MCQ questions)
        if q['options']:
            try:
                opts = json.loads(q['options'])
                question_data['options'] = opts
            except json.JSONDecodeError:
                question_data['options'] = []
        else:
            question_data['options'] = []
        questions.append(question_data)
    print(f"[DEBUG take_quiz] questions_count={len(questions)}")
    # Robust check: If no questions, show error page
    if not questions:
        flash('This quiz has no questions. Please contact your teacher.')
        return redirect(url_for('student.dashboard'))
    # Convert anti_cheating_features to proper JSON if it's a string
    try:
        quiz_dict = dict(quiz)
        if isinstance(quiz['anti_cheating_features'], str):
            quiz_dict['anti_cheating_features'] = json.loads(quiz['anti_cheating_features'])
    except (json.JSONDecodeError, TypeError):
        quiz_dict = dict(quiz)
        quiz_dict['anti_cheating_features'] = {}

    # Log quiz start after all validations pass
    ip = request.remote_addr
    timestamp = int(time.time())
    db.execute('INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
               (session['user_id'], quiz_id, 'start', ip, timestamp))
    db.commit()

    return render_template('quiz.html', quiz=quiz_dict, questions=questions)

@bp_student.route('/quiz/result/<int:result_id>')
@login_required
def quiz_result(result_id):
    db = get_db()
    # Get result, quiz, and all questions/answers
    result = db.execute(
        'SELECT r.score, r.quiz_id, q.title as quiz_title, (SELECT COUNT(id) FROM questions WHERE quiz_id = r.quiz_id) as total_questions FROM results r JOIN quizzes q ON r.quiz_id = q.id WHERE r.id = ? AND r.student_id = ?',
        (result_id, session['user_id'])
    ).fetchone()
    if not result:
        return redirect(url_for('student.dashboard'))
    # Get questions and correct answers
    questions = db.execute('SELECT id, question_text, options, correct_answer FROM questions WHERE quiz_id = ?', (result['quiz_id'],)).fetchall()
    # Get student's answers
    student_answers = {}
    answers = db.execute('SELECT question_id, answer FROM student_answers WHERE result_id = ?', (result_id,)).fetchall()
    for ans in answers:
        student_answers[ans['question_id']] = ans['answer']
    # Prepare solution data
    solution = []
    for q in questions:
        opts = json.loads(q['options'])
        solution.append({
            'question': q['question_text'],
            'options': opts,
            'correct': q['correct_answer'],
            'student_choice': int(student_answers.get(str(q['id']), -1))
        })
    return render_template('quiz_result.html', result=result, solution=solution)

# --- Admin Routes ---
# @bp_admin.route('/dashboard')
# @admin_required
# def dashboard():
#     db = get_db()
#     # Fetch all users, including their password for display
#     users = db.execute('SELECT id, username, email, password, role FROM users ORDER BY role, username').fetchall()
#     return render_template('admin_dashboard.html', users=users, username=session.get('username'))

@bp_admin.route('/dashboard')
@admin_required
def dashboard():
    db = get_db()
    # Fetch data for the new dashboard
    student_count = db.execute("SELECT COUNT(id) FROM users WHERE role = 'student'").fetchone()[0]
    teacher_count = db.execute("SELECT COUNT(id) FROM users WHERE role = 'teacher'").fetchone()[0]
    students = db.execute("SELECT id, username, email, password FROM users WHERE role = 'student' ORDER BY username").fetchall()
    teachers = db.execute("SELECT id, username, email, password FROM users WHERE role = 'teacher' ORDER BY username").fetchall()
    
    return render_template(
        'admin_dashboard_new.html', 
        username=session.get('username'),
        student_count=student_count,
        teacher_count=teacher_count,
        students=students,
        teachers=teachers
    )

@bp_admin.route('/refresh_passwords/<string:role>', methods=['POST'])
@admin_required
def refresh_passwords(role):
    if role not in ['student', 'teacher']:
        flash('Invalid user role specified.', 'error')
        return redirect(url_for('admin.dashboard'))

    db = get_db()
    users_to_update = db.execute("SELECT id FROM users WHERE role = ?", (role,)).fetchall()

    if not users_to_update:
        flash(f'No {role}s found to update.', 'warning')
        return redirect(url_for('admin.dashboard'))
    
    updated_count = 0
    try:
        for user in users_to_update:
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            db.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user['id']))
            updated_count += 1
        db.commit()
        flash(f'Successfully refreshed passwords for {updated_count} {role}(s).', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'An error occurred while refreshing passwords: {e}', 'error')

    return redirect(url_for('admin.dashboard'))

@bp_admin.route('/create_user', methods=('GET', 'POST'))
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        # --- FIX: Generate a random password for the new user ---
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        role = request.form['role']
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, password, role)
            )
            db.commit()
            
            if role == 'student':
                # Send email to student
                email_sent = send_student_email(email, username, password)
                if email_sent:
                    flash(f'User created successfully! Password sent to {email}.', 'success')
                else:
                    flash(f'User created successfully, but failed to send email. Password: {password}', 'error')
            else:
                flash(f'User created successfully! Password: {password}', 'success')

            return redirect(url_for('admin.dashboard'))
        except sqlite3.IntegrityError:
            flash(f"User '{username}' or email '{email}' already exists.", 'error')
    return render_template('create_user.html')

@bp_admin.route('/edit_user/<int:user_id>', methods=('GET', 'POST'))
@admin_required
def edit_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        try:
            db.execute(
                "UPDATE users SET username = ?, email = ?, password = ?, role = ? WHERE id = ?",
                (username, email, password, role, user_id)
            )
            db.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('admin.dashboard'))
        except sqlite3.IntegrityError:
            flash(f"Username '{username}' or email '{email}' already exists.", 'error')

    return render_template('edit_user.html', user=user)

@bp_admin.route('/delete_user/<int:user_id>', methods=('POST',))
@admin_required
def delete_user(user_id):
    db = get_db()
    try:
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash('User deleted successfully.', 'success')
    except sqlite3.Error as e:
        flash(f'Error deleting user: {e}', 'error')
    return redirect(url_for('admin.dashboard'))

# Sending Mail to all---------------------------------------------------
@bp_admin.route('/send_mail', methods=['POST'])
@admin_required
def send_mail_route():
    recipient_type = request.form.get('recipient')
    specific_user_email = request.form.get('specific_user_email')

    if not recipient_type:
        flash('Recipient type is required.', 'error')
        return redirect(url_for('admin.dashboard'))

    db = get_db()
    users_to_email = []

    if recipient_type == 'all_students':
        users = db.execute("SELECT email, username, password FROM users WHERE role = 'student'").fetchall()
        users_to_email.extend(users)
    elif recipient_type == 'all_teachers':
        users = db.execute("SELECT email, username, password FROM users WHERE role = 'teacher'").fetchall()
        users_to_email.extend(users)
    elif recipient_type == 'specific_user':
        if not specific_user_email:
            flash('Email is required for a specific user.', 'error')
            return redirect(url_for('admin.dashboard'))
        user = db.execute("SELECT email, username, password FROM users WHERE email = ?", (specific_user_email,)).fetchone()
        if user:
            users_to_email.append(user)
        else:
            flash(f'No user found with email: {specific_user_email}', 'error')
            return redirect(url_for('admin.dashboard'))
    else:
        flash('Invalid recipient selected.', 'error')
        return redirect(url_for('admin.dashboard'))

    if not users_to_email:
        flash('No recipients found to send credentials to.', 'warning')
        return redirect(url_for('admin.dashboard'))

    success_count = 0
    for user in users_to_email:
        if send_student_email(user['email'], user['username'], user['password']):
            success_count += 1

    if success_count > 0:
        flash(f'Successfully sent credentials to {success_count} user(s).', 'success')
    else:
        flash('Failed to send any credential emails.', 'error')

    return redirect(url_for('admin.dashboard'))

# --- NEW FEATURE: Import students from CSV ---
@bp_admin.route('/import_users', methods=['POST'])
@admin_required
def import_users():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part found in the request.'}), 400
    
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        return jsonify({'error': 'Invalid file. Please upload a valid CSV file.'}), 400

    try:
        # Read the CSV file in memory using DictReader for reliability
        csv_file = file.stream.read().decode('utf-8')
        csv_reader = csv.DictReader(csv_file.splitlines())
        
        db = get_db()
        users_added = 0
        
        for row in csv_reader:
            # Assumes your CSV has 'Username', 'Email', and 'Role' columns
            username = row.get('Username')
            email = row.get('Email')
            role = row.get('Role', 'student').lower() # Defaults to 'student' if Role is missing

            if not all([username, email, role]):
                continue # Skip rows that are missing essential data

            # Use the agreed-upon password length of 8
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            
            try:
                db.execute(
                    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                    (username, email, password, role)
                )
                db.commit()
                # Send email to new students and teachers
                
                # ----------------sending mail---------------------------
                # if role in ['student', 'teacher']:
                #     send_student_email(email, username, password)
                
                users_added += 1
            except sqlite3.IntegrityError:
                # This handles cases where the username or email already exists in the database
                db.rollback()
                print(f"Skipping duplicate user: {username} ({email})")
                
        if users_added > 0:
            return jsonify({'message': f'Successfully imported {users_added} users.'})
        else:
            return jsonify({'error': 'No new users were imported. Check the CSV for duplicates or formatting issues.'})

    except Exception as e:
        db.rollback()
        return jsonify({'error': f'An error occurred during processing: {str(e)}'}), 500

# --- API Routes ---
def generate_unique_room_code(db):
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        if not db.execute('SELECT id FROM quizzes WHERE room_code = ?', (code,)).fetchone(): return code


# --- Teacher: Finalize Quiz Creation (POST, after preview) ---
@bp_teacher.route('/api/quiz/finalize', methods=['POST'])
@login_required
def api_finalize_quiz():
    try:
        data = request.get_json(force=True)
    except Exception as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400
    viva_mode = data.get('mode', 'mcq') == 'viva'
    db = get_db()
    try:
        room_code = generate_unique_room_code(db)
        
        # Process anti-cheating features
        anti_cheating_features = {
            'random_question_order': data.get('random_question_order', False),
            'random_option_order': data.get('random_option_order', False),
            'plagiarism_detection': data.get('plagiarism_detection', False),
            'strict_time_limits': data.get('strict_time_limits', False),
            'auto_submit': data.get('auto_submit', False),
            'speed_monitoring': data.get('speed_monitoring', False),
            'copy_paste_prevention': data.get('copy_paste_prevention', False),
            'tab_switch_detection': data.get('tab_switch_detection', False),
            'fullscreen_mode': data.get('fullscreen_mode', False),
            'duplicate_login_detection': data.get('duplicate_login_detection', False)
        }
        
        cursor = db.execute(
            'INSERT INTO quizzes (title, teacher_id, room_code, time_limit, anti_cheating_features) VALUES (?, ?, ?, ?, ?)',
            (data['title'], session['user_id'], room_code, int(data['time_limit']), json.dumps(anti_cheating_features))
        )
        quiz_id = cursor.lastrowid
        if viva_mode:
            for q in data['questions']:
                db.execute('INSERT INTO questions (quiz_id, question_text, options, correct_answer) VALUES (?, ?, ?, ?)',
                           (quiz_id, q['text'], json.dumps([]), -1))
        else:
            for q in data['questions']:
                db.execute('INSERT INTO questions (quiz_id, question_text, options, correct_answer) VALUES (?, ?, ?, ?)',
                           (quiz_id, q['text'], json.dumps(q['options']), q.get('correct_answer', 0)))
        db.commit()
        return jsonify({'message': 'Quiz created!', 'quiz_id': quiz_id})
    except db.Error as e:
        db.rollback()
        return jsonify({'error': f'Database error: {e}'}), 500

# --- Global error handler for API routes to always return JSON ---
def is_api_request():
    path = request.path
    return (
        path.startswith('/teacher/api/') or
        path.startswith('/student/api/') or
        path.startswith('/api/')
    )

@bp_teacher.app_errorhandler(Exception)
def handle_api_error(error):
    if is_api_request():
        code = 500
        msg = str(error)
        if isinstance(error, HTTPException):
            code = error.code or 500
            msg = error.description
        resp = jsonify({'error': f'Internal server error: {msg}'})
        return make_response(resp, code)
    raise error
# --- Analytics Scaffold (for future expansion) ---
@bp_teacher.route('/analytics')
@login_required
def analytics():
    # Placeholder: In a real system, aggregate quiz/question stats here
    db = get_db()
    quiz_count = db.execute('SELECT COUNT(*) FROM quizzes WHERE teacher_id = ?', (session['user_id'],)).fetchone()[0]
    student_count = db.execute('SELECT COUNT(*) FROM users WHERE role = "student"').fetchone()[0]
    return render_template('analytics.html', quiz_count=quiz_count, student_count=student_count)

@bp_teacher.route('/api/quiz/delete/<int:quiz_id>', methods=['POST'])
@login_required
def api_delete_quiz(quiz_id):
    db = get_db()
    if not db.execute('SELECT id FROM quizzes WHERE id = ? AND teacher_id = ?', (quiz_id, session['user_id'])).fetchone():
        return jsonify({'error': 'Permission denied'}), 403
    try:
        db.execute('DELETE FROM results WHERE quiz_id = ?', (quiz_id,))
        db.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz_id,))
        db.execute('DELETE FROM quizzes WHERE id = ?', (quiz_id,))
        db.commit()
        return jsonify({'message': 'Quiz deleted successfully.'})
    except db.Error as e:
        db.rollback()
        return jsonify({'error': f'Database error: {e}'}), 500

@bp_student.route('/api/quiz/join', methods=['POST'])
@login_required
def api_join_quiz():
    # DEBUG: temporary logging for join flow troubleshooting
    try:
        incoming_json = request.get_json(force=False, silent=True)
    except Exception:
        incoming_json = None
    print(f"[DEBUG api_join_quiz] incoming_json={incoming_json}")
    print(f"[DEBUG api_join_quiz] session_user_id={session.get('user_id')}")

    # Accept JSON body, form POST, or query param as fallback
    room_code = None
    if isinstance(incoming_json, dict):
        room_code = incoming_json.get('room_code')
    if not room_code:
        room_code = request.form.get('room_code') or request.args.get('room_code') or ''
    room_code = str(room_code).strip().upper()
    if not room_code:
        if request.is_json:
            return jsonify({'error': 'Room code is required.'}), 400
        flash('Room code is required.')
        return redirect(url_for('student.dashboard'))

    db = get_db()
    quiz = db.execute('SELECT id, title, room_code FROM quizzes WHERE room_code = ?', (room_code,)).fetchone()
    print(f"[DEBUG api_join_quiz] db_lookup_quiz={dict(quiz) if quiz else None}")

    if quiz:
        # Check if student has already taken this quiz
        result = db.execute('SELECT id FROM results WHERE quiz_id = ? AND student_id = ?',
                          (quiz['id'], session['user_id'])).fetchone()
        if result:
            if request.is_json:
                return jsonify({'error': 'You have already taken this quiz.'}), 400
            flash('You have already taken this quiz.')
            return redirect(url_for('student.dashboard'))

        # Non-JSON (form submit) → redirect directly
        if request.is_json:
            return jsonify({'success': True, 'quiz_id': quiz['id']})
        return redirect(url_for('student.take_quiz', quiz_id=quiz['id']))

    if request.is_json:
        return jsonify({'error': 'Quiz with that room code not found.'}), 404
    flash('Quiz with that room code not found.')
    return redirect(url_for('student.dashboard'))

@bp_student.route('/api/quiz/submit', methods=['POST'])
@login_required
def api_submit_quiz():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        quiz_id = data.get('quiz_id')
        if not quiz_id:
            return jsonify({'error': 'Quiz ID is required'}), 400
            
        answers = data.get('answers', {})
        if not isinstance(answers, dict):
            return jsonify({'error': 'Invalid answers format'}), 400
        
        auto_submit_reason = data.get('auto_submit_reason')
        db = get_db()
        
        # Verify quiz exists and hasn't been taken
        quiz = db.execute('SELECT id FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
        if not quiz:
            return jsonify({'error': 'Quiz not found'}), 404
        
        existing_result = db.execute(
            'SELECT id FROM results WHERE quiz_id = ? AND student_id = ?', 
            (quiz_id, session['user_id'])
        ).fetchone()
        if existing_result:
            return jsonify({'error': 'Quiz already submitted'}), 400
        
        # Begin transaction
        db.execute('BEGIN')
        
        try:
            # Fetch questions and calculate score
            rows = db.execute(
                'SELECT id, correct_answer, question_text FROM questions WHERE quiz_id = ?', 
                (quiz_id,)
            ).fetchall()
            
            if not rows:
                db.execute('ROLLBACK')
                return jsonify({'error': 'No questions found for this quiz'}), 404
                
            correct_answers = {str(r['id']): r['correct_answer'] for r in rows}
            score = sum(1 for q_id, ans in answers.items() 
                       if q_id in correct_answers and 
                       str(ans).strip() == str(correct_answers[q_id]).strip())
            
            # Log submission
            ip = request.remote_addr
            timestamp = int(time.time())
            
            # Log basic submission
            db.execute(
                'INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], quiz_id, 'submit', ip, timestamp)
            )
            if auto_submit_reason:
                db.execute(
                    'INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
                    (session['user_id'], quiz_id, f'auto_submit:{auto_submit_reason}', ip, timestamp)
                )
            
            # Check completion time
            start_log = db.execute(
                '''SELECT timestamp 
                   FROM activity_log 
                   WHERE student_id = ? AND quiz_id = ? AND action = "start" 
                   ORDER BY timestamp ASC LIMIT 1''', 
                (session['user_id'], quiz_id)
            ).fetchone()
            
            if start_log and (timestamp - start_log['timestamp'] < 30):
                db.execute(
                    'INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
                    (session['user_id'], quiz_id, 'fast_completion', ip, timestamp)
                )
            
            # Check tab switches
            tab_switches = db.execute(
                'SELECT COUNT(*) as cnt FROM activity_log WHERE student_id = ? AND quiz_id = ? AND action = "tab_switch"',
                (session['user_id'], quiz_id)
            ).fetchone()
            
            if tab_switches and tab_switches['cnt'] > 3:
                db.execute(
                    'INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
                    (session['user_id'], quiz_id, 'excessive_tab_switch', ip, timestamp)
                )
            
            # Plagiarism check
            suspicious = False
            for q in rows:
                if q['correct_answer'] == -1:  # open-ended
                    ans = answers.get(str(q['id']), '').strip().lower()
                    if ans:
                        similar_answers = db.execute(
                            '''SELECT sa.answer 
                               FROM student_answers sa 
                               JOIN results r ON sa.result_id = r.id 
                               WHERE r.quiz_id = ? AND r.student_id != ? AND sa.question_id = ?''',
                            (quiz_id, session['user_id'], q['id'])
                        ).fetchall()
                        
                        for other_ans in similar_answers:
                            if ans == other_ans['answer'].strip().lower():
                                suspicious = True
                                break
            
            if suspicious:
                db.execute(
                    'INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
                    (session['user_id'], quiz_id, 'plagiarism_detected', ip, timestamp)
                )
            
            # Store results
            cursor = db.execute(
                'INSERT INTO results (student_id, quiz_id, score) VALUES (?, ?, ?)',
                (session['user_id'], quiz_id, score)
            )
            result_id = cursor.lastrowid
            
            # Store individual answers
            for q_id, ans in answers.items():
                if not isinstance(q_id, (str, int)) or not str(q_id).isdigit():
                    continue
                try:
                    db.execute(
                        'INSERT INTO student_answers (result_id, question_id, answer) VALUES (?, ?, ?)',
                        (result_id, int(q_id), str(ans))
                    )
                except (ValueError, sqlite3.Error) as e:
                    print(f"Error storing answer for question {q_id}: {e}")
                    continue
            
            # Commit all changes
            db.execute('COMMIT')
            
            msg = 'Quiz submitted successfully!'
            if suspicious:
                msg += ' (Note: Potential plagiarism detected)'
            
            return jsonify({
                'message': msg,
                'result_id': result_id,
                'score': score
            })
            
        except Exception as e:
            db.execute('ROLLBACK')
            print(f"Error in quiz submission: {e}")
            return jsonify({'error': 'An error occurred while submitting the quiz'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Request error: {str(e)}'}), 400

# --- Log Suspicious Activity (Student API) ---
@bp_student.route('/api/log_suspicious', methods=['POST'])
@login_required
def log_suspicious():
    data = request.get_json(force=True)
    event = data.get('event')
    quiz_id = data.get('quiz_id')
    ip = request.remote_addr
    timestamp = int(time.time())
    if event in ['tab_switch', 'rapid_change'] and quiz_id:
        db = get_db()
        db.execute('INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
                   (session['user_id'], quiz_id, event, ip, timestamp))
        db.commit()
        return jsonify({'status': 'logged'})
    return jsonify({'status': 'ignored'}), 400

@bp_student.route('/api/log_suspicious_js')
def log_suspicious_js():
    quiz_id = request.args.get('quiz_id')
    ip = request.remote_addr
    timestamp = int(time.time())
    db = get_db()
    db.execute('INSERT INTO activity_log (student_id, quiz_id, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)',
               (session.get('user_id'), quiz_id, 'js_disabled', ip, timestamp))
    db.commit()
    # Return a 1x1 transparent gif
    from flask import send_from_directory
    import io
    gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
    return send_file(io.BytesIO(gif), mimetype='image/gif')

# --- App Factory ---
def create_app():
    app = Flask(__name__, instance_relative_config=True)
    
    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Load environment variables
    if os.path.exists('.env'):
        load_dotenv()
    
    # Configure app
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', os.urandom(24)),
        PERMANENT_SESSION_LIFETIME=int(os.getenv('PERMANENT_SESSION_LIFETIME', 2592000)),
        # Allow SESSION_COOKIE_SECURE to be disabled in development (HTTP). Set env var to 'True' for production.
        SESSION_COOKIE_SECURE=(os.getenv('SESSION_COOKIE_SECURE', 'False').lower() in ('1', 'true', 'yes')),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.getenv('SESSION_COOKIE_SAMESITE', 'Lax'),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max file upload
    )
    
    # Initialize session store
    session_store = SessionStore(app.instance_path)
    
    # Load stored credentials into session if they exist
    @app.before_request
    def load_stored_session():
        if 'user_id' not in session and request.endpoint != 'auth.login':
            stored_sessions = session_store.load_credentials()

            for user_id, data in stored_sessions.items():
                if request.cookies.get(f'remember_{user_id}'):
                    session['user_id'] = int(user_id)
                    session['username'] = data['username']
                    session['role'] = data['role']
                    session.permanent = True
                    break
    
    # Configure session
    app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 30  # 30 days in seconds

    app.config['SESSION_COOKIE_SECURE'] = app.config.get('SESSION_COOKIE_SECURE', False)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
    
    try: os.makedirs(app.instance_path)
    except OSError: pass

    # Always initialize the database schema on startup
    with app.app_context():
        db_path = os.path.join(app.instance_path, 'quiz_database.db')
        if not os.path.exists(db_path):
            print("Database not found. Initializing...")
            init_db()
            print("Database initialized.")
        else:
            # Always apply schema to ensure all tables exist
            try:
                with app.open_resource('database.sql') as f:
                    get_db().executescript(f.read().decode('utf8'))
                print("Database schema ensured on startup.")
            except Exception as e:
                print(f"Error ensuring database schema: {e}")
    # -------------------------------/connected-------------------------------------
    with app.app_context():
        db = get_db()
        admin_user = os.getenv('ADMIN_USERNAME')
        admin_pass = os.getenv('ADMIN_PASSWORD')
        if admin_user and admin_pass:
            existing_admin = db.execute('SELECT id FROM users WHERE username = ? AND role = "admin"', (admin_user,)).fetchone()
            if not existing_admin:
                try:
                    db.execute('INSERT INTO users (username, password, role, email) VALUES (?, ?, "admin", ?)', 
                               (admin_user, admin_pass, "admin@intelliquiz.local"))
                    db.commit()
                    print(f"Admin user '{admin_user}' created successfully.")
                except sqlite3.IntegrityError:
                    print(f"Admin user '{admin_user}' already exists.")
    
    # Remove global Groq client; only use if API key is present in .env

    app.register_blueprint(bp_main)
    app.register_blueprint(bp_auth)
    app.register_blueprint(bp_teacher)
    app.register_blueprint(bp_student)
    app.register_blueprint(bp_admin)

    # Register custom Jinja filter for datetime
    from datetime import datetime
    def datetime_filter(ts):
        if not ts:
            return ""
        if isinstance(ts, str):
            return ts
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    app.jinja_env.filters['datetime'] = datetime_filter
    return app


# Serve favicon.ico
from flask import send_from_directory
@bp_main.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(current_app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)