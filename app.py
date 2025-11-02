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
import io

import google.generativeai as genai

from dotenv import load_dotenv
load_dotenv()

from flask import request, jsonify, send_file, Response
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

@bp_main.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        
        if not name or not email or not message:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('main.index') + '#contact')
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO contact (name, email, message) VALUES (?, ?, ?)',
                (name, email, message)
            )
            db.commit()
            flash('Thank you for your message! We will get back to you soon.', 'success')
            return redirect(url_for('main.index') + '#contact')
        except sqlite3.Error as e:
            db.rollback()
            flash('An error occurred while sending your message. Please try again.', 'error')
            return redirect(url_for('main.index') + '#contact')
    
    return redirect(url_for('main.index') + '#contact')

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



# Improved Gemini function
def generate_questions_with_gemini(topic, num_questions, is_viva):
    """Generates quiz questions using Google Gemini API."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"error": "GEMINI_API_KEY not found in .env file."}

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        question_type = "short answer viva questions" if is_viva else "multiple choice questions (MCQ)"
        
        prompt = f"""
            Generate exactly {num_questions} {question_type} about: {topic}

            Requirements:
            - Return ONLY valid JSON array
            - Keep questions and answers short and clear
            - For MCQ: Each object should have: 
            "question" (max 15 words), 
            "options" (array of 4 short strings), 
            "answer" (correct option string)
            - For Viva: Each object should have: 
            "question" (max 15 words), 
            "answer" (concise and accurate, max 25 words)
            - Make questions educational and relevant to the topic
            - Ensure answers are accurate

            Example MCQ format:
            [{{"question": "What is Python?", "options": ["A snake", "Programming language", "A bird", "A car"], "answer": "Programming language"}}]

            Example Viva format:
            [{{"question": "Explain Python programming", "answer": "Python is a high-level programming language used for web, data, and automation."}}]
        """
        

        response = model.generate_content(prompt)
        
        json_text = response.text.strip()
        
        # Clean JSON response
        if '```json' in json_text:
            json_text = json_text.split('```json')[1].split('```')[0].strip()
        elif '```' in json_text:
            json_text = json_text.split('```')[1].strip()
            
        questions = json.loads(json_text)
        
        # Validate structure
        if not isinstance(questions, list):
            return {"error": "Invalid response format from AI"}
            
        return questions

    except Exception as e:
        return {"error": f"Failed to generate questions: {str(e)}"}

import PyPDF2  # PDF padhne ke liye
import docx    # Word doc padhne ke liye
import os      # File save/delete karne ke liye

# Yeh function file se text nikaalega
def extract_text_from_file(file_path, file_extension):
    text = ""
    try:
        if file_extension == ".pdf":
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text += page.extract_text()
        elif file_extension == ".docx":
            doc = docx.Document(file_path)
            for para in doc.paragraphs:
                text += para.text + "\n"
        # Aap .txt, .pptx etc. ke liye bhi support add kar sakte hain
    except Exception as e:
        print(f"Error extracting text: {e}")
    return text

@bp_teacher.route('/preview', methods=['POST'])
@login_required
def preview_generated_questions():
    if session.get('role') != 'teacher': return "Unauthorized", 403

    form_data = request.form
    
    # --- Part 1: Gather Quiz Details ---
    quiz_details = {
        'title': form_data.get('title'),
        'description': form_data.get('description'),
        'time_limit': form_data.get('time_limit'),
        'viva': form_data.get('mode') == 'viva'
    }
    
    # --- NEW: Gather Suspicious Activity Flags ---
    # This reads all the checkbox values from your create_quiz.html form.
    suspicious_activity_flags = {
        'random_question_order': form_data.get('random_question_order') == 'on',
        'random_option_order': form_data.get('random_option_order') == 'on',
        'plagiarism_detection': form_data.get('plagiarism_detection') == 'on',
        'strict_time_limits': form_data.get('strict_time_limits') == 'on',
        'auto_submit': form_data.get('auto_submit') == 'on',
        'speed_monitoring': form_data.get('speed_monitoring') == 'on',
        'copy_paste_prevention': form_data.get('copy_paste_prevention') == 'on',
        'tab_switch_detection': form_data.get('tab_switch_detection') == 'on',
        'fullscreen_mode': form_data.get('fullscreen_mode') == 'on',
        'duplicate_login_detection': form_data.get('duplicate_login_detection') == 'on'
    }

    # --- Part 2: Generate Questions using Gemini ---
    topic_prompt = form_data.get('topic') # Using 'topic' as per our last fix
    num_questions = int(form_data.get('num_questions', 5))
    
    uploaded_file = request.files.get('question_files')
    file_text = ""

    if uploaded_file and uploaded_file.filename != '':
            try:
                # File extension check
                filename = uploaded_file.filename
                file_ext = os.path.splitext(filename)[1].lower()
                
                if file_ext not in ['.pdf', '.docx', '.txt']:
                    flash('Invalid file type. Please upload PDF, DOCX, or TXT.', 'error')
                    return redirect(url_for('teacher.create_quiz'))

                # File ko temporarily save karein
                temp_file_path = os.path.join('uploads', filename) # 'uploads' folder banana padega
                uploaded_file.save(temp_file_path)
                
                # File se text nikaalein
                file_text = extract_text_from_file(temp_file_path, file_ext)
                
                # Temp file delete kardein
                os.remove(temp_file_path)

            except Exception as e:
                flash(f'Error processing file: {e}', 'error')
                return redirect(url_for('teacher.create_quiz'))
            
    final_prompt = topic_prompt + "\n\n" + file_text
    
    generated_questions = generate_questions_with_gemini(
        final_prompt, num_questions, quiz_details['viva']
    )
    
    # 🔹 Transform for HTML rendering
    for q in generated_questions:
        # For question text
        q['text'] = q.get('question', '')
        
        # For MCQ: convert correct answer string to index
        if not quiz_details['viva'] and 'options' in q and 'answer' in q:
            try:
                q['correct_answer'] = q['options'].index(q['answer'])
            except ValueError:
                # fallback: first option
                q['correct_answer'] = 0

    if "error" in generated_questions:
        flash(generated_questions["error"], 'danger')
        return redirect(url_for('teacher.create_quiz'))
        
    # --- Part 3: Store EVERYTHING in the session ---
    session['generated_questions'] = generated_questions
    session['quiz_details'] = quiz_details
    session['suspicious_flags'] = suspicious_activity_flags # Store the new flags

    # --- Part 4: Go to the review page ---
    return render_template(
        'generated_questions.html',
        questions=generated_questions,
        viva=quiz_details['viva']
    )

# # In app.py, replace the existing save_quiz function

@bp_teacher.route('/save_quiz', methods=['POST'])
@login_required
def save_quiz():
    if session.get('role') != 'teacher':
        return redirect(url_for('main.index'))

    # Retrieve all data from the session
    form_data = request.form
    teacher_id = session.get('user_id')
    
    # Retrieve necessary details from the form/session
    quiz_details = session.get('quiz_details', {}) # Fallback to empty dict
    suspicious_flags = session.get('suspicious_flags', {})
    
    # Get details from form (these are the finalized values)
    title = form_data.get('title')
    time_limit = form_data.get('time_limit')
    is_viva = form_data.get('mode') == 'viva'
    
    if not title or not time_limit:
        flash('Quiz title or time limit is missing.', 'danger')
        return redirect(url_for('teacher.create_quiz'))

    db = get_db()
    try:
        # Convert the suspicious flags dictionary to a JSON string
        anti_cheating_json = json.dumps(suspicious_flags)

        # Generate unique room code
        while True:
            room_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            if not db.execute('SELECT id FROM quizzes WHERE room_code = ?', (room_code,)).fetchone():
                break

        # Step 2: Insert the quiz
        cursor = db.execute(
            'INSERT INTO quizzes (teacher_id, title, description, time_limit, is_viva, room_code, anti_cheating_features) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (
                teacher_id,
                title,
                quiz_details.get('description', ''), # Use description from session if needed
                time_limit,
                1 if is_viva else 0,
                room_code,
                anti_cheating_json
            )
        )
        quiz_id = cursor.lastrowid

        # Step 3: Iterate through the questions submitted in the form
        qidx = 0
        while True:
            question_text = form_data.get(f'question_text_{qidx}')
            
            # Stop if we run out of questions
            if not question_text:
                break
                
            # Read Options and Correct Answer Index
            options = []
            opt_idx = 0
            while True:
                option_text = form_data.get(f'option_{qidx}_{opt_idx}')
                if not option_text:
                    break
                options.append(option_text)
                opt_idx += 1
                
            correct_index_str = form_data.get(f'correct_{qidx}')
            
            # Sanitize correct_index and ensure it is an integer
            try:
                correct_index = int(correct_index_str) if correct_index_str else 0
            except (ValueError, TypeError):
                correct_index = 0
            
            # Save Question to DB
            db.execute(
                'INSERT INTO questions (quiz_id, question_text, options, correct_answer) VALUES (?, ?, ?, ?)',
                (
                    quiz_id,
                    question_text,
                    json.dumps(options),
                    correct_index
                )
            )
            
            qidx += 1

        db.commit()

        # Step 4: Clear all temporary session data
        session.pop('quiz_details', None)
        session.pop('generated_questions', None)
        session.pop('suspicious_flags', None)

        

        flash('Quiz and questions have been successfully saved!', 'success')
        return redirect(url_for('teacher.dashboard'))

    except sqlite3.Error as e:
        db.rollback()
        flash(f'A database error occurred: {e}', 'danger')
        return redirect(url_for('teacher.create_quiz'))


# khatam------------------------------------------------------------------------

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

@bp_teacher.route('/quiz/<int:quiz_id>/report')
@login_required
def download_report(quiz_id):
    
    # --- STEP 1: Database se data nikaalna (Aapke style mein) ---
    db = get_db()
    
    # Quiz ki details nikaalna (bilkul aapke dashboard query ki tarah)
    quiz = db.execute(
        'SELECT q.*, COUNT(qu.id) as question_count FROM quizzes q LEFT JOIN questions qu ON q.id = qu.quiz_id WHERE q.id = ? AND q.teacher_id = ? GROUP BY q.id',
        (quiz_id, session['user_id'])
    ).fetchone()

    if not quiz:
        flash('Quiz not found or you do not have permission.', 'error')
        # Note: 'teacher.dashboard' aapke HTML file ke url_for se match hona chahiye
        return redirect(url_for('teacher.dashboard'))

    # Saare results aur students ke naam nikaalna
    # (Yeh query aapke dashboard ke suspicious_logs query jaisi hai)
    results = db.execute(
        'SELECT r.score, u.username FROM results r JOIN users u ON r.student_id = u.id WHERE r.quiz_id = ?',
        (quiz_id,)
    ).fetchall()

    if not results:
        flash('Is quiz ke liye download karne ko koi results nahi hain.', 'info')
        # Note: 'teacher.quiz_details' aapke route ka naam hona chahiye
        return redirect(url_for('teacher.quiz_details', quiz_id=quiz_id))

    # --- STEP 2: CSV file banana (Memory mein) ---
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Column ke naam (Header)
    writer.writerow(['Student Username', 'Score', 'Total Questions', 'Percentage'])
    
    question_count = quiz['question_count']

    # --- STEP 3: CSV mein data bharna ---
    for result in results:
        score = result['score']
        username = result['username']
        
        # Zero se divide hone se bachne ke liye check
        percentage_str = "N/A"
        if question_count > 0:
            percentage = (score / question_count) * 100
            percentage_str = "%.2f%%" % percentage # "%.2f" se 2 decimal point tak round karega
        
        writer.writerow([
            username, 
            score, 
            question_count, 
            percentage_str
        ])
        
    # --- STEP 4: File ko download ke liye bhejna ---
    output.seek(0) # Pointer ko file ke shuru mein laana
    
    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment;filename={quiz['title']}_{quiz['room_code']}.csv"
        }
    )
    
# --- Student Routes ---
@bp_student.route('/dashboard')
@login_required
def dashboard():
    # Ensure only students can access this page
    if session.get('role') != 'student':
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('main.index'))

    user_id = session.get('user_id')
    db = get_db()

    # Fetch all quizzes available in the system
    all_quizzes = db.execute(
        'SELECT id, title, created_at FROM quizzes ORDER BY created_at DESC'
    ).fetchall()

    # Fetch all of this student's past submissions
    student_submissions = db.execute(
        'SELECT quiz_id, score, submitted_at FROM results WHERE student_id = ?', 
        (user_id,)
    ).fetchall()

    # Create a simple dictionary for quick lookups of submitted quizzes
    submitted_quizzes_map = {sub['quiz_id']: sub for sub in student_submissions}

    available_quizzes = []
    completed_quizzes = []

    # Sort all quizzes into two lists: available or completed
    for quiz in all_quizzes:
        if quiz['id'] in submitted_quizzes_map:
            # If the student has a submission for this quiz, add it to the completed list
            submission_details = submitted_quizzes_map[quiz['id']]
            completed_quizzes.append({
                'id': quiz['id'],
                'title': quiz['title'],
                'score': submission_details['score'],
                'submitted_at': submission_details['submitted_at']
            })
        else:
            # Otherwise, it's an available quiz
            available_quizzes.append(quiz)

    # Calculate the average score from the completed quizzes
    total_score = sum(q['score'] for q in completed_quizzes)
    avg_score = (total_score / len(completed_quizzes)) if completed_quizzes else 0

    return render_template(
        'student_dashboard.html',
        username=session.get('username'),
        available_quizzes=available_quizzes,
        completed_quizzes=completed_quizzes,
        available_quiz_count=len(available_quizzes),
        completed_quiz_count=len(completed_quizzes),
        avg_score=avg_score
    )
    
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
    user_id = session.get('user_id')

    # Get the basic result details, ensuring it belongs to the logged-in student
    result = db.execute(
        'SELECT r.id, r.score, r.quiz_id, q.title as quiz_title '
        'FROM results r JOIN quizzes q ON r.quiz_id = q.id '
        'WHERE r.id = ? AND r.student_id = ?',
        (result_id, user_id)
    ).fetchone()

    if not result:
        flash('Result not found or you do not have permission to view it.', 'danger')
        return redirect(url_for('student.dashboard'))

    # Get all questions for that quiz to compare answers
    questions = db.execute(
        'SELECT id, question_text, options, correct_answer FROM questions WHERE quiz_id = ?',
        (result['quiz_id'],)
    ).fetchall()

    # Get the student's answers for this specific result
    student_answers_raw = db.execute('SELECT question_id, answer FROM student_answers WHERE result_id = ?', (result_id,)).fetchall()
    student_answers = {ans['question_id']: ans['answer'] for ans in student_answers_raw}

    # Prepare a clear and simple data structure for the template
    solution_details = []
    correct_count = 0
    for q in questions:
        student_ans = student_answers.get(q['id'])
        
        # Normalize both to indices (convert answer text → index if needed)
        options_list = json.loads(q['options'] or '[]')

        # Try to convert student answer to integer index
        student_index = None
        if student_ans is not None:
            try:
                # First try: if it's already a number (as string or int), use it
                student_index = int(str(student_ans).strip())
                # Validate that the index is within bounds
                if student_index < 0 or student_index >= len(options_list):
                    student_index = None
            except (ValueError, TypeError):
                # Second try: if it's text, find the index in options list
                try:
                    student_index = options_list.index(str(student_ans).strip())
                except (ValueError, AttributeError):
                    student_index = None

        # Normalize correct answer → index
        try:
            correct_index = int(q['correct_answer'])
            # Validate that the correct index is within bounds
            if correct_index < 0 or correct_index >= len(options_list):
                correct_index = None
        except (ValueError, TypeError):
            correct_index = None

        # Compare indices (both must be valid integers)
        is_correct = (student_index is not None and 
                     correct_index is not None and 
                     student_index == correct_index)
        if is_correct:
            correct_count += 1

        solution_details.append({
            'question': q['question_text'],
            'options': options_list,
            'student_answer': student_index,
            'correct_answer': correct_index,
            'is_correct': is_correct
        })
        # is_correct = (str(student_ans) == str(q['correct_answer']))
        # if is_correct:
        #     correct_count += 1
        
        # solution_details.append({
        #     'question': q['question_text'],
        #     'options': json.loads(q['options'] or '[]'), # Safely load options
        #     'student_answer': student_ans,
        #     'correct_answer': q['correct_answer'],
        #     'is_correct': is_correct
        # })
    
    # Add the new data to the result object to pass to the template
    result_with_details = dict(result)
    result_with_details['correct_count'] = correct_count
    result_with_details['total_questions'] = len(questions)

    return render_template(
        'quiz_result.html',
        result=result_with_details,
        solution=solution_details
    )

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
    # Fetch contact messages
    contact_messages = db.execute("SELECT id, name, email, message, created_at FROM contact ORDER BY created_at DESC").fetchall()
    
    return render_template(
        'admin_dashboard_new.html', 
        username=session.get('username'),
        student_count=student_count,
        teacher_count=teacher_count,
        students=students,
        teachers=teachers,
        contact_messages=contact_messages
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

@bp_admin.route('/delete_contact/<int:contact_id>', methods=('POST',))
@admin_required
def delete_contact(contact_id):
    db = get_db()
    try:
        db.execute('DELETE FROM contact WHERE id = ?', (contact_id,))
        db.commit()
        flash('Contact message deleted successfully.', 'success')
    except sqlite3.Error as e:
        flash(f'Error deleting contact message: {e}', 'error')
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
            # Convert both student answer and correct answer to integers for proper comparison
            score = 0
            for q_id, ans in answers.items():
                if q_id in correct_answers:
                    try:
                        student_ans_int = int(str(ans).strip())
                        correct_ans_int = int(str(correct_answers[q_id]).strip())
                        if student_ans_int == correct_ans_int:
                            score += 1
                    except (ValueError, TypeError):
                        # If conversion fails, skip this question
                        continue
            
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