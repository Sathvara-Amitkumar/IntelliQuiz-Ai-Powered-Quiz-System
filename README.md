# AI Viva Quiz

A Flask-based app for creating quizzes (MCQ and viva), managing students, and taking quizzes with anti-cheating features.

## Setup

1) Create a virtual environment and install dependencies:

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2) Create a `.env` in the project root (optional):

```
SECRET_KEY=dev-secret
# Set to True only in production over HTTPS
SESSION_COOKIE_SECURE=False
PERMANENT_SESSION_LIFETIME=2592000
# Optional for AI generation
# GROQ_API_KEY=gsk_...
```

3) Run the app:

```
python app.py
```

The app will initialize the SQLite database in `instance/quiz_database.db` using `database.sql` if missing.

## Default Workflow
- Teacher: Sign up, log in, create quiz, preview questions, save, share room code
- Student: Sign up, log in, enter room code, take quiz, see results

## Notes
- AI question generation requires a valid `GROQ_API_KEY`. Without it, manual questions and file-import workflows still work.
- The app uses encrypted credential storage in `instance/credentials` for "remember me" mode.

