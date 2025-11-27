## IntelliQuiz

IntelliQuiz is a web-based quiz and viva platform built with Flask. Teachers can create quizzes (MCQ or viva), generate questions using Google Gemini, and enable anti-cheating features. Students join quizzes using room codes and get detailed results. Admins manage users and system settings.

[Live demo](https://intelliquiz-76yh.onrender.com/)

**Key features:**
- AI-powered question generation (Google Gemini)
- Role-based access: Admin, Teacher, Student
- Anti-cheating controls: tab-switch detection, copy-paste prevention, fullscreen enforcement, plagiarism alerts
- CSV import, bulk email, and activity logging
- Simple SQLite setup with automatic schema initialization

**Quick Start**

1. Clone:
   ```powershell
   git clone https://github.com/Sathvara-Amitkumar/IntelliQuiz-Ai-Powered-Quiz-System.git
   cd "IntelliQuiz-Ai-Powered-Quiz-System"
   ```
2. Create venv & install:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
3. Create `.env` (example):
   ```env
   SECRET_KEY=replace-me
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=adminpass
   GEMINI_API_KEY=your-gemini-key
   MAIL_SERVER=smtp.example.com
   MAIL_PORT=587
   MAIL_USERNAME=you@example.com
   MAIL_PASSWORD=app-password
   ```
4. Run:
   ```powershell
   python app.py
   ```
5. Visit `http://localhost:5000` or the live demo link above.

**Configuration**
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`: auto-created admin user on first run.
- `GEMINI_API_KEY`: required to enable AI question generation.
- `MAIL_*`: SMTP settings for email notifications.

**File layout (short)**
- `app.py` — Flask application
- `requirements.txt` — dependencies
- `database.sql` — DB schema
- `templates/` — HTML templates
- `static/` — CSS/JS
- `instance/` — runtime DB and uploads

Contributions, issues, and questions are welcome. Replace the SVG screenshot in `assets/live_demo.svg` with a real screenshot if you prefer a photographic preview.

---