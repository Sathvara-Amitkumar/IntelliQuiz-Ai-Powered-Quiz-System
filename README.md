# AI Viva Quiz

A Flask-based web application for creating and managing quizzes (MCQ and viva), handling students, and conducting quizzes with anti-cheating features.

## Features
1. Teacher Dashboard: Create, preview, and manage quizzes. View student performance and suspicious activity logs.
2. Student Dashboard: Join quizzes using a room code, take quizzes, and view results.
3. Quiz Types: Supports both Multiple Choice Questions (MCQ) and open-ended viva questions.
4. Anti-Cheating: Includes features like tab switch detection, plagiarism checks, time limits, and more.
5. AI Question Generation: Optionally generate questions using Groq AI (requires API key).
6. Encrypted Credential Storage: "Remember me" mode uses encrypted storage for user credentials.

## Setup

1. Clone the Repository
    ```sh
    git clone <your-repo-url>
    cd 4_ai viva quiz

2. Create a Virtual Environment and Install Dependencies
    ```sh
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

3. Configure Environment Variables
    - Create a .env file in the project root (optional but recommended):
    ```sh
    SECRET_KEY=dev-secret
    # Set to True only in production over HTTPS
    SESSION_COOKIE_SECURE=False
    PERMANENT_SESSION_LIFETIME=2592000
    # Optional for AI generation
    # GROQ_API_KEY=gsk_...

4. Run the Application
    ```sh
    python app.py

The app will initialize the SQLite database in `instance/quiz_database.db` using `database.sql` if missing.

## Usage Workflow

- Teacher: 
    1. Sign up and log in as a teacher.
    2. Create a quiz (MCQ or viva), preview questions, and save.
    3. Share the room code with students.
    4. View student submissions and analytics.
     
- Student: 
    1. Sign up and log in as a student.
    2. Enter the room code to join a quiz.
    3. Take the quiz and view results.

## Notes
- **AI Question Generation:** Requires a valid GROQ_API_KEY in your .env file. Without it, manual question entry and file-import workflows are available.

- **Anti-Cheating:** The app logs suspicious activities such as tab switching, rapid answer changes, and possible plagiarism.

- **Credential Storage:** Encrypted credentials are stored in instance/credentials for "remember me" mode.

## License
- This project is for Educational purposes.