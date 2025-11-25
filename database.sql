-- database.sql
-- This SQL script defines the structure (schema) of our database.
-- It creates the necessary tables to store users, quizzes, questions, and results.

-- Users Table: A central table to store core authentication data
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT NOT NULL CHECK(role IN ('teacher', 'student', 'admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Students Table: Stores additional information specific to students
CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    enrollment_number TEXT UNIQUE,
    foreign key (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Teachers Table: Stores additional information specific to teachers
CREATE TABLE IF NOT EXISTS teachers (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    department TEXT,
    foreign key (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Admins Table: Stores additional information specific to admins
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    foreign key (user_id) REFERENCES users (id) ON DELETE CASCADE
);


-- Quizzes Table: Stores information about each quiz created by a teacher
CREATE TABLE IF NOT EXISTS quizzes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    room_code TEXT NOT NULL UNIQUE,
    time_limit INTEGER NOT NULL DEFAULT 10,
    anti_cheating_features TEXT DEFAULT '{}',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (teacher_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Questions Table: Stores all questions for every quiz
CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id INTEGER NOT NULL,
    question_text TEXT NOT NULL,
    options TEXT, -- Nullable for viva questions
    correct_answer INTEGER, -- Nullable for viva questions
    FOREIGN KEY (quiz_id) REFERENCES quizzes (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    quiz_id INTEGER NOT NULL,
    score INTEGER NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (quiz_id) REFERENCES quizzes (id) ON DELETE CASCADE
);

-- Activity Log Table: Tracks student actions for anti-cheating
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    quiz_id INTEGER,
    action TEXT NOT NULL,
    ip TEXT,
    timestamp INTEGER,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_questions_quiz_id ON questions(quiz_id);
CREATE INDEX IF NOT EXISTS idx_results_student_id ON results(student_id);
CREATE INDEX IF NOT EXISTS idx_results_quiz_id ON results(quiz_id);
CREATE INDEX IF NOT EXISTS idx_activity_log_student_id ON activity_log(student_id);
CREATE INDEX IF NOT EXISTS idx_activity_log_quiz_id ON activity_log(quiz_id);

-- Student Answers Table: Stores individual responses to questions
CREATE TABLE IF NOT EXISTS student_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    answer TEXT NOT NULL,
    timestamp INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
);

-- Additional Indices for performance
CREATE INDEX IF NOT EXISTS idx_student_answers_result ON student_answers(result_id);
CREATE INDEX IF NOT EXISTS idx_student_answers_question ON student_answers(question_id);
CREATE INDEX IF NOT EXISTS idx_quizzes_room_code ON quizzes(room_code);
CREATE INDEX IF NOT EXISTS idx_quizzes_teacher ON quizzes(teacher_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp);

-- Contact Table: Stores contact form submissions
CREATE TABLE IF NOT EXISTS contact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_contact_created_at ON contact(created_at);

-- Student Profiles Table: Stores additional profile information for students
CREATE TABLE IF NOT EXISTS student_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    photo_path TEXT,
    mobile TEXT,
    enrollment_number TEXT UNIQUE,
    class TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_student_profiles_user_id ON student_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_student_profiles_enrollment ON student_profiles(enrollment_number);