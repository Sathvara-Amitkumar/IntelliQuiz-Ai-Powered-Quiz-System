# IntelliQuiz

IntelliQuiz is a comprehensive web-based quiz management system built with Flask. It enables teachers to create, manage, and distribute quizzes to students, with advanced features like AI-powered question generation, anti-cheating measures, and real-time analytics. The system supports multiple user roles (Admin, Teacher, Student) and includes email notifications, CSV user imports, and detailed result tracking.

## Features

### For Teachers
- **Quiz Creation**: Create quizzes with customizable settings including time limits and anti-cheating features
- **AI-Powered Question Generation**: Use Google Gemini AI to automatically generate multiple-choice or viva (short answer) questions
- **Manual Question Input**: Add questions manually or upload from text files
- **Anti-Cheating Measures**: Implement features like tab switch detection, copy-paste prevention, fullscreen mode, and plagiarism detection
- **Student Management**: View student performance, send quiz invitations via email, and monitor suspicious activities
- **Analytics Dashboard**: Track quiz statistics, student scores, and activity logs

### For Students
- **Quiz Participation**: Join quizzes using room codes and take them with real-time monitoring
- **Result Viewing**: Review quiz results with detailed answer breakdowns
- **Dashboard**: View available and completed quizzes with performance metrics

### For Admins
- **User Management**: Create, edit, delete, and manage users (students and teachers)
- **Bulk Operations**: Import users from CSV files and send bulk email notifications
- **Password Management**: Generate and refresh user passwords
- **System Overview**: Monitor user counts and system statistics

### General Features
- **Secure Authentication**: Role-based access control with session management
- **Email Integration**: SMTP-based email sending for notifications and credentials
- **Database**: SQLite-based with robust error handling and concurrency support
- **Responsive UI**: Modern web interface with CSS and JavaScript enhancements
- **Activity Logging**: Comprehensive logging of user actions and suspicious activities

## Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLite
- **AI Integration**: Google Gemini API for question generation
- **Email**: SMTP for notifications
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: Session-based with role management
- **File Handling**: CSV import for user management

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup Steps

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd IntelliQuiz
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   Create a `.env` file in the root directory with the following variables:
   ```env
   SECRET_KEY=your-secret-key-here
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=adminpassword
   GEMINI_API_KEY=your-gemini-api-key
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   SESSION_COOKIE_SECURE=False  # Set to True in production with HTTPS
   ```

5. **Initialize the database**:
   The database will be automatically initialized when you run the application for the first time.

6. **Run the application**:
   ```bash
   python app.py
   ```

7. **Access the application**:
   Open your browser and navigate to `http://localhost:5000`

## Configuration

### Environment Variables
- `SECRET_KEY`: Flask secret key for session security
- `ADMIN_USERNAME` & `ADMIN_PASSWORD`: Credentials for the admin user (auto-created on first run)
- `GEMINI_API_KEY`: API key for Google Gemini AI (required for question generation)
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`: SMTP settings for email notifications
- `SESSION_COOKIE_SECURE`: Set to `True` for HTTPS in production

### Database
The application uses SQLite with automatic schema initialization. The database file is created in the `instance/` directory.

## Usage

### Getting Started
1. Log in as admin using the credentials from your `.env` file
2. Create teacher and student accounts via the admin dashboard
3. Teachers can create quizzes and generate questions
4. Students can join quizzes using room codes provided by teachers

### Creating a Quiz
1. Log in as a teacher
2. Navigate to "Create Quiz"
3. Fill in quiz details and select anti-cheating features
4. Generate questions using AI or add them manually
5. Preview and save the quiz
6. Share the room code with students

### Taking a Quiz
1. Log in as a student
2. Enter the room code on the dashboard
3. Complete the quiz within the time limit
4. View results after submission

## API Endpoints

The application includes several API endpoints for AJAX functionality:

- `POST /teacher/api/quiz/finalize`: Finalize quiz creation
- `POST /teacher/api/quiz/delete/<quiz_id>`: Delete a quiz
- `POST /student/api/quiz/join`: Join a quiz with room code
- `POST /student/api/quiz/submit`: Submit quiz answers
- `POST /student/api/log_suspicious`: Log suspicious activities

## File Structure

```
IntelliQuiz/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── database.sql           # Database schema
├── .env                   # Environment variables (create this)
├── instance/              # Database and instance files
├── static/                # Static assets (CSS, JS, images)
│   ├── css/
│   ├── js/
│   └── favicon.ico
├── templates/             # HTML templates
├── uploads/               # Uploaded files
└── utils/                 # Utility modules
    └── session_store.py   # Session management
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please contact the development team or create an issue in the repository.

## Changelog

### Version 1.0.0
- Initial release with core quiz functionality
- AI-powered question generation
- Anti-cheating features
- Multi-role user system
- Email notifications
- CSV user import

## Future Enhancements

- Mobile app development
- Advanced analytics and reporting
- Integration with learning management systems
- Real-time quiz monitoring
- Enhanced AI question customization
- Multi-language support
