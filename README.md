# Golf Score Tracker & Handicap System

A web-based golf score tracking and handicap calculation system built with Flask for CSE763 Secure Software Development course.

## Overview

This application allows golfers to track their rounds, calculate handicaps, view leaderboards, and manage golf courses. It includes user authentication, role-based access control, and persistent data storage.

## Features

- User registration and authentication for golfers
- Role-based access (Club Admin and Regular Golfer)
- Golf course management (add/edit courses with hole details)
- Round score tracking with hole-by-hole scoring
- Automatic handicap calculation
- Leaderboards and statistics
- Score history and trends
- SQLite database for data persistence

## Security Features

**Implemented:**
- CSRF protection (Flask-WTF)
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Session-based authentication
- Role-based authorization
- Authorization checks on API endpoints
- Input validation with safe type conversion

**Intentionally Weak (for course assignments):**
- Password hashing uses SHA256 (should use bcrypt)

## Remaining Security Gaps (For Future Assignments)

1. **Weak password hashing** - Uses SHA256 instead of bcrypt/scrypt
2. **No rate limiting** - Vulnerable to brute force attacks
3. **Sensitive data exposure** - All users can view all scores
4. **Session management issues** - Session fixation, long timeout
5. **Limited audit logging** - Basic tracking only
6. **Score manipulation** - No cryptographic integrity checks

## Tech Stack

- **Backend**: Python 3.9+ with Flask
- **Database**: SQLite (easily upgradable to PostgreSQL)
- **Frontend**: HTML, CSS, JavaScript (Vanilla)
- **Containerization**: Docker

## Prerequisites

- Python 3.9 or higher
- Docker and Docker Compose (for containerized deployment)

## Installation and Running

### Option 1: Local Development

1. Clone the repository:
```bash
git clone <your-repo-url>
cd golf-score-tracker
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python init_db.py
```

5. Run the application:
```bash
python app.py
```

6. Access the application at `http://localhost:5001`

### Option 2: Docker Deployment

1. Build and run with Docker Compose:
```bash
docker-compose up --build
```

2. Access the application at `http://localhost:5001`

## Default Accounts

- **Club Admin**:
  - Username: `admin`
  - Password: `admin123`

- **Golfer**:
  - Username: `golfer`
  - Password: `golfer123`

## Application Structure

```
golf-score-tracker/
├── app.py              # Main Flask application
├── models.py           # Database models
├── auth.py             # Authentication logic
├── config.py           # Configuration settings
├── handicap.py         # Handicap calculation logic
├── init_db.py          # Database initialization
├── requirements.txt    # Python dependencies
├── Dockerfile
├── docker-compose.yml
├── CLAUDE.md           # Claude Code project context
├── templates/          # HTML templates
├── static/             # CSS files
├── screenshots/        # Documentation screenshots
├── .github/workflows/  # CI/CD pipelines
└── instance/           # SQLite database (gitignored)
```

## Key Functionalities

### For Golfers:
- Register and login
- View available golf courses
- Enter round scores (hole-by-hole)
- View score history
- Track handicap index
- View leaderboards
- See statistics and trends

### For Club Admins:
- All golfer features
- Add and manage golf courses
- View all users and their scores
- Manage course details (par, slope, rating)
- View system-wide statistics

## API Endpoints

- `GET /` - Home page
- `GET /login` - Login page
- `POST /login` - Login endpoint
- `GET /register` - Registration page
- `POST /register` - Registration endpoint
- `GET /logout` - Logout
- `GET /dashboard` - User dashboard
- `GET /courses` - View all courses
- `GET /courses/add` - Add new course (admin only)
- `POST /courses/add` - Create course (admin only)
- `GET /round/new` - New round entry form
- `POST /round/new` - Submit round scores
- `GET /scores` - View user's score history
- `GET /leaderboard` - View leaderboard
- `GET /admin` - Admin panel (admin only)

## Handicap Calculation

The system calculates handicap index using a simplified version of the USGA Handicap System:
- Uses best 8 of last 20 rounds
- Calculates differential: (Score - Course Rating) * 113 / Slope Rating
- Handicap Index = Average of best differentials * 0.96

## Course Assignments

| Assignment | Focus | Status |
|------------|-------|--------|
| 1 | DevSecOps Pipeline (SAST, dependency scanning) | Complete |
| 2 | Threat Modeling (STRIDE, DFDs, attack trees) | Complete |
| 3 | Crypto APIs (bcrypt, encryption, HMAC) | Complete (assignment3 branch) |
| 4 | DAST Testing (ZAP scans, vulnerability fixes) | Complete |

## License

This project is created for educational purposes as part of CSE763.

## AI Usage

This project starter was created with assistance from Claude (Anthropic) to provide a suitable baseline for the CSE763 course requirements, specifically tailored for golf score tracking and handicap management.
