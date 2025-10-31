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

## Security Features (Initial - Intentionally Weak)

- Basic password hashing (SHA256 - weak)
- Session-based authentication
- Role-based authorization
- User data isolation

## Known Security Gaps (For Course Assignments)

This application intentionally has security vulnerabilities that will be addressed throughout the course:

1. **Weak password hashing** - Uses SHA256 instead of bcrypt/scrypt
2. **No input validation** - Vulnerable to injection attacks
3. **Missing CSRF protection** - Forms not protected against CSRF
4. **No rate limiting** - Vulnerable to brute force attacks
5. **Sensitive data exposure** - Scores and handicaps visible without proper authorization
6. **SQL injection vulnerabilities** - Some queries not properly parameterized
7. **Session management issues** - No timeout, session fixation vulnerability
8. **No security headers** - Missing CSP, HSTS, X-Frame-Options
9. **IDOR vulnerabilities** - Direct object reference without proper checks
10. **Information disclosure** - Error messages reveal system information
11. **No audit logging** - Limited tracking of security events
12. **Score manipulation** - No integrity checks on submitted scores

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

6. Access the application at `http://localhost:5000`

### Option 2: Docker Deployment

1. Build and run with Docker Compose:
```bash
docker-compose up --build
```

2. Access the application at `http://localhost:5000`

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
├── init_db.py          # Database initialization script
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker configuration
├── docker-compose.yml  # Docker Compose configuration
├── .gitignore
├── README.md
├── templates/          # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── courses.html
│   ├── add_course.html
│   ├── round_entry.html
│   ├── scores.html
│   ├── leaderboard.html
│   └── admin.html
├── static/            # Static files
│   └── style.css
└── instance/          # SQLite database (gitignored)
    └── golf.db
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

## Course Assignment Plan

### Assignment 1: DevSecOps Pipeline Setup
- Set up GitHub repository
- Configure GitHub Actions for SAST (Bandit, SonarQube)
- Add dependency scanning (Safety, Snyk)
- Document existing functionalities and security features
- Integrate security scanning tools

### Assignment 2: Security Requirements and Threat Modeling
- Create abuse cases (score manipulation, unauthorized access, data theft)
- Build attack trees
- Perform STRIDE threat modeling
- Create Data Flow Diagrams (DFD)
- Identify attack vectors (score tampering, session hijacking)

### Assignment 3: Implementing Crypto APIs
- Implement bcrypt for password hashing
- Add encryption for sensitive data (handicap calculations, personal info)
- Implement secure session management
- Add HMAC for score integrity verification
- Implement secure password reset tokens
- Digital signatures for score submission

### Assignment 4: DAST Testing
- Run OWASP ZAP scans
- Fix identified vulnerabilities
- Add security headers
- Implement input validation
- Add CSRF protection
- Rate limiting

## Potential Security Improvements

Throughout the course, you will implement:
- Strong password policies
- Multi-factor authentication
- Score integrity checks (digital signatures)
- Audit logging for all score submissions
- Input validation and sanitization
- CSRF tokens
- Rate limiting on login attempts
- Secure session management
- Security headers (CSP, HSTS, etc.)
- Encrypted storage of sensitive data

## License

This project is created for educational purposes as part of CSE763.

## AI Usage

This project starter was created with assistance from Claude (Anthropic) to provide a suitable baseline for the CSE763 course requirements, specifically tailored for golf score tracking and handicap management.
