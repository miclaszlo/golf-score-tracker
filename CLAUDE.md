# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

This is a **Golf Score Tracker & Handicap System** built for CSE763 Secure Software Development course at Boston University. **IMPORTANT**: The application intentionally contains security vulnerabilities that will be addressed progressively through 4 course assignments. Do not treat all security gaps as bugs to be immediately fixed - they are pedagogical features.

## Development Commands

### Local Development (Python Virtual Environment)
```bash
# Setup
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run application
python app.py

# Access at http://localhost:5000
```

### Docker Development (Preferred)
```bash
# Build and run
docker-compose up --build

# Rebuild after dependency changes
docker-compose down
docker-compose up --build

# View logs
docker-compose logs -f

# Stop containers
docker-compose down

# Access at http://localhost:5000
```

### Database Management
```bash
# Reset database (development only)
rm instance/golf.db
python init_db.py

# Or in Docker
docker-compose down -v
docker-compose up --build
```

## Architecture Overview

### Application Structure
This is a **monolithic Flask application** with session-based authentication:

**Core Components:**
- `app.py` - Main Flask application with all route handlers
- `models.py` - SQLAlchemy ORM models for database schema
- `auth.py` - Authentication decorators and utilities
- `handicap.py` - Golf handicap calculation business logic
- `config.py` - Configuration management (dev/prod settings)

**Data Flow:**
1. User authenticates via `/login` → session stored with `user_id`, `username`, `role`
2. Routes protected by `@login_required` or `@admin_required` decorators
3. Database operations via SQLAlchemy ORM (models inherit from `db.Model`)
4. Templates rendered with Jinja2, data passed as context variables

### Database Schema Relationships
```
User (golfer/admin)
  ├─> Round (many) - golf rounds played
  └─> Course (many) - courses created by admins

Course
  ├─> Hole (many) - 18 holes per course
  └─> Round (many) - rounds played on this course

Round
  ├─> Score (many) - individual hole scores
  └─> belongs to User and Course

AuditLog - tracks user actions (no foreign key cascade)
```

### Authentication & Authorization Pattern
```python
# Session-based (stored in Flask session cookie)
session['user_id']    # User ID
session['username']   # Username
session['role']       # 'golfer' or 'admin'

# Decorators control access
@login_required       # Any authenticated user
@admin_required       # Only users with role='admin'

# Current user retrieval
user = get_current_user()  # From auth.py
```

### Handicap Calculation Logic
Located in `handicap.py`. Uses simplified USGA formula:
- Best 8 of last 20 rounds (configurable in `config.py`)
- Differential = (Score - Course Rating) × 113 / Slope Rating
- Handicap Index = Average of best differentials × 0.96
- Requires minimum 5 rounds (configurable)

**Key functions:**
- `calculate_handicap_index(user_id)` - Main handicap calculation
- `get_user_statistics(user_id)` - Stats for dashboard
- `get_leaderboard(course_id, limit)` - Leaderboard rankings

### Template Inheritance
All templates extend `templates/base.html` which provides:
- Navigation bar (changes based on `session['role']`)
- Flash message display
- Common CSS/JS includes
- Bootstrap styling

## Intentional Security Gaps

**DO NOT FIX** these without explicit request - they are course assignment targets:

1. **Weak password hashing** (`models.py:30`) - Uses SHA256, should use bcrypt (Assignment 3)
2. **No CSRF protection** - Forms vulnerable to CSRF attacks (Assignment 4)
3. **Session fixation** (`app.py:102`) - Session not regenerated after login
4. **IDOR vulnerabilities** (`app.py:366-380`) - `/api/handicap/<user_id>` accessible by anyone
5. **Score manipulation** (`models.py:95-96`, `app.py:264`) - Total score not cryptographically verified
6. **Information disclosure** (`app.py:111-113`) - Error messages reveal username validity
7. **No rate limiting** - Brute force attacks possible on login
8. **Missing security headers** - No CSP, HSTS, X-Frame-Options
9. **Input validation gaps** - Weak validation in `auth.py:59-73`
10. **Hardcoded secrets** (`config.py:9`) - Development secret key in code

See `README.md` lines 20-42 for complete list and assignment roadmap.

## Course Assignment Branches

The project follows a 4-assignment structure:

- **Assignment 1** (`assignment1` branch) - DevSecOps pipeline setup, SAST/DAST tool integration
- **Assignment 2** - Threat modeling, STRIDE analysis, attack trees
- **Assignment 3** - Implement crypto APIs (bcrypt, encryption, HMAC)
- **Assignment 4** - DAST testing with OWASP ZAP, vulnerability fixes

When working on assignments, create feature branches from the assignment branch, then open pull requests for review.

## Configuration Management

`config.py` defines configuration classes:
- `Config` - Base configuration with security gaps marked
- `DevelopmentConfig` - Debug enabled, insecure defaults
- `ProductionConfig` - Should use environment variables

**Current settings:**
- Secret key: Hardcoded (intentional gap)
- Session timeout: 24 hours (too long, intentional gap)
- Debug mode: Enabled (intentional gap)
- Database: SQLite at `instance/golf.db`

Environment variables can override settings (not implemented yet).

## Default Test Accounts

Created by `init_db.py`:

**Admin Account:**
- Username: `admin`
- Password: `admin123`
- Role: `admin`

**Golfer Account:**
- Username: `golfer`
- Password: `golfer123`
- Role: `golfer`

**IMPORTANT**: These are for development only. In production, delete these accounts or change credentials.

## API Endpoints Summary

### Public Routes
- `GET/POST /login` - User login
- `GET/POST /register` - User registration

### Authenticated Routes (golfer role)
- `GET /dashboard` - User dashboard with stats
- `GET /courses` - List all courses
- `GET/POST /round/new` - Enter new round scores
- `GET /scores` - View score history
- `GET /leaderboard` - View leaderboard (any course or overall)
- `GET /logout` - Logout

### Admin-Only Routes
- `GET/POST /courses/add` - Create new golf courses with holes
- `GET /admin` - Admin panel (users, logs, system stats)

### API Endpoints
- `GET /api/handicap/<user_id>` - Get user handicap (IDOR vulnerability)

## Key Model Methods

**User model (`models.py`):**
- `set_password(password)` - Hash password (SHA256 - weak)
- `check_password(password)` - Verify password
- `is_admin()` - Check admin role
- `get_handicap_index()` - Calculate handicap

**Round model (`models.py`):**
- `calculate_differential()` - Calculate score differential for handicap
- `verify_total_score()` - Check if total matches hole scores (not enforced)

**Course model (`models.py`):**
- `holes` relationship - Access all 18 holes
- `rounds` relationship - All rounds played on this course

## Common Development Patterns

### Adding a new route
```python
@app.route('/new-route')
@login_required  # or @admin_required
def new_route():
    user = get_current_user()
    # Your logic here
    log_action('ACTION_NAME', resource='resource:id')
    return render_template('template.html', data=data)
```

### Database operations
```python
# Query
users = User.query.filter_by(role='golfer').all()
user = User.query.get(user_id)

# Create
new_object = Model(field=value)
db.session.add(new_object)
db.session.commit()

# Update
user.field = new_value
db.session.commit()

# Delete
db.session.delete(object)
db.session.commit()

# Always wrap in try/except
try:
    db.session.commit()
except Exception as e:
    db.session.rollback()
    # Handle error
```

### Audit logging
```python
from auth import log_action

log_action('ACTION_NAME', resource='resource:id', details='optional details')
```

## Working with Templates

Templates use Jinja2 syntax and extend `base.html`:

```html
{% extends 'base.html' %}

{% block title %}Page Title{% endblock %}

{% block content %}
<!-- Your content -->
{% endblock %}
```

**Available in all templates:**
- `session.user_id` - Current user ID
- `session.username` - Current username
- `session.role` - User role ('golfer' or 'admin')

**Flash messages:**
```python
flash('Message', 'category')  # category: success, danger, warning, info
```

## Docker Volume Persistence

The `docker-compose.yml` mounts:
- `./instance:/app/instance` - Database persists between container restarts
- `.:/app` - Code changes reflect immediately (development mode)

To reset everything: `docker-compose down -v`

## Known Issues & Future Work

**Technical debt** (not security gaps):
- No automated tests (should add pytest)
- No API documentation (consider OpenAPI/Swagger)
- SQLite not suitable for production (migrate to PostgreSQL)
- No database migrations (add Flask-Migrate/Alembic)
- Static files served by Flask (use nginx in production)
- No containerized PostgreSQL option (commented out in docker-compose.yml)

**Security improvements** (for assignments):
- Add Flask-WTF for CSRF protection
- Implement bcrypt for password hashing
- Add Flask-Limiter for rate limiting
- Encrypt sensitive data with Fernet/AES
- Add HMAC signatures for score integrity
- Implement proper input validation
- Add security headers middleware
- Implement proper session management

## Assignment File Exclusions

The `.gitignore` excludes:
- `Assignment-Description.txt` - Course assignment details
- `instance/` directory - SQLite database
- `__pycache__/` - Python bytecode
- `.env` files - Environment variables
- Virtual environment directories

## Dependencies

Core dependencies in `requirements.txt`:
- Flask 2.3.3 - Web framework
- Flask-SQLAlchemy 3.0.5 - ORM
- SQLAlchemy 2.0.20 - Database toolkit
- gunicorn 21.2.0 - WSGI server (production)
- python-dotenv 1.0.0 - Environment variable management

**Commented out** (for Assignment 3):
- bcrypt - For secure password hashing
- cryptography - For data encryption

To add new dependencies: update `requirements.txt` and rebuild Docker containers.

## Debugging

### View logs in Docker
```bash
docker-compose logs -f
```

### Check database contents
```bash
# Install sqlite3 in container
docker exec -it golf-score-tracker sqlite3 /app/instance/golf.db
# Then: .tables, SELECT * FROM users;, etc.
```

### Flask debug mode
Debug mode is enabled in development (`config.py:22`). Provides:
- Detailed error pages with stack traces
- Auto-reload on code changes
- **WARNING**: Information disclosure vulnerability (intentional)

## Project-Specific Conventions

1. **Security comments**: All intentional security gaps are marked with `# SECURITY GAP:` comments
2. **TODO comments**: Future improvements marked with `# TODO:`
3. **Route organization**: All routes in `app.py` (monolithic structure)
4. **Role checking**: Always use decorators (`@admin_required`) rather than inline checks
5. **Audit logging**: Log all important actions (login, data changes, admin actions)
6. **Error handling**: Display user-friendly messages, log technical details to console
7. **Database sessions**: Always rollback on errors, commit on success

## Course Assignment Context

When implementing security improvements:
1. **Check the assignment number** - Don't implement Assignment 3 features during Assignment 1
2. **Document changes** - Keep track of what was changed and why
3. **Create branches** - Use feature branches for each assignment
4. **Compare implementations** - Assignment reports require before/after comparisons
5. **Reference security tools** - Assignments specify which tools to use (Bandit, ZAP, etc.)

## Getting Help

- README.md - Project overview and features
- Assignment-Description.txt - Course assignment details (gitignored)
- Assignment-1-Roadmap.md - Detailed roadmap for Assignment 1
- Code comments - Inline documentation of security gaps and logic
