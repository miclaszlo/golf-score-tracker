# Golf Score Tracker - Application Architecture Documentation

## Overview

This document provides a comprehensive mapping between the **application architecture** and **code structure** for the Golf Score Tracker & Handicap System. The application follows a **monolithic Flask architecture** with session-based authentication, designed for CSE763 Secure Software Development course at Boston University.

**Purpose**: This application is intentionally designed with security vulnerabilities for educational purposes. It will be progressively hardened through 4 course assignments.

---

## Table of Contents

1. [Architectural Pattern](#architectural-pattern)
2. [Layered Architecture](#layered-architecture)
3. [Data Flow Architecture](#data-flow-architecture)
4. [Database Schema Architecture](#database-schema-architecture)
5. [Authentication & Authorization Architecture](#authentication--authorization-architecture)
6. [Business Logic Architecture](#business-logic-architecture)
7. [Template Architecture](#template-architecture)
8. [Deployment Architecture](#deployment-architecture)
9. [File-to-Architecture Mapping](#file-to-architecture-mapping)
10. [Security Architecture Gaps](#security-architecture-gaps)

---

## Architectural Pattern

### Pattern: Monolithic MVC Architecture

**Architecture Decision**: The application uses a **monolithic Model-View-Controller (MVC)** pattern implemented with Flask.

**Code Mapping**:

| Architecture Layer | Code Components | File Location |
|-------------------|-----------------|---------------|
| **Model** | SQLAlchemy ORM models | `models.py` |
| **View** | Jinja2 templates | `templates/*.html` |
| **Controller** | Flask route handlers | `app.py` |
| **Business Logic** | Handicap calculations, utilities | `handicap.py`, `auth.py` |
| **Configuration** | Environment and settings | `config.py` |

**Why Monolithic?**:
- Single deployable unit
- Simple for educational purposes
- All components in one codebase for vulnerability demonstration

---

## Layered Architecture

### Layer 1: Presentation Layer (Views)

**Architecture**: Template-based HTML rendering with Jinja2

**Code Structure**:
```
templates/
├── base.html              # Base template with navigation, layout
├── login.html             # Authentication view
├── register.html          # User registration view
├── dashboard.html         # User statistics dashboard
├── courses.html           # Course listing
├── add_course.html        # Course creation (admin only)
├── round_entry.html       # Score entry form
├── scores.html            # Score history view
├── leaderboard.html       # Handicap rankings
├── admin.html             # Admin panel
├── 404.html               # Error page
└── 500.html               # Error page
```

**Template Inheritance**:
- All templates extend `base.html` (line 1 of each template)
- Base template provides: navigation bar, flash messages, CSS/JS includes
- Navigation adapts based on `session['role']` (golfer vs admin)

### Layer 2: Application Layer (Controllers)

**Architecture**: Flask route handlers in single application file

**Code Structure** (`app.py`):

| Route Pattern | Lines | Function | Access Control |
|--------------|-------|----------|----------------|
| `/` | 31-36 | `index()` | Public (redirects) |
| `/register` | 39-87 | `register()` | Public |
| `/login` | 90-115 | `login()` | Public |
| `/logout` | 118-126 | `logout()` | `@login_required` |
| `/dashboard` | 129-142 | `dashboard()` | `@login_required` |
| `/courses` | 145-150 | `courses()` | `@login_required` |
| `/courses/add` | 153-211 | `add_course()` | `@admin_required` |
| `/round/new` | 214-318 | `new_round()` | `@login_required` |
| `/scores` | 321-332 | `scores()` | `@login_required` |
| `/leaderboard` | 335-357 | `leaderboard()` | `@login_required` |
| `/admin` | 360-382 | `admin_panel()` | `@admin_required` |
| `/api/handicap/<user_id>` | 385-399 | `api_get_handicap()` | `@login_required` (IDOR vuln) |

**Request Lifecycle**:
1. HTTP request → Flask routing
2. Decorator checks session authentication (`@login_required` or `@admin_required`)
3. Route handler retrieves data via ORM
4. Business logic called (handicap calculations, etc.)
5. Data passed to template context
6. Template rendered and returned

### Layer 3: Business Logic Layer

**Architecture**: Separated business logic modules

**Code Structure**:

| Module | File | Responsibilities | Key Functions |
|--------|------|------------------|---------------|
| **Authentication** | `auth.py` | Session management, access control, audit logging | `login_required()` (8-16), `admin_required()` (18-32), `get_current_user()` (34-38), `log_action()` (40-57) |
| **Handicap Calculation** | `handicap.py` | USGA handicap system implementation | `calculate_handicap_index()` (8-55), `get_user_statistics()` (70-93), `get_leaderboard()` (96-149) |
| **Input Validation** | `auth.py` | Password and score validation | `validate_password_strength()` (59-73), `validate_score()` (75-87) |

### Layer 4: Data Access Layer (Models)

**Architecture**: SQLAlchemy ORM for database abstraction

**Code Structure** (`models.py`):

| Model Class | Lines | Represents | Key Methods |
|-------------|-------|------------|-------------|
| `User` | 10-46 | Golfers and admins | `set_password()` (27-30), `check_password()` (32-34), `is_admin()` (36-38), `get_handicap_index()` (40-43) |
| `Course` | 49-69 | Golf courses | N/A (data model only) |
| `Hole` | 72-84 | Individual holes | N/A (data model only) |
| `Round` | 87-119 | Completed rounds | `calculate_differential()` (104-111), `verify_total_score()` (113-116) |
| `Score` | 122-139 | Hole-by-hole scores | N/A (data model only) |
| `AuditLog` | 142-155 | Security audit trail | N/A (data model only) |

**Database Initialization**:
- SQLAlchemy instance created: `models.py:8`
- Initialized in app: `app.py:19`
- Tables created: `app.py:26-28` (before first request)

### Layer 5: Configuration Layer

**Architecture**: Environment-based configuration classes

**Code Structure** (`config.py`):

| Configuration Class | Lines | Purpose |
|---------------------|-------|---------|
| `Config` | 6-30 | Base configuration with security gaps |
| `DevelopmentConfig` | 32-34 | Development overrides |
| `ProductionConfig` | 36-40 | Production settings (currently unused) |

**Active Configuration**: `config.py:43` - DevelopmentConfig used by default

---

## Data Flow Architecture

### Request-Response Flow

```
1. Client Request
   ↓
2. Flask Routing (app.py)
   ↓
3. Authentication Decorator (auth.py)
   │
   ├─ Session Check (session['user_id'])
   │  └─ If failed → Redirect to /login
   │
   └─ Role Check (for @admin_required)
      └─ If failed → Redirect to /dashboard
   ↓
4. Route Handler (app.py)
   ↓
5. Database Query (via SQLAlchemy ORM in models.py)
   ↓
6. Business Logic Processing (handicap.py, auth.py)
   ↓
7. Template Rendering (templates/*.html)
   ↓
8. HTTP Response to Client
```

**Code Example - Dashboard Request Flow**:

```
GET /dashboard
  → app.py:129-142 (dashboard route)
  → auth.py:8-16 (@login_required decorator)
  → auth.py:34-38 (get_current_user())
  → models.py:10-46 (User.query.get())
  → handicap.py:70-93 (get_user_statistics())
  → handicap.py:8-55 (calculate_handicap_index())
  → models.py:87-119 (Round queries)
  → templates/dashboard.html (render_template)
  → HTTP 200 Response
```

### Authentication Flow

**Architecture**: Session-based authentication with server-side storage

**Login Flow** (`app.py:90-115`):
```
1. POST /login
   ↓
2. Extract username/password (lines 94-95)
   ↓
3. Query User model (line 98)
   ↓
4. Verify password via SHA256 hash (models.py:32-34)
   ↓
5. Create session (lines 102-105)
   │  session['user_id'] = user.id
   │  session['username'] = user.username
   │  session['role'] = user.role
   ↓
6. Log action (auth.py:40-57)
   ↓
7. Redirect to /dashboard
```

**Session Storage**:
- **Secret Key**: `config.py:9` (hardcoded - security gap)
- **Cookie Settings**: `config.py:16-20`
- **Session Lifetime**: 24 hours (`config.py:20`)

**Authorization Checks**:
- `@login_required`: `auth.py:8-16` - Checks `session['user_id']`
- `@admin_required`: `auth.py:18-32` - Checks `session['user_id']` AND `user.is_admin()`

### Score Submission Flow

**Architecture**: Multi-step transaction with hole-by-hole validation

**Flow** (`app.py:214-318`):
```
1. GET /round/new
   ↓
2. Load courses with holes (lines 219-238)
   ↓
3. Serialize to JSON for JavaScript (lines 223-237)
   ↓
4. Render round_entry.html
   ↓
5. User enters scores in browser
   ↓
6. POST /round/new
   ↓
7. Extract form data (lines 243-245)
   ↓
8. Validate course exists (lines 255-258)
   ↓
9. Loop through holes (lines 264-281)
   │  ├─ Extract score for each hole
   │  ├─ Validate score (auth.py:75-87)
   │  └─ Accumulate total
   ↓
10. Create Round record (lines 285-294)
   ↓
11. Calculate differential (models.py:104-111)
    │  Differential = (Score - Rating) × 113 / Slope
   ↓
12. Commit Round (line 297)
   ↓
13. Create Score records for each hole (lines 300-306)
   ↓
14. Commit all scores (line 309)
   ↓
15. Log action (lines 310-311)
   ↓
16. Redirect to /scores
```

**Database Transaction**:
- Transaction starts: `app.py:296` (db.session.add)
- First commit: `app.py:297` (creates Round with ID)
- Second commit: `app.py:309` (creates all Score records)
- Rollback on error: `app.py:315`

---

## Database Schema Architecture

### Entity-Relationship Architecture

```
User (1) ──────< (M) Round (M) >────── (1) Course
  │                    │                       │
  │                    │                       │
  │                    └── (1:M) ──> Score <── (M:1) ── Hole
  │
  └── (1:M) ──> AuditLog (optional FK)
```

**Relationships Mapping**:

| Parent | Child | Relationship Type | Code Location | Cascade Behavior |
|--------|-------|-------------------|---------------|------------------|
| User | Round | One-to-Many | `models.py:25` | `cascade='all, delete-orphan'` |
| Course | Hole | One-to-Many | `models.py:65` | `cascade='all, delete-orphan'` |
| Course | Round | One-to-Many | `models.py:66` | No cascade |
| Round | Score | One-to-Many | `models.py:102` | `cascade='all, delete-orphan'` |
| Hole | Score | One-to-Many | `models.py:136` | No cascade |
| User | Course | One-to-Many (created_by) | `models.py:62` | No cascade |
| User | AuditLog | One-to-Many (optional) | `models.py:147` | No cascade |

### Schema Details

**User Table** (`models.py:10-46`):
```python
users (table name: 'users')
├── id (Integer, PK)
├── username (String(80), UNIQUE, NOT NULL)
├── email (String(120), UNIQUE, NOT NULL)
├── password_hash (String(128), NOT NULL)  # SHA256 - SECURITY GAP
├── full_name (String(150))
├── role (String(20), DEFAULT 'golfer')     # 'golfer' or 'admin'
├── created_at (DateTime, DEFAULT utcnow)
└── is_active (Boolean, DEFAULT True)
```

**Course Table** (`models.py:49-69`):
```python
courses (table name: 'courses')
├── id (Integer, PK)
├── name (String(200), NOT NULL)
├── location (String(200))
├── num_holes (Integer, DEFAULT 18)
├── course_rating (Float, NOT NULL)        # e.g., 72.5
├── slope_rating (Integer, NOT NULL)       # e.g., 130
├── par (Integer, NOT NULL)                # Total par
├── created_at (DateTime, DEFAULT utcnow)
└── created_by (Integer, FK → users.id)
```

**Hole Table** (`models.py:72-84`):
```python
holes (table name: 'holes')
├── id (Integer, PK)
├── course_id (Integer, FK → courses.id, NOT NULL)
├── hole_number (Integer, NOT NULL)        # 1-18
├── par (Integer, NOT NULL)                # 3, 4, or 5
├── handicap (Integer)                     # Difficulty rank 1-18
└── yardage (Integer)
```

**Round Table** (`models.py:87-119`):
```python
rounds (table name: 'rounds')
├── id (Integer, PK)
├── user_id (Integer, FK → users.id, NOT NULL)
├── course_id (Integer, FK → courses.id, NOT NULL)
├── date_played (Date, NOT NULL, DEFAULT utcnow)
├── total_score (Integer, NOT NULL)        # SECURITY GAP: Not verified
├── differential (Float)                   # Calculated for handicap
├── notes (Text)
└── created_at (DateTime, DEFAULT utcnow)
```

**Score Table** (`models.py:122-139`):
```python
scores (table name: 'scores')
├── id (Integer, PK)
├── round_id (Integer, FK → rounds.id, NOT NULL)
├── hole_id (Integer, FK → holes.id, NOT NULL)
├── strokes (Integer, NOT NULL)            # SECURITY GAP: Weak validation
├── putts (Integer, NULLABLE)              # Optional stats
├── fairway_hit (Boolean, NULLABLE)        # Optional stats
└── green_in_regulation (Boolean, NULLABLE) # Optional stats
```

**AuditLog Table** (`models.py:142-155`):
```python
audit_logs (table name: 'audit_logs')
├── id (Integer, PK)
├── user_id (Integer, FK → users.id, NULLABLE)
├── action (String(100), NOT NULL)
├── resource (String(100))
├── ip_address (String(45))
├── timestamp (DateTime, DEFAULT utcnow)
└── details (Text)
```

**Database Configuration**:
- **Type**: SQLite (development) - `config.py:13`
- **Location**: `instance/golf.db` - `config.py:13`
- **ORM**: SQLAlchemy 2.0.20 - `requirements.txt`
- **Initialization**: `init_db.py` or `app.py:417-418`

---

## Authentication & Authorization Architecture

### Session-Based Authentication

**Architecture Pattern**: Server-side session storage with signed cookies

**Implementation**:

| Component | Code Location | Details |
|-----------|---------------|---------|
| **Session Creation** | `app.py:102-105` | Sets `user_id`, `username`, `role` |
| **Session Secret** | `config.py:9` | Hardcoded (SECURITY GAP) |
| **Session Cookie Settings** | `config.py:16-20` | HTTPONLY, SameSite=Lax, no SECURE flag |
| **Session Lifetime** | `config.py:20` | 24 hours (too long - SECURITY GAP) |
| **Session Validation** | `auth.py:12` | Checks `'user_id' in session` |
| **Session Destruction** | `app.py:124` | `session.clear()` on logout |

**Security Gaps**:
1. **Session Fixation** (`app.py:102`): Session not regenerated after login
2. **Hardcoded Secret** (`config.py:9`): Not using environment variables
3. **No SECURE Flag** (`config.py:17`): Session cookie sent over HTTP
4. **Long Lifetime** (`config.py:20`): 24-hour sessions increase attack window

### Authorization Levels

**Architecture**: Role-based access control (RBAC) with 2 roles

**Roles**:
- `golfer` (default): Can view own data, submit scores, view leaderboards
- `admin`: All golfer permissions + manage courses, view all users, audit logs

**Authorization Decorators** (`auth.py`):

```python
@login_required (lines 8-16)
├── Checks: 'user_id' in session
├── On failure: Redirect to /login
└── Used by: /dashboard, /courses, /round/new, /scores, /leaderboard

@admin_required (lines 18-32)
├── Checks:
│   ├── 'user_id' in session
│   └── user.is_admin() == True
├── On failure: Redirect to /dashboard
└── Used by: /courses/add, /admin
```

**Role Determination**:
- Set during registration: `app.py:73` (always 'golfer')
- Set during login: `app.py:104` (from database)
- Checked via: `models.py:36-38` (`is_admin()` method)

**Authorization Vulnerabilities**:
1. **IDOR** (`app.py:385-399`): API endpoint `/api/handicap/<user_id>` accepts any user_id
2. **Information Disclosure** (`app.py:339`): Any authenticated user can view all scores
3. **No CSRF Protection** (`app.py:165-166`): Forms lack CSRF tokens

---

## Business Logic Architecture

### Handicap Calculation System

**Architecture**: USGA Handicap System (simplified implementation)

**Algorithm** (`handicap.py:8-55`):

```
1. Retrieve last 20 rounds (line 19-23)
   ├── Filter: user_id = current user
   ├── Filter: differential IS NOT NULL
   └── Order by: date_played DESC

2. Check minimum rounds (line 25-26)
   └── Minimum: 5 rounds (config.py:28)

3. Sort by differential ascending (line 29)

4. Determine count based on rounds played (lines 32-44)
   ├── 20+ rounds → Use best 8
   ├── 15-19 rounds → Use best 6
   ├── 10-14 rounds → Use best 4
   ├── 8-9 rounds → Use best 3
   ├── 6-7 rounds → Use best 2
   └── 5 rounds → Use best 1

5. Calculate average differential (line 50)

6. Multiply by 0.96 (line 53)

7. Round to 1 decimal place (line 55)
```

**Differential Calculation** (`models.py:104-111`):
```
Formula: (Total Score - Course Rating) × 113 / Slope Rating

Example:
  Score = 85
  Course Rating = 72.5
  Slope Rating = 130

  Differential = (85 - 72.5) × 113 / 130 = 10.9
```

**Configuration** (`config.py:27-30`):
```python
MIN_ROUNDS_FOR_HANDICAP = 5
ROUNDS_TO_CONSIDER = 20
BEST_SCORES_COUNT = 8
```

### Statistics Calculation

**User Statistics** (`handicap.py:70-93`):

| Statistic | Calculation | Code Location |
|-----------|-------------|---------------|
| Total Rounds | `len(rounds)` | Line 78 |
| Average Score | `sum(scores) / len(scores)` | Line 89 |
| Best Score | `min(scores)` | Line 90 |
| Worst Score | `max(scores)` | Line 91 |
| Handicap Index | `calculate_handicap_index(user_id)` | Line 92 |

**Leaderboard Calculation** (`handicap.py:96-149`):

**Course-Specific Leaderboard** (lines 103-127):
```sql
SELECT
  User.id,
  User.username,
  User.full_name,
  MIN(Round.total_score) AS best_score,
  COUNT(Round.id) AS rounds_played
FROM User
JOIN Round ON Round.user_id = User.id
WHERE Round.course_id = ?
GROUP BY User.id
ORDER BY MIN(Round.total_score)
LIMIT ?
```

**Overall Handicap Leaderboard** (lines 129-149):
- Query all active users
- Calculate handicap index for each
- Sort by handicap index ascending (best golfers first)
- Return top N entries

---

## Template Architecture

### Template Inheritance Hierarchy

```
base.html (master template)
├── Navigation bar (lines vary per template)
├── Flash message display
├── Content block {% block content %}
└── Footer

├── login.html
├── register.html
├── dashboard.html
│   └── Shows: user stats, recent rounds, handicap
├── courses.html
│   └── Shows: all courses, details
├── add_course.html
│   └── Form: 18-hole course creation
├── round_entry.html
│   └── Form: hole-by-hole score entry
├── scores.html
│   └── Shows: user's score history
├── leaderboard.html
│   └── Shows: rankings by course or overall
├── admin.html
│   └── Shows: users, courses, audit logs, stats
├── 404.html
└── 500.html
```

### Template Data Context

**Session Variables** (available in all templates):
- `session.user_id` - Current user ID
- `session.username` - Current username
- `session.role` - User role ('golfer' or 'admin')

**Template-Specific Context**:

| Template | Context Variables | Passed From |
|----------|------------------|-------------|
| `dashboard.html` | `user`, `stats`, `recent_rounds` | `app.py:142` |
| `courses.html` | `courses` | `app.py:150` |
| `round_entry.html` | `courses` (with holes serialized) | `app.py:239` |
| `scores.html` | `rounds` | `app.py:332` |
| `leaderboard.html` | `leaderboard`, `courses`, `selected_course`, `title` | `app.py:353-357` |
| `admin.html` | `users`, `courses`, `logs`, `stats` | `app.py:381-382` |

### Navigation Logic

**Conditional Navigation** (in `base.html`):
```jinja2
{% if session.role == 'admin' %}
  <!-- Show admin links -->
  <a href="/admin">Admin Panel</a>
  <a href="/courses/add">Add Course</a>
{% endif %}

<!-- Show to all authenticated users -->
<a href="/dashboard">Dashboard</a>
<a href="/courses">Courses</a>
<a href="/round/new">Enter Round</a>
<a href="/scores">My Scores</a>
<a href="/leaderboard">Leaderboard</a>
```

---

## Deployment Architecture

### Docker Architecture

**Multi-Container Setup** (single service currently):

```
docker-compose.yml
└── Service: web
    ├── Build: Dockerfile
    ├── Port: 5001:5001
    ├── Volumes:
    │   ├── ./instance:/app/instance (database persistence)
    │   └── .:/app (code hot-reload)
    └── Environment:
        ├── FLASK_ENV=development
        └── FLASK_DEBUG=1
```

**Dockerfile** (build process):
```dockerfile
FROM python:3.9-slim

1. Set working directory: /app
2. Install system dependencies: gcc
3. Copy requirements.txt
4. Install Python packages
5. Copy application code
6. Create instance directory
7. Expose port 5001
8. CMD: python init_db.py && python app.py
```

**Volume Persistence**:
- `./instance:/app/instance` - SQLite database survives container restarts
- `.:/app` - Code changes reflect immediately (development only)

### Production Considerations (Not Implemented)

**Commented PostgreSQL Service** (`docker-compose.yml:19-35`):
```yaml
# Optional production database
db:
  image: postgres:13
  environment:
    - POSTGRES_USER=golfapp
    - POSTGRES_PASSWORD=securepassword
    - POSTGRES_DB=golf_db
  volumes:
    - postgres_data:/var/lib/postgresql/data
```

**Production Configuration** (`config.py:36-40`):
- `DEBUG = False`
- `SECRET_KEY` from environment variable
- `SESSION_COOKIE_SECURE = True` (requires HTTPS)

---

## File-to-Architecture Mapping

### Complete File Inventory

| File Path | Architecture Component | Purpose | Lines of Code |
|-----------|------------------------|---------|---------------|
| `app.py` | Controller Layer | Route handlers, application logic | 424 |
| `models.py` | Data Access Layer | ORM models, database schema | 156 |
| `auth.py` | Business Logic Layer | Authentication, authorization, audit | 88 |
| `handicap.py` | Business Logic Layer | Handicap calculations, statistics | 150 |
| `config.py` | Configuration Layer | Settings, environment configuration | 44 |
| `init_db.py` | Data Initialization | Database setup, demo data | 236 |
| `Dockerfile` | Deployment Layer | Container image definition | 34 |
| `docker-compose.yml` | Deployment Layer | Multi-container orchestration | 36 |
| `requirements.txt` | Dependency Layer | Python package dependencies | ~10 |
| `templates/base.html` | Presentation Layer | Master template | Variable |
| `templates/*.html` | Presentation Layer | Page-specific templates | Variable |

### Code Organization Principles

**Single Responsibility**:
- `models.py` - Only database models and ORM relationships
- `auth.py` - Only authentication/authorization concerns
- `handicap.py` - Only golf handicap business logic
- `app.py` - Only HTTP request/response handling

**Separation of Concerns**:
```
HTTP Layer (app.py)
    ↓
Business Logic Layer (auth.py, handicap.py)
    ↓
Data Access Layer (models.py)
    ↓
Database (SQLite)
```

**Configuration Centralization**:
- All settings in `config.py`
- Environment-based configuration classes
- No hardcoded values in business logic (except security gaps)

---

## Security Architecture Gaps

### Intentional Vulnerabilities (Educational)

**Authentication & Session Management**:

| Vulnerability | Location | Architecture Impact |
|---------------|----------|---------------------|
| Weak password hashing (SHA256) | `models.py:30` | Data Layer - passwords easily crackable |
| Session fixation | `app.py:102` | Controller Layer - session not regenerated |
| Hardcoded secret key | `config.py:9` | Config Layer - session cookies vulnerable |
| Information disclosure in login | `app.py:111-113` | Controller Layer - reveals username validity |
| Weak password validation | `auth.py:64-73` | Business Logic Layer - allows weak passwords |

**Input Validation**:

| Vulnerability | Location | Architecture Impact |
|---------------|----------|---------------------|
| No CSRF protection | `app.py:165-166, 247` | Controller Layer - forms vulnerable to CSRF |
| Weak score validation | `auth.py:80-85` | Business Logic Layer - unrealistic scores allowed |
| Total score not verified | `models.py:95-96, app.py:283` | Data Layer - score manipulation possible |
| Insufficient input sanitization | `app.py:49-52` | Controller Layer - potential injection |

**Authorization**:

| Vulnerability | Location | Architecture Impact |
|---------------|----------|---------------------|
| IDOR in API endpoint | `app.py:389` | Controller Layer - any user can access any data |
| No rate limiting | `app.py:97` | Controller Layer - brute force attacks possible |
| Information disclosure | `app.py:339, handicap.py:101` | Business Logic Layer - all scores publicly visible |

**Cryptography**:

| Vulnerability | Location | Architecture Impact |
|---------------|----------|---------------------|
| No HMAC for score integrity | `models.py:96` | Data Layer - score tampering undetectable |
| No encryption for sensitive data | All models | Data Layer - plaintext storage |

**Infrastructure**:

| Vulnerability | Location | Architecture Impact |
|---------------|----------|---------------------|
| Debug mode enabled | `config.py:23` | Config Layer - stack traces exposed |
| Missing security headers | Entire app | Infrastructure Layer - no CSP, HSTS, etc. |
| SQLite in production | `config.py:13` | Data Layer - not scalable or secure |
| No HTTPS enforcement | `config.py:17` | Infrastructure Layer - session cookies over HTTP |

### Assignment Roadmap

**Assignment 1**: DevSecOps pipeline, SAST/DAST tools
- No code changes, only tooling integration

**Assignment 2**: Threat modeling, STRIDE analysis
- No code changes, documentation only

**Assignment 3**: Implement cryptographic APIs
- Replace SHA256 with bcrypt (`models.py:30`)
- Add HMAC for score integrity (`models.py:96`)
- Encrypt sensitive data

**Assignment 4**: DAST testing and vulnerability fixes
- Add CSRF protection (Flask-WTF)
- Fix IDOR vulnerabilities
- Implement rate limiting
- Add security headers

---

## Architecture-to-Code Traceability Matrix

### Feature: User Authentication

| Architectural Component | Code Location | Lines |
|------------------------|---------------|-------|
| **UI Layer** | `templates/login.html` | Full template |
| **Controller** | `app.py:login()` | 90-115 |
| **Business Logic** | `models.py:check_password()` | 32-34 |
| **Data Access** | `models.py:User.query.filter_by()` | 98 |
| **Session Management** | `app.py:session['user_id']` | 102-105 |
| **Audit Logging** | `auth.py:log_action()` | 107, 112 |
| **Configuration** | `config.py:SECRET_KEY` | 9 |

### Feature: Score Submission

| Architectural Component | Code Location | Lines |
|------------------------|---------------|-------|
| **UI Layer** | `templates/round_entry.html` | Full template |
| **Controller** | `app.py:new_round()` | 214-318 |
| **Input Validation** | `auth.py:validate_score()` | 275 |
| **Business Logic** | `models.py:calculate_differential()` | 294 |
| **Data Access** | `models.py:Round`, `models.py:Score` | 285-306 |
| **Transaction Management** | `app.py:db.session.commit()` | 297, 309 |
| **Audit Logging** | `auth.py:log_action()` | 310-311 |

### Feature: Handicap Calculation

| Architectural Component | Code Location | Lines |
|------------------------|---------------|-------|
| **UI Layer** | `templates/dashboard.html` | Full template |
| **Controller** | `app.py:dashboard()` | 129-142 |
| **Business Logic** | `handicap.py:calculate_handicap_index()` | 8-55 |
| **Business Logic** | `handicap.py:get_user_statistics()` | 70-93 |
| **Data Access** | `models.py:Round.query.filter_by()` | 19-23, 74 |
| **Configuration** | `config.py:MIN_ROUNDS_FOR_HANDICAP` | 28-30 |

### Feature: Admin Panel

| Architectural Component | Code Location | Lines |
|------------------------|---------------|-------|
| **UI Layer** | `templates/admin.html` | Full template |
| **Controller** | `app.py:admin_panel()` | 360-382 |
| **Authorization** | `auth.py:@admin_required` | 361 |
| **Data Access** | `models.py:User.query.all()` | 364 |
| **Audit Logs** | `models.py:AuditLog.query` | 366 |

---

## Summary

This Golf Score Tracker application follows a **monolithic MVC architecture** with clear separation of concerns:

1. **Presentation Layer** (`templates/`) - Jinja2 templates with inheritance
2. **Controller Layer** (`app.py`) - Flask route handlers
3. **Business Logic Layer** (`auth.py`, `handicap.py`) - Domain logic
4. **Data Access Layer** (`models.py`) - SQLAlchemy ORM
5. **Configuration Layer** (`config.py`) - Environment settings
6. **Deployment Layer** (`Dockerfile`, `docker-compose.yml`) - Containerization

The architecture intentionally includes **security vulnerabilities for educational purposes**, which will be progressively addressed through course assignments. The codebase demonstrates clear traceability between architectural components and implementation code, making it suitable for security analysis and improvement exercises.

**Key Architectural Strengths**:
- Clear separation of concerns
- Modular design with single responsibility
- Template inheritance for DRY principle
- Configuration-based environment management
- Audit logging for security monitoring

**Architectural Weaknesses** (Intentional):
- No defense in depth (single layer of security)
- Insufficient input validation
- Weak cryptographic implementations
- Missing security controls (CSRF, rate limiting)
- No secure development practices (hardcoded secrets)

This architecture provides a foundation for learning secure software development by starting with a vulnerable baseline and systematically improving security through the course assignments.
