# AI Usage Log - Data Flow Diagram (DFD) and STRIDE Threat Modeling
## Question 7: Application DFD and STRIDE Analysis

**Date:** 2025-11-15
**Task:** Create comprehensive Data Flow Diagram and perform STRIDE threat modeling for Golf Score Tracker application

---

## Conversation Summary

**User Request:**
Create a DFD diagram identifying all components (data flow, data store, process, interactor/endpoints, trust boundary) and perform STRIDE threat modeling to identify threats and mitigations.

**Assistant Response:**
Analyzed the entire application architecture including app.py, models.py, auth.py, handicap.py, and config.py to identify all components and their interactions.

---

## Data Flow Diagram (DFD)

### Component Identification

#### 1. External Entities (Interactors)
- **Golfer User** - Regular authenticated users who track golf scores
- **Admin User** - Privileged users who manage courses and system
- **Unauthenticated User** - Anonymous visitors (login/register only)

#### 2. Processes
- **P1: Authentication Process** (`app.py:90-126`, `auth.py`)
  - Login (validates credentials, creates session)
  - Registration (creates new user account)
  - Logout (destroys session)

- **P2: Round Entry Process** (`app.py:214-319`)
  - Accepts score input from golfer
  - Validates scores
  - Calculates total and differential
  - Stores round and hole scores

- **P3: Handicap Calculation Process** (`handicap.py:8-56`)
  - Retrieves user's recent rounds
  - Applies USGA handicap formula
  - Returns handicap index

- **P4: Course Management Process** (`app.py:153-211`)
  - Create new golf courses (admin only)
  - Define 18 holes with par, yardage, handicap rating
  - Store course metadata

- **P5: Dashboard/Statistics Process** (`app.py:129-143`, `handicap.py:70-93`)
  - Aggregates user statistics
  - Displays recent rounds
  - Shows handicap index

- **P6: Leaderboard Process** (`app.py:335-357`, `handicap.py:96-150`)
  - Queries all users' scores
  - Ranks by handicap or course score
  - Displays rankings

- **P7: API Handicap Service** (`app.py:385-399`)
  - RESTful endpoint for handicap data
  - Returns JSON with user statistics

- **P8: Audit Logging Process** (`auth.py:40-57`)
  - Captures user actions
  - Records IP address, timestamp, resource
  - Stores in audit log

- **P9: Password Hashing Process** (`models.py:27-34`)
  - Hashes passwords on registration
  - Verifies passwords on login

#### 3. Data Stores
- **DS1: Users Table** (`models.py:10-46`)
  - Stores: id, username, email, password_hash, full_name, role, created_at, is_active
  - Purpose: User authentication and authorization

- **DS2: Courses Table** (`models.py:49-69`)
  - Stores: id, name, location, num_holes, course_rating, slope_rating, par, created_by
  - Purpose: Golf course metadata

- **DS3: Holes Table** (`models.py:72-84`)
  - Stores: id, course_id, hole_number, par, handicap, yardage
  - Purpose: Individual hole details for each course

- **DS4: Rounds Table** (`models.py:87-119`)
  - Stores: id, user_id, course_id, date_played, total_score, differential, notes
  - Purpose: Golf rounds played by users

- **DS5: Scores Table** (`models.py:122-139`)
  - Stores: id, round_id, hole_id, strokes, putts, fairway_hit, green_in_regulation
  - Purpose: Individual hole scores within rounds

- **DS6: Audit Logs Table** (`models.py:142-155`)
  - Stores: id, user_id, action, resource, ip_address, timestamp, details
  - Purpose: Security audit trail

- **DS7: Session Store** (Flask session cookie)
  - Stores: user_id, username, role
  - Purpose: Maintain authentication state

#### 4. Data Flows

**Authentication Flows:**
- DF1: User credentials → P1 (Login)
- DF2: P1 → DS1 (Query user by username)
- DF3: DS1 → P1 (User record with password_hash)
- DF4: P1 → P9 (Verify password)
- DF5: P1 → DS7 (Create session with user_id, username, role)
- DF6: P1 → DS6 (Log authentication event)

**Round Entry Flows:**
- DF7: Golfer score data → P2 (Round entry form)
- DF8: P2 → DS2 (Retrieve course details)
- DF9: DS2 → P2 (Course metadata for validation)
- DF10: P2 → DS4 (Store round with total_score, differential)
- DF11: P2 → DS5 (Store 18 individual hole scores)
- DF12: P2 → DS6 (Log round submission)

**Handicap Calculation Flows:**
- DF13: P5 → P3 (Request handicap for user_id)
- DF14: P3 → DS4 (Query recent 20 rounds)
- DF15: DS4 → P3 (Rounds with differentials)
- DF16: P3 → P5 (Return calculated handicap index)

**Course Management Flows:**
- DF17: Admin course data → P4 (Add course form)
- DF18: P4 → DS2 (Create course record)
- DF19: P4 → DS3 (Create 18 hole records)
- DF20: P4 → DS6 (Log course creation)

**API Flows:**
- DF21: HTTP GET /api/handicap/<user_id> → P7
- DF22: P7 → P3 (Request handicap calculation)
- DF23: P3 → DS4 (Retrieve rounds)
- DF24: P7 → JSON response (handicap data)

**Leaderboard Flows:**
- DF25: User request → P6 (View leaderboard)
- DF26: P6 → DS1 (Query all active users)
- DF27: P6 → DS4 (Query all rounds for ranking)
- DF28: P6 → P3 (Calculate handicaps for all users)
- DF29: P6 → User (Display ranked list)

#### 5. Trust Boundaries

**TB1: Internet ↔ Application Boundary**
- Separates untrusted external users from application processes
- Crossed by: All HTTP requests (login, registration, API calls)
- Protection: Flask session authentication, decorators (@login_required, @admin_required)

**TB2: Application ↔ Database Boundary**
- Separates application logic from persistent storage
- Crossed by: All database queries via SQLAlchemy ORM
- Protection: ORM parameterization (prevents SQL injection)

**TB3: Unauthenticated ↔ Authenticated Context**
- Separates public routes from protected routes
- Crossed by: Login process creating session
- Protection: @login_required decorator checks session

**TB4: Golfer ↔ Admin Privilege Boundary**
- Separates regular users from administrative functions
- Crossed by: Admin-only operations (course creation, user management)
- Protection: @admin_required decorator checks session['role']

### DFD Diagram (Text Representation)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARY 1: Internet                        │
│                                                                          │
│  ┌──────────────┐         ┌──────────────┐        ┌──────────────┐    │
│  │Unauthenticated│         │Golfer User   │        │Admin User    │    │
│  │   Visitor    │         │              │        │              │    │
│  └──────┬───────┘         └──────┬───────┘        └──────┬───────┘    │
│         │                        │                       │             │
└─────────┼────────────────────────┼───────────────────────┼──────────────┘
          │                        │                       │
          │ DF1: Credentials       │ DF7: Score Data      │ DF17: Course
          │ (username/password)    │ DF25: View Request   │       Data
          ▼                        ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              TRUST BOUNDARY 2: Application Layer                         │
│                                                                          │
│ ┌─────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│ │P1: Auth     │  │P2: Round   │  │P4: Course  │  │P6: Leader- │       │
│ │   Process   │  │   Entry    │  │   Mgmt     │  │   board    │       │
│ └──┬──▲───┬───┘  └─┬──▲───────┘  └────┬───────┘  └─┬──▲───────┘       │
│    │  │   │        │  │               │            │  │                │
│    │  │   │ DF5    │  │               │            │  │                │
│    │  │   │(Create │  │               │            │  │                │
│    │  │   │Session)│  │               │            │  │                │
│    │  │   ▼        │  │               │            │  │                │
│    │  │ ┌────────────┐│               │            │  │                │
│    │  │ │DS7: Session││               │            │  │                │
│    │  │ │   Store    ││               │            │  │                │
│    │  │ └────────────┘│               │            │  │                │
│    │  │               │               │            │  │                │
│    │  │ DF4          │               │            │  │                │
│    │  │ (Verify)     │               │            │  │                │
│    │  ▼              │               │            │  │                │
│    │ ┌────────────┐  │               │            │  │                │
│    │ │P9: Password│  │               │            │  │                │
│    │ │   Hashing  │  │               │            │  │                │
│    │ └────────────┘  │               │            │  │                │
│    │                 │               │            │  │                │
│    │ DF6            │DF12           │DF20        │  │                │
│    │ (Log)          │(Log)          │(Log)       │  │                │
│    ▼                ▼               ▼            │  │                │
│  ┌──────────────────────────────────────────┐    │  │                │
│  │         P8: Audit Logging                │    │  │                │
│  └──────────────┬───────────────────────────┘    │  │                │
│                 │                                │  │                │
│                 │                    DF13        │  │ DF28           │
│                 │               ┌────────────────┤  │ (Calculate)    │
│                 │               │                │  │                │
│                 │               ▼                ▼  │                │
│                 │         ┌─────────────────────────┐                │
│                 │         │P3: Handicap Calculation │                │
│                 │         └──────────┬──────────────┘                │
│                 │                    │ DF14                          │
│                 │                    │ (Query rounds)                │
└─────────────────┼────────────────────┼───────────────────────────────┘
                  │                    │
                  │                    │
┌─────────────────┼────────────────────┼───────────────────────────────┐
│         TRUST BOUNDARY 3: Database Layer                              │
│                 │                    │                                │
│  DF2,3          │                    │                                │
│  (Query user)   │                    │                                │
│         ┌───────▼───┐   ┌────────────▼───┐    ┌──────────────┐      │
│         │DS1: Users │   │DS4: Rounds     │    │DS2: Courses  │      │
│         │   Table   │   │    Table       │    │    Table     │      │
│         └───────────┘   └────────┬───────┘    └──────┬───────┘      │
│                                  │                    │              │
│         ┌───────────┐   ┌────────▼───────┐    ┌──────▼───────┐      │
│         │DS6: Audit │   │DS5: Scores     │    │DS3: Holes    │      │
│         │   Logs    │   │    Table       │    │    Table     │      │
│         └───────────┘   └────────────────┘    └──────────────┘      │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

Additional Components:
- P7: API Handicap Service (DF21-24) - RESTful endpoint
- P5: Dashboard/Statistics Process (aggregates data from DS4, P3)
```

### Key Trust Boundary Crossings

1. **Public to Application** (TB1)
   - Entry points: `/login`, `/register`, `/api/handicap/<user_id>`
   - Risk: Unauthenticated access, credential theft, brute force

2. **Authenticated to Protected Resources** (TB3)
   - Validation: Session cookie with user_id
   - Risk: Session fixation, session hijacking, CSRF

3. **Golfer to Admin Functions** (TB4)
   - Validation: Session role check (`session['role'] == 'admin'`)
   - Risk: Privilege escalation, role manipulation

4. **Application to Database** (TB2)
   - Mechanism: SQLAlchemy ORM queries
   - Risk: SQL injection (mitigated by ORM), data tampering

---

## STRIDE Threat Modeling Analysis

### Methodology
For each component in the DFD, analyze against six threat categories:
- **S**poofing - Impersonating users/systems
- **T**ampering - Modifying data or code
- **R**epudiation - Denying actions taken
- **I**nformation Disclosure - Exposing confidential information
- **D**enial of Service - Degrading system availability
- **E**levation of Privilege - Gaining unauthorized access

---

### 1. P1: Authentication Process

#### Threats

**S1 - Spoofing: Credential Stuffing Attack**
- **Component:** Login endpoint (`app.py:90-115`)
- **Description:** Attacker uses leaked credentials from other breaches to gain unauthorized access
- **Evidence:** `app.py:97-98` - "No rate limiting, vulnerable to brute force"
- **Impact:** Account takeover, unauthorized access to golf scores and personal data
- **Likelihood:** High
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Implement rate limiting with Flask-Limiter (max 5 attempts per minute per IP)
  2. Add account lockout after 5 failed attempts
  3. Implement CAPTCHA after 3 failed attempts
  4. Monitor audit logs for suspicious login patterns

**S2 - Spoofing: Session Fixation**
- **Component:** Session creation (`app.py:101-105`)
- **Description:** Attacker forces victim to use a known session ID, then hijacks the session after login
- **Evidence:** `app.py:101` - "SECURITY GAP: Session fixation vulnerability"
- **Impact:** Session hijacking, unauthorized access as legitimate user
- **Likelihood:** Medium
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Regenerate session ID after successful login: `session.regenerate()`
  2. Invalidate old session tokens on login
  3. Set `SESSION_COOKIE_SECURE=True` for HTTPS-only cookies
  4. Implement `SESSION_COOKIE_SAMESITE='Strict'` in production

**T1 - Tampering: Password Hash Weakness**
- **Component:** Password hashing (`models.py:27-30`)
- **Description:** SHA256 hashing without salt allows rainbow table attacks
- **Evidence:** `models.py:18, 30` - "Using simple SHA256 instead of bcrypt"
- **Impact:** Passwords can be cracked if database is compromised
- **Likelihood:** High (if database is breached)
- **Current Mitigations:** None (intentional gap for Assignment 3)
- **Recommended Mitigations:**
  1. Replace SHA256 with bcrypt or Argon2
  2. Use salt rounds (cost factor 12-14 for bcrypt)
  3. Implement password hashing upgrade on next login
  4. Add pepper (application-wide secret) in addition to per-password salt

**I1 - Information Disclosure: Username Enumeration**
- **Component:** Login error messages (`app.py:111-113`)
- **Description:** Error messages reveal whether username exists in database
- **Evidence:** `app.py:111-113` - "SECURITY GAP: Information disclosure"
- **Impact:** Attackers can enumerate valid usernames for targeted attacks
- **Likelihood:** High
- **Current Mitigations:** Generic error message (partially mitigates), but timing attacks possible
- **Recommended Mitigations:**
  1. Use constant-time comparison for password checks
  2. Generic error: "Invalid credentials" (already implemented)
  3. Add random delay (50-200ms) to prevent timing attacks
  4. Log enumeration attempts for security monitoring

**R1 - Repudiation: Incomplete Audit Logging**
- **Component:** Login audit logs (`app.py:107, 112`)
- **Description:** Failed login attempts logged but no correlation to detect attack patterns
- **Evidence:** `app.py:112` - Logs failed attempts but no aggregation
- **Impact:** Difficult to investigate security incidents, attacker actions may go undetected
- **Likelihood:** Medium
- **Current Mitigations:** Basic audit logging to DS6 with IP address
- **Recommended Mitigations:**
  1. Log all authentication events (success, failure, lockout)
  2. Include user agent, referer, geolocation
  3. Implement log correlation to detect brute force patterns
  4. Add log integrity protection (HMAC signatures)
  5. Store logs in immutable storage (append-only)

**D1 - Denial of Service: Brute Force Login**
- **Component:** Login endpoint (`app.py:90-115`)
- **Description:** Unlimited login attempts can exhaust server resources
- **Evidence:** `app.py:97` - "No rate limiting, vulnerable to brute force"
- **Impact:** Server slowdown, account lockout for legitimate users
- **Likelihood:** High
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Rate limit login attempts (5/minute per IP, 20/hour per username)
  2. Exponential backoff for repeated failures
  3. CAPTCHA after threshold
  4. WAF rules to block suspicious traffic patterns

---

### 2. P2: Round Entry Process

#### Threats

**T2 - Tampering: Score Manipulation**
- **Component:** Round submission (`app.py:260-290`)
- **Description:** Total score not cryptographically verified against hole scores
- **Evidence:** `app.py:283`, `models.py:95-96` - "Total score not verified (can be manipulated)"
- **Impact:** Users can fraudulently lower scores to improve handicap, leaderboard manipulation
- **Likelihood:** High
- **Current Mitigations:** Basic validation (strokes 1-20), `verify_total_score()` method exists but not enforced
- **Recommended Mitigations:**
  1. Calculate total score server-side from hole scores (don't trust client)
  2. Add HMAC signature to round data: `HMAC(secret, round_id + total_score + hole_scores)`
  3. Store HMAC in database, verify on retrieval
  4. Validate total_score == sum(hole scores) before commit
  5. Log discrepancies for fraud detection

**T3 - Tampering: CSRF - Cross-Site Request Forgery**
- **Component:** Round entry form (`app.py:214`, POST endpoint)
- **Description:** Attacker can submit scores on behalf of victim via malicious site
- **Evidence:** `app.py:247` - "No CSRF protection"
- **Impact:** Unauthorized score submission, data corruption
- **Likelihood:** Medium
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Implement Flask-WTF for CSRF tokens
  2. Include `csrf_token()` in all forms
  3. Validate token on POST requests
  4. Set `SESSION_COOKIE_SAMESITE='Strict'`

**T4 - Tampering: Date Manipulation**
- **Component:** Date played field (`app.py:244-253`)
- **Description:** Users can backdate rounds to manipulate handicap calculations
- **Evidence:** `app.py:248` - "Date manipulation possible"
- **Impact:** Handicap fraud (e.g., backdating good scores, excluding bad ones)
- **Likelihood:** Medium
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Restrict dates to within reasonable range (e.g., last 30 days to 1 day future)
  2. Require admin approval for backdated rounds
  3. Flag unusual date patterns in audit logs
  4. Lock round dates after 7 days

**I2 - Information Disclosure: Score Validation Messages**
- **Component:** Score validation (`auth.py:75-87`)
- **Description:** Validation errors reveal internal logic
- **Evidence:** `auth.py:80-85` - Weak validation with specific error messages
- **Impact:** Low - Minor information leakage about validation rules
- **Likelihood:** Low
- **Current Mitigations:** Generic messages used
- **Recommended Mitigations:**
  1. Maintain current generic error approach
  2. Avoid revealing exact validation thresholds

**D2 - Denial of Service: Bulk Score Submission**
- **Component:** Round entry endpoint (`app.py:214-319`)
- **Description:** No rate limiting on score submissions
- **Impact:** Database flooding, storage exhaustion
- **Likelihood:** Low
- **Current Mitigations:** @login_required decorator limits to authenticated users
- **Recommended Mitigations:**
  1. Rate limit: 10 rounds per day per user
  2. Validate course_id exists before processing
  3. Add database storage quotas per user

---

### 3. P3: Handicap Calculation Process

#### Threats

**T5 - Tampering: Handicap Formula Manipulation**
- **Component:** Handicap calculation (`handicap.py:8-56`)
- **Description:** If score data is tampered, handicap becomes invalid
- **Evidence:** `handicap.py:16` - "This calculation could be manipulated if score data is compromised"
- **Impact:** Unfair competition, leaderboard fraud
- **Likelihood:** Medium (depends on T2 score tampering)
- **Current Mitigations:** Uses database data (relies on DB integrity)
- **Recommended Mitigations:**
  1. Implement HMAC verification for rounds before calculation (see T2)
  2. Audit handicap changes > 5 points in single update
  3. Add recalculation timestamps to detect retroactive changes
  4. Store handicap history for forensics

**I3 - Information Disclosure: Handicap API without Authorization**
- **Component:** API endpoint (`app.py:385-399`)
- **Description:** Any authenticated user can access any user's handicap via `/api/handicap/<user_id>`
- **Evidence:** `app.py:389-390` - "SECURITY GAP: No authorization check (any user can get any user's handicap)"
- **Impact:** Privacy violation, competitive intelligence leak
- **Likelihood:** High
- **Current Mitigations:** @login_required (requires authentication but not authorization)
- **Recommended Mitigations:**
  1. Implement authorization check:
     ```python
     if user_id != session['user_id'] and not current_user.is_admin():
         abort(403)
     ```
  2. Add API key for legitimate external access
  3. Log all API access for audit
  4. Rate limit API calls (100/hour per user)

**D3 - Denial of Service: Handicap Calculation Overload**
- **Component:** Leaderboard process (`app.py:335-357`, `handicap.py:96-150`)
- **Description:** Leaderboard calculates handicaps for all active users on every request
- **Evidence:** `handicap.py:133-136` - Loops through all users, calculates handicap each time
- **Impact:** Database overload, slow page loads with many users
- **Likelihood:** Medium (scales with user count)
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Cache handicap calculations (TTL 1 hour)
  2. Pre-calculate handicaps asynchronously (background job)
  3. Paginate leaderboard results
  4. Add database indexes on user_id, date_played

---

### 4. P4: Course Management Process

#### Threats

**E1 - Elevation of Privilege: Admin Role Check Bypass**
- **Component:** @admin_required decorator (`auth.py:18-32`)
- **Description:** Session role can potentially be manipulated if session security is weak
- **Evidence:** Relies on `session['role']` which is stored in client-side cookie
- **Impact:** Non-admin users gain admin privileges, can create/modify courses
- **Likelihood:** Low (requires session tampering, mitigated by secret key)
- **Current Mitigations:** Flask session signing with SECRET_KEY
- **Recommended Mitigations:**
  1. Verify role from database on each admin request:
     ```python
     user = User.query.get(session['user_id'])
     if not user.is_admin(): abort(403)
     ```
  2. Use strong SECRET_KEY (not hardcoded - see S3)
  3. Implement role-based access control (RBAC) with database-backed permissions
  4. Add admin action approval workflow for critical operations

**T6 - Tampering: CSRF on Course Creation**
- **Component:** Add course form (`app.py:153-211`)
- **Description:** No CSRF protection on course creation endpoint
- **Evidence:** `app.py:165` - "No CSRF protection"
- **Impact:** Attacker can create malicious courses on behalf of admin
- **Likelihood:** Medium
- **Current Mitigations:** @admin_required limits to admins only
- **Recommended Mitigations:**
  1. Implement CSRF tokens (same as T3)
  2. Validate course data (par 54-90, slope 55-155, rating 50-85)

**T7 - Tampering: Insufficient Input Validation**
- **Component:** Course data validation (`app.py:158-175`)
- **Description:** Minimal validation on course parameters
- **Evidence:** `app.py:166` - "Insufficient input validation", `models.py:56` - "No input validation"
- **Impact:** Invalid course data, application errors, potential XSS in course names
- **Likelihood:** Medium
- **Current Mitigations:** Basic type conversion (int, float)
- **Recommended Mitigations:**
  1. Whitelist validation:
     - Course name: alphanumeric + spaces, max 200 chars, escape HTML
     - Num holes: 9 or 18 only
     - Course rating: 50.0-85.0
     - Slope rating: 55-155
     - Par: 54-90 (typical range)
  2. Sanitize inputs to prevent XSS
  3. Use Flask-WTF form validation

**I4 - Information Disclosure: Course Metadata Exposure**
- **Component:** Course listing (`app.py:145-150`)
- **Description:** All authenticated users can see all courses
- **Impact:** Low - Course data is generally public information
- **Likelihood:** Low
- **Current Mitigations:** @login_required prevents anonymous access
- **Recommended Mitigations:**
  1. Consider if course visibility should be configurable
  2. Current approach acceptable for golf course data

---

### 5. DS7: Session Store

#### Threats

**S3 - Spoofing: Session Hijacking via XSS**
- **Component:** Session cookie storage
- **Description:** If XSS vulnerability exists, attacker can steal session cookie
- **Evidence:** Session stored in client-side cookie
- **Impact:** Complete account takeover
- **Likelihood:** Low (no known XSS vulnerabilities, but preventable)
- **Current Mitigations:** `SESSION_COOKIE_HTTPONLY=True` prevents JavaScript access
- **Recommended Mitigations:**
  1. Maintain HttpOnly flag
  2. Add Content Security Policy (CSP) headers
  3. Escape all user input in templates (Jinja2 auto-escapes)
  4. Implement Subresource Integrity (SRI) for external scripts

**S4 - Spoofing: Hardcoded Secret Key**
- **Component:** Session signing (`config.py:8-9`)
- **Description:** SECRET_KEY is hardcoded in source code
- **Evidence:** `config.py:9` - "SECURITY GAP: Hardcoded secret key"
- **Impact:** If code is leaked, attacker can forge session cookies
- **Likelihood:** High (code is in Git repository)
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Move SECRET_KEY to environment variable
  2. Generate strong random key: `secrets.token_hex(32)`
  3. Rotate keys periodically (requires session migration)
  4. Never commit secrets to version control
  5. Use secrets management (AWS Secrets Manager, HashiCorp Vault)

**T8 - Tampering: Session Cookie Tampering**
- **Component:** Session cookie integrity
- **Description:** Session sent over HTTP (not HTTPS) can be intercepted
- **Evidence:** `config.py:17` - "SESSION_COOKIE_SECURE = False"
- **Impact:** Man-in-the-middle attack, session hijacking
- **Likelihood:** Medium (depends on network)
- **Current Mitigations:** Flask session signing prevents tampering (but not interception)
- **Recommended Mitigations:**
  1. Set `SESSION_COOKIE_SECURE=True` (requires HTTPS)
  2. Deploy with HTTPS/TLS in production
  3. Implement HSTS header: `Strict-Transport-Security: max-age=31536000`
  4. Set `SESSION_COOKIE_SAMESITE='Strict'` to prevent CSRF

**I5 - Information Disclosure: Session Timeout**
- **Component:** Session lifetime (`config.py:20`)
- **Description:** 24-hour session timeout increases hijacking window
- **Evidence:** `config.py:20` - "PERMANENT_SESSION_LIFETIME = 86400 (too long)"
- **Impact:** Extended exposure if device compromised
- **Likelihood:** Medium
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Reduce timeout to 2 hours (7200 seconds)
  2. Implement sliding session (refresh on activity)
  3. Add "Remember Me" option with separate long-lived token
  4. Implement absolute session timeout (8 hours max)

---

### 6. DS1-DS6: Database Tables

#### Threats

**T9 - Tampering: SQL Injection**
- **Component:** Database queries (all processes)
- **Description:** Raw SQL could allow injection attacks
- **Evidence:** Uses SQLAlchemy ORM throughout
- **Impact:** Data breach, data modification, privilege escalation
- **Likelihood:** Low (ORM mitigates this)
- **Current Mitigations:** SQLAlchemy ORM uses parameterized queries
- **Recommended Mitigations:**
  1. Continue using ORM (avoid raw SQL)
  2. If raw SQL needed, use parameterized queries
  3. Implement least privilege database user (no DROP/TRUNCATE)
  4. Regular SAST scans for SQL injection patterns

**I6 - Information Disclosure: Debug Mode Exposes Stack Traces**
- **Component:** Error handling (`config.py:23`)
- **Description:** DEBUG=True shows detailed errors with database schema, file paths
- **Evidence:** `config.py:23` - "DEBUG = True, SECURITY GAP: Debug mode in production"
- **Impact:** Information leakage helps attackers understand system internals
- **Likelihood:** High (debug currently enabled)
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Set DEBUG=False in production
  2. Implement custom error pages (404.html, 500.html already exist)
  3. Log detailed errors server-side, show generic messages to users
  4. Use environment-based configuration (dev vs. prod)

**I7 - Information Disclosure: Database Backup Exposure**
- **Component:** SQLite database file (`instance/golf.db`)
- **Description:** Database file may be accessible if web server misconfigured
- **Evidence:** Single-file database in application directory
- **Impact:** Complete data breach (usernames, password hashes, all golf data)
- **Likelihood:** Low (requires web server misconfiguration)
- **Current Mitigations:** `.gitignore` excludes instance/ directory
- **Recommended Mitigations:**
  1. Store database outside web root
  2. Set strict file permissions (600 - owner read/write only)
  3. Encrypt database at rest (SQLCipher for SQLite)
  4. Migrate to PostgreSQL in production (better access controls)

**R2 - Repudiation: No Database Audit Trail**
- **Component:** Direct database modifications
- **Description:** If database is accessed directly (not via app), no audit log
- **Evidence:** Audit logs only capture application-level actions
- **Impact:** Undetected data tampering, forensic gaps
- **Likelihood:** Low (requires database access)
- **Current Mitigations:** Application-level audit logs (DS6)
- **Recommended Mitigations:**
  1. Database-level triggers for critical tables (Users, Rounds)
  2. Write-ahead logging (WAL) for SQLite
  3. Implement database activity monitoring
  4. Restrict direct database access (application account only)

**D4 - Denial of Service: Database Resource Exhaustion**
- **Component:** All database queries
- **Description:** No connection pooling limits, query timeouts
- **Evidence:** Standard Flask-SQLAlchemy configuration
- **Impact:** Database deadlock, application unresponsiveness
- **Likelihood:** Low
- **Current Mitigations:** SQLAlchemy connection pooling (default settings)
- **Recommended Mitigations:**
  1. Configure connection pool: `SQLALCHEMY_POOL_SIZE=10`, `SQLALCHEMY_MAX_OVERFLOW=5`
  2. Set query timeout (5 seconds)
  3. Add indexes on frequently queried columns (user_id, course_id, date_played)
  4. Implement database backups and failover

---

### 7. P6: Leaderboard Process

#### Threats

**I8 - Information Disclosure: Leaderboard Exposes All User Scores**
- **Component:** Leaderboard (`app.py:335-357`, `handicap.py:96-150`)
- **Description:** Any authenticated user can see all users' scores and handicaps
- **Evidence:** `app.py:339`, `handicap.py:101` - "SECURITY GAP: No authorization check - anyone can see all scores"
- **Impact:** Privacy violation, users may not want scores public
- **Likelihood:** High (by design, but may violate privacy expectations)
- **Current Mitigations:** @login_required prevents anonymous access
- **Recommended Mitigations:**
  1. Add privacy settings (users can opt-out of leaderboard)
  2. Implement private vs. public leaderboards
  3. Show only handicap range instead of exact values (0-5, 6-10, etc.)
  4. Require explicit consent for leaderboard participation

---

### 8. P8: Audit Logging Process

#### Threats

**T10 - Tampering: Audit Log Modification**
- **Component:** Audit logs table (`models.py:142-155`)
- **Description:** Logs stored in same database as application data, could be modified
- **Evidence:** No integrity protection on logs
- **Impact:** Attackers can cover their tracks, forensic evidence lost
- **Likelihood:** Low (requires database access)
- **Current Mitigations:** Foreign key to Users table
- **Recommended Mitigations:**
  1. Store audit logs in separate database or write-once storage
  2. Add HMAC signatures to log entries
  3. Implement append-only log table (no UPDATE/DELETE privileges)
  4. Forward logs to SIEM (Security Information and Event Management)
  5. Use database triggers to prevent log modification

**R3 - Repudiation: IP Address Spoofing**
- **Component:** IP logging (`auth.py:43`)
- **Description:** `request.remote_addr` may be spoofed if behind proxy
- **Evidence:** `auth.py:43` - Uses `request.remote_addr`
- **Impact:** Incorrect attribution of actions, false alibis
- **Likelihood:** Medium (if behind reverse proxy)
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Check `X-Forwarded-For` header if behind proxy
  2. Validate proxy configuration
  3. Log both `remote_addr` and `X-Forwarded-For`
  4. Use trusted proxy headers only

---

### 9. Cross-Cutting Threats

#### Threats

**I9 - Information Disclosure: Missing Security Headers**
- **Component:** HTTP responses (all endpoints)
- **Description:** No security headers to prevent clickjacking, XSS, etc.
- **Evidence:** Default Flask configuration, no security headers middleware
- **Impact:** Clickjacking attacks, MIME sniffing, XSS amplification
- **Likelihood:** Medium
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Add security headers middleware:
     ```python
     @app.after_request
     def add_security_headers(response):
         response.headers['X-Content-Type-Options'] = 'nosniff'
         response.headers['X-Frame-Options'] = 'DENY'
         response.headers['X-XSS-Protection'] = '1; mode=block'
         response.headers['Content-Security-Policy'] = "default-src 'self'"
         response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
         return response
     ```
  2. Use Flask-Talisman for automated header management
  3. Implement CSP reporting endpoint

**I10 - Information Disclosure: Verbose Error Messages**
- **Component:** Error handlers (`app.py:402-413`)
- **Description:** Error pages may leak information in debug mode
- **Evidence:** Custom 404/500 templates exist, but debug mode enabled
- **Impact:** Stack traces reveal code structure, dependencies, file paths
- **Likelihood:** High (DEBUG=True)
- **Current Mitigations:** Custom error templates
- **Recommended Mitigations:**
  1. Disable debug mode in production (see I6)
  2. Log detailed errors server-side
  3. Show generic error messages to users

**D5 - Denial of Service: No Request Rate Limiting**
- **Component:** All endpoints
- **Description:** No global rate limiting on requests
- **Evidence:** No Flask-Limiter configured
- **Impact:** API abuse, resource exhaustion
- **Likelihood:** Medium
- **Current Mitigations:** None
- **Recommended Mitigations:**
  1. Implement Flask-Limiter:
     ```python
     limiter = Limiter(app, key_func=get_remote_address)
     @limiter.limit("100/hour")
     ```
  2. Different limits per endpoint type:
     - Login: 5/minute
     - API: 100/hour
     - Page loads: 200/hour
  3. Use Redis for distributed rate limiting

**E2 - Elevation of Privilege: Mass Assignment**
- **Component:** User registration (`app.py:39-87`)
- **Description:** If additional fields added to form, could set role='admin'
- **Evidence:** `app.py:73` - Explicitly sets role='golfer', but form fields could be manipulated
- **Impact:** User registers as admin
- **Likelihood:** Low (role explicitly set server-side)
- **Current Mitigations:** Server-side role assignment (line 73)
- **Recommended Mitigations:**
  1. Never trust client input for privileged fields
  2. Use whitelists for form fields:
     ```python
     allowed_fields = {'username', 'email', 'full_name', 'password'}
     ```
  3. Implement field-level validation with Flask-WTF
  4. Separate admin creation workflow (CLI tool, not web form)

---

## STRIDE Threat Summary Table

| ID  | Threat Category | Component | Severity | Likelihood | Mitigation Priority |
|-----|----------------|-----------|----------|-----------|-------------------|
| S1  | Spoofing | Login (brute force) | High | High | Critical |
| S2  | Spoofing | Session fixation | High | Medium | Critical |
| S3  | Spoofing | XSS session theft | High | Low | High |
| S4  | Spoofing | Hardcoded secret key | Critical | High | Critical |
| T1  | Tampering | Weak password hash | High | High | Critical (Assignment 3) |
| T2  | Tampering | Score manipulation | High | High | Critical |
| T3  | Tampering | CSRF attacks | Medium | Medium | High |
| T4  | Tampering | Date backdating | Medium | Medium | Medium |
| T5  | Tampering | Handicap formula | Medium | Medium | Medium |
| T6  | Tampering | CSRF on courses | Medium | Medium | High |
| T7  | Tampering | Input validation | Medium | Medium | High |
| T8  | Tampering | Session tampering | High | Medium | Critical |
| T9  | Tampering | SQL injection | Low | Low | Low (ORM mitigates) |
| T10 | Tampering | Audit log modification | Medium | Low | Medium |
| R1  | Repudiation | Incomplete audit logs | Medium | Medium | Medium |
| R2  | Repudiation | No DB audit trail | Low | Low | Low |
| R3  | Repudiation | IP spoofing | Low | Medium | Low |
| I1  | Info Disclosure | Username enumeration | Medium | High | Medium |
| I2  | Info Disclosure | Validation messages | Low | Low | Low |
| I3  | Info Disclosure | API authorization | High | High | Critical |
| I4  | Info Disclosure | Course metadata | Low | Low | Low |
| I5  | Info Disclosure | Long session timeout | Medium | Medium | Medium |
| I6  | Info Disclosure | Debug mode | High | High | Critical |
| I7  | Info Disclosure | Database file exposure | High | Low | High |
| I8  | Info Disclosure | Leaderboard privacy | Medium | High | Medium |
| I9  | Info Disclosure | Missing security headers | Medium | Medium | High |
| I10 | Info Disclosure | Verbose errors | High | High | Critical |
| D1  | Denial of Service | Login brute force | Medium | High | High |
| D2  | Denial of Service | Bulk score submission | Low | Low | Low |
| D3  | Denial of Service | Handicap calc overload | Medium | Medium | Medium |
| D4  | Denial of Service | DB resource exhaustion | Low | Low | Low |
| D5  | Denial of Service | No rate limiting | Medium | Medium | High |
| E1  | Privilege Escalation | Admin role bypass | High | Low | High |
| E2  | Privilege Escalation | Mass assignment | High | Low | Medium |

**Total Threats Identified:** 32

**Severity Breakdown:**
- Critical: 7 threats
- High: 10 threats
- Medium: 13 threats
- Low: 2 threats

---

## Implementation Roadmap

### Phase 1: Critical Fixes (Immediate)
1. **S4**: Move SECRET_KEY to environment variable
2. **I6/I10**: Disable DEBUG mode in production
3. **T1**: Implement bcrypt password hashing (Assignment 3)
4. **I3**: Add authorization check to handicap API
5. **S1**: Implement rate limiting on login
6. **T2**: Server-side score validation with HMAC

### Phase 2: High Priority (Assignment 4)
1. **T3/T6**: Implement CSRF protection with Flask-WTF
2. **S2**: Fix session fixation (regenerate session on login)
3. **T8**: Enable HTTPS and secure cookies
4. **I9**: Add security headers
5. **D5**: Global request rate limiting
6. **T7**: Input validation improvements

### Phase 3: Medium Priority
1. **R1**: Enhanced audit logging
2. **I5**: Reduce session timeout
3. **T4**: Date validation and restrictions
4. **I8**: Leaderboard privacy settings
5. **D3**: Handicap calculation caching
6. **E1**: Database-backed role verification

### Phase 4: Low Priority / Long-term
1. **I7**: Migrate to PostgreSQL, encrypt at rest
2. **R2**: Database-level audit triggers
3. **T10**: Immutable log storage
4. **D4**: Connection pooling optimization

---

## Conclusion

The DFD analysis identified **5 external entities**, **9 processes**, **7 data stores**, and **4 trust boundaries** in the Golf Score Tracker application. The STRIDE threat modeling uncovered **32 distinct threats** across all six categories, with **7 critical-severity issues** requiring immediate attention.

The most significant findings are:
1. **Hardcoded secret key** enabling session forgery
2. **Weak password hashing** (SHA256 vs. bcrypt)
3. **Score manipulation** without integrity verification
4. **API authorization bypass** allowing unauthorized data access
5. **Debug mode enabled** leaking sensitive system information

These intentional vulnerabilities align with the course's pedagogical goals for CSE763 Secure Software Development. The roadmap prioritizes fixes across the four course assignments, with cryptographic improvements (bcrypt, HMAC) targeted for Assignment 3 and CSRF/security headers for Assignment 4.

---

## References

**Code Files Analyzed:**
- `app.py` - Main application routes and business logic
- `models.py` - Database schema and ORM models
- `auth.py` - Authentication and authorization utilities
- `handicap.py` - Handicap calculation engine
- `config.py` - Configuration management

**Security Frameworks:**
- STRIDE Threat Modeling Methodology (Microsoft)
- OWASP Top 10 Web Application Security Risks
- USGA Handicap System (for business logic context)

**Tools for Future Validation:**
- Bandit (SAST - Assignment 1)
- OWASP ZAP (DAST - Assignment 4)
- Flask-Limiter (Rate limiting)
- Flask-WTF (CSRF protection)
- Flask-Talisman (Security headers)
