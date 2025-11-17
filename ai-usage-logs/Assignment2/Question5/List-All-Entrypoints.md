# AI Usage Log: Entry Points and Attack Vector Analysis

## Session Information
- **Date**: 2025-11-15
- **Task**: List all entry points and API endpoints. Identify possible attack vectors among those interfaces.
- **AI Model**: Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
- **Project**: Golf Score Tracker & Handicap System (CSE763)

## User Request
"Please log our interaction to 'List-All-Entrypoints.md' in the ai-usage-logs/Question5 directory. List all entry points and API endpoints. Identify possible attack vectors among those interfaces."

## Analysis Methodology

I analyzed the main Flask application (`app.py`) to identify all HTTP endpoints, their authentication requirements, methods, and potential security vulnerabilities. Each endpoint was evaluated for attack vectors based on the code implementation and documented security gaps.

---

## Complete Entry Point Inventory

### Public Endpoints (No Authentication Required)

#### 1. `/` - Home Page
- **File Location**: `app.py:31-36`
- **Methods**: GET
- **Authentication**: None
- **Function**: Redirects to dashboard if authenticated, otherwise to login
- **Attack Vectors**:
  - **Information Disclosure**: Reveals authentication state through redirect behavior
  - **Session Enumeration**: Could be used to test session validity

#### 2. `/register` - User Registration
- **File Location**: `app.py:39-87`
- **Methods**: GET, POST
- **Authentication**: None
- **Function**: User registration with username, email, full_name, password
- **Attack Vectors**:
  - **User Enumeration** (`app.py:64-70`): Error messages disclose if username or email already exists
  - **Insufficient Input Validation** (`app.py:49-50`): Basic validation only, marked as SECURITY GAP
  - **No CAPTCHA**: Vulnerable to automated account creation
  - **No Rate Limiting**: Mass registration possible
  - **Password Policy Bypass**: Only basic validation via `validate_password_strength()`
  - **SQL Injection**: Potential if SQLAlchemy not properly escaping inputs
  - **XSS via User Input**: Username, email, full_name stored and displayed without sanitization confirmation

#### 3. `/login` - User Authentication
- **File Location**: `app.py:90-115`
- **Methods**: GET, POST
- **Authentication**: None
- **Function**: Authenticates users with username and password
- **Attack Vectors**:
  - **No Rate Limiting** (`app.py:97`): Explicitly marked as SECURITY GAP, vulnerable to brute force attacks
  - **Username Enumeration** (`app.py:111-113`): Timing attacks possible, marked as information disclosure gap
  - **Session Fixation** (`app.py:101-102`): Session not regenerated after login, marked as SECURITY GAP
  - **Weak Password Hashing**: Uses SHA256 (referenced in CLAUDE.md), should use bcrypt
  - **Credential Stuffing**: No account lockout mechanism
  - **Timing Attacks**: User lookup and password check may have observable timing differences
  - **Audit Log Injection** (`app.py:112`): Failed login logs username without sanitization

---

### Authenticated Endpoints (Any Logged-In User)

#### 4. `/logout` - User Logout
- **File Location**: `app.py:118-126`
- **Methods**: GET
- **Authentication**: `@login_required`
- **Function**: Clears session and logs out user
- **Attack Vectors**:
  - **No CSRF Protection**: GET request for state-changing operation (logout)
  - **Session Hijacking**: If session stolen, attacker can logout legitimate user
  - **Cross-Site Request Forgery**: Can be triggered via image tag or link

#### 5. `/dashboard` - User Dashboard
- **File Location**: `app.py:129-142`
- **Methods**: GET
- **Authentication**: `@login_required`
- **Function**: Displays user statistics and recent rounds
- **Attack Vectors**:
  - **Information Disclosure**: Reveals user statistics and scoring patterns
  - **XSS via Stored Data**: If round notes or user data contain malicious scripts
  - **Template Injection**: Jinja2 template may be vulnerable if user data not escaped

#### 6. `/courses` - View All Courses
- **File Location**: `app.py:145-150`
- **Methods**: GET
- **Authentication**: `@login_required`
- **Function**: Lists all golf courses
- **Attack Vectors**:
  - **Information Disclosure**: All users can see all courses
  - **XSS via Course Data**: Course names/locations stored by admins displayed without confirmed sanitization

#### 7. `/round/new` - Submit New Golf Round
- **File Location**: `app.py:214-318`
- **Methods**: GET, POST
- **Authentication**: `@login_required`
- **Function**: Enter new round scores for a course
- **Attack Vectors**:
  - **No CSRF Protection** (`app.py:247`): Explicitly marked as SECURITY GAP
  - **Date Manipulation** (`app.py:248`): Can submit rounds with arbitrary past dates
  - **Weak Score Validation** (`app.py:274-275`): Marked as SECURITY GAP
  - **Total Score Manipulation** (`app.py:283`): Total score not cryptographically verified, marked as SECURITY GAP
  - **Race Conditions**: Multiple concurrent submissions possible
  - **Business Logic Bypass**: Could submit unrealistic scores (e.g., all hole-in-ones)
  - **Handicap Manipulation**: By submitting fake scores, users can artificially lower handicap
  - **Mass Assignment**: Direct use of form data without proper filtering
  - **Integer Overflow**: Score calculations may overflow with extreme values

#### 8. `/scores` - View Score History
- **File Location**: `app.py:321-332`
- **Methods**: GET
- **Authentication**: `@login_required`
- **Function**: Displays user's score history
- **Attack Vectors**:
  - **Potential IDOR** (`app.py:327`): Comment warns about IDOR if user_id taken from query param
  - **Information Disclosure**: Complete scoring history visible
  - **XSS via Notes Field**: Round notes displayed without confirmed sanitization

#### 9. `/leaderboard` - View Leaderboard
- **File Location**: `app.py:335-357`
- **Methods**: GET
- **Authentication**: `@login_required`
- **Function**: Displays leaderboard for all users or specific course
- **Attack Vectors**:
  - **Privacy Violation** (`app.py:339`): Marked as SECURITY GAP - any logged-in user can see all user scores
  - **IDOR via course_id Parameter** (`app.py:340-344`): No validation that user has access to view course
  - **SQL Injection**: course_id parameter converted to int but may be exploitable
  - **Information Disclosure**: Complete leaderboard data accessible to all users
  - **User Enumeration**: Can identify all active users and their performance

---

### Admin-Only Endpoints

#### 10. `/courses/add` - Add New Course
- **File Location**: `app.py:153-211`
- **Methods**: GET, POST
- **Authentication**: `@admin_required`
- **Function**: Create new golf courses with hole configuration
- **Attack Vectors**:
  - **No CSRF Protection** (`app.py:165`): Explicitly marked as SECURITY GAP
  - **Insufficient Input Validation** (`app.py:166`): Explicitly marked as SECURITY GAP
  - **Mass Assignment**: Direct use of form data for course creation
  - **Type Confusion**: Float/int conversions may cause errors or exploits
  - **Privilege Escalation**: If `@admin_required` decorator bypassed, regular users could create courses
  - **Resource Exhaustion**: Could create courses with excessive holes or data
  - **XSS via Course Details**: Name, location stored and displayed to all users
  - **SQL Injection**: Multiple form inputs directly used in database operations
  - **Integer Overflow**: Yardage, handicap values not properly bounded

#### 11. `/admin` - Admin Panel
- **File Location**: `app.py:360-382`
- **Methods**: GET
- **Authentication**: `@admin_required`
- **Function**: View users, courses, audit logs, and statistics
- **Attack Vectors**:
  - **Information Disclosure**: Complete system information visible
  - **Privilege Escalation**: If decorator bypassed, reveals sensitive data
  - **Audit Log Exposure**: Shows security events including failed login attempts
  - **User Enumeration**: Complete user list with emails and roles
  - **Password Hash Exposure**: If user objects include password hashes in template
  - **System Intelligence**: Reveals application architecture and user behavior patterns

---

### API Endpoints

#### 12. `/api/handicap/<int:user_id>` - Get User Handicap
- **File Location**: `app.py:385-399`
- **Methods**: GET
- **Authentication**: `@login_required`
- **Function**: Returns handicap index and statistics for any user
- **Attack Vectors**:
  - **IDOR Vulnerability** (`app.py:389`): Explicitly marked as SECURITY GAP - no authorization check
  - **No Rate Limiting** (`app.py:390`): Explicitly marked as SECURITY GAP
  - **Privacy Violation**: Any authenticated user can query any other user's data
  - **User Enumeration**: Can iterate through user IDs to discover all users
  - **Information Disclosure**: Complete statistics exposed via JSON API
  - **Automated Data Harvesting**: No rate limiting allows bulk data extraction
  - **Integer Parameter Tampering**: Can try negative or very large user IDs

---

### Error Handlers

#### 13. `/404` - Not Found Handler
- **File Location**: `app.py:403-406`
- **Methods**: All (triggered on 404)
- **Authentication**: None
- **Attack Vectors**:
  - **Path Enumeration**: 404 responses reveal which paths exist
  - **Information Disclosure**: Error page may reveal framework version or paths

#### 14. `/500` - Internal Server Error Handler
- **File Location**: `app.py:409-413`
- **Methods**: All (triggered on 500)
- **Authentication**: None
- **Attack Vectors**:
  - **Information Disclosure**: Debug mode may expose stack traces and code (`config.py:22`)
  - **Database State Leakage**: Error details may reveal database structure
  - **Path Disclosure**: May reveal absolute file paths on server

---

## Attack Vector Summary by Category

### 1. Authentication & Session Vulnerabilities
- **Session Fixation** (`/login` - `app.py:101-102`)
- **No Rate Limiting on Login** (`/login` - `app.py:97`)
- **Weak Password Hashing** (SHA256 instead of bcrypt - `models.py:30` per CLAUDE.md)
- **Session Timeout Too Long** (24 hours - per CLAUDE.md)
- **No Account Lockout Mechanism**
- **Session Hijacking via XSS** (if XSS vulnerabilities exploited)

### 2. Authorization Vulnerabilities
- **IDOR - Handicap API** (`/api/handicap/<user_id>` - `app.py:389`)
- **Potential IDOR - Scores** (`/scores` - `app.py:327`)
- **IDOR - Leaderboard Course Selection** (`/leaderboard` - `app.py:340`)
- **Horizontal Privilege Escalation** (accessing other users' data)
- **Vertical Privilege Escalation** (if decorator bypass possible)

### 3. CSRF Vulnerabilities
- **No CSRF Protection on Any Forms** (marked throughout codebase)
  - `/logout` - State-changing GET request
  - `/register` - Account creation
  - `/login` - Authentication
  - `/courses/add` - Course creation
  - `/round/new` - Score submission

### 4. Input Validation Vulnerabilities
- **Insufficient Input Validation** (`/register`, `/courses/add`, `/round/new`)
- **Weak Score Validation** (`/round/new` - `app.py:274-275`)
- **Date Manipulation** (`/round/new` - `app.py:248`)
- **Total Score Manipulation** (`/round/new` - `app.py:283`)
- **SQL Injection Risk** (unconfirmed sanitization in multiple endpoints)
- **Type Confusion** (float/int conversions without validation)

### 5. Information Disclosure
- **User Enumeration** (`/register` - `app.py:64-70`)
- **Username Enumeration** (`/login` - `app.py:111-113`)
- **Privacy Violation - Leaderboard** (`/leaderboard` - `app.py:339`)
- **Complete User Data via API** (`/api/handicap/<user_id>`)
- **Audit Logs Visible to Admin** (`/admin`)
- **Debug Mode Information Leakage** (`/500` errors)
- **Authentication State Disclosure** (`/`)

### 6. Business Logic Vulnerabilities
- **Score Integrity Bypass** (total_score not verified)
- **Handicap Manipulation** (submit fake rounds to lower handicap)
- **Date Backdating** (submit rounds with past dates)
- **Business Rule Bypass** (unrealistic scores accepted)

### 7. Injection Vulnerabilities
- **XSS via Stored Data** (usernames, course names, round notes)
- **Template Injection** (Jinja2 templates if data not escaped)
- **Audit Log Injection** (`app.py:112` - failed login logging)
- **SQL Injection** (potential in multiple form handlers)

### 8. Denial of Service
- **No Rate Limiting** (all endpoints)
- **Resource Exhaustion** (unlimited course/round creation)
- **Automated Account Creation** (`/register`)
- **Brute Force Attacks** (`/login`)
- **Automated Data Harvesting** (`/api/handicap/<user_id>`)

### 9. Privacy Violations
- **All Users Can View All Scores** (`/leaderboard`)
- **Any User Can Query Any Handicap** (`/api/handicap/<user_id>`)
- **Complete User Enumeration Possible** (multiple endpoints)

### 10. Security Header Gaps
- **No CSP (Content Security Policy)**
- **No HSTS (HTTP Strict Transport Security)**
- **No X-Frame-Options** (clickjacking protection)
- **No X-Content-Type-Options**
- **Hardcoded Secret Key** (`config.py:9` per CLAUDE.md)

---

## High-Risk Attack Scenarios

### Scenario 1: Handicap Manipulation for Tournament Fraud
**Attack Chain**:
1. Attacker registers account via `/register`
2. Submits fake low scores via `/round/new` with manipulated `total_score` (`app.py:283`)
3. Backdates rounds using date manipulation (`app.py:248`)
4. Artificially lowers handicap index
5. Uses low handicap to gain unfair advantage in tournaments

**Vulnerabilities Exploited**:
- Total score not verified (`app.py:283`)
- Date manipulation (`app.py:248`)
- Weak score validation (`app.py:274-275`)

### Scenario 2: Complete User Data Harvesting
**Attack Chain**:
1. Attacker creates account or compromises existing account
2. Iterates through user IDs 1-N via `/api/handicap/<user_id>` (`app.py:385-399`)
3. No authorization check (`app.py:389`) allows access to all user data
4. No rate limiting (`app.py:390`) enables bulk extraction
5. Harvests complete handicap and statistics for all users

**Vulnerabilities Exploited**:
- IDOR vulnerability (`app.py:389`)
- No rate limiting (`app.py:390`)
- Privacy violation (`app.py:339`)

### Scenario 3: Account Takeover via Brute Force
**Attack Chain**:
1. Attacker identifies valid username via `/register` enumeration (`app.py:64`)
2. Brute forces password via `/login` with no rate limiting (`app.py:97`)
3. Session fixation (`app.py:101-102`) may allow pre-set session
4. Weak SHA256 password hashing makes offline cracking feasible
5. Gains account access

**Vulnerabilities Exploited**:
- Username enumeration (`app.py:64`, `app.py:111-113`)
- No rate limiting (`app.py:97`)
- Weak password hashing (SHA256)
- Session fixation (`app.py:101-102`)

### Scenario 4: CSRF-Based Score Submission
**Attack Chain**:
1. Attacker identifies victim golfer
2. Creates malicious webpage with auto-submitting form to `/round/new`
3. No CSRF protection (`app.py:247`) allows cross-origin submission
4. Victim visits attacker's page while authenticated
5. Fake round submitted on victim's behalf, manipulating their handicap

**Vulnerabilities Exploited**:
- No CSRF protection (`app.py:247`)
- No CSRF protection on state-changing operations

### Scenario 5: Admin Panel Access and Data Exfiltration
**Attack Chain**:
1. Attacker exploits potential decorator bypass or finds admin credentials
2. Accesses `/admin` panel (`app.py:360-382`)
3. Views complete user list with emails (`app.py:364`)
4. Accesses audit logs revealing security events (`app.py:366`)
5. Gains complete system intelligence

**Vulnerabilities Exploited**:
- Potential privilege escalation (if `@admin_required` bypassed)
- Information disclosure (`app.py:364-382`)
- Complete audit log exposure (`app.py:366`)

---

## Attack Surface Metrics

### Endpoints by Authentication Level
- **Public**: 3 endpoints (/, /register, /login)
- **Authenticated**: 7 endpoints (/logout, /dashboard, /courses, /round/new, /scores, /leaderboard, /api/handicap/<user_id>)
- **Admin**: 2 endpoints (/courses/add, /admin)
- **Error Handlers**: 2 endpoints (404, 500)
- **Total**: 14 distinct entry points

### Vulnerability Counts by Endpoint
1. `/round/new` - 9 attack vectors (highest risk)
2. `/api/handicap/<user_id>` - 7 attack vectors
3. `/login` - 7 attack vectors
4. `/register` - 7 attack vectors
5. `/courses/add` - 10 attack vectors (admin-only)
6. `/leaderboard` - 5 attack vectors
7. `/admin` - 6 attack vectors (admin-only but high impact)
8. Others - 1-4 attack vectors each

### Critical Vulnerabilities (Marked as SECURITY GAP)
1. **Session Fixation** (`app.py:101-102`)
2. **No Rate Limiting on Login** (`app.py:97`)
3. **Information Disclosure on Login** (`app.py:111-113`)
4. **No CSRF Protection** (`app.py:165`, `app.py:247`, throughout)
5. **Insufficient Input Validation** (`app.py:49`, `app.py:166`)
6. **Date Manipulation** (`app.py:248`)
7. **Weak Score Validation** (`app.py:274-275`)
8. **Total Score Not Verified** (`app.py:283`)
9. **IDOR in Handicap API** (`app.py:389`)
10. **No Rate Limiting on API** (`app.py:390`)
11. **Privacy Violation - Leaderboard** (`app.py:339`)

---

## Recommendations Priority Matrix

### Priority 1 (Critical - Immediate Fix Required)
1. **Implement CSRF Protection** - Add Flask-WTF tokens to all forms
2. **Fix IDOR Vulnerability** - Add authorization checks in `/api/handicap/<user_id>` (`app.py:389`)
3. **Add Rate Limiting** - Implement Flask-Limiter on `/login` and API endpoints
4. **Fix Session Fixation** - Regenerate session ID after login (`app.py:101-102`)
5. **Implement Score Integrity** - Add HMAC signatures to verify `total_score` (`app.py:283`)

### Priority 2 (High - Fix Within Sprint)
1. **Upgrade Password Hashing** - Replace SHA256 with bcrypt
2. **Strengthen Input Validation** - Implement comprehensive validation for all inputs
3. **Remove Information Disclosure** - Generic error messages on `/login` and `/register`
4. **Add Security Headers** - CSP, HSTS, X-Frame-Options
5. **Implement Account Lockout** - Prevent brute force attacks

### Priority 3 (Medium - Fix in Next Release)
1. **Add API Authorization** - Restrict leaderboard and user data access
2. **Implement Audit Logging Review** - Add admin alerts for suspicious activity
3. **Sanitize All User Inputs** - Prevent XSS in usernames, notes, course data
4. **Add Business Logic Validation** - Prevent unrealistic scores and backdating
5. **Reduce Session Timeout** - From 24 hours to 1-2 hours

### Priority 4 (Low - Technical Debt)
1. **Add Automated Tests** - Security regression testing
2. **Implement API Rate Limits** - Granular limits per endpoint
3. **Add Request Logging** - Enhanced security monitoring
4. **Database Migration** - Move from SQLite to PostgreSQL for production

---

## Testing Recommendations

### Manual Testing Checklist
- [ ] Test all endpoints for CSRF vulnerabilities
- [ ] Verify IDOR vulnerabilities in `/api/handicap/<user_id>`
- [ ] Test session fixation on `/login`
- [ ] Enumerate users via `/register` and `/login` error messages
- [ ] Test score manipulation via intercepted `/round/new` requests
- [ ] Verify rate limiting absence on all endpoints
- [ ] Test XSS in username, course name, and notes fields
- [ ] Verify SQL injection in course_id and user_id parameters
- [ ] Test privilege escalation attempts on admin endpoints

### Automated Testing Tools
1. **OWASP ZAP** - Automated DAST scanning (Assignment 4 requirement)
2. **Bandit** - Python SAST scanning (Assignment 1 requirement)
3. **Burp Suite** - Manual penetration testing and proxy
4. **SQLMap** - SQL injection testing
5. **CSRF PoC Generator** - Cross-site request forgery testing

---

## Assignment Context

This analysis supports **CSE763 Secure Software Development** coursework. The identified vulnerabilities are **intentional pedagogical features** that will be addressed across 4 assignments:

- **Assignment 1**: DevSecOps pipeline with SAST/DAST integration
- **Assignment 2**: Threat modeling and STRIDE analysis (current assignment)
- **Assignment 3**: Cryptographic API implementation (bcrypt, HMAC, encryption)
- **Assignment 4**: DAST testing with OWASP ZAP and vulnerability remediation

---

## AI Processing Notes

**Analysis Approach**:
1. Read complete `app.py` source code (424 lines)
2. Catalogued all `@app.route` decorators and their configurations
3. Identified authentication decorators (`@login_required`, `@admin_required`)
4. Documented explicitly marked `# SECURITY GAP` comments
5. Analyzed each endpoint for common web application vulnerabilities (OWASP Top 10)
6. Cross-referenced with `CLAUDE.md` for known intentional gaps
7. Constructed attack scenarios based on vulnerability chains

**Key Insights**:
- 11 explicitly marked security gaps in code comments
- 14 total entry points with varying authentication requirements
- Highest risk endpoints: `/round/new`, `/api/handicap/<user_id>`, `/login`, `/register`
- No CSRF protection across entire application (systemic issue)
- Authorization model relies solely on decorators without defense-in-depth

**Files Analyzed**:
- `app.py` (complete analysis)
- `CLAUDE.md` (referenced for context)
- `models.py` (referenced via CLAUDE.md for password hashing details)
- `config.py` (referenced via CLAUDE.md for configuration gaps)

---

## Conclusion

The Golf Score Tracker application has **14 distinct entry points** with **60+ identified attack vectors** across authentication, authorization, input validation, business logic, and information disclosure categories. The most critical vulnerabilities are:

1. **IDOR in Handicap API** - Complete user data exposure
2. **No CSRF Protection** - All state-changing operations vulnerable
3. **Score Integrity Bypass** - Handicap manipulation possible
4. **Session Fixation** - Account takeover risk
5. **No Rate Limiting** - Brute force and DoS attacks feasible

These vulnerabilities are **intentional educational features** and should be remediated according to the assignment roadmap, not ad-hoc.
