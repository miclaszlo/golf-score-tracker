# Attack Tree Analysis - Golf Score Tracker & Handicap System

**Document Version:** 1.0
**Date:** November 12, 2025
**Assignment:** Assignment 2, Question 3 - Attack Tree Creation
**Course:** CSE763 Secure Software Development

---

## AI Usage Log

### Interaction Summary

**Date:** November 12, 2025
**AI Assistant:** Claude Code (Sonnet 4.5)
**Task:** Attack Tree Creation for Golf Score Tracker Application

**User Request:**
> "Please log our interaction to 'Attack-Tree-Creation.md' in the ai-usage-logs/Question3 directory. Use the abuse cases from Threat-Actor-Analysis.md as the root of attack trees to show detailed possible paths to achieve them. Try to have at least 3 levels of depth in your attack tree. Each attack tree lists subgoals or conditions in a hierarchy structure to achieve the ultimate goal of the attack described by the root node, with the leaf nodes being specific, tangible actions, steps, conditions, or outcomes that an attack must achieve first. The leaf nodes can be specific well-known vulnerability exploits or attacks. The leaf nodes should be easily assessed in terms of possibility, complexity, and cost, so the risk analysis can be done on the root nodes."

**AI Response Process:**

1. **Reviewed threat actor analysis** - Examined Threat-Actor-Analysis.md to identify the 7 primary abuse cases/attack scenarios
2. **Selected representative attacks** - Chose diverse attack scenarios covering different threat actors, attack vectors, and system components
3. **Designed hierarchical structure** - Created multi-level attack trees with:
   - Root nodes: Ultimate attack goals (abuse cases)
   - Intermediate nodes: Subgoals, preconditions, and attack stages
   - Leaf nodes: Specific, measurable attack actions and exploits
4. **Applied attack tree methodology** - Used AND/OR logic gates to represent:
   - AND nodes: All child conditions must be satisfied
   - OR nodes: Any child path can achieve the parent goal
5. **Mapped to code vulnerabilities** - Connected leaf nodes to specific application weaknesses with code references
6. **Added risk assessments** - Evaluated each leaf node for:
   - Feasibility (LOW/MEDIUM/HIGH)
   - Complexity (LOW/MEDIUM/HIGH)
   - Cost (LOW/MEDIUM/HIGH)
   - Detection Risk (LOW/MEDIUM/HIGH)

**Key AI Capabilities Utilized:**
- Attack tree modeling and hierarchical decomposition
- Cybersecurity attack pattern knowledge (MITRE ATT&CK framework)
- Application-specific vulnerability mapping
- Risk assessment and prioritization
- Technical documentation and visual representation

**Output Generated:**
- 7 detailed attack trees corresponding to major abuse cases
- Multi-level hierarchical structures (3-5 levels deep)
- 50+ specific leaf node attack actions
- Risk assessment parameters for each leaf node
- Mitigation recommendations mapped to course assignments

**Validation:**
Attack trees reference actual code locations and vulnerabilities documented in CLAUDE.md. Leaf nodes are specific enough for risk quantification. Structure follows attack tree best practices with clear AND/OR logic gates.

---

## Introduction to Attack Trees

### What is an Attack Tree?

An **attack tree** is a formal, methodical way of describing the security threats against a system based on varying attack goals. Attack trees provide a structured approach to threat modeling by:

1. **Hierarchical Decomposition** - Breaking down complex attacks into simpler subgoals
2. **AND/OR Logic** - Representing alternative paths (OR) and required conditions (AND)
3. **Risk Quantification** - Enabling assessment of attack feasibility, cost, and likelihood
4. **Defense Prioritization** - Identifying critical paths and high-value mitigations

### Attack Tree Structure

```
ROOT (Ultimate Attack Goal)
├─ OR ──┬─ Subgoal 1 (Alternative Path A)
│       │  ├─ AND ──┬─ Condition 1.1 (Both required)
│       │  │        └─ Condition 1.2
│       │  └─ Leaf: Specific Action/Exploit
│       │
│       └─ Subgoal 2 (Alternative Path B)
│          └─ Leaf: Specific Action/Exploit
```

### Reading This Document

- **Root Nodes** - Shown in bold headers, represent ultimate attack objectives
- **Intermediate Nodes** - Subgoals and conditions in the attack path
- **Leaf Nodes** - Marked with `[LEAF]`, represent specific actionable steps
- **Logic Gates:**
  - `[OR]` - Any child path succeeds → parent succeeds
  - `[AND]` - All children required → parent succeeds
- **Risk Metrics:**
  - Feasibility: Likelihood of successful execution
  - Complexity: Technical skill required
  - Cost: Resources/time needed
  - Detection Risk: Likelihood of being caught

---

## Attack Tree 1: Administrative Account Compromise

**Root Goal:** Gain unauthorized administrative access to the Golf Score Tracker system
**Threat Actor:** TA-01 (Script Kiddie / Opportunistic Attacker)
**Impact:** Complete system compromise, data breach, persistent backdoor access
**Code References:** `app.py:86-116` (login), `app.py:111-113` (error messages)

### Attack Tree Structure

```
ROOT: Compromise Administrative Account
│
├─ [OR] ──┬─ Path 1: Brute Force Attack
│         │  │
│         │  ├─ [AND] ──┬─ Subgoal 1.1: Identify Valid Admin Username
│         │  │          │  │
│         │  │          │  ├─ [OR] ──┬─ [LEAF] Username Enumeration via Login Error Messages
│         │  │          │  │         │         • Exploit: Verbose error "Invalid username"
│         │  │          │  │         │         • Vulnerability: app.py:111-113
│         │  │          │  │         │         • Method: Submit random usernames, observe errors
│         │  │          │  │         │         • Feasibility: HIGH
│         │  │          │  │         │         • Complexity: LOW
│         │  │          │  │         │         • Cost: LOW (automated script)
│         │  │          │  │         │         • Detection Risk: LOW (looks like normal login failures)
│         │  │          │  │         │
│         │  │          │  │         ├─ [LEAF] Default Credential Testing
│         │  │          │  │         │         • Try: admin, administrator, root, system
│         │  │          │  │         │         • Vulnerability: Weak default usernames
│         │  │          │  │         │         • Method: Test common admin usernames
│         │  │          │  │         │         • Feasibility: HIGH
│         │  │          │  │         │         • Complexity: LOW
│         │  │          │  │         │         • Cost: LOW (manual or automated)
│         │  │          │  │         │         • Detection Risk: LOW
│         │  │          │  │         │
│         │  │          │  │         └─ [LEAF] Leaderboard/Public Data Scraping
│         │  │          │  │                   • Scrape /leaderboard for potential admin usernames
│         │  │          │  │                   • Vulnerability: Information disclosure
│         │  │          │  │                   • Method: Automated web scraping
│         │  │          │  │                   • Feasibility: MEDIUM
│         │  │          │  │                   • Complexity: LOW
│         │  │          │  │                   • Cost: LOW
│         │  │          │  │                   • Detection Risk: LOW
│         │  │          │  │
│         │  │          │  └─ Subgoal 1.2: Brute Force Password
│         │  │          │     │
│         │  │          │     └─ [AND] ──┬─ [LEAF] Exploit Missing Rate Limiting
│         │  │          │                │       • Vulnerability: app.py:86-116 (no rate limit)
│         │  │          │                │       • Method: Unlimited login attempts allowed
│         │  │          │                │       • Tool: Hydra, Medusa, custom Python script
│         │  │          │                │       • Feasibility: HIGH
│         │  │          │                │       • Complexity: LOW
│         │  │          │                │       • Cost: LOW (automated tool)
│         │  │          │                │       • Detection Risk: MEDIUM (high login volume)
│         │  │          │                │
│         │  │          │                ├─ [LEAF] Use Common Password Wordlist
│         │  │          │                │       • Wordlists: rockyou.txt, common-passwords.txt
│         │  │          │                │       • Target: Weak passwords like "admin123"
│         │  │          │                │       • Method: Dictionary attack
│         │  │          │                │       • Feasibility: HIGH (weak defaults exist)
│         │  │          │                │       • Complexity: LOW
│         │  │          │                │       • Cost: LOW (free wordlists)
│         │  │          │                │       • Detection Risk: MEDIUM
│         │  │          │                │
│         │  │          │                └─ [LEAF] Credential Stuffing Attack
│         │  │          │                        • Use: Leaked passwords from other breaches
│         │  │          │                        • Assumption: Users reuse passwords
│         │  │          │                        • Method: Test leaked credentials
│         │  │          │                        • Feasibility: MEDIUM
│         │  │          │                        • Complexity: LOW
│         │  │          │                        • Cost: LOW (leaked DBs freely available)
│         │  │          │                        • Detection Risk: MEDIUM
│         │  │          │
│         │  │          └─ Subgoal 1.3: Bypass Weak Password Hashing
│         │  │             │
│         │  │             └─ [LEAF] Offline SHA256 Hash Cracking (if DB compromised)
│         │  │                       • Vulnerability: models.py:30 (SHA256 instead of bcrypt)
│         │  │                       • Prerequisite: Database access via SQL injection
│         │  │                       • Method: Extract password hashes, crack with hashcat
│         │  │                       • Speed: Billions of SHA256 hashes/sec with GPU
│         │  │                       • Feasibility: HIGH (if DB obtained)
│         │  │                       • Complexity: MEDIUM
│         │  │                       • Cost: MEDIUM (requires GPU or cloud resources)
│         │  │                       • Detection Risk: LOW (offline attack)
│         │  │
│         │  └─ Post-Compromise Actions
│         │     │
│         │     ├─ [LEAF] Create Backdoor Admin Account
│         │     │         • Access: /admin panel → create user with subtle name
│         │     │         • Example: "administrator" or "admin-backup"
│         │     │         • Purpose: Persistent access even if original admin password changes
│         │     │         • Feasibility: HIGH
│         │     │         • Complexity: LOW
│         │     │         • Cost: LOW
│         │     │         • Detection Risk: MEDIUM
│         │     │
│         │     ├─ [LEAF] Exfiltrate User Database
│         │     │         • Target: instance/golf.db (SQLite file)
│         │     │         • Data: All usernames, password hashes, scores
│         │     │         • Method: Direct file download or SQL export
│         │     │         • Feasibility: HIGH
│         │     │         • Complexity: LOW
│         │     │         • Cost: LOW
│         │     │         • Detection Risk: MEDIUM
│         │     │
│         │     └─ [LEAF] Modify Audit Logs to Hide Tracks
│         │               • Access: AuditLog table via admin panel
│         │               • Action: Delete login records, modify timestamps
│         │               • Vulnerability: Modifiable audit logs
│         │               • Feasibility: HIGH
│         │               • Complexity: LOW
│         │               • Cost: LOW
│         │               • Detection Risk: HIGH (if logs are monitored externally)
│         │
│         ├─ Path 2: Session Fixation Attack
│         │  │
│         │  ├─ [AND] ──┬─ [LEAF] Obtain Valid Session ID
│         │  │          │         • Method: Generate session ID before victim login
│         │  │          │         • Vulnerability: app.py:102 (session not regenerated)
│         │  │          │         • Tool: Browser dev tools to inspect cookies
│         │  │          │         • Feasibility: HIGH
│         │  │          │         • Complexity: MEDIUM
│         │  │          │         • Cost: LOW
│         │  │          │         • Detection Risk: LOW
│         │  │          │
│         │  │          ├─ [LEAF] Trick Admin into Using Attacker's Session
│         │  │          │         • Method: Send phishing link with session cookie
│         │  │          │         • Example: http://golf-app.com/login?session=ATTACKER_SID
│         │  │          │         • Social Engineering: "Please test this link"
│         │  │          │         • Feasibility: MEDIUM (requires social engineering)
│         │  │          │         • Complexity: MEDIUM
│         │  │          │         • Cost: LOW
│         │  │          │         • Detection Risk: LOW
│         │  │          │
│         │  │          └─ [LEAF] Hijack Session After Victim Login
│         │  │                    • Reuse: Same session ID now authenticated as admin
│         │  │                    • Vulnerability: Session ID not regenerated on login
│         │  │                    • Method: Use fixed session cookie in browser
│         │  │                    • Feasibility: HIGH (if victim falls for trick)
│         │  │                    • Complexity: LOW
│         │  │                    • Cost: LOW
│         │  │                    • Detection Risk: MEDIUM
│         │  │
│         │  └─ Post-Compromise Actions (same as Path 1)
│         │
│         └─ Path 3: SQL Injection to Create Admin Account
│            │
│            ├─ [AND] ──┬─ [LEAF] Identify SQL Injection Point
│            │          │         • Target: Course search, username input
│            │          │         • Test Payload: ' OR '1'='1
│            │          │         • Vulnerability: Lack of parameterized queries
│            │          │         • Method: Manual testing or automated scanner
│            │          │         • Feasibility: MEDIUM (depends on input validation)
│            │          │         • Complexity: MEDIUM
│            │          │         • Cost: LOW
│            │          │         • Detection Risk: MEDIUM
│            │          │
│            │          ├─ [LEAF] Escalate to UNION-based SQL Injection
│            │          │         • Determine: Number of columns, database schema
│            │          │         • Payload: ' UNION SELECT 1,2,3,4,5--
│            │          │         • Purpose: Identify injection structure
│            │          │         • Feasibility: MEDIUM
│            │          │         • Complexity: MEDIUM-HIGH
│            │          │         • Cost: LOW
│            │          │         • Detection Risk: MEDIUM
│            │          │
│            │          └─ [LEAF] INSERT Admin User via SQL Injection
│            │                    • Payload: '; INSERT INTO users (username, password, role) VALUES ('hacker','<hash>','admin')--
│            │                    • Requirement: Multi-statement execution support
│            │                    • Feasibility: MEDIUM (SQLite may allow)
│            │                    • Complexity: HIGH
│            │                    • Cost: LOW
│            │                    • Detection Risk: HIGH
│            │
│            └─ [LEAF] Login with Injected Admin Account
│                      • Username: hacker
│                      • Password: Known password used in injection
│                      • Feasibility: HIGH (if injection succeeded)
│                      • Complexity: LOW
│                      • Cost: LOW
│                      • Detection Risk: MEDIUM
```

### Attack Path Summary

| Attack Path | Feasibility | Complexity | Cost | Detection Risk | Priority |
|-------------|-------------|------------|------|----------------|----------|
| Path 1: Brute Force | HIGH | LOW | LOW | MEDIUM | CRITICAL |
| Path 2: Session Fixation | MEDIUM | MEDIUM | LOW | MEDIUM | HIGH |
| Path 3: SQL Injection | MEDIUM | MEDIUM-HIGH | LOW | MEDIUM-HIGH | HIGH |

### Key Vulnerabilities Exploited

1. **No Rate Limiting** (app.py:86-116) - Enables unlimited brute force attempts
2. **Verbose Error Messages** (app.py:111-113) - Username enumeration
3. **Weak Password Hashing** (models.py:30) - SHA256 easily cracked
4. **Session Fixation** (app.py:102) - Session ID not regenerated
5. **SQL Injection** - Lack of parameterized queries
6. **Weak Default Credentials** - "admin123" unchanged

---

## Attack Tree 2: Handicap Inflation for Tournament Advantage

**Root Goal:** Artificially inflate handicap index to compete in easier tournament flights
**Threat Actor:** TA-02 (Competitive Golfer)
**Impact:** Undermines handicap system integrity, financial fraud, unfair competitive advantage
**Code References:** `models.py:95-96`, `app.py:264` (score submission)

### Attack Tree Structure

```
ROOT: Artificially Inflate Handicap Index
│
├─ [OR] ──┬─ Path 1: Direct Score Manipulation
│         │  │
│         │  ├─ [AND] ──┬─ Subgoal 1.1: Intercept Score Submission Request
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Setup HTTP Interception Proxy
│         │  │          │  │         • Tool: Burp Suite, OWASP ZAP, mitmproxy
│         │  │          │  │         • Configuration: Browser proxy settings
│         │  │          │  │         • Purpose: Capture POST to /round/new
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE (Burp Community Edition)
│         │  │          │  │         • Detection Risk: LOW (client-side action)
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Submit Legitimate Round via Web Form
│         │  │          │  │         • Navigate: /round/new
│         │  │          │  │         • Enter: Plausible scores (85-95 range)
│         │  │          │  │         • Purpose: Generate valid request structure
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE
│         │  │          │  │         • Detection Risk: NONE (normal usage)
│         │  │          │  │
│         │  │          │  └─ [LEAF] Capture POST Request in Proxy
│         │  │          │            • Intercept: Before request reaches server
│         │  │          │            • Observe: Form parameters (hole scores, total)
│         │  │          │            • Vulnerability: No cryptographic verification
│         │  │          │            • Feasibility: HIGH
│         │  │          │            • Complexity: LOW
│         │  │          │            • Cost: FREE
│         │  │          │            • Detection Risk: NONE
│         │  │          │
│         │  │          ├─ Subgoal 1.2: Modify Score Data
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Inflate Individual Hole Scores
│         │  │          │  │         • Modify: hole_1=5 → hole_1=7 (add 2 strokes per hole)
│         │  │          │  │         • Constraint: Keep scores plausible (4-8 range)
│         │  │          │  │         • Vulnerability: models.py:95-96 (total not verified)
│         │  │          │  │         • Method: Edit POST parameters in Burp
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE
│         │  │          │  │         • Detection Risk: LOW (if plausible)
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Recalculate Total Score
│         │  │          │  │         • Update: total_score parameter to match modified holes
│         │  │          │  │         • Example: 80 → 116 (inflated by 36 strokes)
│         │  │          │  │         • Vulnerability: app.py:264 (no verification)
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE
│         │  │          │  │         • Detection Risk: LOW
│         │  │          │  │
│         │  │          │  └─ [LEAF] Forward Modified Request
│         │  │          │            • Action: Send tampered POST to server
│         │  │          │            • Server: Accepts without verification
│         │  │          │            • Result: Inflated score stored in database
│         │  │          │            • Feasibility: HIGH
│         │  │          │            • Complexity: LOW
│         │  │          │            • Cost: FREE
│         │  │          │            • Detection Risk: LOW
│         │  │          │
│         │  │          └─ Subgoal 1.3: Repeat for Multiple Rounds
│         │  │             │
│         │  │             └─ [LEAF] Submit 8-10 Inflated Rounds Strategically
│         │  │                       • Strategy: Mix of good and bad rounds (realism)
│         │  │                       • Timing: Spread over weeks/months
│         │  │                       • Calculation: Need 8 worst rounds for handicap
│         │  │                       • Result: Handicap index increases by 10-15 strokes
│         │  │                       • Feasibility: HIGH
│         │  │                       • Complexity: LOW
│         │  │                       • Cost: Time investment only
│         │  │                       • Detection Risk: LOW-MEDIUM (anomaly detection)
│         │  │
│         │  └─ Post-Attack Actions
│         │     │
│         │     └─ [LEAF] Compete in Higher Handicap Flights
│         │               • Tournament: Register for 15-20 handicap division
│         │               • Actual Skill: 5-10 handicap (much better)
│         │               • Outcome: Win against weaker competition
│         │               • Financial: Prize money, betting advantages
│         │               • Feasibility: HIGH
│         │               • Complexity: LOW
│         │               • Cost: Tournament entry fee
│         │               • Detection Risk: MEDIUM (suspicious performance)
│         │
│         ├─ Path 2: Selective Round Reporting
│         │  │
│         │  ├─ [LEAF] Play Multiple Rounds but Only Report Bad Scores
│         │  │         • Method: Only enter rounds where you played poorly
│         │  │         • Assumption: No verification of all rounds played
│         │  │         • Impact: Handicap based only on worst performances
│         │  │         • Feasibility: HIGH (if no external verification)
│         │  │         • Complexity: LOW
│         │  │         • Cost: FREE
│         │  │         • Detection Risk: LOW-MEDIUM
│         │  │
│         │  └─ [LEAF] Delete Good Rounds (if feature exists)
│         │            • Method: Delete or modify score history
│         │            • Vulnerability: Weak access controls on /scores
│         │            • Feasibility: MEDIUM (depends on implementation)
│         │            • Complexity: LOW
│         │            • Cost: FREE
│         │            • Detection Risk: MEDIUM (audit logs)
│         │
│         └─ Path 3: Course Rating Manipulation
│            │
│            ├─ [AND] ──┬─ [LEAF] Compromise Admin Account (see Attack Tree 1)
│            │          │         • Prerequisite: Admin access required
│            │          │         • Feasibility: MEDIUM
│            │          │         • Complexity: MEDIUM
│            │          │
│            │          ├─ [LEAF] Modify Course Ratings/Slope Before Tournament
│            │          │         • Access: /courses/add or direct DB edit
│            │          │         • Modification: Increase rating by 5-10 points
│            │          │         • Example: Rating 72.0 → 77.0
│            │          │         • Impact: Makes course appear harder, inflates handicaps
│            │          │         • Feasibility: MEDIUM (requires admin)
│            │          │         • Complexity: LOW
│            │          │         • Cost: LOW
│            │          │         • Detection Risk: HIGH (visible to all users)
│            │          │
│            │          └─ [LEAF] Revert Changes After Tournament
│            │                    • Action: Change rating back to normal
│            │                    • Purpose: Hide manipulation
│            │                    • Problem: Audit logs may record changes
│            │                    • Feasibility: MEDIUM
│            │                    • Complexity: LOW
│            │                    • Cost: LOW
│            │                    • Detection Risk: HIGH
│            │
│            └─ [LEAF] Exploit Modified Ratings in Tournament
│                      • Benefit: Artificially higher handicap for tournament
│                      • Competitive Edge: Significant stroke advantage
│                      • Feasibility: MEDIUM (high risk of detection)
│                      • Complexity: MEDIUM
│                      • Cost: MEDIUM
│                      • Detection Risk: VERY HIGH
```

### Attack Path Summary

| Attack Path | Feasibility | Complexity | Cost | Detection Risk | Impact |
|-------------|-------------|------------|------|----------------|--------|
| Path 1: Direct Score Manipulation | HIGH | LOW | LOW | LOW-MEDIUM | HIGH |
| Path 2: Selective Reporting | HIGH | LOW | FREE | LOW-MEDIUM | MEDIUM |
| Path 3: Course Rating Manipulation | MEDIUM | MEDIUM | LOW | VERY HIGH | HIGH |

### Key Vulnerabilities Exploited

1. **No Score Verification** (models.py:95-96, app.py:264) - Total doesn't match hole scores
2. **No HMAC/Digital Signatures** - Score authenticity not verified
3. **Client-Side Trust** - Server accepts any POST data
4. **No Anomaly Detection** - Sudden handicap changes not flagged
5. **Weak Admin Controls** - Course ratings modifiable without approval

---

## Attack Tree 3: Mass Data Extraction via IDOR

**Root Goal:** Extract complete user database for sale or exploitation
**Threat Actor:** TA-05 (Data Harvester)
**Impact:** Privacy violation, GDPR breach, credential theft, secondary attacks
**Code References:** `app.py:366-380` (/api/handicap/<user_id>)

### Attack Tree Structure

```
ROOT: Extract All User Data from System
│
├─ [OR] ──┬─ Path 1: IDOR Exploitation (Systematic Harvesting)
│         │  │
│         │  ├─ [AND] ──┬─ Subgoal 1.1: Discover IDOR Vulnerability
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Create Legitimate User Account
│         │  │          │  │         • Register: /register with valid credentials
│         │  │          │  │         • Purpose: Obtain authenticated session
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE
│         │  │          │  │         • Detection Risk: NONE (normal registration)
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Access Own Handicap Data
│         │  │          │  │         • Navigate: /api/handicap/5 (own user_id)
│         │  │          │  │         • Observe: URL structure with user_id parameter
│         │  │          │  │         • Response: JSON with handicap, rounds, stats
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE
│         │  │          │  │         • Detection Risk: NONE
│         │  │          │  │
│         │  │          │  └─ [LEAF] Test IDOR by Modifying user_id Parameter
│         │  │          │            • Test: /api/handicap/1, /api/handicap/2, etc.
│         │  │          │            • Vulnerability: app.py:366-380 (no authorization check)
│         │  │          │            • Observation: Can access other users' data
│         │  │          │            • Feasibility: HIGH
│         │  │          │            • Complexity: LOW
│         │  │          │            • Cost: FREE
│         │  │          │            • Detection Risk: LOW
│         │  │          │
│         │  │          ├─ Subgoal 1.2: Enumerate Valid User IDs
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Sequential ID Enumeration
│         │  │          │  │         • Method: Iterate user_id from 1 to N
│         │  │          │  │         • Pattern: /api/handicap/1, /api/handicap/2, ...
│         │  │          │  │         • Stop Condition: HTTP 404 or error response
│         │  │          │  │         • Assumption: Sequential integer primary keys
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE (automated script)
│         │  │          │  │         • Detection Risk: MEDIUM (high request volume)
│         │  │          │  │
│         │  │          │  └─ [LEAF] Scrape Leaderboard for User IDs
│         │  │          │            • Access: /leaderboard endpoint
│         │  │          │            • Extract: Visible usernames and IDs
│         │  │          │            • Purpose: Targeted data collection
│         │  │          │            • Feasibility: HIGH
│         │  │          │            • Complexity: LOW
│         │  │          │            • Cost: FREE
│         │  │          │            • Detection Risk: LOW
│         │  │          │
│         │  │          └─ Subgoal 1.3: Automate Data Harvesting
│         │  │             │
│         │  │             ├─ [LEAF] Write Python Script for Mass Collection
│         │  │             │         • Tool: requests library, session management
│         │  │             │         • Logic: Loop through user_ids, fetch JSON
│         │  │             │         • Rate: 10-100 requests/second
│         │  │             │         • Data: Username, handicap, rounds, scores
│         │  │             │         • Feasibility: HIGH
│         │  │             │         • Complexity: LOW
│         │  │             │         • Cost: FREE
│         │  │             │         • Detection Risk: MEDIUM
│         │  │             │
│         │  │             ├─ [LEAF] Bypass Rate Limiting (if any)
│         │  │             │         • Technique: Distributed requests, rotating IPs
│         │  │             │         • Current: No rate limiting exists
│         │  │             │         • Feasibility: HIGH (no controls)
│         │  │             │         • Complexity: LOW
│         │  │             │         • Cost: LOW
│         │  │             │         • Detection Risk: LOW
│         │  │             │
│         │  │             └─ [LEAF] Store Harvested Data in Database
│         │  │                       • Storage: Local SQLite, MongoDB, CSV
│         │  │                       • Fields: user_id, username, email, handicap, rounds
│         │  │                       • Volume: Thousands of user records
│         │  │                       • Feasibility: HIGH
│         │  │                       • Complexity: LOW
│         │  │                       • Cost: FREE
│         │  │                       • Detection Risk: NONE (client-side)
│         │  │
│         │  └─ Post-Harvest Actions
│         │     │
│         │     ├─ [OR] ──┬─ [LEAF] Sell Data on Underground Markets
│         │     │         │         • Platforms: Dark web forums, Telegram channels
│         │     │         │         • Price: $0.50-$5 per user record
│         │     │         │         • Buyers: Spammers, phishers, identity thieves
│         │     │         │         • Feasibility: MEDIUM (requires access to markets)
│         │     │         │         • Complexity: MEDIUM
│         │     │         │         • Cost: LOW
│         │     │         │         • Detection Risk: LOW (anonymous markets)
│         │     │         │
│         │     │         ├─ [LEAF] Credential Stuffing Attacks
│         │     │         │         • Use: If passwords obtained via SQL injection
│         │     │         │         • Targets: Other websites where users reuse passwords
│         │     │         │         • Tools: Snipr, OpenBullet, custom scripts
│         │     │         │         • Feasibility: MEDIUM (requires passwords)
│         │     │         │         • Complexity: MEDIUM
│         │     │         │         • Cost: LOW
│         │     │         │
│         │     │         └─ [LEAF] Targeted Phishing Campaigns
│         │     │                   • Use: Email addresses for golf-related phishing
│         │     │                   • Content: "Your handicap has been updated"
│         │     │                   • Goal: Steal more credentials or financial info
│         │     │                   • Feasibility: HIGH
│         │     │                   • Complexity: LOW-MEDIUM
│         │     │                   • Cost: LOW
│         │     │
│         │     └─ [LEAF] Competitive Intelligence Sale
│         │               • Buyers: Professional golfers, coaches
│         │               • Data: Detailed performance analytics
│         │               • Price: Premium for high-profile players
│         │               • Feasibility: MEDIUM
│         │               • Complexity: MEDIUM
│         │               • Cost: LOW
│         │
│         ├─ Path 2: SQL Injection for Database Dump
│         │  │
│         │  ├─ [AND] ──┬─ [LEAF] Identify SQL Injection Vulnerability
│         │  │          │         • Target: Course search, username input
│         │  │          │         • Test: ' OR '1'='1, '; DROP TABLE--, etc.
│         │  │          │         • Vulnerability: Lack of parameterized queries
│         │  │          │         • Tool: sqlmap, manual testing
│         │  │          │         • Feasibility: MEDIUM
│         │  │          │         • Complexity: MEDIUM
│         │  │          │         • Cost: FREE
│         │  │          │         • Detection Risk: MEDIUM
│         │  │          │
│         │  │          ├─ [LEAF] Extract Database Schema
│         │  │          │         • Query: UNION SELECT name FROM sqlite_master
│         │  │          │         • Purpose: Identify tables (users, rounds, scores)
│         │  │          │         • Feasibility: MEDIUM
│         │  │          │         • Complexity: MEDIUM
│         │  │          │         • Cost: FREE
│         │  │          │         • Detection Risk: MEDIUM
│         │  │          │
│         │  │          └─ [LEAF] Dump Entire Users Table
│         │  │                    • Query: ' UNION SELECT username,password,email,role FROM users--
│         │  │                    • Data: All credentials, PII
│         │  │                    • Vulnerability: Weak SHA256 hashing (models.py:30)
│         │  │                    • Feasibility: MEDIUM
│         │  │                    • Complexity: MEDIUM-HIGH
│         │  │                    • Cost: FREE
│         │  │                    • Detection Risk: MEDIUM-HIGH
│         │  │
│         │  └─ Post-Injection Actions
│         │     │
│         │     ├─ [LEAF] Crack SHA256 Password Hashes
│         │     │         • Tool: hashcat with GPU acceleration
│         │     │         • Speed: Billions of hashes/second
│         │     │         • Success Rate: HIGH for weak passwords
│         │     │         • Feasibility: HIGH
│         │     │         • Complexity: MEDIUM
│         │     │         • Cost: MEDIUM (GPU or cloud)
│         │     │         • Detection Risk: NONE (offline)
│         │     │
│         │     └─ [LEAF] Export Complete Database File
│         │               • Method: If admin access obtained
│         │               • Target: instance/golf.db (SQLite file)
│         │               • Size: <100MB typically
│         │               • Feasibility: MEDIUM (requires admin or file access)
│         │               • Complexity: LOW
│         │               • Cost: FREE
│         │               • Detection Risk: MEDIUM
│         │
│         └─ Path 3: Credential Stuffing for Account Access
│            │
│            ├─ [AND] ──┬─ [LEAF] Obtain Leaked Credential Database
│            │          │         • Sources: Previous breaches, dark web
│            │          │         • Format: email:password or username:password
│            │          │         • Assumption: Users reuse passwords
│            │          │         • Feasibility: HIGH (many leaks available)
│            │          │         • Complexity: LOW
│            │          │         • Cost: FREE
│            │          │         • Detection Risk: NONE (data acquisition)
│            │          │
│            │          ├─ [LEAF] Enumerate Valid Usernames
│            │          │         • Method: Login error message analysis
│            │          │         • Vulnerability: app.py:111-113
│            │          │         • Purpose: Create target list
│            │          │         • Feasibility: HIGH
│            │          │         • Complexity: LOW
│            │          │         • Cost: FREE
│            │          │         • Detection Risk: LOW
│            │          │
│            │          └─ [LEAF] Automate Credential Testing
│            │                    • Tool: Custom script or credential stuffer
│            │                    • Method: Try leaked passwords for enumerated users
│            │                    • Vulnerability: No rate limiting
│            │                    • Success Rate: 5-15% typically
│            │                    • Feasibility: HIGH
│            │                    • Complexity: LOW
│            │                    • Cost: FREE
│            │                    • Detection Risk: MEDIUM
│            │
│            └─ [LEAF] Access Compromised Accounts
│                      • Action: Login with successful credentials
│                      • Data: Access handicap, scores, personal info
│                      • Scale: Multiply across hundreds of accounts
│                      • Feasibility: HIGH
│                      • Complexity: LOW
│                      • Cost: FREE
│                      • Detection Risk: MEDIUM
```

### Attack Path Summary

| Attack Path | Feasibility | Complexity | Cost | Detection Risk | Impact |
|-------------|-------------|------------|------|----------------|--------|
| Path 1: IDOR Exploitation | HIGH | LOW | FREE | MEDIUM | HIGH |
| Path 2: SQL Injection Dump | MEDIUM | MEDIUM-HIGH | FREE | MEDIUM-HIGH | CRITICAL |
| Path 3: Credential Stuffing | HIGH | LOW | FREE | MEDIUM | MEDIUM-HIGH |

### Key Vulnerabilities Exploited

1. **IDOR at /api/handicap/<user_id>** (app.py:366-380) - No authorization check
2. **No Rate Limiting** - Unlimited automated requests
3. **SQL Injection** - Lack of parameterized queries
4. **Weak Password Hashing** (models.py:30) - SHA256 easily cracked
5. **Username Enumeration** (app.py:111-113) - Verbose error messages
6. **Missing Audit Logging** - Mass data access goes undetected

---

## Attack Tree 4: Insider Handicap Fraud Operation

**Root Goal:** Systematically manipulate handicaps for financial gain
**Threat Actor:** TA-03 (Malicious Administrator)
**Impact:** CRITICAL system-wide integrity compromise, systematic fraud, audit log tampering
**Code References:** Admin privileges, database access, modifiable audit logs

### Attack Tree Structure

```
ROOT: Operate Lucrative Handicap Manipulation Service
│
├─ [AND] ──┬─ Subgoal 1: Obtain or Maintain Admin Access
│          │  │
│          │  ├─ [OR] ──┬─ [LEAF] Legitimate Admin Account (Rogue Insider)
│          │  │         │         • Scenario: Golf course employee with admin role
│          │  │         │         • Access: Already have credentials
│          │  │         │         • Feasibility: MEDIUM (requires insider)
│          │  │         │         • Complexity: NONE
│          │  │         │         • Cost: NONE
│          │  │         │         • Detection Risk: HIGH (actions tied to account)
│          │  │         │
│          │  │         └─ [LEAF] Compromise Admin Account (See Attack Tree 1)
│          │  │                   • Method: Brute force, phishing, social engineering
│          │  │                   • Feasibility: MEDIUM
│          │  │                   • Complexity: MEDIUM
│          │  │                   • Cost: LOW
│          │  │                   • Detection Risk: MEDIUM
│          │  │
│          │  └─ [LEAF] Create Hidden Backdoor Admin Account
│          │            • Username: Subtle variation (e.g., "admin-backup")
│          │            • Purpose: Persistent access if primary detected
│          │            • Feasibility: HIGH (once admin access obtained)
│          │            • Complexity: LOW
│          │            • Cost: FREE
│          │            • Detection Risk: MEDIUM-HIGH
│          │
│          ├─ Subgoal 2: Recruit Paying Clients
│          │  │
│          │  ├─ [LEAF] Identify High-Stakes Tournament Players
│          │  │         • Targets: Players in competitive leagues
│          │  │         • Motivation: Financial prizes, status
│          │  │         • Outreach: Discrete personal contact
│          │  │         • Feasibility: MEDIUM
│          │  │         • Complexity: LOW
│          │  │         • Cost: NONE
│          │  │         • Detection Risk: LOW (offline recruitment)
│          │  │
│          │  ├─ [LEAF] Establish Pricing Structure
│          │  │         • Model: $500-$2000 per handicap manipulation
│          │  │         • Payment: Cash, cryptocurrency for anonymity
│          │  │         • Service: Increase handicap by 5-10 strokes
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW
│          │  │         • Cost: NONE
│          │  │         • Detection Risk: LOW
│          │  │
│          │  └─ [LEAF] Build Reputation Through Word-of-Mouth
│          │            • Method: Early clients refer others
│          │            • Trust: Demonstrate successful manipulations
│          │            • Growth: Expand client base over time
│          │            • Feasibility: MEDIUM-HIGH
│          │            • Complexity: LOW
│          │            • Cost: NONE
│          │            • Detection Risk: MEDIUM (more clients = more risk)
│          │
│          ├─ Subgoal 3: Execute Handicap Manipulations
│          │  │
│          │  ├─ [AND] ──┬─ [LEAF] Direct Database Modification
│          │  │          │         • Access: Direct SQL to instance/golf.db
│          │  │          │         • Method: UPDATE rounds SET total_score=X WHERE user_id=Y
│          │  │          │         • Strategy: Modify historical rounds organically
│          │  │          │         • Example: Change 80 → 95 on select rounds
│          │  │          │         • Feasibility: HIGH (admin DB access)
│          │  │          │         • Complexity: LOW
│          │  │          │         • Cost: FREE
│          │  │          │         • Detection Risk: MEDIUM (DB logs if enabled)
│          │  │          │
│          │  │          ├─ [LEAF] Modify Individual Hole Scores
│          │  │          │         • Target: Score table for granular changes
│          │  │          │         • Method: UPDATE scores SET strokes=X WHERE round_id=Y
│          │  │          │         • Benefit: More realistic than total-only changes
│          │  │          │         • Feasibility: HIGH
│          │  │          │         • Complexity: LOW
│          │  │          │         • Cost: FREE
│          │  │          │         • Detection Risk: LOW (harder to detect)
│          │  │          │
│          │  │          └─ [LEAF] Spread Changes Over Time
│          │  │                    • Pattern: Modify 1-2 rounds per week
│          │  │                    • Strategy: Gradual handicap increase (realism)
│          │  │                    • Timeline: 2-3 months for 10-stroke inflation
│          │  │                    • Feasibility: HIGH
│          │  │                    • Complexity: LOW
│          │  │                    • Cost: Time investment
│          │  │                    • Detection Risk: LOW (avoids sudden changes)
│          │  │
│          │  └─ [OR] ──┬─ [LEAF] Alternative: Manipulate Course Ratings
│          │            │         • Method: Temporarily inflate course difficulty
│          │            │         • Example: Rating 72.0 → 75.0 before client plays
│          │            │         • Impact: Client's differential increases
│          │            │         • Revert: Change back after round submitted
│          │            │         • Feasibility: MEDIUM
│          │            │         • Complexity: LOW
│          │            │         • Cost: FREE
│          │            │         • Detection Risk: HIGH (visible to all users)
│          │            │
│          │            └─ [LEAF] Alternative: Inject Fake Rounds
│          │                      • Method: INSERT new rounds with high scores
│          │                      • Data: Use plausible dates, course_ids
│          │                      • Benefit: Avoids modifying existing data
│          │                      • Feasibility: HIGH
│          │                      • Complexity: LOW
│          │                      • Cost: FREE
│          │                      • Detection Risk: MEDIUM (audit logs)
│          │
│          └─ Subgoal 4: Cover Tracks and Avoid Detection
│             │
│             ├─ [AND] ──┬─ [LEAF] Delete or Modify Audit Log Entries
│             │          │         • Access: AuditLog table via admin panel or DB
│             │          │         • Method: DELETE FROM audit_log WHERE user_id=1
│             │          │         • Target: Remove login records, data modifications
│             │          │         • Vulnerability: Modifiable audit logs
│             │          │         • Feasibility: HIGH
│             │          │         • Complexity: LOW
│             │          │         • Cost: FREE
│             │          │         • Detection Risk: HIGH (if external monitoring)
│             │          │
│             │          ├─ [LEAF] Manipulate Timestamps
│             │          │         • Method: Backdate modifications to look historical
│             │          │         • Example: Change created_at to 3 months ago
│             │          │         • Purpose: Make changes appear legitimate
│             │          │         • Feasibility: HIGH
│             │          │         • Complexity: LOW
│             │          │         • Cost: FREE
│             │          │         • Detection Risk: MEDIUM
│             │          │
│             │          ├─ [LEAF] Use Backdoor Account for Operations
│             │          │         • Benefit: Primary admin account stays clean
│             │          │         • Strategy: Attribute actions to "system" account
│             │          │         • Feasibility: HIGH
│             │          │         • Complexity: LOW
│             │          │         • Cost: FREE
│             │          │         • Detection Risk: MEDIUM
│             │          │
│             │          └─ [LEAF] Maintain Plausible Deniability
│             │                    • Strategy: Claim account was compromised
│             │                    • Evidence: Delete incriminating communications
│             │                    • Fallback: Blame "unknown attacker"
│             │                    • Feasibility: MEDIUM (depends on investigation)
│             │                    • Complexity: LOW
│             │                    • Cost: NONE
│             │                    • Detection Risk: MEDIUM
│             │
│             └─ [LEAF] Monitor for Anomaly Detection Systems
│                       • Watch: Admin panel for new security features
│                       • Adjust: Reduce activity if monitoring increases
│                       • Exit Strategy: Cash out and disappear if threatened
│                       • Feasibility: HIGH
│                       • Complexity: LOW
│                       • Cost: NONE
│                       • Detection Risk: LOW
│
└─ Post-Operation Outcomes
   │
   ├─ [LEAF] Financial Gain
   │         • Revenue: $500-$2000 per client × 10-50 clients
   │         • Total: $5,000-$100,000 over months/years
   │         • Risk: Money laundering investigation
   │         • Feasibility: HIGH (if undetected)
   │         • Complexity: LOW
   │         • Cost: NONE
   │
   └─ [LEAF] System Integrity Destruction
             • Impact: Handicap system loses all credibility
             • Consequence: Tournaments become meaningless
             • Discovery: Forensic analysis extremely difficult
             • Feasibility: HIGH
             • Complexity: N/A
             • Cost: Reputational damage to organization
```

### Attack Path Summary

| Attack Component | Feasibility | Complexity | Cost | Detection Risk | Impact |
|------------------|-------------|------------|------|----------------|--------|
| Obtain Admin Access | MEDIUM | MEDIUM | LOW | MEDIUM | CRITICAL |
| Recruit Clients | MEDIUM | LOW | NONE | LOW | N/A |
| Manipulate Handicaps | HIGH | LOW | FREE | MEDIUM | CRITICAL |
| Cover Tracks | HIGH | LOW | FREE | MEDIUM-HIGH | N/A |

### Key Vulnerabilities Exploited

1. **Excessive Admin Privileges** - No segregation of duties
2. **Modifiable Audit Logs** - Attackers can erase evidence
3. **Direct Database Access** - No change approval workflow
4. **Weak SHA256 Hashing** (models.py:30) - Compromised admin credentials easily used
5. **No Anomaly Detection** - Systematic fraud goes unnoticed
6. **No Multi-Party Approval** - Single admin can make any change

---

## Attack Tree 5: Website Defacement and Service Disruption

**Root Goal:** Disrupt service and deface website for visibility/activism
**Threat Actor:** TA-06 (Vandal / Hacktivist)
**Impact:** Service disruption during tournaments, reputational damage, media coverage
**Code References:** Admin access, template modification, DoS vulnerabilities

### Attack Tree Structure

```
ROOT: Disrupt Golf Score Tracker Service and Deface Website
│
├─ [OR] ──┬─ Path 1: Website Defacement
│         │  │
│         │  ├─ [AND] ──┬─ Subgoal 1.1: Gain Admin Access (See Attack Tree 1)
│         │  │          │         • Required for template modification
│         │  │          │         • Feasibility: MEDIUM
│         │  │          │         • Complexity: MEDIUM
│         │  │          │
│         │  │          ├─ [LEAF] Access Base Template File
│         │  │          │         • File: templates/base.html
│         │  │          │         • Access: Via admin panel file editor (if exists)
│         │  │          │         •   OR: Direct file system access via compromised server
│         │  │          │         • Feasibility: HIGH (once admin)
│         │  │          │         • Complexity: LOW
│         │  │          │         • Cost: FREE
│         │  │          │         • Detection Risk: HIGH (immediate visibility)
│         │  │          │
│         │  │          ├─ [LEAF] Inject Defacement Content
│         │  │          │         • Method: Modify base.html with political message
│         │  │          │         • Content: Manifestos, memes, protest messages
│         │  │          │         • Example: Replace navbar with "HACKED BY [GROUP]"
│         │  │          │         • Visual: Garish colors, animated GIFs
│         │  │          │         • Feasibility: HIGH
│         │  │          │         • Complexity: LOW
│         │  │          │         • Cost: FREE
│         │  │          │         • Detection Risk: IMMEDIATE (visible to all)
│         │  │          │
│         │  │          └─ [LEAF] Inject Malicious JavaScript
│         │  │                    • Code: Redirect users to attacker site
│         │  │                    • Example: <script>window.location='attacker.com'</script>
│         │  │                    • Impact: All users redirected
│         │  │                    • Feasibility: HIGH
│         │  │                    • Complexity: LOW
│         │  │                    • Cost: FREE
│         │  │                    • Detection Risk: IMMEDIATE
│         │  │
│         │  └─ Post-Defacement Actions
│         │     │
│         │     ├─ [LEAF] Screenshot and Publicize
│         │     │         • Action: Capture defaced website image
│         │     │         • Platforms: Twitter, hacker forums, media outlets
│         │     │         • Purpose: Maximize visibility and embarrassment
│         │     │         • Feasibility: HIGH
│         │     │         • Complexity: LOW
│         │     │         • Cost: FREE
│         │     │         • Detection Risk: NONE (already public)
│         │     │
│         │     └─ [LEAF] Publish Technical Details
│         │               • Content: Vulnerability disclosure, exploit code
│         │               • Platform: GitHub, Pastebin, security blogs
│         │               • Impact: Enables copycat attacks
│         │               • Feasibility: HIGH
│         │               • Complexity: LOW
│         │               • Cost: FREE
│         │               • Detection Risk: NONE
│         │
│         ├─ Path 2: Application-Layer Denial of Service
│         │  │
│         │  ├─ [AND] ──┬─ Subgoal 2.1: Identify Resource-Intensive Endpoints
│         │  │          │  │
│         │  │          │  ├─ [LEAF] Target Score Submission Endpoint
│         │  │          │  │         • Endpoint: POST /round/new
│         │  │          │  │         • Resource Cost: Database writes, score calculations
│         │  │          │  │         • Vulnerability: No rate limiting (app.py:264)
│         │  │          │  │         • Feasibility: HIGH
│         │  │          │  │         • Complexity: LOW
│         │  │          │  │         • Cost: FREE
│         │  │          │  │         • Detection Risk: MEDIUM
│         │  │          │  │
│         │  │          │  └─ [LEAF] Target Login Endpoint
│         │  │          │            • Endpoint: POST /login
│         │  │          │            • Resource Cost: Password hashing (SHA256)
│         │  │          │            • Vulnerability: No rate limiting (app.py:86-116)
│         │  │          │            • Feasibility: HIGH
│         │  │          │            • Complexity: LOW
│         │  │          │            • Cost: FREE
│         │  │          │            • Detection Risk: MEDIUM
│         │  │          │
│         │  │          └─ Subgoal 2.2: Automate High-Volume Requests
│         │  │             │
│         │  │             ├─ [LEAF] Write DoS Script
│         │  │             │         • Tool: Python requests, threading/asyncio
│         │  │             │         • Method: Flood endpoint with thousands of POSTs
│         │  │             │         • Rate: 100-1000 requests/second
│         │  │             │         • Feasibility: HIGH
│         │  │             │         • Complexity: LOW
│         │  │             │         • Cost: FREE
│         │  │             │         • Detection Risk: HIGH (traffic spike)
│         │  │             │
│         │  │             ├─ [LEAF] Use Distributed Botnet (if available)
│         │  │             │         • Method: DDoS from multiple IPs
│         │  │             │         • Scale: 10-100 compromised hosts
│         │  │             │         • Benefit: Harder to block single source
│         │  │             │         • Feasibility: LOW (requires botnet access)
│         │  │             │         • Complexity: HIGH
│         │  │             │         • Cost: MEDIUM (rent botnet or use own)
│         │  │             │         • Detection Risk: HIGH
│         │  │             │
│         │  │             └─ [LEAF] Exhaust Server Resources
│         │  │                       • Target: CPU, memory, database connections
│         │  │                       • Symptom: 500 errors, timeouts, crashes
│         │  │                       • Impact: Legitimate users cannot access
│         │  │                       • Feasibility: MEDIUM (depends on server capacity)
│         │  │                       • Complexity: LOW
│         │  │                       • Cost: FREE
│         │  │                       • Detection Risk: IMMEDIATE
│         │  │
│         │  └─ Timing for Maximum Impact
│         │     │
│         │     └─ [LEAF] Launch During Major Tournament
│         │               • Timing: Weekend tournament registration
│         │               • Impact: Players cannot submit scores
│         │               • Chaos: Manual backup processes fail
│         │               • Visibility: Media coverage of disruption
│         │               • Feasibility: HIGH
│         │               • Complexity: LOW
│         │               • Cost: NONE
│         │               • Detection Risk: IMMEDIATE (but damage done)
│         │
│         └─ Path 3: Database Destruction
│            │
│            ├─ [AND] ──┬─ [LEAF] Gain Admin or SQL Injection Access
│            │          │         • Methods: See Attack Trees 1 and 3
│            │          │         • Requirement: Ability to execute SQL
│            │          │         • Feasibility: MEDIUM
│            │          │         • Complexity: MEDIUM
│            │          │
│            │          ├─ [LEAF] Execute DROP TABLE Commands
│            │          │         • SQL: DROP TABLE users; DROP TABLE rounds;
│            │          │         • Impact: Complete data loss
│            │          │         • Irreversibility: Unless backups exist
│            │          │         • Feasibility: MEDIUM (depends on DB permissions)
│            │          │         • Complexity: LOW
│            │          │         • Cost: FREE
│            │          │         • Detection Risk: IMMEDIATE
│            │          │
│            │          └─ [LEAF] Alternative: Corrupt Data Instead of Delete
│            │                    • SQL: UPDATE users SET password='hacked';
│            │                    • Impact: All users locked out (worse than deletion)
│            │                    • Recovery: More difficult than restore from backup
│            │                    • Feasibility: HIGH
│            │                    • Complexity: LOW
│            │                    • Cost: FREE
│            │                    • Detection Risk: DELAYED (users report login failures)
│            │
│            └─ Post-Attack Impact
│               │
│               └─ [LEAF] Service Outage for Days/Weeks
│                         • Recovery: Restore from backups (if they exist)
│                         • Investigation: Forensic analysis delays restoration
│                         • Reputational: Users lose trust in platform
│                         • Financial: Tournament revenue lost
│                         • Feasibility: HIGH (if attack succeeds)
│                         • Complexity: N/A
│                         • Cost: Victim's incident response costs
```

### Attack Path Summary

| Attack Path | Feasibility | Complexity | Cost | Detection Risk | Impact |
|-------------|-------------|------------|------|----------------|--------|
| Path 1: Website Defacement | MEDIUM | LOW | FREE | IMMEDIATE | HIGH |
| Path 2: Application DoS | HIGH | LOW | FREE | MEDIUM-HIGH | HIGH |
| Path 3: Database Destruction | MEDIUM | MEDIUM | FREE | IMMEDIATE | CRITICAL |

### Key Vulnerabilities Exploited

1. **Weak Admin Authentication** - Brute forceable credentials
2. **No Rate Limiting** (app.py:86-116, /round/new) - DoS attacks possible
3. **Modifiable Templates** - Admin can inject malicious code
4. **SQL Injection** - Database destruction commands
5. **No CAPTCHA** - Automated attacks not prevented
6. **Missing Security Monitoring** - Attacks not detected until damage visible

---

## Attack Tree 6: Unauthorized Competitive Intelligence Gathering

**Root Goal:** Access competitors' detailed performance data without authorization
**Threat Actor:** TA-07 (Curious Insider / Authorized User)
**Impact:** Privacy violations, unfair competitive advantages
**Code References:** `app.py:366-380` (/api/handicap/<user_id>)

### Attack Tree Structure

```
ROOT: Gather Competitive Intelligence on Rival Golfers
│
├─ [AND] ──┬─ Subgoal 1: Obtain Authenticated User Account
│          │  │
│          │  └─ [LEAF] Register Legitimate Account
│          │            • Endpoint: /register
│          │            • Credentials: Valid email, username, password
│          │            • Purpose: Gain system access
│          │            • Feasibility: HIGH
│          │            • Complexity: LOW
│          │            • Cost: FREE
│          │            • Detection Risk: NONE (normal registration)
│          │
│          ├─ Subgoal 2: Discover IDOR Vulnerability
│          │  │
│          │  ├─ [LEAF] Access Own Handicap Data
│          │  │         • Navigate: Dashboard or profile page
│          │  │         • Observe: URL structure /api/handicap/5
│          │  │         • Note: user_id parameter in URL
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: NONE
│          │  │
│          │  ├─ [LEAF] Experiment with URL Parameters
│          │  │         • Test: Change /api/handicap/5 to /api/handicap/6
│          │  │         • Observe: Another user's data returned
│          │  │         • Vulnerability: app.py:366-380 (authentication but no authorization)
│          │  │         • Discovery: Accidental or deliberate
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: LOW
│          │  │
│          │  └─ [LEAF] Confirm Vulnerability Scope
│          │            • Test: Multiple user IDs to verify access
│          │            • Data: Handicap index, round history, statistics
│          │            • Limitation: Must be logged in (authentication exists)
│          │            • Feasibility: HIGH
│          │            • Complexity: LOW
│          │            • Cost: FREE
│          │            • Detection Risk: LOW (few requests, plausible)
│          │
│          ├─ Subgoal 3: Identify Target Competitors
│          │  │
│          │  ├─ [LEAF] Browse Leaderboard for User IDs
│          │  │         • Endpoint: /leaderboard
│          │  │         • Data: Usernames, scores, rankings
│          │  │         • Correlation: Map usernames to user_ids
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: NONE (public page)
│          │  │
│          │  ├─ [LEAF] Identify Tournament Rivals
│          │  │         • Method: Offline knowledge of competitor names
│          │  │         • Cross-reference: With system usernames
│          │  │         • Priority: Top-ranked players in flight
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW
│          │  │         • Cost: NONE
│          │  │         • Detection Risk: NONE
│          │  │
│          │  └─ [LEAF] Enumerate User IDs Sequentially
│          │            • Range: user_id 1 to 100 (exploratory)
│          │            • Purpose: Discover all users in system
│          │            • Method: Automated script or manual iteration
│          │            • Feasibility: HIGH
│          │            • Complexity: LOW
│          │            • Cost: FREE
│          │            • Detection Risk: MEDIUM (if rate limiting existed)
│          │
│          ├─ Subgoal 4: Analyze Competitor Data
│          │  │
│          │  ├─ [LEAF] Review Round History
│          │  │         • Data: Scores by course, date, conditions
│          │  │         • Analysis: Performance trends over time
│          │  │         • Insight: Are they improving or declining?
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: NONE (client-side analysis)
│          │  │
│          │  ├─ [LEAF] Identify Course Preferences and Weaknesses
│          │  │         • Pattern: High scores on specific courses
│          │  │         • Example: "Player X struggles with water hazards"
│          │  │         • Advantage: Choose favorable tournament venues
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: NONE
│          │  │
│          │  ├─ [LEAF] Calculate True Skill Level
│          │  │         • Data: Best rounds, average scores
│          │  │         • Analysis: Is handicap accurate or sandbagged?
│          │  │         • Purpose: Predict tournament performance
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: LOW-MEDIUM
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: NONE
│          │  │
│          │  └─ [LEAF] Monitor Recent Form
│          │            • Frequency: Check before tournaments
│          │            • Data: Last 5-10 rounds performance
│          │            • Purpose: Assess current competitiveness
│          │            • Feasibility: HIGH
│          │            • Complexity: LOW
│          │            • Cost: FREE
│          │            • Detection Risk: LOW (no audit logging)
│          │
│          └─ Subgoal 5: Exploit Intelligence in Competition
│             │
│             ├─ [LEAF] Adjust Tournament Strategy
│             │         • Example: Play aggressively vs. struggling rival
│             │         • Tactic: Target weak holes (data shows high scores)
│             │         • Psychological: Confidence from knowledge advantage
│             │         • Feasibility: HIGH
│             │         • Complexity: LOW
│             │         • Cost: NONE
│             │         • Detection Risk: NONE (gameplay only)
│             │
│             ├─ [LEAF] Share Technique with Friends
│             │         • Method: Tell other golfers about IDOR
│             │         • Justification: "It's public information"
│             │         • Spread: Vulnerability becomes widely exploited
│             │         • Feasibility: HIGH
│             │         • Complexity: LOW
│             │         • Cost: NONE
│             │         • Detection Risk: MEDIUM (widespread abuse noticed)
│             │
│             └─ [LEAF] Rationalize as "Not Really Hacking"
│                       • Mindset: "I'm just looking at URLs"
│                       • Justification: "There's no password required"
│                       • Reality: Still unauthorized access violation
│                       • Consequence: Privacy breach normalized
│                       • Feasibility: HIGH (psychological)
│                       • Complexity: NONE
│                       • Cost: NONE
│                       • Detection Risk: LOW (no perceived wrongdoing)
│
└─ Post-Access Impact
   │
   ├─ [LEAF] Privacy Violations Spread
   │         • Pattern: More users discover technique
   │         • Impact: All user data effectively public
   │         • Trust: Users lose confidence in system
   │         • Feasibility: HIGH (once known)
   │         • Complexity: NONE
   │         • Cost: NONE
   │
   └─ [LEAF] Competitive Integrity Undermined
             • Effect: Information asymmetry in tournaments
             • Fairness: Players with tech skills have advantages
             • Ethical: Violates sportsmanship principles
             • Feasibility: HIGH
             • Complexity: NONE
             • Cost: Reputation of fair play
```

### Attack Path Summary

| Attack Component | Feasibility | Complexity | Cost | Detection Risk | Impact |
|------------------|-------------|------------|------|----------------|--------|
| Discover IDOR | HIGH | LOW | FREE | LOW | N/A |
| Access Competitor Data | HIGH | LOW | FREE | LOW | MEDIUM |
| Analyze Intelligence | HIGH | LOW-MEDIUM | FREE | NONE | MEDIUM |
| Exploit in Competition | HIGH | LOW | NONE | NONE | MEDIUM |

### Key Vulnerabilities Exploited

1. **IDOR at /api/handicap/<user_id>** (app.py:366-380) - Authentication without authorization
2. **No Audit Logging** - Data access not tracked
3. **Missing Principle of Least Privilege** - All authenticated users can view all data
4. **No Privacy Controls** - Users can't restrict who sees their data
5. **No Anomaly Detection** - Unusual access patterns not flagged

---

## Attack Tree 7: Complete Database Extraction via SQL Injection

**Root Goal:** Extract entire database including credentials and performance data
**Threat Actor:** TA-01 (Script Kiddie) / TA-05 (Data Harvester)
**Impact:** Complete data breach, credential compromise, GDPR violations
**Code References:** SQL injection points, weak password hashing (models.py:30)

### Attack Tree Structure

```
ROOT: Extract Complete Database Contents
│
├─ [AND] ──┬─ Subgoal 1: Identify SQL Injection Vulnerability
│          │  │
│          │  ├─ [OR] ──┬─ [LEAF] Manual Testing of Input Fields
│          │  │         │         • Targets: Course search, login username, registration
│          │  │         │         • Payloads: ', ", --, ;, OR 1=1, UNION SELECT
│          │  │         │         • Observation: Error messages, unexpected behavior
│          │  │         │         • Feasibility: HIGH
│          │  │         │         • Complexity: LOW-MEDIUM
│          │  │         │         • Cost: FREE
│          │  │         │         • Detection Risk: MEDIUM
│          │  │         │
│          │  │         └─ [LEAF] Automated Scanning with sqlmap
│          │  │                   • Tool: sqlmap -u "http://app.com/courses?search=test"
│          │  │                   • Method: Automated injection pattern testing
│          │  │                   • Detection: Identifies vulnerable parameters
│          │  │                   • Feasibility: HIGH
│          │  │                   • Complexity: LOW (tool automates everything)
│          │  │                   • Cost: FREE
│          │  │                   • Detection Risk: MEDIUM-HIGH (many requests)
│          │  │
│          │  └─ [LEAF] Analyze Error Messages
│          │            • Vulnerability: Verbose SQL error messages exposed
│          │            • Information: Database type (SQLite), table names, syntax
│          │            • Example: "no such column: xyz" reveals schema
│          │            • Feasibility: HIGH (if errors not suppressed)
│          │            • Complexity: LOW
│          │            • Cost: FREE
│          │            • Detection Risk: LOW
│          │
│          ├─ Subgoal 2: Determine Database Schema
│          │  │
│          │  ├─ [LEAF] Extract Table Names
│          │  │         • SQLite: ' UNION SELECT name FROM sqlite_master WHERE type='table'--
│          │  │         • Result: users, rounds, courses, holes, scores, audit_log
│          │  │         • Purpose: Identify targets for extraction
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: MEDIUM
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: MEDIUM
│          │  │
│          │  ├─ [LEAF] Extract Column Names
│          │  │         • SQLite: ' UNION SELECT sql FROM sqlite_master WHERE name='users'--
│          │  │         • Result: CREATE TABLE users (id, username, password, role, email...)
│          │  │         • Data: Complete schema for users table
│          │  │         • Feasibility: HIGH
│          │  │         • Complexity: MEDIUM
│          │  │         • Cost: FREE
│          │  │         • Detection Risk: MEDIUM
│          │  │
│          │  └─ [LEAF] Determine Number of Columns (for UNION)
│          │            • Method: ' UNION SELECT NULL,NULL,NULL--
│          │            • Trial: Increase NULL count until no error
│          │            • Purpose: Match SELECT clause column count
│          │            • Feasibility: HIGH
│          │            • Complexity: LOW-MEDIUM
│          │            • Cost: FREE
│          │            • Detection Risk: LOW-MEDIUM
│          │
│          ├─ Subgoal 3: Extract Sensitive Data
│          │  │
│          │  ├─ [AND] ──┬─ [LEAF] Dump Users Table with Credentials
│          │  │          │         • Payload: ' UNION SELECT id,username,password,email,role FROM users--
│          │  │          │         • Data: All usernames and SHA256 password hashes
│          │  │          │         • Volume: All registered users (potentially thousands)
│          │  │          │         • Feasibility: HIGH
│          │  │          │         • Complexity: MEDIUM
│          │  │          │         • Cost: FREE
│          │  │          │         • Detection Risk: MEDIUM
│          │  │          │
│          │  │          ├─ [LEAF] Extract Rounds and Scores Data
│          │  │          │         • Tables: rounds, scores
│          │  │          │         • Purpose: Performance analytics, PII
│          │  │          │         • Data: Complete scoring history for all users
│          │  │          │         • Feasibility: HIGH
│          │  │          │         • Complexity: MEDIUM
│          │  │          │         • Cost: FREE
│          │  │          │         • Detection Risk: MEDIUM
│          │  │          │
│          │  │          └─ [LEAF] Extract Audit Logs
│          │  │                    • Table: audit_log
│          │  │                    • Purpose: Understand user behavior patterns
│          │  │                    • Data: Login times, actions, IP addresses
│          │  │                    • Feasibility: HIGH
│          │  │                    • Complexity: MEDIUM
│          │  │                    • Cost: FREE
│          │  │                    • Detection Risk: MEDIUM
│          │  │
│          │  └─ [LEAF] Automate Extraction with sqlmap --dump
│          │            • Command: sqlmap -u [URL] --dump -D golf_db -T users
│          │            • Method: Fully automated extraction
│          │            • Output: CSV or text file with all data
│          │            • Feasibility: HIGH
│          │            • Complexity: LOW (automated)
│          │            • Cost: FREE
│          │            • Detection Risk: HIGH (many requests)
│          │
│          └─ Subgoal 4: Crack Password Hashes
│             │
│             ├─ [AND] ──┬─ [LEAF] Identify Hash Algorithm
│             │          │         • Observation: 64-character hex strings
│             │          │         • Analysis: SHA256 (not bcrypt)
│             │          │         • Vulnerability: models.py:30 (weak hashing)
│             │          │         • Feasibility: HIGH
│             │          │         • Complexity: LOW
│             │          │         • Cost: FREE
│             │          │         • Detection Risk: NONE (offline analysis)
│             │          │
│             │          ├─ [LEAF] Setup Hashcat with GPU
│             │          │         • Tool: hashcat -m 1400 (SHA256)
│             │          │         • Hardware: GPU acceleration (NVIDIA/AMD)
│             │          │         • Speed: Billions of hashes/second
│             │          │         • Feasibility: HIGH
│             │          │         • Complexity: MEDIUM
│             │          │         • Cost: MEDIUM (GPU or cloud rental)
│             │          │         • Detection Risk: NONE (offline attack)
│             │          │
│             │          ├─ [LEAF] Dictionary Attack with rockyou.txt
│             │          │         • Wordlist: 14 million common passwords
│             │          │         • Success: 20-40% of passwords typically cracked
│             │          │         • Time: Minutes to hours depending on GPU
│             │          │         • Feasibility: HIGH
│             │          │         • Complexity: LOW
│             │          │         • Cost: FREE (wordlist) + GPU cost
│             │          │         • Detection Risk: NONE
│             │          │
│             │          ├─ [LEAF] Rule-Based Attack
│             │          │         • Method: Apply transformations (append123, capitalize)
│             │          │         • Example: password → Password123
│             │          │         • Success: +10-20% more cracks
│             │          │         • Feasibility: HIGH
│             │          │         • Complexity: LOW-MEDIUM
│             │          │         • Cost: FREE + GPU cost
│             │          │         • Detection Risk: NONE
│             │          │
│             │          └─ [LEAF] Rainbow Table Attack (alternative)
│             │                    • Precomputed: SHA256 rainbow tables
│             │                    • Trade-off: Disk space for computation time
│             │                    • Limitation: Only works for unsalted hashes
│             │                    • Feasibility: MEDIUM (large tables needed)
│             │                    • Complexity: LOW
│             │                    • Cost: MEDIUM (storage + download)
│             │                    • Detection Risk: NONE
│             │
│             └─ Post-Cracking Access
│                │
│                └─ [LEAF] Login with Cracked Credentials
│                          • Method: Use username:password pairs
│                          • Target: High-value accounts (admins, popular users)
│                          • Purpose: Account takeover for further attacks
│                          • Feasibility: HIGH
│                          • Complexity: LOW
│                          • Cost: FREE
│                          • Detection Risk: MEDIUM (account access from new location)
│
└─ Post-Extraction Actions
   │
   ├─ [OR] ──┬─ [LEAF] Sell Database on Dark Web
   │         │         • Market: Dark web forums, private channels
   │         │         • Price: $500-$5000 depending on data value
   │         │         • Buyers: Spammers, credential stuffers, competitors
   │         │         • Feasibility: MEDIUM (requires dark web access)
   │         │         • Complexity: MEDIUM
   │         │         • Cost: LOW
   │         │
   │         ├─ [LEAF] Blackmail Organization
   │         │         • Threat: "Pay or we leak database publicly"
   │         │         • Ransom: Bitcoin payment
   │         │         • Risk: Criminal prosecution if caught
   │         │         • Feasibility: LOW-MEDIUM (ethical/legal barriers)
   │         │         • Complexity: MEDIUM
   │         │         • Cost: LOW
   │         │
   │         ├─ [LEAF] Responsible Disclosure (Ethical Path)
   │         │         • Action: Report vulnerability to organization
   │         │         • Purpose: Get bug bounty or recognition
   │         │         • Ethical: Delete extracted data
   │         │         • Feasibility: MEDIUM (requires ethical attacker)
   │         │         • Complexity: LOW
   │         │         • Cost: NONE
   │         │
   │         └─ [LEAF] Public Dump (Maximum Damage)
   │                   • Method: Post to Pastebin, GitHub, social media
   │                   • Impact: CRITICAL reputation damage, GDPR fines
   │                   • Irreversible: Data in public domain forever
   │                   • Feasibility: HIGH
   │                   • Complexity: LOW
   │                   • Cost: NONE
   │
   └─ [LEAF] Potential Escalation to Destructive Attack
             • Method: ' OR 1=1; DROP TABLE users--
             • Impact: Complete data destruction
             • Motive: Vandalism after extraction complete
             • Feasibility: MEDIUM (depends on DB permissions)
             • Complexity: LOW
             • Cost: FREE
             • Detection Risk: IMMEDIATE
```

### Attack Path Summary

| Attack Component | Feasibility | Complexity | Cost | Detection Risk | Impact |
|------------------|-------------|------------|------|----------------|--------|
| Identify SQL Injection | HIGH | LOW-MEDIUM | FREE | MEDIUM | N/A |
| Extract Schema | HIGH | MEDIUM | FREE | MEDIUM | N/A |
| Dump Database | HIGH | MEDIUM | FREE | MEDIUM-HIGH | CRITICAL |
| Crack Passwords | HIGH | MEDIUM | MEDIUM | NONE | CRITICAL |

### Key Vulnerabilities Exploited

1. **SQL Injection** - Lack of parameterized queries across application
2. **Verbose Error Messages** - Database schema leaked via errors
3. **Weak Password Hashing** (models.py:30) - SHA256 instead of bcrypt
4. **No Salting** - Rainbow tables and GPU cracking highly effective
5. **No Input Validation** - User input reaches SQL queries unsanitized
6. **Missing Database Activity Monitoring** - Extraction goes undetected

---

## Summary: Attack Tree Risk Analysis

### Highest Risk Attack Paths (Likelihood × Impact)

| Attack Tree | Root Goal | Feasibility | Complexity | Impact | Priority |
|-------------|-----------|-------------|------------|--------|----------|
| Tree 2 | Handicap Inflation (Score Manipulation) | HIGH | LOW | HIGH | CRITICAL |
| Tree 3 | Mass Data Extraction (IDOR) | HIGH | LOW | HIGH | CRITICAL |
| Tree 1 | Admin Account Compromise | MEDIUM-HIGH | LOW-MEDIUM | CRITICAL | HIGH |
| Tree 7 | SQL Injection Database Dump | MEDIUM | MEDIUM | CRITICAL | HIGH |
| Tree 4 | Insider Fraud Operation | MEDIUM | LOW | CRITICAL | HIGH |
| Tree 5 | Website Defacement/DoS | MEDIUM | LOW | HIGH | MEDIUM |
| Tree 6 | Competitive Intelligence (IDOR) | HIGH | LOW | MEDIUM | MEDIUM |

### Common Critical Leaf Nodes Across Trees

**Highest Impact Leaf Nodes (appear in multiple trees):**

1. **Exploit Missing Rate Limiting** (Trees 1, 3, 5)
   - Feasibility: HIGH | Complexity: LOW | Cost: FREE
   - Impact: Enables brute force, DoS, mass data harvesting

2. **IDOR at /api/handicap/<user_id>** (Trees 3, 6)
   - Feasibility: HIGH | Complexity: LOW | Cost: FREE
   - Impact: Complete privacy violation, competitive intelligence

3. **Direct Score Manipulation via HTTP Interception** (Tree 2)
   - Feasibility: HIGH | Complexity: LOW | Cost: FREE
   - Impact: Undermines entire handicap system integrity

4. **Username Enumeration via Error Messages** (Trees 1, 3, 7)
   - Feasibility: HIGH | Complexity: LOW | Cost: FREE
   - Impact: Enables targeted brute force and credential stuffing

5. **SQL Injection Exploitation** (Trees 1, 5, 7)
   - Feasibility: MEDIUM | Complexity: MEDIUM | Cost: FREE
   - Impact: Complete database compromise

6. **SHA256 Password Hash Cracking** (Trees 1, 3, 7)
   - Feasibility: HIGH | Complexity: MEDIUM | Cost: MEDIUM (GPU)
   - Impact: Credential theft, account takeover

7. **Modifiable Audit Logs** (Trees 1, 4)
   - Feasibility: HIGH | Complexity: LOW | Cost: FREE
   - Impact: Attackers cover tracks, forensics impossible

### Defense Priority Matrix

Based on leaf node analysis, the highest priority defenses are:

| Vulnerability | Affected Trees | Fix Complexity | Impact Reduction | Priority |
|---------------|----------------|----------------|------------------|----------|
| No HMAC/signatures on scores | Tree 2 | MEDIUM | CRITICAL | 1 |
| IDOR at /api/handicap | Trees 3, 6 | LOW | HIGH | 2 |
| Weak password hashing (SHA256) | Trees 1, 3, 7 | MEDIUM | HIGH | 3 |
| No rate limiting | Trees 1, 3, 5 | MEDIUM | HIGH | 4 |
| SQL injection vulnerabilities | Trees 1, 5, 7 | MEDIUM | CRITICAL | 5 |
| Username enumeration | Trees 1, 3, 7 | LOW | MEDIUM | 6 |
| Session fixation | Tree 1 | LOW | MEDIUM | 7 |
| Modifiable audit logs | Trees 1, 4 | MEDIUM | MEDIUM | 8 |

### Assignment Alignment

**Assignment 3 (Cryptographic APIs):**
- Implement bcrypt for password hashing (mitigates Trees 1, 3, 7)
- Add HMAC signatures to scores (mitigates Tree 2 - CRITICAL)
- Encrypt sensitive PII data (mitigates Trees 3, 7)

**Assignment 4 (DAST & Vulnerability Fixes):**
- Fix IDOR vulnerabilities with proper authorization (mitigates Trees 3, 6)
- Implement rate limiting (mitigates Trees 1, 3, 5)
- Add CSRF tokens (mitigates Trees 2, 4, 5)
- Fix SQL injection with parameterized queries (mitigates Trees 1, 5, 7)
- Regenerate session IDs on login (mitigates Tree 1)
- Implement security headers and monitoring (mitigates all trees)

---

## Conclusion

These seven attack trees demonstrate the multiple paths adversaries can exploit to compromise the Golf Score Tracker & Handicap System. The analysis reveals:

1. **Ease of Attack:** Most high-impact attacks require LOW complexity and FREE cost, making them accessible to Script Kiddies and Competitive Golfers alike.

2. **Critical Vulnerabilities:** The lack of cryptographic score verification (Tree 2), IDOR vulnerabilities (Trees 3, 6), and weak password hashing (Trees 1, 3, 7) represent the most critical weaknesses.

3. **Cascading Impact:** Administrative compromise (Tree 1) enables all other attacks, making it a high-priority target for attackers and defenders.

4. **Detection Gaps:** The absence of rate limiting, audit logging, and anomaly detection means attacks succeed undetected until significant damage occurs.

5. **Insider Threats:** Malicious administrators (Tree 4) represent CRITICAL impact scenarios that are difficult to detect and prevent without segregation of duties and multi-party approval.

The leaf nodes in these attack trees are specific, measurable, and directly tied to code vulnerabilities, enabling quantitative risk assessment and prioritized remediation planning for Assignments 3 and 4.

---

**Document Prepared By:** Claude Code (AI Assistant)
**Review Status:** Draft for Assignment 2, Question 3
**Next Steps:** Use attack trees to inform STRIDE analysis, prioritize remediation roadmap
