# Threat Actor Analysis - Golf Score Tracker & Handicap System

**Document Version:** 1.0
**Date:** November 12, 2025
**Assignment:** Assignment 2 - Threat Modeling
**Course:** CSE763 Secure Software Development

---

## AI Usage Log

### Interaction Summary

**Date:** November 12, 2025
**AI Assistant:** Claude Code (Sonnet 4.5)
**Task:** Threat Actor Analysis for Golf Score Tracker Application

**User Request:**
> "Please log our interaction to 'Threat-Actor-Analysis.md' in the ai-usage-logs directory. Identify application threat actors and define possible adversaries."

**AI Response Process:**

1. **Checked existing directory structure** - Verified ai-usage-logs directory exists and reviewed existing documentation patterns
2. **Analyzed application context** - Reviewed CLAUDE.md project documentation to understand:
   - Intentional security vulnerabilities in the application
   - Golf handicap system domain and business logic
   - Known weaknesses (IDOR, weak password hashing, score manipulation, etc.)
   - Assignment progression (threat modeling is Assignment 2)

3. **Developed threat actor taxonomy** - Created 7 distinct adversary profiles based on:
   - Relationship to system (external, insider, competitive)
   - Technical sophistication (script kiddie to APT)
   - Motivations (financial, competitive, curiosity, vandalism)
   - Application-specific threats (handicap manipulation, score tampering)

4. **Created comprehensive profiles** - For each threat actor, documented:
   - Description and background
   - Motivations and goals
   - Technical capabilities and tools
   - Primary attack vectors
   - Potential targets in the application
   - Specific attack scenarios with code references
   - Risk level assessment (likelihood + impact)

5. **Prioritized threats** - Developed risk matrix identifying:
   - TA-02 (Competitive Golfer) as highest priority due to direct threat to core business function
   - TA-01 (Script Kiddie) as most likely to attack
   - TA-03 (Malicious Admin) as highest potential impact

6. **Mapped to remediation** - Connected threat actors to specific vulnerabilities that will be addressed in Assignments 3 and 4

**Key AI Capabilities Utilized:**
- Domain knowledge of common web application threat actors
- Understanding of golf handicap system vulnerabilities
- Mapping generic threats to application-specific attack scenarios
- Risk assessment and prioritization
- Technical documentation writing

**Output Generated:**
- Comprehensive threat actor analysis document (438 lines)
- 7 detailed threat actor profiles
- Risk prioritization matrix
- Actionable recommendations mapped to course assignments

**Validation:**
Document references actual code locations (app.py line numbers, models.py vulnerabilities) and aligns with intentional security gaps documented in CLAUDE.md. Content is appropriate for Assignment 2 threat modeling phase.

---

## Executive Summary

This document identifies and analyzes potential threat actors who may target the Golf Score Tracker & Handicap System. Understanding adversary motivations, capabilities, and attack vectors is critical for implementing effective security controls and prioritizing vulnerability remediation efforts.

The analysis categorizes threat actors by their relationship to the system, technical sophistication, and primary motivations. Each threat actor profile includes attack scenarios specific to the golf handicap tracking domain.

---

## Threat Actor Categories

### 1. External Threat Actors
Adversaries with no legitimate access to the system attempting to compromise it from outside.

### 2. Malicious Insiders
Users with legitimate accounts who abuse their access privileges for personal gain or sabotage.

### 3. Opportunistic Attackers
Low-skill adversaries exploiting publicly known vulnerabilities using automated tools.

### 4. Competitive Adversaries
Individuals motivated by gaining unfair advantages in golf competitions or rankings.

---

## Detailed Threat Actor Profiles

### TA-01: Script Kiddie / Opportunistic Attacker

**Description:**
Low-to-moderate skill attackers using automated tools and publicly available exploits. They scan the internet for vulnerable applications and exploit common weaknesses.

**Motivations:**
- Curiosity and learning
- Bragging rights in hacker communities
- Random vandalism or defacement
- Practice for developing technical skills

**Capabilities:**
- Use of automated vulnerability scanners (Nmap, Nikto, OWASP ZAP)
- Deployment of pre-built exploit scripts
- SQL injection via automated tools (sqlmap)
- Basic credential stuffing attacks
- Limited understanding of underlying vulnerabilities

**Primary Attack Vectors:**
- Automated scanning of `/login` endpoint for weak credentials
- SQL injection attempts on input fields (course search, username)
- Brute force attacks on login (no rate limiting - `app.py:86-116`)
- CSRF token absence exploitation
- Session fixation attacks (session not regenerated - `app.py:102`)

**Potential Targets:**
- Public-facing login page (`/login`)
- User registration endpoint (`/register`)
- Leaderboard and public score displays (`/leaderboard`)
- API endpoints without authentication

**Attack Scenarios:**
1. **Brute Force Login:** Use Hydra or similar tool to brute force admin credentials
2. **Default Credentials:** Attempt login with `admin:admin123` (known test credentials)
3. **Session Fixation:** Force victim to use attacker's session ID, then steal authenticated session
4. **Information Disclosure:** Enumerate valid usernames through login error messages (`app.py:111-113`)

**Risk Level:** MEDIUM
**Likelihood:** HIGH (public web application, known vulnerabilities)
**Impact:** MEDIUM (account compromise, data exposure)

---

### TA-02: Competitive Golfer / Handicap Cheater

**Description:**
Authenticated users (golfers) who manipulate their handicap index to gain unfair advantages in tournaments or betting pools. They have legitimate access but abuse the system for personal gain.

**Motivations:**
- Winning golf tournaments with handicap-based scoring
- Financial gain from tournament prizes or betting
- Reputation and status in golf community
- Sandbagging (artificially inflating handicap for easier competition)

**Capabilities:**
- Legitimate user account access
- Understanding of golf handicap calculation rules
- Basic web application interaction skills
- Ability to intercept/modify HTTP requests (Burp Suite basics)
- Social engineering of course administrators

**Primary Attack Vectors:**
- Score manipulation via proxy tools (total score not verified - `models.py:95-96`, `app.py:264`)
- Selective entry of only good rounds (deleting bad scores if deletion implemented)
- Entering fictitious rounds on easy courses
- Manipulating course ratings/slope to affect handicap calculations
- IDOR exploitation to view/modify other users' data (`/api/handicap/<user_id>`)

**Potential Targets:**
- Round score submission form (`/round/new`)
- Course difficulty ratings (if user-modifiable)
- Handicap calculation logic (`handicap.py`)
- Score history endpoint (`/scores`)
- Other users' handicap data via IDOR

**Attack Scenarios:**
1. **Score Tampering:** Intercept POST request to `/round/new`, modify individual hole scores without changing total
2. **Selective Reporting:** Only enter good rounds to lower handicap, never report bad rounds
3. **IDOR Handicap Viewing:** Access `/api/handicap/5` to view competitor's detailed scoring history
4. **Course Rating Abuse:** If admin access compromised, modify course ratings to make difficult courses appear easier

**Risk Level:** HIGH
**Likelihood:** MEDIUM-HIGH (strong financial/competitive motivations)
**Impact:** HIGH (undermines entire handicap system integrity)

---

### TA-03: Malicious Administrator / Insider Threat

**Description:**
A compromised or malicious user with administrative privileges. This could be a rogue golf course operator, disgruntled employee, or external attacker who gained admin access.

**Motivations:**
- Financial fraud (manipulating tournament outcomes)
- Sabotage and revenge against organization
- Data theft for competitive intelligence
- System disruption or ransomware deployment

**Capabilities:**
- Full administrative access to application
- Database manipulation capabilities
- Ability to create/modify courses and user accounts
- Access to audit logs (can potentially cover tracks)
- Understanding of application internals

**Primary Attack Vectors:**
- Direct database manipulation via admin panel or SQL access
- Creation of backdoor admin accounts
- Manipulation of course difficulty ratings to favor specific players
- Mass data exfiltration of user information
- Audit log tampering to hide malicious actions
- Privilege escalation if not full admin initially

**Potential Targets:**
- User database (`User` model - passwords weakly hashed with SHA256)
- Course configuration and ratings (`Course`, `Hole` models)
- Audit logs (`AuditLog` model - potential deletion/modification)
- Round and score data (`Round`, `Score` models)
- Application configuration (`config.py` - secret keys)

**Attack Scenarios:**
1. **Handicap Manipulation Ring:** Systematically modify handicaps for paying customers
2. **Data Breach:** Export all user credentials (SHA256 hashes easily crackable)
3. **Tournament Rigging:** Adjust course ratings just before tournament to favor specific players
4. **Backdoor Creation:** Add hidden admin account with subtle username variation
5. **Ransomware:** Encrypt database, demand payment for restoration

**Risk Level:** CRITICAL
**Likelihood:** LOW-MEDIUM (requires insider access or account compromise)
**Impact:** CRITICAL (complete system compromise, data breach, integrity loss)

---

### TA-04: Advanced Persistent Threat (APT) / Professional Hacker

**Description:**
Highly skilled, well-resourced attackers targeting the application for financial gain, espionage, or as part of a larger campaign. While less likely for a golf app, possible if system stores high-value data or is part of larger organization.

**Motivations:**
- Financial theft (credit card data if payment processing added)
- Corporate espionage (stealing proprietary handicap algorithms)
- Reconnaissance for broader organizational network access
- Cryptocurrency mining on compromised servers
- Building botnet infrastructure

**Capabilities:**
- Custom exploit development
- Zero-day vulnerability research
- Advanced persistent backdoors
- Sophisticated social engineering
- Multi-stage attack campaigns
- Anti-forensics and evasion techniques

**Primary Attack Vectors:**
- Exploitation of known CVEs in Flask/SQLAlchemy dependencies
- Supply chain attacks via compromised Python packages
- Advanced SQL injection with second-order exploitation
- Server-side template injection (Jinja2 vulnerabilities)
- Container escape (if Docker vulnerabilities exist)
- Network-level attacks (if deployed on vulnerable infrastructure)

**Potential Targets:**
- Application server (Flask instance)
- Database server (SQLite file, future PostgreSQL)
- Docker container environment
- CI/CD pipeline (if implemented)
- Underlying operating system
- Network infrastructure

**Attack Scenarios:**
1. **Dependency Exploitation:** Exploit CVE in Flask 2.3.3 or SQLAlchemy 2.0.20 for RCE
2. **Template Injection:** Inject malicious Jinja2 code if user input reaches template rendering
3. **Container Escape:** Break out of Docker container to access host system
4. **Lateral Movement:** Use golf app as foothold to access other university systems
5. **Persistent Backdoor:** Install webshell for long-term access

**Risk Level:** MEDIUM
**Likelihood:** LOW (unlikely target unless part of larger organization)
**Impact:** CRITICAL (complete infrastructure compromise)

---

### TA-05: Data Harvester / Privacy Violator

**Description:**
Attackers seeking to collect and monetize personal information. They target user databases for email addresses, names, and behavioral data for spam, phishing, or sale on dark web.

**Motivations:**
- Selling personal information on underground markets
- Building phishing/spam target lists
- Identity theft preparation
- Competitive intelligence (golfer performance data)

**Capabilities:**
- Web scraping and automated data collection
- SQL injection for database extraction
- IDOR exploitation for systematic data access
- Basic authentication bypass techniques
- Credential stuffing with leaked password databases

**Primary Attack Vectors:**
- SQL injection to dump user table
- IDOR to iterate through all user IDs (`/api/handicap/<user_id>`)
- Leaderboard scraping for user enumeration
- Credential stuffing to access multiple accounts
- Registration abuse to flood database with fake accounts

**Potential Targets:**
- User credentials table (usernames, password hashes)
- Email addresses (if collected during registration)
- Golfer performance statistics
- Audit logs (user behavioral data)
- Public leaderboards for user enumeration

**Attack Scenarios:**
1. **Mass IDOR Scraping:** Iterate through `/api/handicap/1` to `/api/handicap/10000` to collect all user data
2. **SQL Injection Dump:** Extract entire user table via vulnerable search parameter
3. **Credential Stuffing Campaign:** Use leaked passwords from other breaches to access accounts
4. **Leaderboard Mining:** Scrape all usernames from public leaderboards, cross-reference with other data

**Risk Level:** MEDIUM-HIGH
**Likelihood:** MEDIUM (valuable user data, weak access controls)
**Impact:** MEDIUM (privacy violation, GDPR concerns, reputation damage)

---

### TA-06: Vandal / Hacktivist

**Description:**
Attackers motivated by causing disruption, defacement, or making political/social statements. They may target the application if affiliated with controversial organization or as random target of opportunity.

**Motivations:**
- Disrupting services for chaos or political statement
- Website defacement for visibility
- Protest against golf/sports organizations
- Reputation damage to hosting organization

**Capabilities:**
- Website defacement techniques
- DoS/DDoS attack tools
- Database deletion/corruption
- Social media amplification
- Basic web application exploitation

**Primary Attack Vectors:**
- Admin account compromise for defacement
- SQL injection for database deletion (`DROP TABLE`)
- Application-layer DoS (resource exhaustion)
- CSRF to trick admin into destructive actions
- Session hijacking for unauthorized admin access

**Potential Targets:**
- Homepage and public-facing templates
- User database (mass deletion)
- Course and hole configuration
- Audit logs
- Docker container (if can gain access)

**Attack Scenarios:**
1. **Homepage Defacement:** Compromise admin account, modify `base.html` template with political message
2. **Database Wipe:** SQL injection to `DROP TABLE users; DROP TABLE rounds;`
3. **Application DoS:** Flood `/round/new` with thousands of requests (no rate limiting)
4. **Reputation Attack:** Leak "security is terrible" findings to social media

**Risk Level:** MEDIUM
**Likelihood:** LOW-MEDIUM (depends on organization visibility)
**Impact:** HIGH (service disruption, reputation damage)

---

### TA-07: Curious Insider / Authorized User with Malicious Intent

**Description:**
Legitimate users (golfers) who exceed their authorization boundaries out of curiosity, nosiness, or to gain unfair information about competitors. They don't necessarily want to cheat, but want to "peek" at others' data.

**Motivations:**
- Curiosity about other players' performance
- Competitive intelligence gathering
- Checking if friends/rivals are cheating
- Testing security boundaries
- Learning about system vulnerabilities

**Capabilities:**
- Basic web application usage
- Browser developer tools knowledge
- Understanding of URL parameters
- Ability to modify simple HTTP requests
- Trial-and-error exploration

**Primary Attack Vectors:**
- IDOR manipulation to view other users' scores
- URL tampering to access unauthorized pages
- Session cookie manipulation
- Exploiting verbose error messages
- Social engineering of other users

**Potential Targets:**
- Other users' handicap data (`/api/handicap/<user_id>`)
- Score history of competitors
- Admin panel (if weak authentication)
- Audit logs (if accessible without proper authorization)

**Attack Scenarios:**
1. **Competitor Spying:** Change URL from `/api/handicap/3` (own ID) to `/api/handicap/7` (rival's ID)
2. **Admin Page Probing:** Try accessing `/admin` URL to see if additional checks beyond session role exist
3. **Score History Snooping:** Attempt to modify parameters on `/scores` to view other users' rounds
4. **Username Enumeration:** Use login error messages to confirm which usernames exist

**Risk Level:** MEDIUM
**Likelihood:** MEDIUM-HIGH (low barrier to entry, curious users common)
**Impact:** LOW-MEDIUM (privacy violation, but limited damage)

---

## Cross-Cutting Threat Considerations

### Automated Bots and Scanners
**Threat:** Continuous internet scanning by botnets looking for vulnerable applications.
**Relevance:** Public-facing web app will be discovered and scanned within hours/days of deployment.
**Mitigation Priority:** Medium

### Social Engineering
**Threat:** Attackers tricking users into revealing credentials or performing harmful actions.
**Relevance:** Users may be targeted via phishing emails impersonating the golf system.
**Mitigation Priority:** Low-Medium (user education required)

### Supply Chain Attacks
**Threat:** Compromised Python packages in `requirements.txt` containing malware.
**Relevance:** Dependencies like Flask, SQLAlchemy could be targets for attackers.
**Mitigation Priority:** Medium (dependency scanning needed)

---

## Threat Actor Prioritization Matrix

| Threat Actor | Likelihood | Impact | Risk Level | Mitigation Priority |
|--------------|------------|--------|------------|---------------------|
| TA-01: Script Kiddie | HIGH | MEDIUM | MEDIUM | HIGH |
| TA-02: Competitive Golfer | MEDIUM-HIGH | HIGH | HIGH | CRITICAL |
| TA-03: Malicious Admin | LOW-MEDIUM | CRITICAL | CRITICAL | HIGH |
| TA-04: APT/Professional | LOW | CRITICAL | MEDIUM | MEDIUM |
| TA-05: Data Harvester | MEDIUM | MEDIUM | MEDIUM-HIGH | HIGH |
| TA-06: Vandal/Hacktivist | LOW-MEDIUM | HIGH | MEDIUM | MEDIUM |
| TA-07: Curious Insider | MEDIUM-HIGH | LOW-MEDIUM | MEDIUM | MEDIUM |

---

## Key Findings and Recommendations

### Highest Priority Threat Actors
1. **TA-02 (Competitive Golfer)** - Direct threat to core business function (handicap integrity)
2. **TA-03 (Malicious Admin)** - Highest potential impact, complete system compromise
3. **TA-01 (Script Kiddie)** - Most likely to actually attack due to public exposure

### Critical Vulnerabilities to Address
Based on threat actor analysis, prioritize fixing:

1. **Score Integrity** - Implements HMAC/digital signatures to prevent TA-02 score tampering
2. **IDOR Vulnerabilities** - Fix `/api/handicap/<user_id>` access control to prevent TA-02, TA-05, TA-07
3. **Weak Password Hashing** - Migrate SHA256 to bcrypt to protect against TA-03 credential theft
4. **No Rate Limiting** - Add login throttling to mitigate TA-01 brute force
5. **Session Fixation** - Regenerate session ID on login to prevent TA-01 hijacking

### Defense-in-Depth Strategies
- **Prevention:** Input validation, authentication strengthening, CSRF tokens
- **Detection:** Comprehensive audit logging, anomaly detection for unusual handicap changes
- **Response:** Incident response plan for handicap fraud, data breach procedures
- **Recovery:** Database backups, integrity verification mechanisms

---

## Threat Actor Evolution

### Short-Term (Current State)
- Script kiddies will exploit obvious vulnerabilities (weak passwords, no rate limiting)
- Competitive golfers will discover score manipulation through trial and error

### Medium-Term (6-12 months)
- If application gains popularity, more sophisticated attackers will target it
- Automated attacks will increase as application appears in Shodan/search engines

### Long-Term (1+ years)
- If used for high-stakes tournaments, professional fraud may emerge
- If integrated with payment systems, financial criminals will be attracted

---

## Conclusion

The Golf Score Tracker & Handicap System faces a diverse threat landscape ranging from opportunistic script kiddies to motivated competitive golfers seeking to manipulate their handicaps. The most critical threats stem from:

1. **Integrity Attacks** - TA-02 (Competitive Golfers) undermining handicap system trust
2. **Confidentiality Breaches** - TA-05 (Data Harvesters) exploiting weak access controls
3. **Availability Disruption** - TA-06 (Vandals) causing service outages

Understanding these threat actors enables risk-based prioritization of security controls. Assignment 3 (cryptographic controls) and Assignment 4 (vulnerability remediation) should focus on mitigating TA-02 and TA-01 as the highest likelihood, highest impact threats.

---

**Document Prepared By:** Claude Code (AI Assistant)
**Review Status:** Draft for Assignment 2 Submission
**Next Steps:** Map threat actors to STRIDE threat model, develop attack trees
