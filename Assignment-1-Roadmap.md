# Assignment 1 Roadmap: Project Proposal and DevSecOps Pipeline Setup

## Overview
This roadmap outlines the tasks required to complete Project Assignment 1 for CS763 Secure Software Development.

---

## Deliverables Checklist

### 1. GitHub Repository
- [x] Create GitHub repository
- [x] Push initial codebase to main branch
- [x] Create `assignment1` branch for assignment work

### 2. Report Sections

#### Section 1: Overview
- [x] **Write project overview**
  - [x] Describe the Golf Score Tracker application
  - [x] Explain why this project meets the criteria:
    - [x] Authentication/authorization required ✓
    - [x] Permanent data storage with security requirements ✓
    - [x] Security is not perfect (identify gaps) ✓
    - [x] Manageable complexity ✓
  - [x] State origin of project (self-developed)
  - [x] Justify project choice

#### Section 2: Current Implementation Stack and Code Structure
- [x] **Document technology stack**
  - [x] Backend: Python/Flask
  - [x] Database: SQLite with SQLAlchemy
  - [x] Frontend: HTML/CSS/JavaScript (Jinja2 templates)
  - [x] Deployment: Docker/Docker Compose

- [x] **Explain code structure**
  - [x] `app.py` - Main Flask application and routes
  - [x] `auth.py` - Authentication logic
  - [x] `models.py` - Database models (User, Round)
  - [x] `handicap.py` - Golf handicap calculation logic
  - [x] `config.py` - Application configuration
  - [x] `init_db.py` - Database initialization
  - [x] `templates/` - HTML templates
  - [x] `static/` - CSS/JavaScript assets
  - [x] `Dockerfile` & `docker-compose.yml` - Containerization

#### Section 3: Build Process
- [x] **Document build steps**
  - [x] Prerequisites (Docker, Docker Compose)
  - [x] Clone repository command
  - [x] Docker build command
  - [x] Docker run/compose up command
  - [x] Access URL (localhost:5001)

- [x] **Verify Docker setup**
  - [x] Test Docker build locally
  - [x] Test Docker run locally
  - [x] Verify application starts successfully

- [x] **Capture screenshots**
  - [x] Docker build process
  - [x] Docker containers running (`docker ps`)
  - [x] Application running in browser

#### Section 4: Existing Functionalities
- [x] **Document each functionality** ✓ COMPLETE
  - [x] User Registration
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of registration form
  - [x] User Login
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of login form
  - [x] User Logout
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot showing logout functionality
  - [x] Dashboard
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of dashboard
  - [x] View Golf Courses
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of courses list
  - [x] Add Golf Course (Admin Only)
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of add course form
  - [x] Enter Golf Round
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of round entry form
  - [x] View Score History
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of score history
  - [x] View Handicap
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of handicap display
  - [x] Leaderboard
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of leaderboard
  - [x] Admin Panel
    - [x] Description: Comprehensive write-up with implementation details
    - [x] Screenshot of admin panel

#### Section 5: Existing Security Features
- [x] **Authentication and Session Management** ✓ COMPLETE
  - [x] Identify password hashing mechanism (SHA256 - weak, documented)
  - [x] Session management implementation (Flask sessions, documented)
  - [x] Login/logout functionality (documented with security assessment)
  - [x] Session timeout settings (24 hours - documented as gap)

- [x] **Authorization** ✓ COMPLETE
  - [x] User-specific data access controls (RBAC documented)
  - [x] Login required decorators (documented with code snippets)
  - [x] Data ownership verification (documented with IDOR vulnerability)

- [x] **Data Protection and Encryption** ✓ COMPLETE
  - [x] Password storage (SHA256 hashing - documented as weak)
  - [x] Database security (no encryption at rest - documented)
  - [x] Sensitive data handling (no encryption - documented as gap)

- [x] **Compliance** ✓ COMPLETE
  - [x] GDPR/CCPA compliance analysis (non-compliant, documented)
  - [x] Privacy considerations (documented with remediation requirements)

- [x] **Security Gaps/Weaknesses** ✓ COMPLETE (20 vulnerabilities cataloged)
  - [x] Hardcoded secret keys in `config.py` (documented as High severity)
  - [x] Debug mode enabled (documented as Medium severity)
  - [x] Insecure session cookie settings (documented as High severity)
  - [x] Long session timeout (24 hours) (documented as Medium severity)
  - [x] No SQL injection vulnerabilities (ORM protection verified)
  - [x] XSS vulnerabilities (documented as Low severity risk)
  - [x] No CSRF protection (documented as Critical severity)
  - [x] Input validation gaps (documented with examples)
  - [x] Session fixation vulnerability (documented as Critical severity)
  - [x] IDOR vulnerability (documented as Critical severity)
  - [x] Weak password hashing (documented as Critical severity)
  - [x] Score manipulation (documented as Critical severity)
  - [x] No rate limiting (documented as High severity)
  - [x] Audit logging (documented with strengths/weaknesses)
  - [x] Username enumeration (documented as Medium severity)
  - [x] Missing security headers (documented as Medium severity)
  - [x] No encryption at rest (documented as Medium severity)
  - [x] No MFA (documented as Low severity)
  - [x] No account lockout (documented as Low severity)
  - [x] No compliance framework (documented as Low severity)

#### Section 6: Security Tools Research (Minimum 2 Tools)

**Tool 1: Bandit (SAST Tool)** ✓ COMPLETE
- [x] **Research and document**
  - [x] Developer/organization (PyCQA/OpenStack)
  - [x] Open source (Apache License 2.0)
  - [x] Purpose and key features (40+ Python security checks, SAST)
  - [x] Installation steps (pip, source, various formats)
  - [x] Usage instructions (basic, advanced, configuration)
  - [x] How to interpret results (severity/confidence matrix)
  - [x] GitHub workflow integration (full YAML examples, SARIF support)
  - [x] Expected findings for Golf Score Tracker documented

**Tool 2: Safety (Dependency Scanning)** ✓ COMPLETE
- [x] **Research and document**
  - [x] Developer/organization (Safety Cybersecurity/pyup.io)
  - [x] Open source (MIT License, commercial available)
  - [x] Purpose and key features (60k+ vulnerabilities, SafetyDB)
  - [x] Installation steps (pip, pipx, Docker)
  - [x] Usage instructions (basic, advanced, policy files)
  - [x] How to interpret results (CVSS scoring, remediation advice)
  - [x] GitHub workflow integration (full YAML examples, scheduled scans)
  - [x] Expected findings for Golf Score Tracker documented

**Tool 3: Trivy (Container Scanning)** ✓ COMPLETE
- [x] **Research and document**
  - [x] Developer/organization (Aqua Security)
  - [x] Open source (Apache License 2.0)
  - [x] Purpose and key features (200k+ CVEs, multi-target scanning, SBOM)
  - [x] Installation steps (binary, Homebrew, apt, Docker, package managers)
  - [x] Usage instructions (basic, advanced, config files, .trivyignore)
  - [x] How to interpret results (OS/dependencies/secrets/misconfigs)
  - [x] GitHub workflow integration (official action, SARIF upload, artifacts)
  - [x] Expected findings for Golf Score Tracker documented
  - [x] Trivy selected for Section 8 GitHub Actions integration

**Tool Comparison Matrix** ✓ COMPLETE
- [x] Comparison table with features, speed, licensing
- [x] Recommendation and rationale documented
- [x] Implementation priority roadmap defined

#### Section 7: AI Tool Research (Minimum 1 Tool)

**AI Tool: Anthropic Claude** ✓ COMPLETE
- [x] **Research and document**
  - [x] Tool name and provider (Anthropic PBC, Claude 3.5 Sonnet)
  - [x] How it enhances application security (5 key capabilities documented)
  - [x] Example prompts for security analysis (3 detailed prompts with expected outputs)
  - [x] Process for using the tool (4-step methodology documented)
  - [x] Limitations and considerations (misinformation, copyright, security-specific limits)

- [x] **Example use cases**
  - [x] Code review for security vulnerabilities (Section 5 comprehensive assessment)
  - [x] Threat modeling assistance (STRIDE analysis examples)
  - [x] Security test case generation (pytest examples documented)
  - [x] Secure coding suggestions (bcrypt refactoring example)
  - [x] Documentation generation (3,500+ lines of assignment report)

**Additional Documentation** ✓ COMPLETE
- [x] Comparison with other AI tools (Copilot, CodeWhisperer, ChatGPT)
- [x] Best practices for AI-assisted security development
- [x] 4 detailed use cases from this project
- [x] References to official documentation and security frameworks

#### Section 8: GitHub Action Workflow ✓ WORKFLOW CREATED & DOCUMENTED

- [x] **Select tool for integration** (from researched tools)
  - [x] Trivy selected for comprehensive container + dependency + secret scanning
  - [x] Rationale documented with comparison to alternatives (Bandit, Safety, Snyk, Clair)

- [x] **Create workflow file**
  - [x] Created `.github/workflows/` directory
  - [x] Created `trivy-scan.yml` workflow file
  - [x] Configured tool parameters (severity levels, scanners, output formats)
  - [x] Set up triggers (push to main/assignment1, pull_request, schedule, workflow_dispatch)
  - [x] Configured 10-step workflow with SARIF upload, artifacts, and summary generation

- [ ] **Test workflow** (Requires GitHub repository - To be completed by user)
  - [ ] Push workflow to GitHub repository
  - [ ] Trigger workflow execution (manual or via push)
  - [ ] Review workflow results in Actions tab
  - [ ] Capture screenshots of:
    - [ ] Screenshot 15: Workflow file in GitHub (.github/workflows/trivy-scan.yml)
    - [ ] Screenshot 16: Workflow running in Actions tab
    - [ ] Screenshot 17: Workflow results/completion status
    - [ ] Screenshot 18: Security findings in Security tab (optional)

- [x] **Document findings** (Expected findings documented)
  - [x] List expected security issues by category (base image, dependencies, misconfigs, secrets)
  - [x] Explain severity levels (CRITICAL, HIGH, MEDIUM, LOW)
  - [x] Document expected false positives with justification
  - [x] Provide remediation guidance for each finding type
  - [x] Create vulnerability count estimate table (41-59 expected findings)

**Additional Documentation Completed:**
- [x] Comprehensive workflow configuration explanation (all 10 steps documented)
- [x] Trigger events and rationale explained
- [x] Prerequisites for testing documented
- [x] Screenshot capture instructions with detailed steps
- [x] Result interpretation guide (accessing SARIF, JSON, logs)
- [x] Result analysis workflow (categorize, prioritize, document)
- [x] Continuous improvement roadmap (Phase 1, 2, long-term)
- [x] .trivyignore example for false positive suppression
- [x] 8 comprehensive references

#### Section 9: References ✓ COMPLETE
- [x] **Compile all references** ✓ COMPLETE (77 references across 9 categories)
  - [x] Tool documentation URLs (29 references)
  - [x] GitHub workflow marketplace links (6 references)
  - [x] Security best practices articles (26 references)
  - [x] Python/Flask security resources (12 references)
  - [x] Development tools and frameworks (12 references)
  - [x] Security standards and databases (7 references)
  - [x] AI tools documentation (7 references)
  - [x] Course and academic resources (4 references)
  - [x] Additional community resources (9 references)

#### Section 10: AI Usage Section (Required) ✓ COMPLETE
- [x] **Document AI tool usage** ✓ COMPLETE (~850 lines comprehensive documentation)
  - [x] Which AI tools were used (Claude 3.5 Sonnet via Claude Code CLI)
  - [x] What tasks they helped with (8 major categories documented):
    - [x] Initial project code generation (~800 lines Python code)
    - [x] Security vulnerability analysis (20 vulnerabilities identified)
    - [x] Security tools research (Bandit, Safety, Trivy - 1,300 lines)
    - [x] AI tool research (Claude documentation - 250 lines)
    - [x] GitHub Actions workflow (Trivy integration - 800 lines)
    - [x] Assignment report documentation (Sections 1-4, 9)
    - [x] Troubleshooting and debugging (3 major issues resolved)
    - [x] Code review and quality assurance
  - [x] How suggestions were verified/modified:
    - [x] 5 verification methodologies documented
    - [x] 10 modification examples with rationales
    - [x] Functional testing results included
    - [x] Security analysis verification documented
  - [x] Include chat log links or appendix:
    - [x] Session overview (2 sessions, ~10 hours, 60+ interactions)
    - [x] 6 key conversation topics documented
    - [x] Example prompt/response structures provided
    - [x] Chat log excerpts included
  - [x] Additional documentation:
    - [x] 5 limitations and challenges of AI usage
    - [x] Best practices learned (5 key practices)
    - [x] Academic integrity statement with percentage breakdowns
    - [x] Learning outcomes reflection

---

## Recommended Task Sequence

### Phase 1: Setup and Understanding (Week 1, Days 1-2)
1. Verify Docker setup works
2. Run application locally and test all features
3. Document code structure and implementation stack
4. Capture screenshots of all functionalities

### Phase 2: Security Analysis (Week 1, Days 3-4)
1. Analyze existing security features
2. Identify security gaps and weaknesses
3. Map authentication, authorization, and data protection mechanisms
4. Document findings

### Phase 3: Tool Research (Week 1, Days 5-6)
1. Research SAST tools (compare 2-3 options)
2. Research dependency/container scanning tools
3. Research AI security tools
4. Select tools for integration
5. Test tools locally before GitHub integration

### Phase 4: GitHub Workflow Integration (Week 2, Days 1-2)
1. Create GitHub workflow YAML file
2. Configure selected security tool
3. Test workflow execution
4. Review and document results
5. Capture screenshots

### Phase 5: Report Writing (Week 2, Days 3-4)
1. Compile all documentation
2. Write report sections in order
3. Insert screenshots
4. Review for completeness
5. Proofread and edit

### Phase 6: Final Review (Week 2, Day 5)
1. Verify all deliverables are complete
2. Check GitHub repository is properly organized
3. Ensure report has all required sections
4. Submit assignment

---

## Recommended Security Tools

### SAST Tools (Pick 1)
- **Bandit** - Python-specific, easy to integrate, free
- **Semgrep** - Multi-language, powerful rules, free tier
- **SonarQube** - Comprehensive, requires more setup

### Dependency Scanning (Pick 1)
- **Safety** - Python-specific, simple to use, free
- **Snyk** - Multi-language, good GitHub integration, free tier
- **OWASP Dependency-Check** - Comprehensive, free

### Container Scanning (Optional)
- **Trivy** - Easy to use, comprehensive, free
- **Clair** - More complex, free

### AI Tools (Pick 1)
- **GitHub Copilot** - IDE integration, security suggestions
- **ChatGPT/Claude** - Security code review, threat modeling
- **Amazon CodeWhisperer** - Free, security scanning built-in

---

## Tips for Success

1. **Start Early**: Don't underestimate screenshot capture time
2. **Test Everything**: Verify all functionalities work before documenting
3. **Organize Screenshots**: Name them descriptively (e.g., `01-login-screen.png`)
4. **Keep Notes**: Document issues encountered during setup
5. **Read Tool Docs**: Understanding tools deeply helps with integration
6. **Check GitHub Actions Marketplace**: Pre-built workflows can save time
7. **Version Control**: Commit frequently with clear messages
8. **Backup Work**: Keep report drafts in multiple locations

---

## Report Structure Template

```markdown
# CS763 Project Assignment 1: Golf Score Tracker

## 1. Overview
[Project description and justification]

## 2. Current Implementation Stack and Code Structure
[Technology stack and code organization]

## 3. Build Process
[Docker setup and build steps with screenshots]

## 4. Existing Functionalities
[Feature list with descriptions and screenshots]

## 5. Existing Security Features
[Security analysis by category]

## 6. Security Tools
### 6.1 Tool 1: [Name]
### 6.2 Tool 2: [Name]
### 6.3 Tool 3: [Name] (if applicable)

## 7. AI Tool for Security Enhancement
[AI tool description and usage]

## 8. GitHub Action Workflow
[Workflow setup and results with screenshots]

## 9. References
[All sources]

## 10. AI Usage
[Required section documenting AI assistance]
```

---

## Questions to Answer During Analysis

1. Is password hashing implemented? Which algorithm?
2. Are sessions secure? HttpOnly? Secure flag? CSRF protection?
3. Is input validation performed? Which endpoints?
4. Are there SQL injection vulnerabilities?
5. Are there XSS vulnerabilities?
6. Is there proper error handling that doesn't leak information?
7. Are secrets stored securely or hardcoded?
8. Is HTTPS enforced? (Development vs. production)
9. Are there rate limiting protections?
10. Is there logging for security events?

---

## Expected Findings (Preliminary)

Based on code review of `config.py`, expect to find:
- Hardcoded secret key in development mode
- Debug mode enabled
- Session cookie not secure (no HTTPS)
- Long session timeout (24 hours)
- Need to verify: password hashing, input validation, SQL injection protection

These will form the basis for identifying security improvements in later assignments.
