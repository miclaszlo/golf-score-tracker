"""
Golf Score Tracker & Handicap System - Main Flask Application
CSE763 Secure Software Development Project

This application has intentional security gaps for educational purposes.
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf.csrf import CSRFProtect
from models import db, User, Course, Hole, Round, Score, AuditLog
from auth import login_required, admin_required, get_current_user, log_action, validate_password_strength, validate_score
from handicap import calculate_handicap_index, get_user_statistics, get_leaderboard
from config import config
from datetime import datetime
import os


def safe_int(value, field_name="value"):
    """
    Safely convert a form input to an integer.

    Args:
        value: The value to convert (typically from request.form.get())
        field_name: Human-readable name for error messages

    Returns:
        tuple: (int_value, error_message) - error_message is None if successful
    """
    if value is None or value == '':
        return None, f"Please provide a valid {field_name}."
    try:
        return int(value), None
    except (ValueError, TypeError):
        return None, f"Invalid {field_name}: '{value}' is not a valid number."


app = Flask(__name__)
app.config.from_object(config)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize database
db.init_app(app)

# Create instance folder if it doesn't exist
os.makedirs('instance', exist_ok=True)


@app.before_request
def create_tables():
    """Create database tables before first request"""
    db.create_all()


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Content-Security-Policy: Allow self and Bootstrap CDN
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "frame-ancestors 'none'"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Server'] = 'Golf-Tracker'
    return response


@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # SECURITY GAP: Insufficient input validation
        if not username or not email or not password or not full_name:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        is_valid, message = validate_password_strength(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('register'))

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        # Create new user
        new_user = User(username=username, email=email, full_name=full_name, role='golfer')
        new_user.set_password(password)

        db.session.add(new_user)
        try:
            db.session.commit()
            log_action('USER_REGISTERED', resource=f'user:{username}')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration.', 'danger')
            print(f"Registration error: {e}")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # SECURITY GAP: No rate limiting, vulnerable to brute force
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_active:
            # SECURITY GAP: Session fixation vulnerability
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session.permanent = True

            log_action('USER_LOGIN', resource=f'user:{username}')
            flash(f'Welcome back, {user.full_name or user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # SECURITY GAP: Information disclosure
            log_action('FAILED_LOGIN', resource=f'user:{username}', details='Invalid credentials')
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    username = session.get('username', 'Unknown')
    log_action('USER_LOGOUT', resource=f'user:{username}')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = get_current_user()
    stats = get_user_statistics(user.id)

    # Get recent rounds
    recent_rounds = Round.query.filter_by(user_id=user.id)\
        .order_by(Round.date_played.desc())\
        .limit(5)\
        .all()

    return render_template('dashboard.html', user=user, stats=stats, recent_rounds=recent_rounds)


@app.route('/courses')
@login_required
def courses():
    """View all golf courses"""
    all_courses = Course.query.all()
    return render_template('courses.html', courses=all_courses)


@app.route('/courses/add', methods=['GET', 'POST'])
@admin_required
def add_course():
    """Add a new golf course (admin only)"""
    if request.method == 'POST':
        name = request.form.get('name')
        location = request.form.get('location')
        num_holes = int(request.form.get('num_holes', 18))
        course_rating = float(request.form.get('course_rating'))
        slope_rating = int(request.form.get('slope_rating'))
        par = int(request.form.get('par'))

        # SECURITY GAP: Insufficient input validation

        new_course = Course(
            name=name,
            location=location,
            num_holes=num_holes,
            course_rating=course_rating,
            slope_rating=slope_rating,
            par=par,
            created_by=session['user_id']
        )

        db.session.add(new_course)
        try:
            db.session.commit()

            # Add holes for the course
            for i in range(1, num_holes + 1):
                hole_par_key = f'hole_{i}_par'
                hole_handicap_key = f'hole_{i}_handicap'
                hole_yardage_key = f'hole_{i}_yardage'

                hole_par = int(request.form.get(hole_par_key, 4))
                hole_handicap = int(request.form.get(hole_handicap_key, i))
                hole_yardage = int(request.form.get(hole_yardage_key, 400))

                hole = Hole(
                    course_id=new_course.id,
                    hole_number=i,
                    par=hole_par,
                    handicap=hole_handicap,
                    yardage=hole_yardage
                )
                db.session.add(hole)

            db.session.commit()
            log_action('COURSE_CREATED', resource=f'course:{new_course.id}')
            flash(f'Course "{name}" added successfully!', 'success')
            return redirect(url_for('courses'))

        except Exception as e:
            db.session.rollback()
            flash('Error adding course.', 'danger')
            print(f"Error adding course: {e}")

    return render_template('add_course.html')


@app.route('/round/new', methods=['GET', 'POST'])
@login_required
def new_round():
    """Enter a new round of golf"""
    if request.method == 'GET':
        courses = Course.query.all()
        # Convert courses and holes to dictionaries for JSON serialization
        courses_data = []
        for course in courses:
            course_dict = {
                'id': course.id,
                'name': course.name,
                'par': course.par,
                'holes': [
                    {
                        'id': hole.id,
                        'hole_number': hole.hole_number,
                        'par': hole.par,
                        'handicap': hole.handicap,
                        'yardage': hole.yardage
                    }
                    for hole in sorted(course.holes, key=lambda h: h.hole_number)
                ]
            }
            courses_data.append(course_dict)
        return render_template('round_entry.html', courses=courses_data)

    # POST: Process the round entry
    user = get_current_user()
    course_id, error = safe_int(request.form.get('course_id'), 'course')
    if error:
        flash(error, 'danger')
        return redirect(url_for('new_round'))
    date_played_str = request.form.get('date_played')
    notes = request.form.get('notes', '')

    # SECURITY GAP: Date manipulation possible

    try:
        date_played = datetime.strptime(date_played_str, '%Y-%m-%d').date()
    except:
        date_played = datetime.utcnow().date()

    course = Course.query.get(course_id)
    if not course:
        flash('Invalid course selected.', 'danger')
        return redirect(url_for('new_round'))

    # Calculate total score from hole scores
    total_score = 0
    hole_scores = []

    for hole in course.holes:
        score_key = f'hole_{hole.hole_number}_score'
        strokes_raw = request.form.get(score_key)

        strokes, error = safe_int(strokes_raw, f'score for hole {hole.hole_number}')
        if error:
            flash(error, 'danger')
            return redirect(url_for('new_round'))

        # SECURITY GAP: Weak validation
        is_valid, message = validate_score(strokes, hole.par)
        if not is_valid:
            flash(f'Hole {hole.hole_number}: {message}', 'danger')
            return redirect(url_for('new_round'))

        total_score += strokes
        hole_scores.append((hole.id, strokes))

    # SECURITY GAP: Total score not verified (could be manually manipulated)
    # Create round
    new_round_entry = Round(
        user_id=user.id,
        course_id=course_id,
        date_played=date_played,
        total_score=total_score,
        notes=notes
    )

    # Calculate differential
    new_round_entry.calculate_differential()

    db.session.add(new_round_entry)
    db.session.commit()

    # Add individual hole scores
    for hole_id, strokes in hole_scores:
        score_entry = Score(
            round_id=new_round_entry.id,
            hole_id=hole_id,
            strokes=strokes
        )
        db.session.add(score_entry)

    try:
        db.session.commit()
        log_action('ROUND_SUBMITTED', resource=f'round:{new_round_entry.id}',
                  details=f'Course: {course.name}, Score: {total_score}')
        flash(f'Round submitted! Total score: {total_score}', 'success')
        return redirect(url_for('scores'))
    except Exception as e:
        db.session.rollback()
        flash('Error submitting round.', 'danger')
        print(f"Error submitting round: {e}")
        return redirect(url_for('new_round'))


@app.route('/scores')
@login_required
def scores():
    """View user's score history"""
    user = get_current_user()

    # SECURITY GAP: Potential IDOR if user_id taken from query param
    user_rounds = Round.query.filter_by(user_id=user.id)\
        .order_by(Round.date_played.desc())\
        .all()

    return render_template('scores.html', rounds=user_rounds)


@app.route('/leaderboard')
@login_required
def leaderboard():
    """View leaderboard"""
    # SECURITY GAP: Anyone logged in can see all user scores
    course_id = request.args.get('course_id')

    if course_id:
        course = Course.query.get(int(course_id))
        leaderboard_data = get_leaderboard(course_id=int(course_id), limit=20)
        title = f"Leaderboard - {course.name}"
    else:
        leaderboard_data = get_leaderboard(limit=20)
        course = None
        title = "Overall Handicap Leaderboard"

    courses_list = Course.query.all()

    return render_template('leaderboard.html',
                         leaderboard=leaderboard_data,
                         courses=courses_list,
                         selected_course=course,
                         title=title)


@app.route('/admin')
@admin_required
def admin_panel():
    """Admin panel"""
    users = User.query.all()
    courses_list = Course.query.all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()

    # Statistics
    total_users = User.query.count()
    total_courses = Course.query.count()
    total_rounds = Round.query.count()
    active_users = User.query.filter_by(is_active=True).count()

    stats = {
        'total_users': total_users,
        'total_courses': total_courses,
        'total_rounds': total_rounds,
        'active_users': active_users
    }

    return render_template('admin.html', users=users, courses=courses_list,
                         logs=recent_logs, stats=stats)


@app.route('/api/handicap/<int:user_id>', methods=['GET'])
@login_required
def api_get_handicap(user_id):
    """API endpoint to get user handicap"""
    # SECURITY GAP: No rate limiting
    current_user = get_current_user()

    # Authorization check: users can only view their own handicap unless admin
    if current_user.id != user_id and not current_user.is_admin():
        log_action('UNAUTHORIZED_HANDICAP_ACCESS',
                   resource=f'user:{user_id}',
                   details=f'User {current_user.id} attempted to access handicap of user {user_id}')
        return jsonify({'error': 'Unauthorized access'}), 403

    handicap = calculate_handicap_index(user_id)
    stats = get_user_statistics(user_id)

    return jsonify({
        'user_id': user_id,
        'handicap_index': handicap,
        'statistics': stats
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('500.html'), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

    print(f"Starting Golf Score Tracker on {config.HOST}:{config.PORT}")
    print("SECURITY WARNING: This application has intentional security gaps for educational purposes.")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
