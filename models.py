"""
Database models for Golf Score Tracker Application
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib

db = SQLAlchemy()

class User(db.Model):
    """User model for golfers and admins"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # SECURITY GAP: Using simple SHA256 instead of bcrypt
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(150))
    role = db.Column(db.String(20), default='golfer')  # 'golfer' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    rounds = db.relationship('Round', backref='golfer', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """Hash password using SHA256 (SECURITY GAP: weak hashing)"""
        # TODO: Replace with bcrypt in Assignment 3
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        """Verify password against hash"""
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'

    def get_handicap_index(self):
        """Calculate handicap index"""
        from handicap import calculate_handicap_index
        return calculate_handicap_index(self.id)

    def __repr__(self):
        return f'<User {self.username}>'


class Course(db.Model):
    """Golf course model"""
    __tablename__ = 'courses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200))
    # SECURITY GAP: No input validation
    num_holes = db.Column(db.Integer, default=18)
    course_rating = db.Column(db.Float, nullable=False)  # e.g., 72.5
    slope_rating = db.Column(db.Integer, nullable=False)  # e.g., 130
    par = db.Column(db.Integer, nullable=False)  # Total par
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    holes = db.relationship('Hole', backref='course', lazy=True, cascade='all, delete-orphan')
    rounds = db.relationship('Round', backref='course', lazy=True)

    def __repr__(self):
        return f'<Course {self.name}>'


class Hole(db.Model):
    """Individual hole on a course"""
    __tablename__ = 'holes'

    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    hole_number = db.Column(db.Integer, nullable=False)  # 1-18
    par = db.Column(db.Integer, nullable=False)  # 3, 4, or 5
    handicap = db.Column(db.Integer)  # Hole handicap (1-18, difficulty ranking)
    yardage = db.Column(db.Integer)

    def __repr__(self):
        return f'<Hole {self.hole_number} on Course {self.course_id}>'


class Round(db.Model):
    """Golf round played by a user"""
    __tablename__ = 'rounds'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    date_played = db.Column(db.Date, nullable=False, default=datetime.utcnow().date)
    # SECURITY GAP: Total score not verified against hole scores (can be manipulated)
    total_score = db.Column(db.Integer, nullable=False)
    differential = db.Column(db.Float)  # Score differential for handicap
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scores = db.relationship('Score', backref='round', lazy=True, cascade='all, delete-orphan')

    def calculate_differential(self):
        """Calculate score differential for handicap"""
        course = Course.query.get(self.course_id)
        if course:
            # Differential = (Score - Course Rating) * 113 / Slope Rating
            self.differential = (self.total_score - course.course_rating) * 113 / course.slope_rating
            return self.differential
        return None

    def verify_total_score(self):
        """Verify total score matches sum of hole scores (SECURITY: currently not enforced)"""
        calculated_total = sum(score.strokes for score in self.scores)
        return calculated_total == self.total_score

    def __repr__(self):
        return f'<Round {self.id} - User {self.user_id} - Score {self.total_score}>'


class Score(db.Model):
    """Score for individual hole in a round"""
    __tablename__ = 'scores'

    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey('rounds.id'), nullable=False)
    hole_id = db.Column(db.Integer, db.ForeignKey('holes.id'), nullable=False)
    # SECURITY GAP: No validation on strokes (could be negative or unrealistic)
    strokes = db.Column(db.Integer, nullable=False)
    putts = db.Column(db.Integer)  # Optional detailed stats
    fairway_hit = db.Column(db.Boolean)  # Optional
    green_in_regulation = db.Column(db.Boolean)  # Optional

    # Relationship to hole
    hole = db.relationship('Hole', backref='scores')

    def __repr__(self):
        return f'<Score Round {self.round_id} Hole {self.hole_id}: {self.strokes}>'


class AuditLog(db.Model):
    """Audit log for tracking important actions"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

    def __repr__(self):
        return f'<AuditLog {self.action} by user {self.user_id}>'
