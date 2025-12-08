"""
Database initialization script for Golf Score Tracker
Creates tables and populates with demo data
"""
from app import app
from models import db, User, Course, Hole, Round, Score
from datetime import datetime, timedelta
import random

def init_database():
    """Initialize database with tables and demo data"""
    with app.app_context():
        print("Creating database tables...")
        db.create_all()

        # Check if data already exists
        if User.query.filter_by(username='admin').first():
            print("Demo data already exists. Skipping initialization.")
            return

        print("Creating demo users...")

        # Create admin user
        admin = User(
            username='admin',
            email='admin@golfclub.com',
            full_name='Admin User',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)

        # Create regular golfers
        golfer1 = User(
            username='golfer',
            email='golfer@example.com',
            full_name='John Smith',
            role='golfer'
        )
        golfer1.set_password('golfer123')
        db.session.add(golfer1)

        golfer2 = User(
            username='jane_doe',
            email='jane@example.com',
            full_name='Jane Doe',
            role='golfer'
        )
        golfer2.set_password('jane123')
        db.session.add(golfer2)

        golfer3 = User(
            username='mike_golf',
            email='mike@example.com',
            full_name='Mike Johnson',
            role='golfer'
        )
        golfer3.set_password('mike123')
        db.session.add(golfer3)

        db.session.commit()

        print("Creating demo golf courses...")

        # Create Pebble Beach Golf Course
        pebble_beach = Course(
            name='Pebble Beach Golf Links',
            location='Pebble Beach, CA',
            num_holes=18,
            course_rating=74.5,
            slope_rating=145,
            par=72,
            created_by=admin.id
        )
        db.session.add(pebble_beach)
        db.session.commit()

        # Add holes for Pebble Beach
        pebble_holes = [
            (1, 4, 1, 381), (2, 5, 11, 507), (3, 4, 7, 388), (4, 4, 13, 327),
            (5, 3, 17, 188), (6, 5, 3, 516), (7, 3, 15, 106), (8, 4, 5, 431),
            (9, 4, 9, 464), (10, 4, 4, 495), (11, 4, 16, 380), (12, 3, 18, 202),
            (13, 4, 10, 404), (14, 5, 2, 573), (15, 4, 12, 397), (16, 4, 8, 402),
            (17, 3, 14, 188), (18, 5, 6, 543)
        ]

        for hole_num, par, handicap, yardage in pebble_holes:
            hole = Hole(
                course_id=pebble_beach.id,
                hole_number=hole_num,
                par=par,
                handicap=handicap,
                yardage=yardage
            )
            db.session.add(hole)

        # Create Augusta National
        augusta = Course(
            name='Augusta National Golf Club',
            location='Augusta, GA',
            num_holes=18,
            course_rating=76.2,
            slope_rating=148,
            par=72,
            created_by=admin.id
        )
        db.session.add(augusta)
        db.session.commit()

        # Add holes for Augusta
        augusta_holes = [
            (1, 4, 11, 445), (2, 5, 7, 575), (3, 4, 15, 350), (4, 3, 9, 240),
            (5, 4, 1, 495), (6, 3, 17, 180), (7, 4, 13, 450), (8, 5, 3, 570),
            (9, 4, 5, 460), (10, 4, 2, 495), (11, 4, 8, 505), (12, 3, 16, 155),
            (13, 5, 4, 510), (14, 4, 12, 440), (15, 5, 6, 530), (16, 3, 14, 170),
            (17, 4, 10, 440), (18, 4, 18, 465)
        ]

        for hole_num, par, handicap, yardage in augusta_holes:
            hole = Hole(
                course_id=augusta.id,
                hole_number=hole_num,
                par=par,
                handicap=handicap,
                yardage=yardage
            )
            db.session.add(hole)

        # Create local municipal course
        muni_course = Course(
            name='Riverside Municipal Golf Course',
            location='Springfield, IL',
            num_holes=18,
            course_rating=70.8,
            slope_rating=125,
            par=71,
            created_by=admin.id
        )
        db.session.add(muni_course)
        db.session.commit()

        # Add holes for Municipal course (simpler layout)
        for i in range(1, 19):
            if i in [3, 7, 12, 15, 17]:  # Par 3s
                par = 3
                yardage = random.randint(150, 220)  # nosec B311 - test data generation
            elif i in [2, 9, 14]:  # Par 5s
                par = 5
                yardage = random.randint(480, 550)  # nosec B311 - test data generation
            else:  # Par 4s
                par = 4
                yardage = random.randint(340, 430)  # nosec B311 - test data generation

            hole = Hole(
                course_id=muni_course.id,
                hole_number=i,
                par=par,
                handicap=i,
                yardage=yardage
            )
            db.session.add(hole)

        db.session.commit()

        print("Creating demo rounds...")

        # Create rounds for golfers
        courses = [pebble_beach, augusta, muni_course]
        golfers = [golfer1, golfer2, golfer3]

        for golfer in golfers:
            # Create 8-12 rounds for each golfer
            num_rounds = random.randint(8, 12)  # nosec B311 - test data generation

            for i in range(num_rounds):
                course = random.choice(courses)  # nosec B311 - test data generation
                days_ago = random.randint(1, 180)  # nosec B311 - test data generation
                date_played = (datetime.utcnow() - timedelta(days=days_ago)).date()

                # Generate realistic scores
                total_score = 0
                round_entry = Round(
                    user_id=golfer.id,
                    course_id=course.id,
                    date_played=date_played,
                    total_score=0,  # Will calculate
                    notes=f"Round at {course.name}"
                )
                db.session.add(round_entry)
                db.session.commit()

                # Add hole scores
                for hole in course.holes:
                    # Generate score relative to par (more realistic distribution)
                    rand = random.random()  # nosec B311 - test data generation
                    if rand < 0.05:  # 5% eagle
                        strokes = hole.par - 2
                    elif rand < 0.20:  # 15% birdie
                        strokes = hole.par - 1
                    elif rand < 0.50:  # 30% par
                        strokes = hole.par
                    elif rand < 0.80:  # 30% bogey
                        strokes = hole.par + 1
                    elif rand < 0.95:  # 15% double bogey
                        strokes = hole.par + 2
                    else:  # 5% triple+
                        strokes = hole.par + 3

                    total_score += strokes

                    score_entry = Score(
                        round_id=round_entry.id,
                        hole_id=hole.id,
                        strokes=strokes
                    )
                    db.session.add(score_entry)

                # Update total score and calculate differential
                round_entry.total_score = total_score
                round_entry.calculate_differential()

        db.session.commit()

        print("Database initialization completed successfully!")
        print("\nDemo accounts created:")
        print("  Admin - username: admin, password: admin123")
        print("  Golfer - username: golfer, password: golfer123")
        print("  Golfer - username: jane_doe, password: jane123")
        print("  Golfer - username: mike_golf, password: mike123")
        print(f"\nTotal users: {User.query.count()}")
        print(f"Total courses: {Course.query.count()}")
        print(f"Total rounds: {Round.query.count()}")

if __name__ == '__main__':
    init_database()
