"""
Handicap calculation logic
Simplified version of USGA Handicap System
"""
from models import db, Round, User
from config import config

def calculate_handicap_index(user_id):
    """
    Calculate handicap index for a user
    Uses simplified USGA formula:
    - Take best 8 of last 20 rounds
    - Average the differentials
    - Multiply by 0.96

    SECURITY NOTE: This calculation could be manipulated if score data is compromised
    """
    # Get user's most recent rounds with differentials
    recent_rounds = Round.query.filter_by(user_id=user_id)\
        .filter(Round.differential.isnot(None))\
        .order_by(Round.date_played.desc())\
        .limit(config.ROUNDS_TO_CONSIDER)\
        .all()

    if len(recent_rounds) < config.MIN_ROUNDS_FOR_HANDICAP:
        return None  # Not enough rounds

    # Sort by differential (best scores first)
    sorted_rounds = sorted(recent_rounds, key=lambda r: r.differential)

    # Determine how many to use based on total rounds
    num_rounds = len(recent_rounds)
    if num_rounds >= 20:
        num_to_use = config.BEST_SCORES_COUNT
    elif num_rounds >= 15:
        num_to_use = 6
    elif num_rounds >= 10:
        num_to_use = 4
    elif num_rounds >= 8:
        num_to_use = 3
    elif num_rounds >= 6:
        num_to_use = 2
    else:
        num_to_use = 1

    # Get best differentials
    best_differentials = [r.differential for r in sorted_rounds[:num_to_use]]

    # Calculate average
    avg_differential = sum(best_differentials) / len(best_differentials)

    # Multiply by 0.96 to get handicap index
    handicap_index = avg_differential * 0.96

    return round(handicap_index, 1)


def calculate_course_handicap(handicap_index, slope_rating, course_rating, par):
    """
    Calculate course handicap for a specific course
    Formula: Handicap Index * Slope Rating / 113 + (Course Rating - Par)
    """
    if handicap_index is None:
        return None

    course_handicap = (handicap_index * slope_rating / 113) + (course_rating - par)
    return round(course_handicap)


def get_user_statistics(user_id):
    """
    Get statistical information for a user
    """
    rounds = Round.query.filter_by(user_id=user_id).all()

    if not rounds:
        return {
            'total_rounds': 0,
            'average_score': None,
            'best_score': None,
            'worst_score': None,
            'handicap_index': None
        }

    scores = [r.total_score for r in rounds]

    return {
        'total_rounds': len(rounds),
        'average_score': round(sum(scores) / len(scores), 1),
        'best_score': min(scores),
        'worst_score': max(scores),
        'handicap_index': calculate_handicap_index(user_id)
    }


def get_leaderboard(course_id=None, limit=10):
    """
    Get leaderboard of users by handicap index
    Optionally filter by course for best scores on that course

    SECURITY GAP: No authorization check - anyone can see all scores
    """
    if course_id:
        # Get best scores for specific course
        from sqlalchemy import func
        leaderboard = db.session.query(
            User.id,
            User.username,
            User.full_name,
            func.min(Round.total_score).label('best_score'),
            func.count(Round.id).label('rounds_played')
        ).join(Round).filter(Round.course_id == course_id)\
         .group_by(User.id)\
         .order_by(func.min(Round.total_score))\
         .limit(limit)\
         .all()

        return [
            {
                'user_id': row.id,
                'username': row.username,
                'full_name': row.full_name,
                'best_score': row.best_score,
                'rounds_played': row.rounds_played
            }
            for row in leaderboard
        ]
    else:
        # Get users by handicap index
        users = User.query.filter_by(is_active=True).all()
        leaderboard_data = []

        for user in users:
            handicap = calculate_handicap_index(user.id)
            if handicap is not None:
                stats = get_user_statistics(user.id)
                leaderboard_data.append({
                    'user_id': user.id,
                    'username': user.username,
                    'full_name': user.full_name,
                    'handicap_index': handicap,
                    'average_score': stats['average_score'],
                    'rounds_played': stats['total_rounds']
                })

        # Sort by handicap index
        leaderboard_data.sort(key=lambda x: x['handicap_index'])

        return leaderboard_data[:limit]
