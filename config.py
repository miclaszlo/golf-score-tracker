"""
Configuration file for Golf Score Tracker Application
"""
import os
import secrets

class Config:
    """Base configuration"""
    # Load SECRET_KEY from environment variable with secure fallback
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Database configuration
    # Use absolute path for database to avoid path resolution issues
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'golf.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session configuration (SECURITY GAP: insecure defaults)
    SESSION_COOKIE_SECURE = False  # Should be True with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours (too long)

    # Application settings
    DEBUG = True  # SECURITY GAP: Debug mode in production
    # Load HOST from environment variable with secure default (B104 fix)
    # Use '127.0.0.1' for local development, set HOST=0.0.0.0 in production if needed
    HOST = os.environ.get('HOST', '127.0.0.1')
    PORT = int(os.environ.get('PORT', 5001))  # Changed from 5000 (commonly used by macOS AirPlay Receiver)

    # Handicap calculation settings
    MIN_ROUNDS_FOR_HANDICAP = 5
    ROUNDS_TO_CONSIDER = 20
    BEST_SCORES_COUNT = 8

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    # Inherits secure SECRET_KEY from Config base class
    SESSION_COOKIE_SECURE = True

# Default configuration
config = DevelopmentConfig()
