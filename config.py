import os
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///email_monitor.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Gmail OAuth2 credentials
    # Get these from Google Cloud Console
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:8000/callback')
    
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.settings.basic'
    ]
    
    # ==================== SECURITY SETTINGS ====================
    
    # Session Security
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = True  # Only send over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Not accessible to JavaScript
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    SESSION_REFRESH_EACH_REQUEST = True
    
    # Password Security
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_PASSWORD_UPPERCASE = True
    REQUIRE_PASSWORD_LOWERCASE = True
    REQUIRE_PASSWORD_NUMBERS = True
    REQUIRE_PASSWORD_SPECIAL_CHARS = True
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    RATELIMIT_LOGIN_ATTEMPTS = "5 per minute"
    RATELIMIT_API_CALLS = "1000 per hour"
    
    # Account Security
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = 900  # 15 minutes in seconds
    
    # Two-Factor Authentication
    TOTP_ISSUER = "Email Monitor"
    TOTP_WINDOW = 1  # Allows 30 seconds on each side
    
    # JWT Configuration
    JWT_SECRET = os.environ.get('JWT_SECRET') or 'jwt-secret-key-change-in-production'
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_DELTA = timedelta(days=7)
    
    # File Upload Security
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
    ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx', 'txt'}
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25MB max file size
    SCAN_UPLOADS = True  # Scan uploads for malware
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    }
    
    # Audit Logging
    ENABLE_AUDIT_LOG = True
    AUDIT_LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'audit.log')
    AUDIT_LOG_RETENTION_DAYS = 90
    
    # Database Encryption
    ENCRYPT_SENSITIVE_DATA = True
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:5000,http://localhost:3000').split(',')
    
    # Email Configuration (for alerts)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', True)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    
    # Notification Settings
    ENABLE_EMAIL_NOTIFICATIONS = True
    ENABLE_IN_APP_NOTIFICATIONS = True
    NOTIFICATION_RETENTION_DAYS = 30
