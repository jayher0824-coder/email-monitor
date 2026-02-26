"""
Security utilities for Email Monitor
Handles encryption, password validation, token generation, etc.
"""

import os
import re
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import pyotp
from flask import request, session, redirect, url_for, jsonify, current_app
import jwt

# ==================== ENCRYPTION ====================

class EncryptionService:
    """Handles encryption/decryption of sensitive data"""
    
    @staticmethod
    def get_cipher():
        """Get Fernet cipher from environment"""
        key = os.environ.get('ENCRYPTION_KEY')
        if not key:
            key = Fernet.generate_key()
            os.environ['ENCRYPTION_KEY'] = key.decode()
        return Fernet(key)
    
    @staticmethod
    def encrypt(data: str) -> str:
        """Encrypt sensitive data"""
        if not data:
            return None
        cipher = EncryptionService.get_cipher()
        return cipher.encrypt(data.encode()).decode()
    
    @staticmethod
    def decrypt(encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not encrypted_data:
            return None
        try:
            cipher = EncryptionService.get_cipher()
            return cipher.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return None


# ==================== PASSWORD VALIDATION ====================

class PasswordValidator:
    """Validate password strength and security requirements"""
    
    @staticmethod
    def validate(password: str, min_length: int = 12, require_upper: bool = True,
                 require_lower: bool = True, require_numbers: bool = True,
                 require_special: bool = True) -> tuple:
        """
        Validate password strength
        Returns: (is_valid, error_message)
        """
        if not password:
            return False, "Password is required"
        
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters long"
        
        if require_upper and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if require_lower and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if require_numbers and not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            return False, "Password must contain at least one special character"
        
        return True, None


# ==================== TOKEN GENERATION ====================

class TokenService:
    """Handle JWT token generation and validation"""
    
    @staticmethod
    def generate_token(user_id: int, expires_in_days: int = 7) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(days=expires_in_days),
            'iat': datetime.utcnow()
        }
        token = jwt.encode(
            payload,
            current_app.config['JWT_SECRET'],
            algorithm=current_app.config['JWT_ALGORITHM']
        )
        return token
    
    @staticmethod
    def verify_token(token: str) -> dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET'],
                algorithms=[current_app.config['JWT_ALGORITHM']]
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    @staticmethod
    def generate_refresh_token() -> str:
        """Generate secure refresh token"""
        return secrets.token_urlsafe(32)


# ==================== TWO-FACTOR AUTHENTICATION ====================

class TwoFactorService:
    """Handle 2FA/TOTP operations"""
    
    @staticmethod
    def generate_secret() -> str:
        """Generate TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp(secret: str) -> pyotp.TOTP:
        """Get TOTP object from secret"""
        return pyotp.TOTP(secret)
    
    @staticmethod
    def get_provisioning_uri(secret: str, name: str, issuer: str = "Email Monitor") -> str:
        """Get provisioning URI for QR code"""
        totp = TwoFactorService.get_totp(secret)
        return totp.provisioning_uri(name=name, issuer_name=issuer)
    
    @staticmethod
    def verify_token(secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        try:
            totp = TwoFactorService.get_totp(secret)
            return totp.verify(token, valid_window=window)
        except Exception:
            return False
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> list:
        """Generate backup codes for 2FA"""
        return [secrets.token_hex(4) for _ in range(count)]


# ==================== INPUT VALIDATION & SANITIZATION ====================

class InputValidator:
    """Validate and sanitize user inputs"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Remove path separators and special characters
        filename = os.path.basename(filename)
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        return filename[:255]  # Limit length
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """Remove potentially dangerous HTML"""
        import bleach
        allowed_tags = ['b', 'i', 'u', 'p', 'br', 'a']
        allowed_attributes = {'a': ['href']}
        return bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes)
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*$'
        return re.match(pattern, url) is not None


# ==================== RATE LIMITING & SECURITY CHECKS ====================

class SecurityChecker:
    """Check for security issues and rate limiting"""
    
    @staticmethod
    def get_client_ip():
        """Get client IP address"""
        if request.environ.get('HTTP_CF_CONNECTING_IP'):
            return request.environ.get('HTTP_CF_CONNECTING_IP')
        return request.environ.get('REMOTE_ADDR')
    
    @staticmethod
    def get_user_agent():
        """Get user agent"""
        return request.environ.get('HTTP_USER_AGENT', '')
    
    @staticmethod
    def hash_password_attempt(password: str, salt: str) -> str:
        """Hash password attempt for comparison"""
        return hashlib.sha256((password + salt).encode()).hexdigest()


# ==================== DECORATORS ====================

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        from models import User
        user = User.query.get(session['user_id'])
        
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


def role_required(roles: list):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            from models import User
            user = User.query.get(session['user_id'])
            
            if not user or user.role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_2fa(f):
    """Decorator to require 2FA verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if '2fa_verified' not in session:
            return redirect(url_for('verify_2fa'))
        return f(*args, **kwargs)
    return decorated_function


def rate_limit(max_calls: int, time_period: int):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Implementation would depend on Flask-Limiter
            return f(*args, **kwargs)
        return decorated_function
    return decorator
