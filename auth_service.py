"""
Authentication module for Email Monitor
Handles user login, registration, session management with enhanced security
"""

from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, TwoFactorAuth, LoginHistory
from security import (
    PasswordValidator, TwoFactorService, EncryptionService,
    InputValidator, TokenService, SecurityChecker
)
from services import AuditService, NotificationService
from datetime import datetime, timedelta
import os

class AuthService:
    """Service to handle user authentication with enhanced security"""
    
    @staticmethod
    def validate_registration(email: str, password: str, confirm_password: str) -> tuple:
        """
        Validate registration input
        Returns: (is_valid, error_message, error_field)
        """
        # Validate email
        if not InputValidator.validate_email(email):
            return False, "Invalid email format", "email"
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            return False, "Email already registered", "email"
        
        # Validate passwords match
        if password != confirm_password:
            return False, "Passwords do not match", "password"
        
        # Validate password strength
        is_valid, error_msg = PasswordValidator.validate(
            password,
            min_length=12,
            require_upper=True,
            require_lower=True,
            require_numbers=True,
            require_special=True
        )
        
        if not is_valid:
            return False, error_msg, "password"
        
        return True, None, None
    
    @staticmethod
    def create_user(email: str, password: str, full_name: str = None) -> User:
        """
        Create a new user account
        
        Args:
            email: User email
            password: User password (must meet security requirements)
            full_name: Optional user full name
            
        Returns:
            User object or raises exception
        """
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            raise ValueError(f"User with email {email} already exists")
        
        # Validate password
        is_valid, error_msg = PasswordValidator.validate(password)
        if not is_valid:
            raise ValueError(error_msg)
        
        # Create new user with hashed password
        user = User(
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16),
            full_name=full_name,
            role='user',  # Default role
            is_active=True
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log user creation
        AuditService.log_action(
            action='user_created',
            resource_type='user',
            resource_id=user.id,
            details=f"New user registered: {email}"
        )
        
        # Create notification
        NotificationService.create_notification(
            user_id=user.id,
            title="Welcome to Email Monitor",
            message="Your account has been created successfully. Set up two-factor authentication for enhanced security.",
            notification_type='success'
        )
        
        return user
    
    @staticmethod
    def validate_login(email: str, password: str) -> tuple:
        """
        Validate login credentials
        Returns: (user_object, error_message)
        """
        # Validate email format
        if not InputValidator.validate_email(email):
            AuditService.log_login(None, success=False, failure_reason='invalid_email')
            return None, "Invalid email or password"
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if not user:
            AuditService.log_login(None, success=False, failure_reason='user_not_found')
            return None, "Invalid email or password"
        
        # Check if account is locked
        if user.is_locked():
            AuditService.log_login(user.id, success=False, failure_reason='account_locked')
            return None, f"Account is locked. Try again later."
        
        # Check password
        if not check_password_hash(user.password_hash, password):
            # Increment login attempts
            user.login_attempts += 1
            
            # Lock account after max attempts
            if user.login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
                
                AuditService.log_security_event(
                    event_type='account_locked',
                    details=f"Account {email} locked after 5 failed login attempts",
                    severity='warning'
                )
                
                return None, "Account locked due to multiple failed login attempts"
            
            db.session.commit()
            AuditService.log_login(user.id, success=False, failure_reason='wrong_password')
            return None, "Invalid email or password"
        
        # Check if account is active
        if not user.is_active:
            AuditService.log_login(user.id, success=False, failure_reason='account_inactive')
            return None, "Account is inactive"
        
        # Reset login attempts on successful authentication
        user.login_attempts = 0
        user.locked_until = None
        
        db.session.commit()
        
        # Log successful login
        AuditService.log_login(user.id, success=True)
        
        return user, None
    
    @staticmethod
    def update_last_login(user_id: int):
        """Update user's last login time"""
        try:
            user = User.query.get(user_id)
            if user:
                user.last_login = datetime.utcnow()
                db.session.commit()
        except Exception as e:
            print(f"Failed to update last login: {str(e)}")
    
    @staticmethod
    def change_password(user_id: int, old_password: str, new_password: str, 
                       confirm_password: str) -> tuple:
        """
        Change user password
        Returns: (success, error_message)
        """
        user = User.query.get(user_id)
        
        if not user:
            return False, "User not found"
        
        # Verify old password
        if not check_password_hash(user.password_hash, old_password):
            AuditService.log_security_event(
                event_type='password_change_failed',
                details=f"Invalid old password",
                severity='warning'
            )
            return False, "Current password is incorrect"
        
        # Validate new password
        if new_password != confirm_password:
            return False, "New passwords do not match"
        
        # Validate password strength
        is_valid, error_msg = PasswordValidator.validate(new_password)
        if not is_valid:
            return False, error_msg
        
        # Check password is different from old
        if check_password_hash(user.password_hash, new_password):
            return False, "New password must be different from current password"
        
        # Update password
        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        user.last_password_change = datetime.utcnow()
        
        db.session.commit()
        
        # Log password change
        AuditService.log_action(
            action='password_changed',
            resource_type='user',
            resource_id=user.id
        )
        
        NotificationService.create_notification(
            user_id=user.id,
            title="Password Changed",
            message="Your password has been successfully changed.",
            notification_type='success'
        )
        
        return True, None
    
    @staticmethod
    def enable_2fa(user_id: int) -> tuple:
        """
        Enable 2FA for user
        Returns: (secret, provisioning_uri)
        """
        user = User.query.get(user_id)
        if not user:
            return None, None
        
        # Generate TOTP secret
        secret = TwoFactorService.generate_secret()
        
        # Get provisioning URI for QR code
        provisioning_uri = TwoFactorService.get_provisioning_uri(
            secret,
            user.email,
            "Email Monitor"
        )
        
        # Store encrypted secret (don't mark as verified yet)
        encrypted_secret = EncryptionService.encrypt(secret)
        
        twofa = TwoFactorAuth.query.filter_by(user_id=user_id).first()
        
        if twofa:
            twofa.secret = encrypted_secret
            twofa.is_verified = False
        else:
            twofa = TwoFactorAuth(
                user_id=user_id,
                secret=encrypted_secret,
                is_verified=False
            )
            db.session.add(twofa)
        
        db.session.commit()
        
        return secret, provisioning_uri
    
    @staticmethod
    def verify_2fa_token(user_id: int, token: str) -> bool:
        """Verify 2FA token"""
        twofa = TwoFactorAuth.query.filter_by(user_id=user_id).first()
        
        if not twofa:
            return False
        
        # Decrypt secret
        secret = EncryptionService.decrypt(twofa.secret)
        
        if not secret:
            return False
        
        # Verify token
        return TwoFactorService.verify_token(secret, token)
    
    @staticmethod
    def confirm_2fa(user_id: int, token: str) -> bool:
        """Confirm 2FA setup with verification token"""
        if not AuthService.verify_2fa_token(user_id, token):
            return False
        
        # Mark 2FA as verified
        twofa = TwoFactorAuth.query.filter_by(user_id=user_id).first()
        if twofa:
            twofa.is_verified = True
            db.session.commit()
            
            # Enable 2FA for user
            user = User.query.get(user_id)
            user.two_factor_enabled = True
            db.session.commit()
            
            # Log this event
            AuditService.log_security_event(
                event_type='2fa_enabled',
                details=f"Two-factor authentication enabled for user {user.email}",
                severity='info'
            )
            
            NotificationService.create_notification(
                user_id=user_id,
                title="2FA Enabled",
                message="Two-factor authentication has been successfully enabled on your account.",
                notification_type='success'
            )
            
            return True
        
        return False
    
    @staticmethod
    def disable_2fa(user_id: int) -> bool:
        """Disable 2FA for user"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False
            
            user.two_factor_enabled = False
            
            twofa = TwoFactorAuth.query.filter_by(user_id=user_id).first()
            if twofa:
                db.session.delete(twofa)
            
            db.session.commit()
            
            # Log this event
            AuditService.log_security_event(
                event_type='2fa_disabled',
                details=f"Two-factor authentication disabled for user {user.email}",
                severity='warning'
            )
            
            NotificationService.create_notification(
                user_id=user_id,
                title="2FA Disabled",
                message="Two-factor authentication has been disabled on your account.",
                notification_type='info'
            )
            
            return True
        except Exception as e:
            print(f"Failed to disable 2FA: {str(e)}")
            return False
    
    @staticmethod
    def user_exists(email: str) -> bool:
        """Check if user exists"""
        return User.query.filter_by(email=email).first() is not None

