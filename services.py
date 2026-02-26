"""
Audit logging module for Email Monitor
Tracks all user actions for security and compliance
"""

import logging
import os
from datetime import datetime
from flask import request, session
from models import db, AuditLog
from security import SecurityChecker

# Configure audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Ensure logs directory exists
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

# File handler for audit log
audit_file = os.path.join(log_dir, 'audit.log')
handler = logging.FileHandler(audit_file)
handler.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
audit_logger.addHandler(handler)


class AuditService:
    """Service to log audit events"""
    
    @staticmethod
    def log_action(action: str, resource_type: str = None, resource_id: int = None,
                   changes: dict = None, details: str = None):
        """
        Log an action to the audit log
        
        Args:
            action: Action type (e.g., 'login', 'upload', 'delete')
            resource_type: Type of resource affected (e.g., 'document', 'user')
            resource_id: ID of resource affected
            changes: Dictionary of changes made
            details: Additional details about the action
        """
        try:
            user_id = session.get('user_id')
            ip_address = SecurityChecker.get_client_ip()
            user_agent = SecurityChecker.get_user_agent()
            
            # Create audit log entry
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                changes=str(changes) if changes else None,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
            # Also log to file
            log_message = f"User: {user_id}, Action: {action}, Resource: {resource_type}/{resource_id}, IP: {ip_address}"
            if details:
                log_message += f", Details: {details}"
            
            audit_logger.info(log_message)
            
        except Exception as e:
            audit_logger.error(f"Failed to create audit log: {str(e)}")
    
    @staticmethod
    def log_login(user_id: int, success: bool = True, failure_reason: str = None):
        """Log login attempt"""
        from models import LoginHistory, User
        
        try:
            ip_address = SecurityChecker.get_client_ip()
            user_agent = SecurityChecker.get_user_agent()
            
            login_entry = LoginHistory(
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                failure_reason=failure_reason
            )
            
            db.session.add(login_entry)
            db.session.commit()
            
            # Log to audit
            status = "Success" if success else f"Failed ({failure_reason})"
            audit_logger.info(f"User {user_id} login {status} from IP {ip_address}")
            
        except Exception as e:
            audit_logger.error(f"Failed to log login: {str(e)}")
    
    @staticmethod
    def log_file_operation(operation: str, filename: str, file_size: int = None, user_id: int = None):
        """Log file operations (upload, download, delete)"""
        try:
            if not user_id:
                user_id = session.get('user_id')
            
            ip_address = SecurityChecker.get_client_ip()
            
            message = f"User {user_id} {operation} file '{filename}'"
            if file_size:
                message += f" (Size: {file_size} bytes)"
            message += f" from IP {ip_address}"
            
            audit_logger.info(message)
            
        except Exception as e:
            audit_logger.error(f"Failed to log file operation: {str(e)}")
    
    @staticmethod
    def log_security_event(event_type: str, details: str, severity: str = "info"):
        """Log security events"""
        try:
            user_id = session.get('user_id')
            ip_address = SecurityChecker.get_client_ip()
            
            message = f"[{severity.upper()}] Security Event: {event_type}, User: {user_id}, IP: {ip_address}, Details: {details}"
            
            if severity.lower() == "error":
                audit_logger.error(message)
            elif severity.lower() == "warning":
                audit_logger.warning(message)
            else:
                audit_logger.info(message)
            
        except Exception as e:
            audit_logger.error(f"Failed to log security event: {str(e)}")
    
    @staticmethod
    def cleanup_old_logs(days: int = 90):
        """Delete old audit logs"""
        try:
            from datetime import timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            AuditLog.query.filter(AuditLog.timestamp < cutoff_date).delete()
            db.session.commit()
            
            audit_logger.info(f"Cleaned up audit logs older than {days} days")
            
        except Exception as e:
            audit_logger.error(f"Failed to cleanup old logs: {str(e)}")
    
    @staticmethod
    def get_recent_activity(user_id: int = None, limit: int = 50):
        """Get recent audit log entries"""
        try:
            query = AuditLog.query.order_by(AuditLog.timestamp.desc())
            
            if user_id:
                query = query.filter_by(user_id=user_id)
            
            return query.limit(limit).all()
        
        except Exception as e:
            audit_logger.error(f"Failed to retrieve audit logs: {str(e)}")
            return []


class NotificationService:
    """Service to create and manage notifications"""
    
    @staticmethod
    def create_notification(user_id: int, title: str, message: str, 
                           notification_type: str = 'info', action_url: str = None):
        """Create an in-app notification"""
        try:
            from models import Notification
            
            notification = Notification(
                user_id=user_id,
                title=title,
                message=message,
                type=notification_type,
                action_url=action_url
            )
            
            db.session.add(notification)
            db.session.commit()
            
            return notification
        
        except Exception as e:
            print(f"Failed to create notification: {str(e)}")
            return None
    
    @staticmethod
    def mark_as_read(notification_id: int):
        """Mark notification as read"""
        try:
            from models import Notification
            
            notification = Notification.query.get(notification_id)
            if notification:
                notification.is_read = True
                db.session.commit()
                return True
            return False
        
        except Exception as e:
            print(f"Failed to mark notification as read: {str(e)}")
            return False
    
    @staticmethod
    def get_unread_count(user_id: int) -> int:
        """Get count of unread notifications"""
        try:
            from models import Notification
            return Notification.query.filter_by(user_id=user_id, is_read=False).count()
        except Exception:
            return 0
    
    @staticmethod
    def send_email_notification(user_email: str, subject: str, body: str):
        """Send email notification (implementation depends on email service)"""
        try:
            # This would integrate with your email service
            # For now, just log it
            audit_logger.info(f"Email notification sent to {user_email}: {subject}")
            return True
        except Exception as e:
            audit_logger.error(f"Failed to send email notification: {str(e)}")
            return False


class AnalyticsService:
    """Service for email and usage analytics"""
    
    @staticmethod
    def record_daily_stats(user_id: int, incoming: int = 0, outgoing: int = 0,
                           unread: int = 0, with_attachments: int = 0,
                           total_size: int = 0, unique_senders: int = 0):
        """Record daily email statistics"""
        try:
            from models import EmailStatistics
            from datetime import date
            
            today = date.today()
            
            stats = EmailStatistics.query.filter_by(
                user_id=user_id,
                stat_date=today
            ).first()
            
            if not stats:
                stats = EmailStatistics(
                    user_id=user_id,
                    stat_date=today,
                    incoming_count=incoming,
                    outgoing_count=outgoing,
                    unread_count=unread,
                    with_attachments_count=with_attachments,
                    total_size_bytes=total_size,
                    unique_senders=unique_senders
                )
                db.session.add(stats)
            else:
                stats.incoming_count = incoming
                stats.outgoing_count = outgoing
                stats.unread_count = unread
                stats.with_attachments_count = with_attachments
                stats.total_size_bytes = total_size
                stats.unique_senders = unique_senders
            
            db.session.commit()
            return True
        
        except Exception as e:
            audit_logger.error(f"Failed to record stats: {str(e)}")
            return False
    
    @staticmethod
    def get_user_stats(user_id: int, days: int = 30):
        """Get user statistics for last N days"""
        try:
            from models import EmailStatistics
            from datetime import timedelta, date
            
            start_date = date.today() - timedelta(days=days)
            
            stats = EmailStatistics.query.filter(
                EmailStatistics.user_id == user_id,
                EmailStatistics.stat_date >= start_date
            ).all()
            
            return stats
        
        except Exception as e:
            audit_logger.error(f"Failed to get stats: {str(e)}")
            return []
