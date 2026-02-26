from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

# ==================== USER MODELS ====================

class User(db.Model):
    """Staff user model for document system"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(500), nullable=False)
    full_name = db.Column(db.String(255))
    role = db.Column(db.String(20), default='user')  # 'admin', 'user', 'viewer'
    is_active = db.Column(db.Boolean, default=True)
    
    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)  # Account lockout expiration
    
    # Gmail Integration
    gmail_connected = db.Column(db.Boolean, default=False)
    gmail_credentials = db.Column(db.Text)  # Encrypted OAuth2 credentials
    gmail_connected_at = db.Column(db.DateTime)
    
    # Preferences
    email_notifications = db.Column(db.Boolean, default=True)
    in_app_notifications = db.Column(db.Boolean, default=True)
    theme = db.Column(db.String(20), default='light')  # 'light' or 'dark'
    
    # Relationships
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    documents = db.relationship('Document', backref='created_by_user', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True, cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')
    tags = db.relationship('Tag', backref='created_by', lazy=True, cascade='all, delete-orphan')
    two_factor = db.relationship('TwoFactorAuth', backref='user', uselist=False, cascade='all, delete-orphan')
    login_history = db.relationship('LoginHistory', backref='user', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.email}>'
    
    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until:
            return self.locked_until > datetime.utcnow()
        return False


class TwoFactorAuth(db.Model):
    """Two-factor authentication settings"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    
    # TOTP Secret
    secret = db.Column(db.String(32), nullable=False)  # Encrypted secret
    backup_codes = db.Column(db.Text)  # JSON list of backup codes
    is_verified = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<TwoFactorAuth user_id={self.user_id}>'


class LoginHistory(db.Model):
    """Track login attempts and history"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    user_agent = db.Column(db.Text)
    success = db.Column(db.Boolean, default=True)
    failure_reason = db.Column(db.String(255))  # 'wrong_password', 'invalid_email', 'locked_account'
    
    login_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<LoginHistory user_id={self.user_id} success={self.success}>'


class AuditLog(db.Model):
    """Audit logging for security and compliance"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    
    # Action details
    action = db.Column(db.String(100), nullable=False, index=True)  # 'login', 'logout', 'upload', 'download', 'delete', etc.
    resource_type = db.Column(db.String(50))  # 'document', 'user', 'settings'
    resource_id = db.Column(db.Integer)
    
    # Change details
    changes = db.Column(db.Text)  # JSON format for what changed
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<AuditLog {self.action}>'


# ==================== DOCUMENT MODELS ====================

class Document(db.Model):
    """Document model for incoming/outgoing documents"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    document_id = db.Column(db.String(100), unique=True, nullable=False)
    
    # Document details
    title = db.Column(db.String(500), nullable=False, index=True)
    sender = db.Column(db.String(255), nullable=False, index=True)
    recipient = db.Column(db.String(255), nullable=False)
    document_date = db.Column(db.DateTime, nullable=False)
    
    # Direction and status
    direction = db.Column(db.String(10), nullable=False)  # 'incoming' or 'outgoing'
    status = db.Column(db.String(20), default='pending', index=True)  # 'pending', 'received', 'sent', 'filed'
    priority = db.Column(db.String(20), default='normal')  # 'low', 'normal', 'high', 'urgent'
    
    # File information
    file_name = db.Column(db.String(255))
    file_path = db.Column(db.Text)
    file_size = db.Column(db.Integer)  # in bytes
    file_hash = db.Column(db.String(64))  # SHA256 for integrity checking
    
    # Additional details
    description = db.Column(db.Text)
    content = db.Column(db.Text)  # For email body content
    remarks = db.Column(db.Text)
    has_attachments = db.Column(db.Boolean, default=False)
    is_favorite = db.Column(db.Boolean, default=False)
    is_archived = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)  # For tracking email read status
    
    # Gmail integration
    gmail_id = db.Column(db.String(255), index=True)  # For tracking synced emails
    
    # Tracking
    viewed_count = db.Column(db.Integer, default=0)
    last_viewed = db.Column(db.DateTime)
    
    # Relationships
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    filed_at = db.Column(db.DateTime)
    
    tags = db.relationship('Tag', secondary='document_tag', backref='documents', lazy=True)

    def __repr__(self):
        return f'<Document {self.title}>'


class DocumentTag(db.Model):
    """Association table for document tags"""
    __tablename__ = 'document_tag'
    
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), primary_key=True)


class Tag(db.Model):
    """Email/Document tags for organization"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(7), default='#3b82f6')  # Hex color code
    description = db.Column(db.Text)
    
    # Relationships
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='unique_user_tag_name'),)

    def __repr__(self):
        return f'<Tag {self.name}>'


# ==================== SYNC & FILTER MODELS ====================

class SyncFilter(db.Model):
    """Email sync filter preferences for each user"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    
    # Filter criteria
    enabled = db.Column(db.Boolean, default=True)
    days_back = db.Column(db.Integer, default=7)  # Sync last N days
    max_results = db.Column(db.Integer, default=20)  # Max emails to fetch
    
    # Sender filter (comma-separated)
    sender_include = db.Column(db.Text)  # Whitelist: only from these senders
    sender_exclude = db.Column(db.Text)  # Blacklist: exclude these senders
    
    # Subject filter (comma-separated keywords)
    subject_keywords = db.Column(db.Text)  # Only emails with these keywords
    subject_exclude = db.Column(db.Text)  # Exclude emails with these keywords
    
    # Attachment filter
    has_attachments_only = db.Column(db.Boolean, default=False)  # Only sync emails with attachments
    
    # Automation settings
    auto_sync_enabled = db.Column(db.Boolean, default=False)
    auto_sync_interval = db.Column(db.Integer, default=60)  # Minutes between auto-syncs
    last_sync = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<SyncFilter user_id={self.user_id}>'


# ==================== NOTIFICATION MODELS ====================

class Notification(db.Model):
    """In-app notifications for users"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')  # 'info', 'warning', 'error', 'success'
    
    is_read = db.Column(db.Boolean, default=False)
    action_url = db.Column(db.String(255))  # URL to navigate to when clicked
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime)  # Auto-delete old notifications

    def __repr__(self):
        return f'<Notification {self.title}>'


class EmailAlert(db.Model):
    """Configure email alerts for specific conditions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    name = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    
    # Alert conditions
    alert_type = db.Column(db.String(50), nullable=False)  # 'vip_sender', 'keyword', 'attachment', 'large_file'
    condition_value = db.Column(db.Text)  # Stored as JSON
    
    # Alert settings
    send_email = db.Column(db.Boolean, default=True)
    send_notification = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<EmailAlert {self.name}>'


# ==================== STATS & REPORTING MODELS ====================

class EmailStatistics(db.Model):
    """Daily email statistics for reporting"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    stat_date = db.Column(db.Date, nullable=False)  # Date of statistics
    
    # Email counts
    incoming_count = db.Column(db.Integer, default=0)
    outgoing_count = db.Column(db.Integer, default=0)
    unread_count = db.Column(db.Integer, default=0)
    with_attachments_count = db.Column(db.Integer, default=0)
    
    # Additional metrics
    total_size_bytes = db.Column(db.BigInteger, default=0)
    unique_senders = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'stat_date', name='unique_user_date_stats'),)

    def __repr__(self):
        return f'<EmailStatistics {self.stat_date}>'


# ==================== DOCUMENT APPROVAL MODELS ====================

class DocumentApproval(db.Model):
    """Document approval workflow tracking"""
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False, unique=True, index=True)
    
    # Approval status
    status = db.Column(db.String(20), default='pending', index=True)  # 'pending', 'approved', 'rejected', 'needs_revision'
    
    # Approver information
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)  # Admin who approves
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)  # User who submitted
    
    # Approval details
    comments = db.Column(db.Text)  # Comments from approver
    revision_notes = db.Column(db.Text)  # Notes if needs revision
    
    # Dates
    requested_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    approved_at = db.Column(db.DateTime)
    rejected_at = db.Column(db.DateTime)
    
    # Relationships
    document = db.relationship('Document', backref='approval_workflow', uselist=False)
    approver = db.relationship('User', foreign_keys=[approver_id], backref='approvals_given')
    requester = db.relationship('User', foreign_keys=[requester_id], backref='pending_approvals')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<DocumentApproval doc_id={self.document_id} status={self.status}>'
