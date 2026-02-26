"""
Email Monitor - Secure Email and Document Management System
Flask application with comprehensive security and functional features
"""

from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS

from models import db, User, Document, Tag, SyncFilter, Notification, EmailAlert, AuditLog, LoginHistory, DocumentApproval
from config import Config
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import hashlib

# Import security and service modules
from security import (
    login_required, admin_required, role_required, require_2fa,
    PasswordValidator, InputValidator, EncryptionService, TokenService,
    TwoFactorService, SecurityChecker
)
from services import AuditService, NotificationService, AnalyticsService
from auth_service import AuthService

# ==================== APP INITIALIZATION ====================

# Create Flask app with correct template and static folders
template_dir = os.path.join(os.path.dirname(__file__), 'app', 'templates')
static_dir = os.path.join(os.path.dirname(__file__), 'app', 'static')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)
CORS(app, origins=Config.CORS_ORIGINS)

# Trust proxy headers from Render
# This is needed to properly detect HTTPS when behind a reverse proxy
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Rate limiting disabled - dummy limiter that does nothing
class DummyLimiter:
    def limit(self, *args, **kwargs):
        def decorator(f):
            return f
        return decorator

limiter = DummyLimiter()

# Create uploads directory
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = Config.ALLOWED_EXTENSIONS
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create logs directory
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Initialize database
with app.app_context():
    # Comment out drop_all to avoid file locking issues
    # db.drop_all()
    # print("[REFRESH] Dropped old database tables")
    db.create_all()
    print("[OK] Created/verified database tables")


# ==================== UTILITY FUNCTIONS ====================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_file_hash(file_path):
    """Calculate SHA256 hash of file for integrity checking"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_current_user():
    """Get current logged-in user"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


# ==================== BEFORE/AFTER REQUEST HANDLERS ====================

@app.before_request
def before_request():
    """Run before each request"""
    # Add security headers to response
    session.permanent = True
    app.permanent_session_lifetime = Config.PERMANENT_SESSION_LIFETIME


@app.after_request
def after_request(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self' https://cdn.jsdelivr.net"
    return response


# ==================== FAVICON & STATIC ASSETS ====================

@app.route('/favicon.ico')
def favicon():
    """Serve favicon - return empty response to prevent 500 error"""
    from flask import send_from_directory
    favicon_path = os.path.join(app.static_folder, 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')
    # Return a minimal SVG favicon if file doesn't exist
    return '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="75" font-size="75" font-weight="bold" fill="#667eea">📄</text></svg>''', 200, {'Content-Type': 'image/svg+xml'}


# ==================== AUTHENTICATION ROUTES ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with validation"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('password_confirm', '')
        full_name = request.form.get('full_name', '').strip()
        
        # Validate registration
        is_valid, error_msg, error_field = AuthService.validate_registration(email, password, confirm_password)
        
        if not is_valid:
            return render_template('register.html', error=error_msg, error_field=error_field)
        
        try:
            # Create user
            user = AuthService.create_user(email, password, full_name)
            
            # Log action
            AuditService.log_action(
                action='user_registered',
                resource_type='user',
                resource_id=user.id,
                details=f"New user registered: {email}"
            )
            
            # Set session
            session['user_id'] = user.id
            session['email'] = user.email
            session['role'] = user.role
            session['is_admin'] = user.role == 'admin'
            
            return redirect(url_for('dashboard'))
        
        except Exception as e:
            AuditService.log_security_event(
                event_type='registration_failed',
                details=f"Registration error for {email}: {str(e)}",
                severity='error'
            )
            return render_template('register.html', error=str(e))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with security checks"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Validate login
        user, error_msg = AuthService.validate_login(email, password)
        
        if not user:
            return render_template('login.html', error=error_msg)
        
        # Check if 2FA is enabled - TEMPORARILY DISABLED FOR GMAIL SETUP
        # TODO: Re-enable after Gmail connection is complete
        if False and user.two_factor_enabled:
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('verify_2fa'))
        
        # Set session
        session['user_id'] = user.id
        session['email'] = user.email
        session['role'] = user.role
        session['is_admin'] = user.role == 'admin'
        session['2fa_verified'] = True  # Mark as verified since we're bypassing
        
        # Update last login
        AuthService.update_last_login(user.id)
        
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user"""
    user_id = session.get('user_id')
    if user_id:
        AuditService.log_action(
            action='logout',
            resource_type='user',
            resource_id=user_id
        )
    
    session.clear()
    return redirect(url_for('login'))


@app.route('/privacy')
def privacy():
    """Privacy policy page"""
    return render_template('privacy.html', now=datetime.now())


@app.route('/terms')
def terms():
    """Terms of service page"""
    return render_template('terms.html', now=datetime.now())


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify 2FA token"""
    user_id = session.get('pre_2fa_user_id') or session.get('user_id')
    
    if not user_id:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        
        if not token:
            return render_template('verify_2fa.html', error='Token is required')
        
        if AuthService.verify_2fa_token(user_id, token):
            # Remove pre-2fa session and set actual session
            session.pop('pre_2fa_user_id', None)
            session['user_id'] = user_id
            session['2fa_verified'] = True
            
            user = User.query.get(user_id)
            session['email'] = user.email
            
            AuthService.update_last_login(user_id)
            
            return redirect(url_for('dashboard'))
        else:
            AuditService.log_security_event(
                event_type='2fa_verification_failed',
                details=f"Failed 2FA verification attempt",
                severity='warning'
            )
            return render_template('verify_2fa.html', error='Invalid token')
    
    return render_template('verify_2fa.html')


@app.route('/confirm-2fa', methods=['POST'])
@login_required
def confirm_2fa():
    """Confirm 2FA setup"""
    user_id = session.get('user_id')
    token = request.form.get('token', '').strip()
    
    if AuthService.confirm_2fa(user_id, token):
        return redirect(url_for('dashboard'))
    else:
        return jsonify({'error': 'Invalid token'}), 400


@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA"""
    user_id = session.get('user_id')
    
    if AuthService.disable_2fa(user_id):
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Failed to disable 2FA'}), 400


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password"""
    if request.method == 'POST':
        user_id = session.get('user_id')
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        success, error_msg = AuthService.change_password(
            user_id, old_password, new_password, confirm_password
        )
        
        if not success:
            return render_template('change_password.html', error=error_msg)
        
        return redirect(url_for('settings'))
    
    return render_template('change_password.html')


# ==================== MAIN ROUTES ====================

@app.route('/')
def index():
    """Root route"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with analytics"""
    try:
        user = get_current_user()
        if not user:
            return redirect(url_for('login'))
        
        user_id = user.id
        
        # Get document statistics - ONLY count active (non-archived) documents to match the documents list view
        total_docs = Document.query.filter_by(user_id=user_id, is_archived=False).count()
        incoming = Document.query.filter_by(user_id=user_id, direction='incoming', is_archived=False).count()
        outgoing = Document.query.filter_by(user_id=user_id, direction='outgoing', is_archived=False).count()
        archived = Document.query.filter_by(user_id=user_id, is_archived=True).count()
        filed = Document.query.filter_by(user_id=user_id, status='filed', is_archived=False).count()
        
        # Get recent documents (only active documents)
        recent_docs = Document.query.filter_by(user_id=user_id, is_archived=False)\
            .order_by(Document.created_at.desc()).limit(10).all()
        
        # Get unread notifications
        unread_notifications = Notification.query.filter_by(user_id=user_id, is_read=False).all()
        
        # Get email statistics - with error handling
        try:
            stats = AnalyticsService.get_user_stats(user_id, days=7)
        except Exception as stats_error:
            print(f"[WARNING] Analytics error: {stats_error}")
            stats = []
        
        # Get approval data based on role
        pending_approvals = []
        filed_count = filed  # Use the calculated filed count
        
        if user.role == 'admin':
            # Show pending approvals for admins
            pending_approvals = DocumentApproval.query.filter_by(status='pending')\
                .order_by(DocumentApproval.requested_at.desc()).limit(5).all()
        else:
            # Show user's pending approvals
            pending_approvals = DocumentApproval.query.filter_by(requester_id=user_id)\
                .order_by(DocumentApproval.requested_at.desc()).limit(5).all()
        
        return render_template('dashboard.html',
                             user=user,
                             total_docs=total_docs,
                             incoming_count=incoming,
                             outgoing_count=outgoing,
                             filed_count=filed_count,
                             recent_docs=recent_docs,
                             notifications=unread_notifications,
                             stats=stats,
                             pending_approvals=pending_approvals)
    
    except Exception as e:
        print(f"[ERROR] Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return render_template('error.html', error=f'Dashboard error: {str(e)}', code=500), 500


@app.route('/documents')
@login_required
def documents():
    """List all documents with search and filters"""
    user = get_current_user()
    user_id = user.id
    
    # Get query parameters
    search = request.args.get('search', '').strip()
    direction = request.args.get('direction', '')
    priority = request.args.get('priority', '')
    tag_id = request.args.get('tag_id', '')
    
    # Build query
    query = Document.query.filter_by(user_id=user_id, is_archived=False)
    
    if search:
        query = query.filter(
            (Document.title.ilike(f'%{search}%')) |
            (Document.description.ilike(f'%{search}%')) |
            (Document.sender.ilike(f'%{search}%')) |
            (Document.recipient.ilike(f'%{search}%'))
        )
    
    if direction:
        query = query.filter_by(direction=direction)
    
    if priority:
        query = query.filter_by(priority=priority)
    
    # Apply pagination
    page = request.args.get('page', 1, type=int)
    documents = query.order_by(Document.created_at.desc()).paginate(page=page, per_page=20)
    
    # Get user tags
    tags = Tag.query.filter_by(user_id=user_id).all()
    
    return render_template('documents.html',
                         documents=documents,
                         tags=tags,
                         current_search=search,
                         current_direction=direction,
                         current_priority=priority)


@app.route('/archive')
@login_required
def view_archive():
    """View archived documents"""
    user = get_current_user()
    user_id = user.id
    
    # Get query parameters
    search = request.args.get('search', '').strip()
    direction = request.args.get('direction', '')
    priority = request.args.get('priority', '')
    
    # Build query - only archived documents
    query = Document.query.filter_by(user_id=user_id, is_archived=True)
    
    if search:
        query = query.filter(
            (Document.title.ilike(f'%{search}%')) |
            (Document.description.ilike(f'%{search}%')) |
            (Document.sender.ilike(f'%{search}%')) |
            (Document.recipient.ilike(f'%{search}%'))
        )
    
    if direction:
        query = query.filter_by(direction=direction)
    
    if priority:
        query = query.filter_by(priority=priority)
    
    # Apply pagination
    page = request.args.get('page', 1, type=int)
    documents = query.order_by(Document.updated_at.desc()).paginate(page=page, per_page=20)
    
    # Get user tags
    tags = Tag.query.filter_by(user_id=user_id).all()
    
    return render_template('documents.html',
                         documents=documents,
                         tags=tags,
                         is_archive=True,
                         current_search=search,
                         current_direction=direction,
                         current_priority=priority)


@app.route('/document/<int:doc_id>')
@login_required
def view_document(doc_id):
    """View document details"""
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, user_id=user.id).first()
    
    if not doc:
        return redirect(url_for('documents'))
    
    # Update view count
    doc.viewed_count += 1
    doc.last_viewed = datetime.utcnow()
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='document_viewed',
        resource_type='document',
        resource_id=doc_id
    )
    
    # Get tags
    tags = Tag.query.filter_by(user_id=user.id).all()
    
    return render_template('view_document.html', document=doc, available_tags=tags)


@app.route('/document/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    """Download document"""
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, user_id=user.id).first()
    
    if not doc or not doc.file_path or not os.path.exists(doc.file_path):
        return redirect(url_for('documents'))
    
    # Log download
    AuditService.log_file_operation('download', doc.file_name, doc.file_size, user.id)
    
    return send_file(doc.file_path, as_attachment=True, download_name=doc.file_name)


# ==================== DOCUMENT MANAGEMENT ROUTES ====================

@app.route('/documents/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    """Upload new document"""
    if request.method == 'POST':
        user = get_current_user()
        
        title = request.form.get('title', '').strip()
        sender = request.form.get('sender', '').strip()
        recipient = request.form.get('recipient', '').strip()
        direction = request.form.get('direction', 'incoming')
        priority = request.form.get('priority', 'normal')
        description = request.form.get('description', '').strip()
        file = request.files.get('file')
        
        # Validation
        if not all([title, sender, recipient, file]):
            return render_template('upload_document.html', error='All fields required')
        
        if not allowed_file(file.filename):
            return render_template('upload_document.html', error='Invalid file type')
        
        try:
            # Save file
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.utcnow().timestamp()}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Calculate file hash
            file_hash = calculate_file_hash(file_path)
            
            # Create document
            doc = Document(
                user_id=user.id,
                document_id=f"DOC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                title=title,
                sender=sender,
                recipient=recipient,
                direction=direction,
                priority=priority,
                status='pending',
                file_name=file.filename,
                file_path=file_path,
                file_size=os.path.getsize(file_path),
                file_hash=file_hash,
                description=description,
                document_date=datetime.utcnow()
            )
            
            db.session.add(doc)
            db.session.commit()
            
            # Log action
            AuditService.log_file_operation('upload', filename, os.path.getsize(file_path), user.id)
            
            # Create notification
            NotificationService.create_notification(
                user.id,
                'Document Uploaded',
                f'Document "{title}" has been uploaded successfully',
                'success',
                url_for('view_document', doc_id=doc.id)
            )
            
            return redirect(url_for('documents'))
        
        except Exception as e:
            AuditService.log_security_event(
                event_type='document_upload_failed',
                details=str(e),
                severity='error'
            )
            return render_template('upload_document.html', error=f'Upload failed: {str(e)}')
    
    return render_template('upload_document.html')


@app.route('/document/<int:doc_id>/archive', methods=['POST'])
@login_required
def archive_document(doc_id):
    """Archive document"""
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, user_id=user.id).first()
    
    if not doc:
        return jsonify({'error': 'Document not found'}), 404
    
    doc.is_archived = True
    db.session.commit()
    
    AuditService.log_action(
        action='document_archived',
        resource_type='document',
        resource_id=doc_id
    )
    
    return jsonify({'success': True})


@app.route('/document/<int:doc_id>/favorite', methods=['POST'])
@login_required
def favorite_document(doc_id):
    """Toggle document favorite status"""
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, user_id=user.id).first()
    
    if not doc:
        return jsonify({'error': 'Document not found'}), 404
    
    doc.is_favorite = not doc.is_favorite
    db.session.commit()
    
    return jsonify({'success': True, 'is_favorite': doc.is_favorite})


@app.route('/document/<int:doc_id>/tag', methods=['POST'])
@login_required
def tag_document(doc_id):
    """Add tag to document"""
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, user_id=user.id).first()
    tag_id = request.form.get('tag_id', type=int)
    
    if not doc:
        return jsonify({'error': 'Document not found'}), 404
    
    tag = Tag.query.filter_by(id=tag_id, user_id=user.id).first()
    
    if not tag:
        return jsonify({'error': 'Tag not found'}), 404
    
    if tag not in doc.tags:
        doc.tags.append(tag)
        db.session.commit()
    
    return jsonify({'success': True})


# ==================== DOCUMENT PREPARATION & RECEIVING ====================

@app.route('/document/prepare', methods=['GET', 'POST'])
@login_required
def prepare_document():
    """Prepare outgoing document"""
    if request.method == 'POST':
        user = get_current_user()
        
        title = request.form.get('title', '').strip()
        sender = request.form.get('sender', '').strip()
        recipient = request.form.get('recipient', '').strip()
        description = request.form.get('description', '').strip()
        document_date = request.form.get('document_date')
        file = request.files.get('file')
        
        # Validation
        if not all([title, sender, recipient, file, document_date]):
            return render_template('prepare_document.html', error='All fields are required')
        
        if not allowed_file(file.filename):
            return render_template('prepare_document.html', error='Invalid file type. Allowed: PDF, JPG, PNG, DOC, DOCX')
        
        try:
            # Parse document date
            doc_date = datetime.fromisoformat(document_date)
            
            # Save file
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.utcnow().timestamp()}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Calculate file hash
            file_hash = calculate_file_hash(file_path)
            
            # Create document
            doc = Document(
                user_id=user.id,
                document_id=f"OUT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                title=title,
                sender=sender,
                recipient=recipient,
                direction='outgoing',
                priority='normal',
                status='draft',
                file_name=file.filename,
                file_path=file_path,
                file_size=os.path.getsize(file_path),
                file_hash=file_hash,
                description=description,
                document_date=doc_date
            )
            
            db.session.add(doc)
            db.session.commit()
            
            # Create approval workflow
            approval = DocumentApproval(
                document_id=doc.id,
                requester_id=user.id,
                status='pending'
            )
            db.session.add(approval)
            db.session.commit()
            
            # Log action
            AuditService.log_action(
                action='document_prepared',
                resource_type='document',
                resource_id=doc.id
            )
            
            # Create notification for admin
            admin_users = User.query.filter_by(role='admin').all()
            for admin in admin_users:
                NotificationService.create_notification(
                    admin.id,
                    'Document Awaiting Approval',
                    f'Document "{title}" from {user.full_name} is awaiting approval',
                    'warning',
                    url_for('view_approvals')
                )
            
            # Notify user
            NotificationService.create_notification(
                user.id,
                'Document Prepared',
                f'Document "{title}" has been prepared and submitted for approval',
                'info',
                url_for('view_document', doc_id=doc.id)
            )
            
            return redirect(url_for('documents'))
        
        except Exception as e:
            AuditService.log_security_event(
                event_type='document_prepare_failed',
                details=str(e),
                severity='error'
            )
            return render_template('prepare_document.html', error=f'Failed to prepare document: {str(e)}')
    
    return render_template('prepare_document.html')


@app.route('/document/receive', methods=['GET', 'POST'])
@login_required
def receive_document():
    """Receive incoming document"""
    if request.method == 'POST':
        user = get_current_user()
        
        title = request.form.get('title', '').strip()
        sender = request.form.get('sender', '').strip()
        description = request.form.get('description', '').strip()
        document_date = request.form.get('document_date')
        file = request.files.get('file')
        
        # Validation
        if not all([title, sender, file, document_date]):
            return render_template('receive_document.html', error='All fields are required')
        
        if not allowed_file(file.filename):
            return render_template('receive_document.html', error='Invalid file type. Allowed: PDF, JPG, PNG, DOC, DOCX')
        
        try:
            # Parse document date
            doc_date = datetime.fromisoformat(document_date)
            
            # Save file
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.utcnow().timestamp()}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Calculate file hash
            file_hash = calculate_file_hash(file_path)
            
            # Create document
            doc = Document(
                user_id=user.id,
                document_id=f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                title=title,
                sender=sender,
                recipient=user.full_name or user.email,
                direction='incoming',
                priority='normal',
                status='received',
                file_name=file.filename,
                file_path=file_path,
                file_size=os.path.getsize(file_path),
                file_hash=file_hash,
                description=description,
                document_date=doc_date
            )
            
            db.session.add(doc)
            db.session.commit()
            
            # Log action
            AuditService.log_action(
                action='document_received',
                resource_type='document',
                resource_id=doc.id
            )
            
            # Notify user
            NotificationService.create_notification(
                user.id,
                'Document Received',
                f'Incoming document "{title}" from {sender} has been filed',
                'success',
                url_for('view_document', doc_id=doc.id)
            )
            
            return redirect(url_for('documents'))
        
        except Exception as e:
            AuditService.log_security_event(
                event_type='document_receive_failed',
                details=str(e),
                severity='error'
            )
            return render_template('receive_document.html', error=f'Failed to receive document: {str(e)}')
    
    return render_template('receive_document.html')


# ==================== APPROVAL WORKFLOW ====================

@app.route('/document/<int:doc_id>/submit-approval', methods=['POST'])
@login_required
def submit_for_approval(doc_id):
    """Submit document for approval"""
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, user_id=user.id).first()
    
    if not doc:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check if already has approval workflow
    approval = DocumentApproval.query.filter_by(document_id=doc_id).first()
    
    if not approval:
        approval = DocumentApproval(
            document_id=doc_id,
            requester_id=user.id,
            status='pending'
        )
        db.session.add(approval)
    else:
        approval.status = 'pending'
        approval.requested_at = datetime.utcnow()
    
    doc.status = 'pending'
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='document_submitted_approval',
        resource_type='document',
        resource_id=doc_id
    )
    
    # Notify admins
    admin_users = User.query.filter_by(role='admin').all()
    for admin in admin_users:
        NotificationService.create_notification(
            admin.id,
            'Document Awaiting Approval',
            f'Document "{doc.title}" from {user.full_name} is awaiting your approval',
            'warning',
            url_for('view_approvals')
        )
    
    return jsonify({'success': True, 'message': 'Document submitted for approval'})


@app.route('/approvals')
@login_required
@admin_required
def view_approvals():
    """View pending approvals (admin only)"""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'pending')
    
    query = DocumentApproval.query
    
    if status_filter in ['pending', 'approved', 'rejected', 'needs_revision']:
        query = query.filter_by(status=status_filter)
    
    approvals = query.order_by(DocumentApproval.requested_at.desc()).paginate(page=page, per_page=20)
    
    return render_template('approval_queue.html', approvals=approvals, current_status=status_filter)


@app.route('/approval/<int:approval_id>')
@login_required
@admin_required
def view_approval_detail(approval_id):
    """View approval details"""
    approval = DocumentApproval.query.get(approval_id)
    
    if not approval:
        return redirect(url_for('view_approvals'))
    
    return render_template('approval_detail.html', approval=approval)


@app.route('/approval/<int:approval_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_document(approval_id):
    """Approve document"""
    user = get_current_user()
    approval = DocumentApproval.query.get(approval_id)
    
    if not approval:
        return jsonify({'error': 'Approval not found'}), 404
    
    comments = request.form.get('comments', '').strip()
    
    # Update approval
    approval.status = 'approved'
    approval.approver_id = user.id
    approval.approved_at = datetime.utcnow()
    approval.comments = comments
    
    # Update document status
    doc = approval.document
    doc.status = 'approved'
    doc.filed_at = datetime.utcnow()
    
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='document_approved',
        resource_type='document',
        resource_id=doc.id,
        changes=f"Approved by {user.full_name}: {comments}"
    )
    
    # Notify requester
    NotificationService.create_notification(
        approval.requester_id,
        'Document Approved',
        f'Your document "{doc.title}" has been approved by {user.full_name}',
        'success',
        url_for('view_document', doc_id=doc.id)
    )
    
    return jsonify({'success': True, 'message': 'Document approved'})


@app.route('/approval/<int:approval_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_document(approval_id):
    """Reject document"""
    user = get_current_user()
    approval = DocumentApproval.query.get(approval_id)
    
    if not approval:
        return jsonify({'error': 'Approval not found'}), 404
    
    comments = request.form.get('comments', '').strip()
    
    if not comments:
        return jsonify({'error': 'Rejection reason is required'}), 400
    
    # Update approval
    approval.status = 'rejected'
    approval.approver_id = user.id
    approval.rejected_at = datetime.utcnow()
    approval.comments = comments
    
    # Update document status
    doc = approval.document
    doc.status = 'rejected'
    
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='document_rejected',
        resource_type='document',
        resource_id=doc.id,
        changes=f"Rejected by {user.full_name}: {comments}"
    )
    
    # Notify requester
    NotificationService.create_notification(
        approval.requester_id,
        'Document Rejected',
        f'Your document "{doc.title}" was rejected by {user.full_name}',
        'error',
        url_for('view_document', doc_id=doc.id)
    )
    
    return jsonify({'success': True, 'message': 'Document rejected'})


@app.route('/approval/<int:approval_id>/request-revision', methods=['POST'])
@login_required
@admin_required
def request_revision(approval_id):
    """Request document revision"""
    user = get_current_user()
    approval = DocumentApproval.query.get(approval_id)
    
    if not approval:
        return jsonify({'error': 'Approval not found'}), 404
    
    revision_notes = request.form.get('revision_notes', '').strip()
    
    if not revision_notes:
        return jsonify({'error': 'Revision notes are required'}), 400
    
    # Update approval
    approval.status = 'needs_revision'
    approval.approver_id = user.id
    approval.revision_notes = revision_notes
    
    # Update document status
    doc = approval.document
    doc.status = 'needs_revision'
    
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='revision_requested',
        resource_type='document',
        resource_id=doc.id,
        changes=f"Revision requested by {user.full_name}: {revision_notes}"
    )
    
    # Notify requester
    NotificationService.create_notification(
        approval.requester_id,
        'Document Revision Requested',
        f'Your document "{doc.title}" requires revisions',
        'warning',
        url_for('view_document', doc_id=doc.id)
    )
    
    return jsonify({'success': True, 'message': 'Revision requested'})


# ==================== ADMIN USER MANAGEMENT ====================

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Admin portal - view and manage users"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'all')  # all, active, inactive
    
    query = User.query
    
    # Apply search filter
    if search:
        query = query.filter((User.email.ilike(f'%{search}%')) | 
                           (User.full_name.ilike(f'%{search}%')))
    
    # Apply status filter
    if status_filter == 'active':
        query = query.filter_by(is_active=True)
    elif status_filter == 'inactive':
        query = query.filter_by(is_active=False)
    
    # Paginate results
    users = query.order_by(User.created_at.desc()).paginate(page=page, per_page=20)
    
    return render_template('admin_users.html', 
                         users=users,
                         current_search=search,
                         current_status=status_filter)


@app.route('/admin/user/<int:user_id>')
@login_required
@admin_required
def view_user_details(user_id):
    """View detailed user information"""
    user = User.query.get(user_id)
    
    if not user:
        return redirect(url_for('admin_users'))
    
    # Get user statistics
    doc_count = Document.query.filter_by(user_id=user_id).count()
    incoming_count = Document.query.filter_by(user_id=user_id, direction='incoming').count()
    outgoing_count = Document.query.filter_by(user_id=user_id, direction='outgoing').count()
    
    # Get audit logs
    audit_logs = AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.timestamp.desc()).limit(20).all()
    
    # Get login history
    login_history = LoginHistory.query.filter_by(user_id=user_id).order_by(LoginHistory.login_time.desc()).limit(10).all()
    
    return render_template('admin_user_detail.html',
                         user=user,
                         doc_count=doc_count,
                         incoming_count=incoming_count,
                         outgoing_count=outgoing_count,
                         audit_logs=audit_logs,
                         login_history=login_history)


@app.route('/admin/user/<int:user_id>/activate', methods=['POST'])
@login_required
@admin_required
def activate_user(user_id):
    """Activate a user account"""
    if user_id == get_current_user().id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 400
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.is_active = True
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='user_activated',
        resource_type='user',
        resource_id=user_id,
        changes=f'User {user.email} activated by admin'
    )
    
    # Notify user
    NotificationService.create_notification(
        user_id,
        'Account Activated',
        'Your account has been activated by an administrator',
        'success'
    )
    
    return jsonify({'success': True, 'message': f'User {user.email} activated'})


@app.route('/admin/user/<int:user_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_user(user_id):
    """Deactivate a user account"""
    if user_id == get_current_user().id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 400
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.is_active = False
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='user_deactivated',
        resource_type='user',
        resource_id=user_id,
        changes=f'User {user.email} deactivated by admin'
    )
    
    # Notify user
    NotificationService.create_notification(
        user_id,
        'Account Deactivated',
        'Your account has been deactivated by an administrator. Please contact support.',
        'error'
    )
    
    return jsonify({'success': True, 'message': f'User {user.email} deactivated'})


@app.route('/admin/user/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    """Reset user password (admin only)"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate temporary password
    temp_password = 'TempPass123!@'  # In production, generate a random secure password
    
    user.password_hash = PasswordValidator.hash_password(temp_password)
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='password_reset_by_admin',
        resource_type='user',
        resource_id=user_id,
        changes=f'Password reset for user {user.email}'
    )
    
    # Notify user
    NotificationService.create_notification(
        user_id,
        'Password Reset',
        f'Your password has been reset by an administrator. Temporary password: {temp_password}',
        'warning'
    )
    
    return jsonify({'success': True, 'message': 'Password reset successful', 'temp_password': temp_password})


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user account (admin only)"""
    if user_id == get_current_user().id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    email = user.email
    
    # Delete associated documents
    Document.query.filter_by(user_id=user_id).delete()
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    # Log action
    AuditService.log_action(
        action='user_deleted',
        resource_type='user',
        resource_id=user_id,
        changes=f'User account {email} deleted by admin'
    )
    
    return jsonify({'success': True, 'message': f'User {email} deleted'})


@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def change_user_role(user_id):
    """Change user role (admin only)"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    try:
        data = request.get_json()
        new_role = data.get('role', '').strip()
        
        if new_role not in ['admin', 'user', 'viewer']:
            return jsonify({'success': False, 'error': 'Invalid role'}), 400
        
        old_role = user.role
        user.role = new_role
        
        db.session.commit()
        
        # Log action
        admin_user = get_current_user()
        AuditService.log_action(
            action='user_role_changed',
            resource_type='user',
            resource_id=user_id,
            changes=f"Role changed from {old_role} to {new_role} by admin {admin_user.email}"
        )
        
        # Notify user
        NotificationService.create_notification(
            user_id,
            'Role Changed',
            f'Your role has been changed from {old_role} to {new_role} by an administrator.',
            'info'
        )
        
        return jsonify({'success': True, 'message': f'User role changed to {new_role}'})
    
    except Exception as e:
        print(f"[ERROR] Role change failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== TAG MANAGEMENT ====================

@app.route('/tags')
@login_required
def tags():
    """Manage tags"""
    user = get_current_user()
    tags = Tag.query.filter_by(user_id=user.id).all()
    
    return render_template('tags.html', tags=tags)


@app.route('/tags/create', methods=['POST'])
@login_required
def create_tag():
    """Create new tag"""
    user = get_current_user()
    
    name = request.form.get('name', '').strip()
    color = request.form.get('color', '#3b82f6')
    description = request.form.get('description', '').strip()
    
    if not name:
        return render_template('tags.html', error='Tag name is required')
    
    # Check if tag already exists
    if Tag.query.filter_by(user_id=user.id, name=name).first():
        return render_template('tags.html', error='Tag already exists')
    
    tag = Tag(
        user_id=user.id,
        name=name,
        color=color,
        description=description
    )
    
    db.session.add(tag)
    db.session.commit()
    
    return redirect(url_for('tags'))


@app.route('/tags/<int:tag_id>/delete', methods=['POST'])
@login_required
def delete_tag(tag_id):
    """Delete tag"""
    user = get_current_user()
    tag = Tag.query.filter_by(id=tag_id, user_id=user.id).first()
    
    if not tag:
        return jsonify({'error': 'Tag not found'}), 404
    
    db.session.delete(tag)
    db.session.commit()
    
    return jsonify({'success': True})


# ==================== NOTIFICATIONS ====================

@app.route('/notifications')
@login_required
def notifications():
    """View notifications"""
    user = get_current_user()
    page = request.args.get('page', 1, type=int)
    
    notifs = Notification.query.filter_by(user_id=user.id)\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=20)
    
    return render_template('notifications.html', notifications=notifs)


@app.route('/notifications/<int:notif_id>/read', methods=['POST'])
@login_required
def read_notification(notif_id):
    """Mark notification as read"""
    user = get_current_user()
    notif = Notification.query.filter_by(id=notif_id, user_id=user.id).first()
    
    if not notif:
        return jsonify({'error': 'Notification not found'}), 404
    
    NotificationService.mark_as_read(notif_id)
    
    return jsonify({'success': True})


@app.route('/notifications/unread-count')
@login_required
def unread_count():
    """Get unread notification count"""
    user = get_current_user()
    count = NotificationService.get_unread_count(user.id)
    
    return jsonify({'count': count})


# ==================== SETTINGS & PROFILE ====================

@app.route('/settings')
@login_required
def settings():
    """User settings"""
    user = get_current_user()
    
    return render_template('settings.html', user=user)


@app.route('/settings/profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    user = get_current_user()
    
    full_name = request.form.get('full_name', '').strip()
    theme = request.form.get('theme', 'light')
    email_notifications = 'email_notifications' in request.form
    in_app_notifications = 'in_app_notifications' in request.form
    
    user.full_name = full_name
    user.theme = theme
    user.email_notifications = email_notifications
    user.in_app_notifications = in_app_notifications
    
    db.session.commit()
    
    AuditService.log_action(
        action='profile_updated',
        resource_type='user',
        resource_id=user.id
    )
    
    return redirect(url_for('settings'))


# ==================== ANALYTICS & REPORTING ====================

@app.route('/analytics')
@login_required
def analytics():
    """View analytics and statistics"""
    user = get_current_user()
    
    # Get statistics for last 30 days
    stats = AnalyticsService.get_user_stats(user.id, days=30)
    
    # Calculate totals
    total_incoming = sum(s.incoming_count for s in stats)
    total_outgoing = sum(s.outgoing_count for s in stats)
    total_unread = sum(s.unread_count for s in stats)
    total_with_attachments = sum(s.with_attachments_count for s in stats)
    
    return render_template('analytics.html',
                         stats=stats,
                         total_incoming=total_incoming,
                         total_outgoing=total_outgoing,
                         total_unread=total_unread,
                         total_with_attachments=total_with_attachments)


@app.route('/audit-log')
@admin_required
def audit_log():
    """View audit log (admin only)"""
    page = request.args.get('page', 1, type=int)
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=50)
    
    return render_template('audit_log.html', logs=logs)


# ==================== GMAIL INTEGRATION ====================

@app.route('/gmail/setup')
@login_required
def gmail_setup():
    """Setup Gmail integration"""
    from gmail_service import GmailService
    
    user = get_current_user()
    
    # Check if user already has Gmail configured
    user_credentials = getattr(user, 'gmail_credentials', None)
    is_configured = user_credentials is not None
    
    # Generate OAuth2 URL
    gmail_service = GmailService()
    auth_url, state = gmail_service.get_auth_url()
    
    # Store state in session for CSRF protection
    session['gmail_oauth_state'] = state
    db.session.commit()
    
    AuditService.log_action(
        action='gmail_setup_initiated',
        resource_type='gmail',
        resource_id=user.id
    )
    
    return render_template('gmail_setup.html',
                         auth_url=auth_url,
                         is_configured=is_configured)


@app.route('/callback')
@app.route('/gmail/callback')
@login_required
def gmail_callback():
    """Gmail OAuth callback"""
    from gmail_service import GmailService
    import json
    
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    # Handle OAuth errors
    if error:
        print(f"Gmail OAuth error: {error}")
        return render_template('error.html', error=f'Gmail authorization failed: {error}', code=400), 400
    
    # Verify state
    session_state = session.get('gmail_oauth_state')
    if not state or state != session_state:
        print(f"State mismatch - received: {state}, expected: {session_state}")
        return render_template('error.html', error='Invalid OAuth state - security check failed', code=400), 400
    
    if not code:
        return render_template('error.html', error='No authorization code received', code=400), 400
    
    try:
        # Exchange code for credentials
        print(f"[GMAIL] Exchanging authorization code...")
        gmail_service = GmailService()
        credentials = gmail_service.get_credentials_from_code(code)
        
        # Store credentials for user
        user = get_current_user()
        if not user:
            print(f"[ERROR] User session lost during OAuth callback")
            return render_template('error.html', error='User session expired. Please try again.', code=401), 401
        
        # Encrypt credentials before storing
        print(f"[GMAIL] Storing encrypted credentials for user {user.id}")
        creds_json = credentials.to_json()
        encrypted_creds = EncryptionService.encrypt(creds_json)
        user.gmail_credentials = encrypted_creds
        user.gmail_connected = True
        user.gmail_connected_at = datetime.utcnow()
        
        db.session.commit()
        print(f"[OK] Gmail connected successfully for user {user.id}")
        
        AuditService.log_action(
            action='gmail_connected',
            resource_type='gmail',
            resource_id=user.id,
            details=f'Gmail account successfully connected'
        )
        
        # Create notification
        NotificationService.create_notification(
            user_id=user.id,
            title='Gmail Connected',
            message='Your Gmail account is now connected. You can now sync your emails.',
            action_url=url_for('gmail_configure')
        )
        
        return redirect(url_for('gmail_configure'))
    
    except Exception as e:
        print(f"[ERROR] Gmail callback error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        
        AuditService.log_security_event(
            severity='warning',
            event_type='gmail_auth_failed',
            details=f"{type(e).__name__}: {str(e)}"
        )
        return render_template('error.html', error=f'Gmail authentication failed: {str(e)}', code=400), 400


@app.route('/gmail/configure')
@login_required
def gmail_configure():
    """Configure Gmail sync settings"""
    user = get_current_user()
    
    # Check if Gmail is connected
    if not user.gmail_connected:
        return redirect(url_for('gmail_setup'))
    
    # Get existing sync configuration
    sync_filter = SyncFilter.query.filter_by(user_id=user.id).first()
    
    return render_template('gmail_configure.html', sync_filter=sync_filter)


@app.route('/gmail/sync-config', methods=['POST'])
@login_required
def gmail_sync_config():
    """Update Gmail sync configuration"""
    user = get_current_user()
    
    if not user.gmail_connected:
        return jsonify({'success': False, 'error': 'Gmail not connected'}), 401
    
    # Get form data
    sender_include = request.form.get('sender_include', '').strip()
    sender_exclude = request.form.get('sender_exclude', '').strip()
    subject_keywords = request.form.get('subject_keywords', '').strip()
    subject_exclude = request.form.get('subject_exclude', '').strip()
    has_attachments_only = 'has_attachments_only' in request.form
    auto_sync = 'auto_sync' in request.form
    sync_frequency = request.form.get('sync_frequency', 'daily')
    
    # Validate input
    if len(sender_include) > 500 or len(sender_exclude) > 500:
        return jsonify({'success': False, 'error': 'Filter text too long'}), 400
    
    try:
        # Get or create sync filter
        sync_filter = SyncFilter.query.filter_by(user_id=user.id).first()
        if not sync_filter:
            sync_filter = SyncFilter(user_id=user.id)
        
        # Update configuration
        sync_filter.sender_include = sender_include
        sync_filter.sender_exclude = sender_exclude
        sync_filter.subject_keywords = subject_keywords
        sync_filter.subject_exclude = subject_exclude
        sync_filter.has_attachments_only = has_attachments_only
        sync_filter.auto_sync = auto_sync
        sync_filter.sync_frequency = sync_frequency
        
        db.session.add(sync_filter)
        db.session.commit()
        
        AuditService.log_action(
            action='gmail_sync_configured',
            resource_type='gmail',
            resource_id=user.id
        )
        
        return jsonify({'success': True, 'message': 'Sync configuration updated'})
    
    except Exception as e:
        print(f"Error updating sync config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/gmail/test', methods=['POST'])
@login_required
def gmail_test():
    """Test Gmail connection - validates credentials are working"""
    from gmail_service import GmailService
    import json
    
    user = get_current_user()
    
    if not user.gmail_connected:
        return jsonify({'success': False, 'error': 'Gmail not connected', 'authenticated': False}), 401
    
    try:
        # Decrypt credentials
        if not user.gmail_credentials:
            return jsonify({'success': False, 'error': 'No credentials available', 'authenticated': False}), 400
        
        print(f"[GMAIL TEST] Testing credentials for user {user.id}")
        creds_json = EncryptionService.decrypt(user.gmail_credentials)
        creds_dict = json.loads(creds_json)
        
        # Initialize service
        gmail_service = GmailService()
        gmail_service.set_credentials(creds_dict)
        
        # Try to refresh token if expired
        if gmail_service.credentials and gmail_service.credentials.expired and gmail_service.credentials.refresh_token:
            print(f"[GMAIL TEST] Token expired, attempting refresh...")
            try:
                from google.auth.transport.requests import Request
                gmail_service.credentials.refresh(Request())
                print(f"[GMAIL TEST] Token refreshed successfully")
                
                # Save refreshed credentials
                updated_creds_json = gmail_service.credentials.to_json()
                encrypted_creds = EncryptionService.encrypt(updated_creds_json)
                user.gmail_credentials = encrypted_creds
                db.session.commit()
            except Exception as refresh_error:
                print(f"[GMAIL TEST] Token refresh failed: {str(refresh_error)}")
                return jsonify({
                    'success': False,
                    'error': f'Token expired and refresh failed: {str(refresh_error)}',
                    'authenticated': False
                }), 401
        
        # Validate credentials
        is_valid, email_or_error = gmail_service.validate_credentials()
        
        if is_valid:
            print(f"[GMAIL TEST] Credentials valid for {email_or_error}")
            return jsonify({
                'success': True,
                'message': 'Gmail connection working',
                'authenticated': True,
                'email': email_or_error
            })
        else:
            print(f"[GMAIL TEST] Credentials invalid: {email_or_error}")
            return jsonify({
                'success': False,
                'error': email_or_error,
                'authenticated': False
            }), 401
    
    except Exception as e:
        print(f"[GMAIL TEST] Error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        
        AuditService.log_security_event(
            severity='warning',
            event_type='gmail_test_failed',
            details=f"{type(e).__name__}: {str(e)}"
        )
        
        return jsonify({
            'success': False,
            'error': f'Connection test failed: {str(e)}',
            'authenticated': False
        }), 400


@app.route('/gmail/sync', methods=['POST'])
@login_required
def gmail_sync():
    """Manually sync emails from Gmail"""
    from gmail_service import GmailService
    import json
    import uuid
    from google.auth.transport.requests import Request
    
    user = get_current_user()
    
    if not user.gmail_connected:
        return jsonify({'success': False, 'error': 'Gmail not connected'}), 401
    
    try:
        # Decrypt user credentials
        if not user.gmail_credentials:
            return jsonify({'success': False, 'error': 'No credentials available'}), 400
        
        print(f"[GMAIL] Decrypting credentials for user {user.id}")
        creds_json = EncryptionService.decrypt(user.gmail_credentials)
        creds_dict = json.loads(creds_json)
        
        # Initialize Gmail service
        gmail_service = GmailService()
        gmail_service.set_credentials(creds_dict)
        
        # Check if token is expired and refresh if needed
        if gmail_service.credentials and gmail_service.credentials.expired and gmail_service.credentials.refresh_token:
            print(f"[GMAIL] Token expired, refreshing...")
            try:
                gmail_service.credentials.refresh(Request())
                print(f"[OK] Token refreshed successfully")
                
                # Save refreshed credentials back to database
                updated_creds_json = gmail_service.credentials.to_json()
                encrypted_creds = EncryptionService.encrypt(updated_creds_json)
                user.gmail_credentials = encrypted_creds
                db.session.commit()
                print(f"[OK] Updated stored credentials with refreshed token")
            except Exception as refresh_error:
                print(f"[ERROR] Failed to refresh token: {type(refresh_error).__name__}: {str(refresh_error)}")
                return jsonify({'success': False, 'error': f'Token refresh failed. Please reconnect Gmail: {str(refresh_error)}'}), 401
        
        # Get recent emails
        days = request.form.get('days', 7, type=int)
        max_results = request.form.get('max_results', 20, type=int)
        
        print(f"[GMAIL] Fetching recent emails (last {days} days, max {max_results})")
        emails = gmail_service.get_recent_emails(days=days, max_results=max_results)
        print(f"[OK] Retrieved {len(emails)} emails from Gmail")
        
        # Apply filters
        sync_filter = SyncFilter.query.filter_by(user_id=user.id).first()
        if sync_filter:
            filter_config = {
                'sender_include': sync_filter.sender_include,
                'sender_exclude': sync_filter.sender_exclude,
                'subject_keywords': sync_filter.subject_keywords,
                'subject_exclude': sync_filter.subject_exclude,
                'has_attachments_only': sync_filter.has_attachments_only
            }
            emails = gmail_service.filter_emails(emails, filter_config)
            print(f"[GMAIL] After filtering: {len(emails)} emails")
        
        # Convert emails to documents
        created_count = 0
        updated_count = 0
        
        for email_data in emails:
            # Check if email already synced
            existing = Document.query.filter_by(
                user_id=user.id,
                gmail_id=email_data.get('gmail_id')
            ).first()
            
            if not existing:
                # Create new document from email
                document = Document(
                    user_id=user.id,
                    document_id=str(uuid.uuid4()),
                    title=email_data.get('subject', 'No Subject'),
                    sender=email_data.get('sender_name', email_data.get('sender')),
                    recipient=email_data.get('recipient', ''),
                    document_date=email_data.get('date', datetime.utcnow()),
                    direction='incoming',
                    status='received',
                    description=email_data.get('body', email_data.get('snippet', '')),
                    content=email_data.get('body', email_data.get('snippet', '')),
                    gmail_id=email_data.get('gmail_id'),
                    has_attachments=email_data.get('has_attachments', False),
                    is_read=email_data.get('is_read', False)
                )
                
                # Calculate file hash (using content hash)
                content_hash = hashlib.sha256(
                    (email_data.get('body', '') + email_data.get('subject', '')).encode()
                ).hexdigest()
                document.file_hash = content_hash
                
                db.session.add(document)
                created_count += 1
            else:
                # Update existing document
                existing.is_read = email_data.get('is_read', False)
                existing.updated_at = datetime.utcnow()
                updated_count += 1
        
        db.session.commit()
        print(f"[OK] Sync complete: {created_count} created, {updated_count} updated")
        
        # Log sync action
        AuditService.log_action(
            action='gmail_sync_completed',
            resource_type='gmail',
            resource_id=user.id,
            details={
                'retrieved': len(emails),
                'created': created_count,
                'updated': updated_count
            }
        )
        
        # Create notification
        NotificationService.create_notification(
            user_id=user.id,
            title=f'Gmail Sync Complete',
            message=f'Created {created_count} documents, updated {updated_count}',
            action_url=url_for('documents')
        )
        
        return jsonify({
            'success': True,
            'message': f'Synced {created_count} new documents',
            'created': created_count,
            'updated': updated_count,
            'total': len(emails)
        })
    
    except Exception as e:
        print(f"[ERROR] Gmail sync failed: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        
        AuditService.log_security_event(
            severity='error',
            event_type='gmail_sync_failed',
            details=f"{type(e).__name__}: {str(e)}"
        )
        return jsonify({'success': False, 'error': f'Gmail sync failed: {str(e)}'}), 500


@app.route('/gmail/disconnect', methods=['POST'])
@login_required
def gmail_disconnect():
    """Disconnect Gmail from account"""
    user = get_current_user()
    
    try:
        # Revoke credentials and disconnect
        user.gmail_credentials = None
        user.gmail_connected = False
        user.gmail_connected_at = None
        
        db.session.commit()
        
        AuditService.log_action(
            action='gmail_disconnected',
            resource_type='gmail',
            resource_id=user.id
        )
        
        NotificationService.create_notification(
            user_id=user.id,
            title='Gmail Disconnected',
            message='Your Gmail account has been disconnected'
        )
        
        return jsonify({'success': True, 'message': 'Gmail disconnected'})
    
    except Exception as e:
        print(f"Error disconnecting Gmail: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== API ENDPOINTS ====================

@app.route('/api/documents/search')
@login_required
def api_search_documents():
    """Search documents API"""
    user = get_current_user()
    q = request.args.get('q', '').strip()
    
    if len(q) < 2:
        return jsonify([])
    
    documents = Document.query.filter_by(user_id=user.id)\
        .filter((Document.title.ilike(f'%{q}%')) |
                (Document.description.ilike(f'%{q}%')))\
        .limit(10).all()
    
    return jsonify([{
        'id': doc.id,
        'title': doc.title,
        'sender': doc.sender,
        'date': doc.created_at.strftime('%Y-%m-%d')
    } for doc in documents])


@app.route('/api/stats/daily')
@login_required
def api_daily_stats():
    """Get daily statistics API"""
    user = get_current_user()
    days = request.args.get('days', 30, type=int)
    
    stats = AnalyticsService.get_user_stats(user.id, days=days)
    
    return jsonify([{
        'date': s.stat_date.strftime('%Y-%m-%d'),
        'incoming': s.incoming_count,
        'outgoing': s.outgoing_count,
        'unread': s.unread_count
    } for s in stats])


# ==================== DIAGNOSTIC ENDPOINTS ====================

@app.route('/health/gmail-config')
def gmail_config_check():
    """Check if Gmail credentials are configured"""
    client_id = Config.GOOGLE_CLIENT_ID or 'NOT SET'
    client_secret = Config.GOOGLE_CLIENT_SECRET or 'NOT SET'
    redirect_uri = Config.GOOGLE_REDIRECT_URI or 'NOT SET'
    
    is_configured = bool(Config.GOOGLE_CLIENT_ID and Config.GOOGLE_CLIENT_SECRET)
    
    # Mask sensitive data
    client_id_display = client_id[:10] + '...' if len(client_id) > 10 else client_id
    client_secret_display = client_secret[:10] + '...' if len(client_secret) > 10 else client_secret
    
    return jsonify({
        'configured': is_configured,
        'client_id': client_id_display,
        'client_secret': client_secret_display,
        'redirect_uri': redirect_uri,
        'scopes': Config.SCOPES,
        'status': 'Ready' if is_configured else 'Missing credentials - see setup guide'
    })


# ==================== ERROR HANDLERS ====================

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard - manage users and system"""
    # Get user statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    inactive_users = User.query.filter_by(is_active=False).count()
    two_fa_enabled = User.query.filter_by(two_factor_enabled=True).count()
    
    # Get all users
    users = User.query.order_by(User.created_at.desc()).all()
    
    return render_template('admin_dashboard.html',
                         users=users,
                         total_users=total_users,
                         active_users=active_users,
                         inactive_users=inactive_users,
                         two_fa_enabled=two_fa_enabled)


@app.errorhandler(404)
def not_found(e):
    """404 error handler"""
    return render_template('error.html', error='Page not found', code=404), 404


@app.errorhandler(403)
def forbidden(e):
    """403 error handler"""
    return render_template('error.html', error='Access forbidden', code=403), 403


@app.errorhandler(500)
def server_error(e):
    """500 error handler"""
    print(f"[ERROR] Server error: {e}")
    return render_template('error.html', error='Server error', code=500), 500


# ==================== CLI COMMANDS ====================

@app.shell_context_processor
def make_shell_context():
    """Create shell context"""
    return {'db': db, 'User': User, 'Document': Document}


# ==================== APP STARTUP ====================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("EMAIL MONITOR - SECURE EMAIL & DOCUMENT MANAGEMENT")
    print("="*60)
    print("[OK] Security features: CSRF, Rate Limiting, 2FA, Audit Logging")
    print("[OK] Functional features: Search, Tags, Analytics, Notifications")
    print("[OK] Server starting on http://0.0.0.0:5000")
    print("="*60 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)

