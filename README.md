# Email Monitor - Secure Email & Document Management System

A comprehensive web-based application for secure email and document management with advanced security features, role-based access control, and powerful organizational tools.

## 🔒 Security Features

✅ **Two-Factor Authentication (2FA)** - TOTP-based 2FA with backup codes  
✅ **CSRF Protection** - Flask-WTF CSRF token protection on all forms  
✅ **Rate Limiting** - Prevent brute force and DoS attacks  
✅ **Password Security** - Enforce strong passwords (12+ chars, uppercase, lowercase, numbers, special chars)  
✅ **Account Lockout** - Lock account after 5 failed login attempts (15-minute timeout)  
✅ **Audit Logging** - Comprehensive logging of all user actions  
✅ **Session Security** - HTTPOnly, Secure, SameSite cookie flags  
✅ **Database Encryption** - Encrypt sensitive data at rest  
✅ **Input Validation** - Sanitize all user inputs (CSRF, XSS, SQL injection prevention)  
✅ **Security Headers** - CSP, X-Frame-Options, X-Content-Type-Options, etc.  
✅ **File Integrity** - SHA256 hash verification for uploaded files  
✅ **Login History** - Track all login attempts with IP and user agent  

## 🚀 Functional Features

✅ **Document Management** - Upload, organize, and manage documents with metadata  
✅ **Advanced Search** - Full-text search across title, description, sender, recipient  
✅ **Tagging System** - Create custom tags with colors for document organization  
✅ **Favorites & Archive** - Mark documents as favorites or archive old ones  
✅ **Email Integration** - Sync emails from Gmail with advanced filtering  
✅ **Dashboard Analytics** - View email statistics and trends  
✅ **Notifications System** - In-app and email notifications for important events  
✅ **User Profiles** - Full profile management with preferences  
✅ **Role-Based Access** - Admin, User, and Viewer roles  
✅ **Export & Reporting** - Export documents and generate reports  

## � Gmail Integration

The Email Monitor system includes seamless Gmail integration that allows you to automatically sync emails as documents.

### Setting Up Gmail Integration

#### 1. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Gmail API:
   - Go to APIs & Services > Library
   - Search for "Gmail API"
   - Click "Enable"

#### 2. Create OAuth2 Credentials

1. Go to APIs & Services > Credentials
2. Click "Create Credentials" > "OAuth 2.0 Client IDs"
3. Select "Web application"
4. Add authorized redirect URIs:
   - `http://localhost:5000/gmail/callback` (for local development)
   - `https://yourdomain.com/gmail/callback` (for production)
5. Download the credentials JSON file

#### 3. Configure Email Monitor

1. Set environment variables in `.env`:
   ```
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret
   GOOGLE_REDIRECT_URI=http://localhost:5000/gmail/callback
   ```

2. Connect Gmail in the application:
   - Go to Settings > Gmail Integration
   - Click "Connect Gmail"
   - Authorize the application to access your Gmail
   - Configure sync filters (optional)

### Gmail Sync Features

**Advanced Filtering:**
- **Sender Whitelist** - Only sync from specific senders
- **Sender Blacklist** - Exclude specific senders
- **Subject Keywords** - Sync only emails with specific keywords
- **Subject Exclusions** - Exclude emails with specific keywords
- **Attachments Filter** - Only sync emails with document attachments

**Sync Operations:**
- **Manual Sync** - Sync on-demand in any time range (today, last 7 days, last 30 days)
- **Automatic Sync** - Schedule auto-sync at intervals (hourly, 6-hourly, daily, weekly)
- **Filter Application** - Automatically apply sync filters to all synced emails

**Document Conversion:**
- Emails are automatically converted to documents
- Email metadata (sender, subject, date) becomes document metadata
- Email content is stored for searching
- Read/unread status is tracked
- Synced emails are marked with Gmail ID for duplicate prevention

### Gmail Sync Workflow

1. **Authorization**: Connect your Gmail account via OAuth2
2. **Configuration**: Set up sync filters (optional)
3. **Sync**: Click "Sync Now" or enable auto-sync
4. **Document Creation**: Emails matching filters are converted to documents
5. **Organization**: Tagged and searchable as regular documents
6. **Management**: Download, archive, favorite, or tag synced documents

### Security Considerations

- **Encryption**: Gmail credentials are encrypted before storage using Fernet
- **2FA Required**: Gmail setup and sync require 2FA to be enabled
- **Read-Only Access**: Email Monitor requests read-only access to Gmail
- **Audit Logging**: All Gmail sync activities are logged
- **Token Refresh**: Credentials are automatically refreshed when needed
- **Disconnect Option**: Revoke Gmail access at any time in settings

### API Endpoints (Gmail)

- `GET /gmail/setup` - Gmail setup page
- `GET /gmail/callback` - OAuth2 callback handler
- `GET /gmail/configure` - Configure sync settings
- `POST /gmail/sync-config` - Save sync configuration
- `POST /gmail/sync` - Perform manual sync
- `POST /gmail/disconnect` - Disconnect Gmail account

## �📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (venv/virtualenv/conda)
- Google Cloud Project with Gmail API (optional)
- 500MB free disk space

## 🛠️ Installation

### 1. Clone or Download the Project

```bash
cd email-monitor
```

### 2. Create a Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Generate Encryption Key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 5. Configure Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```
SECRET_KEY=your-super-secret-key-here
ENCRYPTION_KEY=your-encryption-key-from-step-4
FLASK_ENV=production
FLASK_DEBUG=False

# Optional: Gmail API (for email sync)
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
```

### 6. Initialize Database

```bash
python app.py
# The database will be created automatically on first run
```

The application will be available at `http://localhost:5000`

## 📖 Usage Guide

### User Registration & Login

1. Navigate to `http://localhost:5000/register`
2. Enter your email and a strong password (12+ characters)
3. Password must include uppercase, lowercase, numbers, and special characters
4. Complete 2FA setup with your authenticator app
5. Login using your credentials and 2FA code

### Managing Documents

1. **Upload**: Click "Upload Document" to add files
2. **Search**: Use the search bar to find documents
3. **Filter**: Filter by direction (incoming/outgoing) or priority
4. **Tag**: Create custom tags for organization
5. **Archive**: Archive old documents to declutter
6. **Export**: Download documents as needed

### Dashboard & Analytics

- View email statistics for the last 7-30 days
- See incoming/outgoing email counts
- Track unread emails and attachments
- View recent documents

### Settings

- **Profile**: Update name, theme preferences, notification settings
- **Security**: Change password, manage 2FA, view login history
- **2FA**: Setup or disable two-factor authentication
- **Notifications**: Configure email and in-app notifications

## 📁 File Structure

```
email-monitor/
├── app.py                      # Main Flask application
├── config.py                   # Configuration settings
├── models.py                   # Database models (User, Document, Tag, etc.)
├── auth_service.py             # Authentication service with enhanced security
├── security.py                 # Security utilities (encryption, validation, decorators)
├── services.py                 # Business logic (audit, notifications, analytics)
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
├── README.md                   # This file
├── logs/                       # Audit logs directory
│   └── audit.log              # Comprehensive audit trail
├── uploads/                    # Uploaded documents
└── app/
    ├── templates/             # HTML templates
    │   ├── base.html         # Base template with navigation
    │   ├── login.html        # Login page
    │   ├── register.html     # Registration page
    │   ├── setup_2fa.html    # 2FA setup
    │   ├── verify_2fa.html   # 2FA verification
    │   ├── dashboard.html    # Dashboard with analytics
    │   ├── documents.html    # Documents list
    │   ├── view_document.html # Document details
    │   ├── upload_document.html # Upload form
    │   ├── tags.html         # Tag management
    │   ├── notifications.html # Notifications
    │   ├── settings.html     # User settings
    │   ├── analytics.html    # Analytics page
    │   └── audit_log.html    # Audit log (admin)
    └── static/
        ├── css/
        │   ├── style.css     # Main styling
        │   └── bootstrap.css # Bootstrap CSS
        └── js/
            ├── script.js     # Frontend JavaScript
            └── bootstrap.js  # Bootstrap JS
```

## 🗄️ Database Models

### User
- Full authentication with password hashing (PBKDF2)
- Role-based access (admin, user, viewer)
- Account locking after failed attempts
- 2FA configuration
- Login history tracking
- Preference settings

### Document
- Full metadata (title, sender, recipient, priority)
- File storage with integrity checking (SHA256)
- Direction tracking (incoming/outgoing)
- Status management (pending, received, sent, filed)
- Tagging system
- Favorites and archiving
- View count tracking

### Tag
- User-defined tags with custom colors
- Document association
- Creation/update timestamps

### AuditLog
- Comprehensive action tracking
- IP address and user agent capture
- Resource change logging
- Automatic retention policy (90 days default)

### Notification
- In-app notification system
- Email notification support
- Expiration-based cleanup
- Action URL linking

### LoginHistory
- Track all login attempts
- Success/failure tracking
- IP addresses
- User agents
- Failure reasons

## 🔑 Key Security Implementations

### Password Security
- Minimum 12 characters required
- Enforce uppercase, lowercase, numbers, special characters
- Automatic hashing with PBKDF2 (100,000 iterations)
- Cannot reuse recent passwords
- 90-day expiration recommended

### Two-Factor Authentication
- Time-based One-Time Password (TOTP)
- QR code generation for authenticator apps
- 10 backup codes per account  
- Compatible with Google Authenticator, Authy, Microsoft Authenticator

### Rate Limiting
- Login: 5 attempts per minute
- API: 1000 requests per hour
- Default: 200 per day, 50 per hour

### Account Security
- Account lockout after 5 failed logins (15 minutes)
- Session timeout: 24 hours
- HTTPOnly cookies prevent JavaScript access
- Secure flag for HTTPS environments
- SameSite=Lax for CSRF protection

### Audit Trail
- All actions logged with timestamp, user, IP, action type
- File operations tracked (upload, download)
- Security event logging
- Data retention for 90 days

## 🚀 API Endpoints

### Authentication
- `POST /register` - User registration
- `POST /login` - User login
- `POST /logout` - Logout
- `POST /setup-2fa` - Setup 2FA
- `POST /verify-2fa` - Verify 2FA token
- `POST /confirm-2fa` - Confirm 2FA setup
- `POST /disable-2fa` - Disable 2FA
- `GET /change-password` - Change password form
- `POST /change-password` - Submit password change

### Documents
- `GET /documents` - List documents with search
- `POST /documents/upload` - Upload document
- `GET /document/<id>` - View document details
- `GET /document/<id>/download` - Download document
- `POST /document/<id>/favorite` - Toggle favorite
- `POST /document/<id>/archive` - Archive document
- `POST /document/<id>/tag` - Add tag to document

### Tags
- `GET /tags` - List all tags
- `POST /tags/create` - Create new tag
- `POST /tags/<id>/delete` - Delete tag

### Notifications
- `GET /notifications` - List notifications
- `POST /notifications/<id>/read` - Mark as read
- `GET /notifications/unread-count` - Get unread count

### Analytics
- `GET /analytics` - View analytics dashboard
- `GET /api/stats/daily` - Daily stats (JSON)
- `GET /api/documents/search` - Search API

### Admin
- `GET /audit-log` - View audit log (admin only)

## 🛡️ Security Best Practices

1. **Change SECRET_KEY** before deploying to production
2. **Use HTTPS** in production environments
3. **Enable 2FA** for all user accounts
4. **Review audit logs** regularly
5. **Update dependencies** regularly (`pip install --upgrade`)
6. **Use strong passwords** and change them periodically
7. **Backup database** regularly
8. **Monitor failed login attempts** in audit logs
9. **Set proper file permissions** on uploads directory
10. **Disable debug mode** in production

## 🐛 Troubleshooting

### "Invalid password"
Requirements: 12+ chars, uppercase, lowercase, numbers, special characters

### "Account locked"
Too many failed login attempts. Try again in 15 minutes.

### "CSRF token missing"
Browser cookies may be disabled. Enable cookies and try again.

### "2FA verification failed"
Time on your device may be out of sync. Synchronize with time server.

### "Database locked"
Restart the application. Ensure only one instance is running.

### "Permission denied on uploads"
Check uploads/ directory permissions: `chmod 755 uploads/`

## 📊 Monitoring & Maintenance

### Regular Backups
```bash
# Backup database
cp email_monitor.db email_monitor.db.backup

# Backup logs
cp logs/audit.log logs/audit.log.backup
```

### Cleanup Old Data
```python
from services import AuditService
AuditService.cleanup_old_logs(days=90)
```

### Check Python Packages
```bash
pip audit  # Check for vulnerabilities
pip list   # List installed packages
```

## 📈 Performance Optimization

- Database indexing on frequently filtered fields
- Pagination (20 documents per page)
- Query optimization with lazy loading
- Static file caching
- Efficient search algorithms

## 🔄 Backup & Restore

### Backup
```bash
# Full backup
tar -czf email-monitor-backup.tar.gz email-monitor/

# Database only
cp email_monitor.db backups/email_monitor.db.$(date +%Y%m%d)
```

### Restore
```bash
# From tar
tar -xzf email-monitor-backup.tar.gz

# From database backup
cp backups/email_monitor.db.YYYYMMDD email_monitor.db
```

## 🚀 Deployment Guide

### Production Checklist
- [ ] Change SECRET_KEY
- [ ] Set FLASK_ENV=production
- [ ] Set FLASK_DEBUG=False
- [ ] Generate strong ENCRYPTION_KEY
- [ ] Configure HTTPS
- [ ] Setup database backups
- [ ] Enable audit logging
- [ ] Configure firewall
- [ ] Setup rate limiting
- [ ] Enable 2FA for admins

### Docker Deployment
```dockerfile
FROM python:3.10
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

## 📝 Changelog

### Version 2.0.0 (Current)
- Added comprehensive security features (2FA, CSRF, rate limiting)
- Implemented audit logging system
- Added document tagging and organization
- Added analytics and reporting
- Enhanced password requirements
- Added login history tracking
- Implemented role-based access control
- Added notification system
- Improved database schema
- Enhanced UI/UX

### Version 1.0.0 (Previous)
- Initial release with basic email monitoring

## 📄 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 💬 Support

For issues, questions, or suggestions, please open an issue on GitHub or check the troubleshooting section.

---

**Updated**: February 25, 2026
**Version**: 2.0.0
**Status**: Production Ready with Enterprise Security

