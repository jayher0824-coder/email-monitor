# 📄 Email Monitor - Secure Email & Document Management System

A comprehensive Flask-based web application for managing emails, documents, and approval workflows with enterprise-grade security features.

## 🚀 Features

### Core Features
- **Email Integration**: Gmail OAuth2 integration for email monitoring and management
- **Document Management**: Upload, store, and organize documents with metadata tracking
- **Approval Workflows**: Multi-stage document approval process with audit trails
- **Document Filing**: Automatic categorization and filing of incoming/outgoing documents
- **Email Search & Tags**: Advanced search with tagging system

### Security Features
- **Two-Factor Authentication (2FA)**: SMS-based 2FA support
- **Secure Password Hashing**: PBKDF2 with salt
- **CSRF Protection**: WTForms CSRF tokens
- **Rate Limiting**: Configurable rate limiting on sensitive endpoints
- **Account Lockout**: Automatic lockout after failed login attempts
- **Audit Logging**: Comprehensive action tracking and security events
- **Input Validation**: XSS protection and SQL injection prevention
- **Content Security Policy**: CSP headers for additional protection
- **Encrypted Sessions**: Secure cookie-based sessions

### Admin Features
- **User Management**: Create, view, activate/deactivate user accounts
- **Audit Dashboard**: View system-wide security events and actions
- **User Analytics**: Login history, document statistics per user
- **Password Reset**: Admin can reset user passwords
- **User Deletion**: Remove users and associated documents

## 📋 Tech Stack

- **Backend**: Flask (Python 3.11)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: Jinja2 templates, Bootstrap styling, Chart.js
- **Authentication**: Flask-Session, custom auth service
- **Email**: Gmail API via OAuth2
- **Security**: Flask-WTF, Flask-Limiter, custom security modules

## 🛠️ Installation

### Prerequisites
- Python 3.11+
- pip

### Setup Steps

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/email-monitor.git
cd email-monitor
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your settings
```

5. **Set up Gmail OAuth credentials**
- Go to [Google Cloud Console](https://console.cloud.google.com/)
- Create OAuth 2.0 credentials (Desktop application)
- Download credentials JSON
- Place in project root as `credentials.json`

6. **Run the application**
```bash
python app.py
```

Visit `http://localhost:5000` in your browser.

## 📁 Project Structure

```
email-monitor/
├── app.py                    # Main Flask application
├── config.py               # Configuration settings
├── models.py               # SQLAlchemy models
├── auth_service.py         # Authentication logic
├── security.py             # Security utilities
├── services.py             # Service classes
├── gmail_service.py        # Gmail integration
├── email_categorizer.py    # Email categorization
├── requirements.txt        # Python dependencies
├── app/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css   # Global styles
│   │   └── js/
│   │       └── script.js   # Client-side scripts
│   └── templates/          # Jinja2 templates
│       ├── base.html       # Base template
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       ├── emails.html
│       ├── documents.html
│       ├── approval_queue.html
│       ├── admin_users.html
│       └── ...
├── logs/                   # Application logs
├── uploads/                # Uploaded files
└── instance/               # Instance-specific files
```

## 🔑 Key Endpoints

### Authentication
- `GET/POST /register` - User registration
- `GET/POST /login` - User login
- `GET/POST /setup-2fa` - Set up two-factor authentication
- `GET/POST /verify-2fa` - Verify 2FA code
- `GET/POST /change-password` - Change password

### Documents
- `GET /dashboard` - Main dashboard
- `GET/POST /document/prepare` - Create outgoing documents
- `GET/POST /document/receive` - Log incoming documents
- `GET /documents` - View all documents
- `GET /archive` - View archived documents

### Approval Workflow
- `GET /approvals` - View pending approvals (admin)
- `GET /approval/<id>` - View approval detail
- `POST /approval/<id>/approve` - Approve document
- `POST /approval/<id>/reject` - Reject document
- `POST /approval/<id>/request-revision` - Request revision

### Admin
- `GET /admin/users` - User management dashboard
- `GET /admin/user/<id>` - View user details
- `POST /admin/user/<id>/activate` - Activate user
- `POST /admin/user/<id>/deactivate` - Deactivate user
- `POST /admin/user/<id>/reset-password` - Reset user password

## ⚙️ Configuration

Edit `config.py` to customize:
- Password requirements (uppercase, lowercase, numbers, special chars, min length)
- Session security (cookie settings, lifetime)
- Rate limiting rules
- Account lockout duration
- CSRF protection settings

## 🚨 Security Notes

### Before Deployment
1. **Change SECRET_KEY** in config.py (use strong random key)
2. **Set SESSION_COOKIE_SECURE = False** for development, `True` for HTTPS
3. **Use environment variables** for sensitive data
4. **Never commit** credentials.json, token.json, or .env files
5. **Use HTTPS** in production
6. **Configure database** to use PostgreSQL for production
7. **Set up proper logging** and monitoring
8. **Enable CORS** only for trusted domains
9. **Review rate limiting** settings for your use case

### Sensitive Files (Not Committed)
- `.env` - Environment variables
- `credentials.json` - Gmail OAuth credentials
- `token.json` - Gmail API tokens
- `*.db` - Database files
- `logs/` - Log files containing sensitive data

## 📊 Database Models

### User
- Email, password hash, role, 2FA settings
- Account status, login history, audit logs

### Document
- Title, file path, metadata, tags
- Status tracking (filed, archived, etc.)

### DocumentApproval
- Approval workflow tracking
- Requester, approver, status, comments
- Timestamps for audit trail

### AuditLog
- Comprehensive action logging
- Security events, changes tracking

## 🧪 Testing

Run development server with debug disabled:
```bash
python app.py
```

The application uses SQLite in-memory storage for rate limiting by default. For production, configure Redis as storage backend.

## 📝 License

[Choose your license - MIT, Apache 2.0, etc.]

## 🤝 Contributing

1. Create a feature branch (`git checkout -b feature/AmazingFeature`)
2. Commit changes (`git commit -m 'Add AmazingFeature'`)
3. Push to branch (`git push origin feature/AmazingFeature`)
4. Open a Pull Request

## ⚠️ Important Before Publishing

- [ ] Remove/regenerate SECRET_KEY
- [ ] Remove credentials.json and token.json
- [ ] Update .env.example with placeholder values
- [ ] Add license file (LICENSE)
- [ ] Review all hardcoded values in code
- [ ] Update database URI for PostgreSQL (production)
- [ ] Verify .gitignore includes all sensitive files
- [ ] Add CONTRIBUTING.md
- [ ] Add CODE_OF_CONDUCT.md

## 📞 Support

For issues and questions, please open an issue on GitHub.

## 👤 Author

[Your Name/Organization]

---

**Last Updated**: February 2026
**Status**: Active Development
