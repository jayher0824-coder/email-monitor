"""
Email Monitor API Documentation
================================

BASE URL: http://localhost:8000

## Authentication
All endpoints except /login and /demo require an active session.

## Endpoints

### Dashboard & Core
GET  /                          - Main dashboard with stats and charts
GET  /login                     - Login page (redirects to demo)
GET  /demo                      - Demo login with sample emails
GET  /logout                    - Logout and clear session

### Email Management
GET  /emails                    - Email logs page with filters
POST /sync-emails               - Sync emails from Gmail

### API Endpoints (JSON)
GET  /api/stats                 - Get current statistics
GET  /api/analytics             - Get comprehensive analytics data
GET  /api/email/<id>            - Get detailed email information
POST /api/email/<id>/read       - Mark email as read/unread
POST /api/email/<id>/star       - Toggle email star status
POST /api/search/advanced       - Advanced search with multiple filters

## Detailed Endpoint Descriptions

### GET /api/stats
Returns current email statistics.

Response:
{
  "total_emails": 100,
  "incoming": 60,
  "outgoing": 40,
  "unread": 5,
  "with_attachments": 12,
  "work": 45,
  "personal": 30,
  "general": 25,
  "starred": 8
}

### GET /api/analytics
Returns comprehensive analytics data for visualization.

Response:
{
  "direction": {
    "incoming": 60,
    "outgoing": 40
  },
  "category": {
    "work": 45,
    "personal": 30,
    "general": 25
  },
  "emails_by_day": {
    "2026-02-24": 10,
    "2026-02-23": 8,
    ...
  },
  "status": {
    "read": 95,
    "unread": 5,
    "starred": 8,
    "with_attachments": 12
  },
  "total_unique_senders": 35,
  "average_emails_per_day": 14.3
}

### GET /api/email/<id>
Returns detailed information about a specific email.

Response:
{
  "id": 1,
  "gmail_id": "187d123abc",
  "sender": "john@company.com",
  "recipient": "you@gmail.com",
  "subject": "Project Update",
  "direction": "in",
  "category": "work",
  "received_at": "2026-02-24T10:30:00",
  "snippet": "Here's the latest project update...",
  "has_attachment": true,
  "is_read": true,
  "is_starred": false,
  "stored_at": "2026-02-24T10:35:00"
}

### POST /api/email/<id>/read
Mark an email as read or unread.

Request Body:
{
  "is_read": true
}

Response:
{
  "success": true,
  "message": "Email status updated",
  "is_read": true
}

### POST /api/email/<id>/star
Toggle star status of an email.

Request Body: (empty)

Response:
{
  "success": true,
  "message": "Email starred status updated",
  "is_starred": true
}

### POST /api/search/advanced
Advanced search with multiple filters.

Request Body:
{
  "direction": "in",           // "in", "out", or "all"
  "category": "work",          // "work", "personal", "general", or "all"
  "read_status": "unread",     // "read", "unread", or null
  "starred_only": false,       // boolean
  "has_attachments_only": false,  // boolean
  "search_text": "project",    // search text
  "from_date": "2026-02-20",   // ISO date
  "to_date": "2026-02-25",     // ISO date
  "page": 1,                   // page number
  "per_page": 20               // results per page
}

Response:
{
  "success": true,
  "results": [
    {
      "id": 1,
      "sender": "john@company.com",
      "recipient": "you@gmail.com",
      "subject": "Project Update",
      "direction": "in",
      "category": "work",
      "received_at": "2026-02-24T10:30:00",
      "is_read": true,
      "is_starred": false,
      "has_attachment": true
    }
  ],
  "total": 25,
  "pages": 2,
  "current_page": 1
}

### GET /emails?direction=in&category=work&search=project&page=1
Email logs page with filters.

Parameters:
- direction: "all", "in", or "out"
- category: "all", "work", "personal", or "general"
- search: search text
- page: page number

### POST /sync-emails
Sync emails from Gmail account.

Response:
{
  "success": true,
  "message": "Emails synced successfully",
  "inbox_count": 10,
  "sent_count": 5,
  "total_synced": 15,
  "mode": "real" or "demo"
}

## Error Responses

All endpoints return appropriate HTTP status codes:
- 200: Success
- 401: Unauthorized (not logged in)
- 404: Not found
- 500: Server error

Error Response Format:
{
  "error": "Error message describing what went wrong"
}

## Features

### Smart Email Categorization
Emails are automatically categorized into:
- Work: Detected by work-related keywords, corporate email domains
- Personal: Detected by personal keywords and relationships
- General: Newsletters, notifications, promotional content

### Metadata Extraction
- Attachment detection
- Read/unread status tracking
- Star/flag status
- Direction detection (incoming vs outgoing)
- Email threading (reply/forward detection)

### Real-time Updates
- Dashboard stats update every 30 seconds
- Email counts refresh automatically
- Analytics data updates with each sync

### Privacy & Security
- All data stored locally in SQLite database
- Sessions managed securely
- Demo mode for testing without Gmail credentials
- OAuth2 integration for real Gmail accounts
