"""
Gmail Service - Gmail API integration for Email Monitor
Handles OAuth2 authentication and email syncing
"""

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import base64
import re
from email.mime.text import MIMEText
from config import Config
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class GmailService:
    """Service to handle Gmail API interactions"""
    
    def __init__(self, credentials_json=None):
        self.service = None
        self.credentials = None
        self.credentials_json = credentials_json
    
    def get_auth_url(self):
        """Get the OAuth2 authentication URL"""
        flow = Flow.from_client_config(
            self._get_client_config(),
            scopes=Config.SCOPES,
            redirect_uri=Config.GOOGLE_REDIRECT_URI
        )
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        return auth_url, state
    
    def get_credentials_from_code(self, code):
        """Exchange authorization code for credentials"""
        try:
            print(f"\n📧 Starting token exchange for authorization code")
            print(f"   Redirect URI: {Config.GOOGLE_REDIRECT_URI}")
            print(f"   Client ID: {Config.GOOGLE_CLIENT_ID[:20]}...")
            
            flow = Flow.from_client_config(
                self._get_client_config(),
                scopes=Config.SCOPES,
                redirect_uri=Config.GOOGLE_REDIRECT_URI
            )
            
            print(f"   Flow created, calling fetch_token...")
            flow.fetch_token(code=code)
            credentials = flow.credentials
            
            print(f"✅ Token exchange successful")
            print(f"   Access Token: {credentials.token[:30]}...")
            print(f"   Refresh Token: {credentials.refresh_token[:30] if credentials.refresh_token else 'None'}...")
            
            return credentials
        
        except Exception as e:
            print(f"\n❌ Token exchange failed: {type(e).__name__}: {str(e)}")
            if hasattr(e, 'response'):
                print(f"   Response status: {e.response.status}")
                print(f"   Response body: {e.response.content}")
            raise Exception(f"Failed to exchange authorization code: {str(e)}")
    
    def set_credentials(self, token_json):
        """Set credentials from JSON token"""
        self.credentials = Credentials.from_authorized_user_info(
            token_json,
            scopes=Config.SCOPES
        )
        self._build_service()
    
    def set_credentials_object(self, credentials):
        """Set credentials from Credentials object"""
        self.credentials = credentials
        self._build_service()
    
    def refresh_credentials(self, refresh_token):
        """Refresh access token using refresh token"""
        self.credentials = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=Config.GOOGLE_CLIENT_ID,
            client_secret=Config.GOOGLE_CLIENT_SECRET,
            scopes=Config.SCOPES
        )
        self.credentials.refresh(Request())
        self._build_service()
        return self.credentials
    
    def _build_service(self):
        """Build Gmail service"""
        if self.credentials:
            self.service = build('gmail', 'v1', credentials=self.credentials)
    
    def get_profile(self):
        """Get user's Gmail profile"""
        if not self.service:
            return None
        profile = self.service.users().getProfile(userId='me').execute()
        return profile
    
    def get_recent_emails(self, days=7, max_results=20, query=''):
        """
        Get recent emails from Gmail
        
        Args:
            days: Number of days back to fetch
            max_results: Maximum number of emails to return
            query: Additional Gmail search query
            
        Returns:
            List of email dictionaries
        """
        try:
            if not self.service:
                return []
            
            # Build search query for recent emails
            start_date = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d')
            search_query = f'after:{start_date}'
            
            if query:
                search_query += f' {query}'
            
            # Get email IDs
            results = self.service.users().messages().list(
                userId='me',
                q=search_query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            # Get full email data for each message
            for msg in messages:
                email_data = self._get_message_data(msg['id'])
                if email_data:
                    emails.append(email_data)
            
            logger.info(f"Retrieved {len(emails)} emails from Gmail")
            return emails
        
        except Exception as e:
            logger.error(f"Failed to get recent emails: {str(e)}")
            print(f"Error getting emails: {e}")
            return []
    
    def _get_message_data(self, message_id):
        """Get full message data from Gmail"""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            headers = message['payload']['headers']
            header_dict = {h['name']: h['value'] for h in headers}
            
            # Extract header information
            subject = header_dict.get('Subject', 'No Subject')
            sender = header_dict.get('From', 'Unknown')
            recipient = header_dict.get('To', '')
            date_str = header_dict.get('Date', '')
            
            # Parse email body
            body = self._get_message_body(message)
            
            # Check for attachments
            has_attachments = 'parts' in message['payload'] and any(
                part.get('filename') for part in message['payload'].get('parts', [])
            )
            
            # Parse date
            try:
                # Try to parse various date formats
                if ',' in date_str:
                    email_date = datetime.strptime(date_str.split(',')[1].strip()[:16], '%d %b %Y %H:%M')
                else:
                    email_date = datetime.strptime(date_str[:16], '%Y-%m-%d %H:%M')
            except:
                email_date = datetime.utcnow()
            
            # Check if read
            is_read = 'UNREAD' not in message.get('labelIds', [])
            
            return {
                'gmail_id': message_id,
                'subject': subject,
                'sender': self._extract_email(sender),
                'sender_name': sender,
                'recipient': self._extract_email(recipient),
                'body': body,
                'snippet': message.get('snippet', ''),
                'date': email_date,
                'has_attachments': has_attachments,
                'is_read': is_read
            }
        
        except Exception as e:
            logger.error(f"Failed to get message data for {message_id}: {str(e)}")
            return None
    
    def _get_message_body(self, message):
        """Extract message body from Gmail message"""
        try:
            if 'parts' in message['payload']:
                parts = message['payload']['parts']
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        if 'data' in part['body']:
                            data = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            return data[:500]  # Limit to 500 chars
            else:
                if 'data' in message['payload']['body']:
                    data = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')
                    return data[:500]
        except:
            pass
        
        return message.get('snippet', '')[:500]
    
    def _extract_email(self, email_string):
        """Extract email address from name <email> format"""
        if '<' in email_string and '>' in email_string:
            return email_string.split('<')[1].split('>')[0].strip()
        return email_string.strip()
    
    def filter_emails(self, emails, filter_config):
        """
        Filter emails based on configuration
        
        Args:
            emails: List of email dictionaries
            filter_config: Dictionary with filter settings
                
        Returns:
            Filtered list of emails
        """
        if not filter_config:
            return emails
        
        filtered = []
        
        for email in emails:
            # Check attachment filter
            if filter_config.get('has_attachments_only') and not email.get('has_attachments'):
                continue
            
            # Check sender include (whitelist)
            sender_include = filter_config.get('sender_include', '').strip()
            if sender_include:
                include_list = [s.strip().lower() for s in sender_include.split(',') if s.strip()]
                if include_list and email['sender'].lower() not in include_list:
                    continue
            
            # Check sender exclude (blacklist)
            sender_exclude = filter_config.get('sender_exclude', '').strip()
            if sender_exclude:
                exclude_list = [s.strip().lower() for s in sender_exclude.split(',') if s.strip()]
                if any(email['sender'].lower() == ex for ex in exclude_list):
                    continue
            
            # Check subject keywords (must contain at least one)
            subject_keywords = filter_config.get('subject_keywords', '').strip()
            if subject_keywords:
                keyword_list = [k.strip().lower() for k in subject_keywords.split(',') if k.strip()]
                if keyword_list and not any(kw in email['subject'].lower() for kw in keyword_list):
                    continue
            
            # Check subject exclude
            subject_exclude = filter_config.get('subject_exclude', '').strip()
            if subject_exclude:
                exclude_keywords = [k.strip().lower() for k in subject_exclude.split(',') if k.strip()]
                if any(kw in email['subject'].lower() for kw in exclude_keywords):
                    continue
            
            filtered.append(email)
        
        logger.info(f"Filtered {len(emails)} emails to {len(filtered)} emails")
        return filtered
    
    def get_inbox_stats(self):
        """Get inbox statistics"""
        if not self.service:
            return None
        
        try:
            # Get total messages
            profile = self.service.users().getProfile(userId='me').execute()
            total_messages = profile.get('messagesTotal', 0)
            unread_messages = profile.get('messagesUnread', 0)
            
            # Get received emails (last 7 days)
            start_date = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
            query = f'in:inbox after:{start_date}'
            received = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=1
            ).execute()
            received_count = received.get('resultSizeEstimate', 0)
            
            # Get sent emails (last 7 days)
            query = f'in:sent after:{start_date}'
            sent = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=1
            ).execute()
            sent_count = sent.get('resultSizeEstimate', 0)
            
            return {
                'total_messages': total_messages,
                'unread_messages': unread_messages,
                'received_count': received_count,
                'sent_count': sent_count
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            print(f"Error getting stats: {e}")
            return {
                'total_messages': 0,
                'unread_messages': 0,
                'received_count': 0,
                'sent_count': 0
            }
    
    def _get_client_config(self):
        """Get OAuth2 client configuration"""
        return {
            'installed': {
                'client_id': Config.GOOGLE_CLIENT_ID,
                'client_secret': Config.GOOGLE_CLIENT_SECRET,
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [Config.GOOGLE_REDIRECT_URI]
            }
        }
