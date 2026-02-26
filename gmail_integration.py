import os
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.api_core import retry
from googleapiclient.discovery import build
from datetime import datetime, timedelta

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class GmailService:
    """Service to interact with Gmail API"""
    
    def __init__(self):
        self.service = None
        self.creds = None
    
    def authenticate(self, credentials_file='credentials.json', token_file='token.json'):
        """Authenticate with Gmail API using OAuth2"""
        print(f"\n[SECURE] Starting Gmail authentication...")
        print(f"   Looking for credentials file: {credentials_file}")
        
        # Check if token already exists
        if os.path.exists(token_file):
            print(f"[OK] Found existing token: {token_file}")
            self.creds = Credentials.from_authorized_user_file(token_file, SCOPES)
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
                print(f"[OK] Token refreshed")
        
        # If no token, get new credentials
        if not self.creds or not self.creds.valid:
            if not os.path.exists(credentials_file):
                raise FileNotFoundError(
                    f"[ERROR] {credentials_file} not found!\n"
                    "Get it from Google Cloud Console:\n"
                    "1. Go to https://console.cloud.google.com\n"
                    "2. Create a project\n"
                    "3. Enable Gmail API\n"
                    "4. Create OAuth 2.0 credentials (Desktop app)\n"
                    "5. Download and save as credentials.json"
                )
            
            print(f"[BROWSER] Opening browser for Gmail login...")
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_file, SCOPES)
            self.creds = flow.run_local_server(port=8080)
            
            # Save the token for future use
            with open(token_file, 'w') as token:
                token.write(self.creds.to_json())
            print(f"[OK] Token saved: {token_file}")
        
        # Build Gmail service
        self.service = build('gmail', 'v1', credentials=self.creds)
        print(f"[OK] Gmail service authenticated")
        return self.service
    
    def get_messages(self, query='', max_results=10):
        """Get messages from Gmail"""
        try:
            print(f"\n[EMAIL] Fetching messages with query: '{query}'")
            results = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            print(f"[OK] Found {len(messages)} messages")
            return messages
        except Exception as e:
            print(f"[ERROR] Error fetching messages: {e}")
            return []
    
    def get_message(self, msg_id):
        """Get full message details"""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=msg_id,
                format='full'
            ).execute()
            return message
        except Exception as e:
            print(f"[ERROR] Error getting message {msg_id}: {e}")
            return None
    
    def parse_message(self, message):
        """Parse Gmail message into structured format"""
        try:
            headers = message['payload']['headers']
            
            # Extract headers
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            recipient = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown')
            date_str = next((h['value'] for h in headers if h['name'] == 'Date'), None)
            
            # Parse date
            try:
                from email.utils import parsedate_to_datetime
                date_obj = parsedate_to_datetime(date_str) if date_str else datetime.utcnow()
            except:
                date_obj = datetime.utcnow()
            
            # Get body
            body = self.get_message_body(message)
            
            # Check for attachments
            has_attachments = self.check_attachments(message)
            
            return {
                'gmail_id': message['id'],
                'subject': subject,
                'sender': sender,
                'recipient': recipient,
                'date': date_obj,
                'body': body[:500],  # First 500 chars
                'has_attachments': has_attachments
            }
        except Exception as e:
            print(f"[ERROR] Error parsing message: {e}")
            return None
    
    def get_message_body(self, message):
        """Extract message body"""
        try:
            payload = message['payload']
            
            if 'parts' in payload:
                # Multi-part message
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        data = part['body'].get('data', '')
                        return base64.urlsafe_b64decode(data).decode('utf-8')
            else:
                # Simple message
                data = payload['body'].get('data', '')
                if data:
                    return base64.urlsafe_b64decode(data).decode('utf-8')
            
            return ''
        except:
            return ''
    
    def check_attachments(self, message):
        """Check if message has attachments"""
        try:
            payload = message['payload']
            if 'parts' in payload:
                for part in payload['parts']:
                    if part.get('filename'):
                        return True
            return False
        except:
            return False
    
    def get_attachment(self, msg_id, att_id):
        """Download attachment"""
        try:
            attachment = self.service.users().messages().attachments().get(
                userId='me',
                messageId=msg_id,
                id=att_id
            ).execute()
            
            data = attachment['data']
            file_data = base64.urlsafe_b64decode(data)
            return file_data
        except Exception as e:
            print(f"[ERROR] Error downloading attachment: {e}")
            return None
    
    def get_recent_emails(self, days=7, max_results=20):
        """Get recent emails from the last N days"""
        from_date = (datetime.utcnow() - timedelta(days=days)).strftime('%Y/%m/%d')
        query = f'after:{from_date}'
        
        messages = self.get_messages(query, max_results)
        
        parsed_messages = []
        for msg in messages:
            full_msg = self.get_message(msg['id'])
            if full_msg:
                parsed = self.parse_message(full_msg)
                if parsed:
                    parsed_messages.append(parsed)
        
        return parsed_messages
    
    def filter_emails(self, emails, filters):
        """Apply user filters to emails"""
        if not filters or not emails:
            return emails
        
        filtered = []
        
        for email in emails:
            # Check sender whitelist (include_only)
            if filters.get('sender_include'):
                senders = [s.strip().lower() for s in filters['sender_include'].split(',') if s.strip()]
                email_from = email['sender'].lower()
                if not any(sender in email_from for sender in senders):
                    continue
            
            # Check sender blacklist (exclude)
            if filters.get('sender_exclude'):
                senders = [s.strip().lower() for s in filters['sender_exclude'].split(',') if s.strip()]
                email_from = email['sender'].lower()
                if any(sender in email_from for sender in senders):
                    continue
            
            # Check subject keywords (include)
            if filters.get('subject_keywords'):
                keywords = [k.strip().lower() for k in filters['subject_keywords'].split(',') if k.strip()]
                subject = email['subject'].lower()
                if not any(keyword in subject for keyword in keywords):
                    continue
            
            # Check subject exclusions
            if filters.get('subject_exclude'):
                keywords = [k.strip().lower() for k in filters['subject_exclude'].split(',') if k.strip()]
                subject = email['subject'].lower()
                if any(keyword in subject for keyword in keywords):
                    continue
            
            # Check attachment requirement
            if filters.get('has_attachments_only') and not email['has_attachments']:
                continue
            
            filtered.append(email)
        
        return filtered
