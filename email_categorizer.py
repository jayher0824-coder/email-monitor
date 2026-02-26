"""
Email Categorization and Intelligence Module
Automatically categorizes emails and extracts intelligent metadata
"""

import re
from typing import Tuple

class EmailCategorizer:
    """Smart email categorization engine"""
    
    # Keywords for work emails
    WORK_KEYWORDS = [
        r'\b(project|deadline|meeting|conference|workshop|presentation|proposal|contract|invoice|payment|budget|report|analysis|strategy|implementation|documentation|code|bug|issue|feature|release|deploy|schedule|task|assigned|team|department|office|workplace|professional|business|corporate|client|customer|vendor|supplier|partner|account|deal|sales|marketing|development|engineering|support|ticket|incident|alert|critical|urgent)\b',
        r'\b(re:|fwd:|[a-z0-9._%+-]+@[a-z0-9.-]+\.(com|org|net|gov|edu|io))\b',
    ]
    
    # Keywords for general/notification emails
    GENERAL_KEYWORDS = [
        r'\b(newsletter|notification|alert|update|news|magazine|subscription|promotion|discount|offer|sale|deal|coupon|store|shop|order|shipping|delivery|confirmation|receipt|invoice|bill|statement|unsubscribe|copyright|hello|hi|hey|friend|family|personal|birthday|anniversary|vacation|travel|holiday|weekend|dinner|lunch|coffee|drinks)\b',
    ]
    
    @classmethod
    def categorize_email(cls, sender: str, recipient: str, subject: str, body: str = '') -> str:
        """
        Categorize an email into work or general.
        
        Args:
            sender: Email sender address
            recipient: Email recipient address
            subject: Email subject line
            body: Email body text (optional)
        
        Returns:
            Category: 'work' or 'general'
        """
        # Combine all text for analysis
        text = f"{sender} {recipient} {subject} {body}".lower()
        
        # Check for work indicators
        if cls._has_keywords(text, cls.WORK_KEYWORDS, threshold=1):
            return 'work'
        
        # Default to general (includes personal emails, newsletters, notifications)
        return 'general'
    
    @classmethod
    def _has_keywords(cls, text: str, patterns: list, threshold: int = 1) -> bool:
        """Check if text contains keywords from patterns"""
        matches = 0
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches += 1
                if matches >= threshold:
                    return True
        return False
    
    @classmethod
    def extract_email_domain(cls, email: str) -> str:
        """Extract domain from email address"""
        if '@' in email:
            return email.split('@')[1]
        return ''
    
    @classmethod
    def is_work_email(cls, email_address: str) -> bool:
        """Check if email is from a work domain"""
        domain = cls.extract_email_domain(email_address)
        # Common corporate domains
        corporate_domains = ['company', 'corp', 'business', 'office', 'corporate', 'work', 'professional', 'enterprise', 'industry', 'tech', 'software', 'solutions', 'consulting', 'agency', 'studio']
        
        for corp in corporate_domains:
            if corp in domain:
                return True
        
        # Check if domain is NOT a common personal email
        personal_domains = ['gmail', 'yahoo', 'outlook', 'hotmail', 'aol', 'protonmail', 'mail', 'email']
        for personal in personal_domains:
            if personal in domain:
                return False
        
        # If not personal and not generic, probably work
        return not any(p in domain for p in personal_domains)


class EmailAnalyzer:
    """Analyzes email content for metadata extraction"""
    
    @staticmethod
    def is_likely_reply(subject: str) -> bool:
        """Check if email is likely a reply"""
        return bool(re.match(r'^re:', subject, re.IGNORECASE))
    
    @staticmethod
    def is_likely_forward(subject: str) -> bool:
        """Check if email is likely a forward"""
        return bool(re.match(r'^fwd:', subject, re.IGNORECASE))
    
    @staticmethod
    def extract_primary_email(email_addresses: list) -> str:
        """Extract primary email from a list"""
        if not email_addresses:
            return ''
        # Usually the first one is primary
        return email_addresses[0]
    
    @staticmethod
    def is_bulk_email(sender: str, recipient_list: list) -> bool:
        """Check if email appears to be sent to bulk recipients"""
        # If there are many recipients, it's probably bulk/newsletter
        return len(recipient_list) > 5
    
    @staticmethod
    def contains_attachment_keywords(subject: str, body: str = '') -> bool:
        """Check if email mentions attachments"""
        keywords = ['attachment', 'attached', 'document', 'file', 'download', 'see attached', 'attached below']
        text = f"{subject} {body}".lower()
        return any(keyword in text for keyword in keywords)
