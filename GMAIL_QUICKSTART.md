# Gmail Integration Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Prerequisites
- ✅ Email Monitor account (already created)
- ✅ 2FA enabled (go to Settings → Security → Enable 2FA if not done)
- ✅ Gmail account (Google account)

### Step 2: Google Cloud Setup (One-Time)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project: Click "Select a Project" → "New Project"
   - Name: "Email Monitor"
   - Click "Create"

3. Enable Gmail API:
   - Click "APIs & Services" in left menu
   - Click "Library"
   - Search: "Gmail API"
   - Click the result
   - Click "Enable"

4. Create OAuth2 Credentials:
   - Click "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth 2.0 Client IDs"
   - Select "Web application"
   - Under "Authorized redirect URIs", add:
     ```
     http://localhost:5000/gmail/callback
     ```
   - Click "Create"
   - Copy the Client ID and Client Secret

5. Set Environment Variables:
   - Open `.env` file in Email Monitor directory
   - Add:
     ```
     GOOGLE_CLIENT_ID=your-client-id-here
     GOOGLE_CLIENT_SECRET=your-client-secret-here
     GOOGLE_REDIRECT_URI=http://localhost:5000/gmail/callback
     ```
   - Save and restart Email Monitor

### Step 3: Connect Gmail (In Email Monitor)

1. Log in to Email Monitor
2. Go to **Settings** (top right profile menu)
3. Click **Gmail Integration** tab
4. Click **Connect Gmail** button
5. You'll be redirected to Google
6. Click **Allow** to give Email Monitor permission
7. You'll return to Email Monitor
8. ✅ Gmail is now connected!

### Step 4: Configure Filters (Optional)

1. Click **Configure Sync** (or go to Settings → Gmail Integration)
2. Set up filters:
   - **Include Senders** - e.g., `boss@company.com, hr@company.com`
   - **Exclude Senders** - e.g., `noreply@service.com`
   - **Include Keywords** - e.g., `invoice, report`
   - **Attachments Only** - Check if you only want emails with files
3. Click **Save Configuration**

### Step 5: Start Syncing

**Option A: Manual Sync**
- Click **Sync Now** button
- Choose time range (Last 24 Hours, 7 Days, 30 Days)
- Wait for sync to complete
- ✅ New documents appear in your Documents page

**Option B: Automatic Sync**
1. Go to Settings → Gmail Integration
2. Click **Configure Sync**
3. Check **Enable automatic syncing**
4. Choose frequency (hourly, daily, weekly)
5. Click **Save**
6. ✅ Email Monitor will sync automatically

---

## 📧 What Gets Synced?

Each Gmail email becomes a **Document** with:
- **Title** = Email subject
- **Sender** = From address
- **Recipient** = To address  
- **Date** = Received date
- **Content** = Email body
- **Tags** = You can add tags to organize

---

## 🎯 Common Scenarios

### Scenario 1: Sync Only Important Emails
```
Include Keywords: invoice, report, urgent
Enable: Attachments Only
→ Only emails with keywords AND attachments sync
```

### Scenario 2: Sync from Specific People
```
Include Senders: john@company.com, mary@company.com
Exclude Senders: noreply@service.com
→ Only emails from John or Mary (not noreply)
```

### Scenario 3: Keep It Simple
```
Leave all filters empty
→ Sync all recent emails
```

### Scenario 4: Hourly Updates
```
Enable Automatic Sync
Frequency: Every hour
→ Email Monitor checks Gmail every hour
```

---

## 🔍 Finding Synced Emails

1. Go to **Documents**
2. Use search: Type sender name, keyword, date
3. Filter by tags (if you added any)
4. Sort by date: Most recent first
5. ✅ Download, archive, or tag as needed

---

## ⚙️ Management

### To Change Filters:
1. Settings → Gmail Integration
2. Click **Configure Sync**
3. Update filters
4. Click **Save Configuration**

### To Sync Specific Date Range:
1. Settings → Gmail Integration
2. Click **Quick Sync** buttons
3. Choose: 24 Hours / 7 Days / 30 Days

### To Disconnect Gmail:
1. Settings → Gmail Integration
2. Click **Disconnect Gmail** button
3. Confirm
4. ✅ Gmail access revoked
5. Existing synced emails remain as documents

---

## 🔐 Security Notes

✅ **Your credentials are encrypted** - Stored safely in database  
✅ **Read-only access** - Email Monitor can't modify your emails  
✅ **2FA required** - Gmail operations need 2-factor authentication  
✅ **Audit logging** - All syncs logged for compliance  
✅ **Easy disconnect** - Revoke access any time  

---

## ❓ FAQ

**Q: Does Email Monitor store my Gmail password?**
A: No! We use OAuth2 tokens, not passwords. Your password never leaves Google.

**Q: Can Email Monitor send or delete emails?**
A: No! We request only read-only access to Gmail.

**Q: Do I need 2FA enabled?**
A: Yes! It's a security requirement for Gmail operations.

**Q: How often can I sync?**
A: Manual sync anytime (rate-limited to 10/hour). Auto-sync as frequent as hourly.

**Q: What if I disconnect Gmail?**
A: Synced documents remain. New emails won't sync. You can reconnect anytime.

**Q: Can multiple users sync different Gmail accounts?**
A: Yes! Each user can connect their own Gmail account.

**Q: Do synced emails have attachments?**
A: Not yet. We sync email content. Attachments stored separately in Gmail.

---

## 🆘 Troubleshooting

### "OAuth authorization failed"
- Clear browser cookies
- Try again
- If persists, check Client ID/Secret in `.env`

### "Gmail not connected"
- Go to Settings → Gmail Integration
- Click "Connect Gmail" again
- Complete authorization flow

### "No documents appearing"
- Check filters - may be too restrictive
- Try "Last 24 Hours" sync
- Ensure emails match your filter criteria

### "Sync taking too long"
- First sync downloads many emails (normal)
- Large attachments slow things down
- Try smaller date ranges

### "Permission denied error"
- Revoke Gmail access in Google Account Settings
- Go to Settings → Gmail Integration → Disconnect
- Reconnect and re-authorize

---

## 📊 Tips & Tricks

1. **Use Keywords** - Set filters to sync only important emails
2. **Tag Synced Emails** - Add tags for better organization
3. **Archive Old** - Archive emails after processing
4. **Favorite Important** - Star important synced documents
5. **Regular Cleanup** - Export documents and archive old emails
6. **Backup Often** - Download important documents

---

## 📞 Support

If you encounter issues:
1. Check the Troubleshooting section above
2. Review README.md for general setup
3. Check GMAIL_INTEGRATION.md for detailed docs
4. Review audit logs in Admin panel (if admin)

---

**Welcome to Gmail Integration!** 🎉  
Happy document management! 📄
