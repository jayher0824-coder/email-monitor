# ✅ GitHub Publication Checklist

Complete this checklist before pushing to GitHub to ensure security and quality.

## 🔒 Security & Sensitive Data

- [ ] **Remove sensitive files from git history**
  ```bash
  git rm --cached credentials.json token.json .env
  ```
- [ ] **Verify .gitignore includes:**
  - [ ] `.env` and `.env.local`
  - [ ] `credentials.json`
  - [ ] `token.json`
  - [ ] `*.db` and `*.sqlite*`
  - [ ] `__pycache__/`
  - [ ] `.vscode/` and `.idea/`
  - [ ] `instance/`
  - [ ] `logs/`

- [ ] **Remove/regenerate secrets:**
  - [ ] Change `SECRET_KEY` in config.py
  - [ ] Do NOT commit `credentials.json`
  - [ ] Do NOT commit Gmail access tokens
  - [ ] Review all `config.py` for hardcoded values

- [ ] **Create .env.example** with placeholder values (already included)

## 📝 Documentation

- [ ] **README.md is complete** with:
  - [ ] Project description
  - [ ] Installation steps
  - [ ] Configuration instructions
  - [ ] Feature list
  - [ ] Project structure
  - [ ] Key endpoints reference
  - [ ] Security notes
  - [ ] Known issues/limitations

- [ ] **Add LICENSE file** (choose one):
  - [ ] MIT License
  - [ ] Apache 2.0
  - [ ] GNU GPL
  - [ ] Other: ___________

- [ ] **Add CONTRIBUTING.md** with:
  - [ ] How to contribute guidelines
  - [ ] Development setup steps
  - [ ] Code style guidelines
  - [ ] Pull request process

- [ ] **Add CODE_OF_CONDUCT.md** (optional but recommended)

## 🧪 Code Quality

- [ ] **No debug mode in production code**
  ```python
  app.run(debug=False)  # ✓ Correct
  ```

- [ ] **Test the application** works correctly:
  - [ ] Can register new users
  - [ ] Can login
  - [ ] Can upload documents
  - [ ] Can view documents
  - [ ] Can use approval workflow
  - [ ] 2FA works
  - [ ] Rate limiting works

- [ ] **No console.log() or print() statements** for debugging (should be logging instead)

- [ ] **Remove any hardcoded paths** (use `os.environ` instead)

- [ ] **Database commands commented out** (or use proper migrations)

## 📦 Dependencies

- [ ] **requirements.txt is up to date**
  ```bash
  pip freeze > requirements.txt
  ```

- [ ] **Test installation from requirements.txt**
  ```bash
  python -m venv test_env
  test_env/Scripts/activate
  pip install -r requirements.txt
  ```

- [ ] **No unnecessary dependencies** (clean up any unused packages)

## 🎯 Configuration Files

- [ ] **config.py safe for public**:
  - [ ] No real API keys
  - [ ] No real passwords
  - [ ] No real database credentials
  - [ ] Example values only

- [ ] **Verified all imports work** and no import errors

## 🔗 Git Repository Setup

- [ ] **Repository name** is descriptive: `email-monitor` or similar
- [ ] **Repository description** is clear and accurate
- [ ] **Visibility set to Public** (or Private if needed)
- [ ] **Add appropriate topics/tags**:
  - `flask`
  - `email-management`
  - `document-management`
  - `security`
  - `python`

- [ ] **.gitignore is in place** before first push
  ```bash
  git add .gitignore
  git commit -m "Add .gitignore"
  ```

## 📋 Before Initial Commit

- [ ] **Clean up repository:**
  ```bash
  # Remove backup files
  rm -rf __pycache__
  rm -rf .pytest_cache
  rm *.pyc
  ```

- [ ] **Initial commit message is clear:**
  ```bash
  git commit -m "Initial commit: Email Monitor webapp with auth, documents, and approval workflows"
  ```

- [ ] **No merge conflicts** before pushing

## 🚀 Final Steps

- [ ] **Create initial release/tag:**
  ```bash
  git tag -a v1.0.0 -m "Initial release"
  git push origin v1.0.0
  ```

- [ ] **Add branch protection rules** (Settings > Branches):
  - [ ] Require pull request reviews
  - [ ] Require status checks to pass
  - [ ] Require branches to be up to date

- [ ] **Add GitHub Actions** for:
  - [ ] Testing on push
  - [ ] Code quality checks
  - [ ] Security scanning

## ⚠️ Production Deployment Notes

If deploying to production later:

- [ ] **Use PostgreSQL** instead of SQLite
  ```python
  SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@localhost/email_monitor'
  ```

- [ ] **Use environment variables** from `.env` file (never hardcode):
  ```bash
  SECRET_KEY = os.environ.get('SECRET_KEY')
  ```

- [ ] **Use WSGI server** (Gunicorn/uWSGI) instead of Flask dev server
  ```bash
  gunicorn --bind 0.0.0.0:5000 app:app
  ```

- [ ] **Enable HTTPS/SSL** and set:
  ```python
  SESSION_COOKIE_SECURE = True
  PREFERRED_URL_SCHEME = 'https'
  ```

- [ ] **Set up logging** to file for debugging

- [ ] **Configure backup strategy** for database

- [ ] **Set up monitoring** for uptime and errors

- [ ] **Use environment-specific configs**:
  ```
  config/
  ├── base.py       # Shared settings
  ├── dev.py        # Development
  ├── prod.py       # Production
  └── test.py       # Testing
  ```

## 📞 Contacts & Resources

- GitHub Issues Template: Create issue templates for bugs/features
- GitHub Discussions: Enable if you want community discussions
- Security Policy: Add SECURITY.md for reporting vulnerabilities

---

**Last Updated**: February 2026
**Status**: Ready for GitHub publication

Once all items are checked, you're ready to push to GitHub! 🚀
