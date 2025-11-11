# Quick Setup Guide

## First-Time Setup (5 Minutes)

Follow these steps to get the PCI DSS Script Integrity Monitor running:

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
```bash
# Copy the example environment file
cp .env.example .env

# (Optional) Edit .env to customize settings
# nano .env
```

**Important:** The `.env` file is required! Without it, the database will be initialized with a random token that won't match the admin panel.

### 3. Initialize Database
```bash
npm run db:init
```

This will create the SQLite database and a default admin user.

**Default Credentials:**
- Username: `admin`
- Password: `admin123`
- API Token: `demo-token-12345`

### 4. Start the Server
```bash
# Production mode
npm start

# Development mode (auto-restart on changes)
npm run dev
```

The server will start on `http://localhost:3000`

### 5. Access Admin Panel
Open your browser and navigate to:
```
http://localhost:3000/admin-panel.html
```

**Login with:**
- API Token: `demo-token-12345`

---

## Common Issues

### ❌ "Nothing happens when I click login"

**Cause:** The database was initialized before creating the `.env` file, so the token doesn't match.

**Fix:**
```bash
# Ensure .env exists
cp .env.example .env

# Re-initialize database
npm run db:init

# Try logging in with: demo-token-12345
```

### ❌ "npm install fails with compilation errors"

**Cause:** This shouldn't happen anymore - we use `sql.js` which requires no compilation.

**Fix:** Make sure you're using Node.js v14 or higher:
```bash
node --version
```

### ❌ "Cannot find module 'sql.js'"

**Fix:**
```bash
# Clean install
rm -rf node_modules package-lock.json
npm install
```

---

## Next Steps

1. **Test the monitoring:** Open `example-payment-page.html` in a browser
2. **Review pending scripts:** Check the admin panel for any detected scripts
3. **Configure alerts:** Set up email/Slack notifications in `.env`
4. **Deploy to production:** Follow the checklist in `.env.example`

---

## Security Note

**⚠️ IMPORTANT:** The default credentials are for development only!

Before deploying to production:
1. Change `DEFAULT_ADMIN_TOKEN` in `.env`
2. Update the admin password in the database
3. Set `NODE_ENV=production`
4. Configure proper CORS origins
5. Set up SSL/TLS certificates

See the full checklist in `.env.example` (lines 181-196)

---

## File Structure

```
jscrambler-pci-dss/
├── .env                          # Your configuration (create from .env.example)
├── .env.example                  # Configuration template
├── script-integrity-monitor.js   # Client-side monitor (loads first)
├── script-integrity-config.js    # Client configuration
├── server-alert-handler.js       # Backend server
├── database-manager.js           # Database abstraction
├── database-schema.sql           # Database schema
├── public/
│   └── admin-panel.html         # Admin dashboard
├── scripts/
│   └── init-database.js         # Database initialization
├── data/
│   └── integrity-monitor.db     # SQLite database (auto-created)
└── README.md                    # Full documentation
```

---

## Support

For issues or questions:
- Check `README.md` for full documentation
- Review `APPROVAL-WORKFLOW.md` for workflow details
- See `QUICKSTART-ENHANCED.md` for deployment guide

---

**You're ready to go! 🚀**
