# Quick Start Guide - Enhanced Script Integrity Monitor

## 5-Minute Setup

### Step 1: Install Dependencies (1 min)

```bash
npm install
```

### Step 2: Configure Environment (1 min)

```bash
# Copy environment template
cp .env.example .env

# For development, default values work fine
# Edit .env only if you need custom configuration
```

### Step 3: Initialize Database (1 min)

```bash
npm run db:init
```

**Output:**
```
========================================
Database Initialization
========================================

[Init] Creating default admin user...
[Init] Default admin user created

========================================
Initialization Complete!
========================================

Default Admin Credentials:
  Username: admin
  Password: admin123
  API Token: demo-token-12345

⚠️  IMPORTANT: Change these credentials in production!

You can now start the server:
  npm start
  npm run dev (for development)

Admin Panel:
  http://localhost:3000/admin-panel.html
========================================
```

### Step 4: Start Server (1 min)

```bash
npm run dev
```

**Output:**
```
========================================
Script Integrity Monitor Server
========================================
Server running on port 3000
Database: sqlite

Public API Endpoints:
  POST   http://localhost:3000/api/scripts/register
  GET    http://localhost:3000/api/scripts/status/:hash
  POST   http://localhost:3000/api/scripts/violation

Admin API Endpoints (require authentication):
  GET    http://localhost:3000/api/admin/scripts/pending
  POST   http://localhost:3000/api/admin/scripts/:id/approve
  POST   http://localhost:3000/api/admin/scripts/:id/reject
  GET    http://localhost:3000/api/admin/violations
  GET    http://localhost:3000/api/admin/dashboard

Admin Panel:
  http://localhost:3000/admin-panel.html

Health Check:
  GET    http://localhost:3000/health
========================================
```

### Step 5: Test the System (1 min)

#### 5a. Access Admin Panel

1. Open browser: `http://localhost:3000/admin-panel.html`
2. Enter API Token: `demo-token-12345`
3. Click "Login"
4. You should see the dashboard with statistics

#### 5b. Test Client-Side Detection

Open the test page in another tab:

```bash
# If you have a local web server
open test-script-integrity.html

# Or use Python
python3 -m http.server 8080
# Then open http://localhost:8080/test-script-integrity.html
```

The test page will:
- Load the monitoring scripts
- Detect test scripts
- Auto-register new scripts with the server
- Show detection results in the console

Check the admin panel - you should see pending scripts!

## Testing the Workflow

### Test 1: Approve a New Script

1. **Detect a script**: The test page has detected scripts
2. **View in admin panel**: Go to "Pending Approvals" tab
3. **Click "Approve"** on a script
4. **Fill in the form**:
   ```
   Business Justification: Test script for demonstration purposes
   Script Purpose: Testing auto-detection workflow
   Script Owner: Development Team
   Risk Level: Low
   ```
5. **Click "Approve"** button
6. **Refresh the page**: Script should move from pending to approved

### Test 2: Reject a Script

1. **View pending scripts** in admin panel
2. **Click "Reject"** on a script
3. **Fill in reason**:
   ```
   Rejection Reason: Test rejection workflow
   Notes: This is a test rejection
   ```
4. **Click "Reject"** button
5. **Check violations tab**: Should show the rejection

### Test 3: Integrity Violation

1. **Create a baseline hash** for a known script:
   ```javascript
   // In browser console
   SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()
   ```
2. **Copy the output** and add to `script-integrity-config.js`:
   ```javascript
   baselineHashes: {
     'https://cdn.example.com/test.js': 'sha384-copied-hash-here'
   }
   ```
3. **Modify the script** (change content)
4. **Reload the page**
5. **Check violations**: Should detect HASH_MISMATCH

## Integration with Your Application

### Method 1: Direct HTML Integration

Add to your HTML pages (must be FIRST):

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Your Page</title>

  <!-- STEP 1: Load configuration FIRST -->
  <script src="/path/to/script-integrity-config.js"></script>

  <!-- STEP 2: Load monitor SECOND -->
  <script src="/path/to/script-integrity-monitor.js"></script>

  <!-- STEP 3: Other scripts (these will be monitored) -->
  <script src="https://cdn.example.com/jquery.js"></script>
  <script src="/js/your-app.js"></script>
</head>
<body>
  <!-- Your content -->
</body>
</html>
```

### Method 2: Build Tool Integration

If using webpack/rollup/vite:

```javascript
// webpack.config.js
module.exports = {
  entry: {
    // Integrity monitoring MUST be first
    'integrity-config': './script-integrity-config.js',
    'integrity-monitor': './script-integrity-monitor.js',
    // Your app
    'app': './src/index.js'
  },
  // ... rest of config
};
```

In your HTML:

```html
<!-- Load in order -->
<script src="/dist/integrity-config.js"></script>
<script src="/dist/integrity-monitor.js"></script>
<script src="/dist/app.js"></script>
```

## Configuration

### Configure Server Endpoints

Edit `script-integrity-config.js`:

```javascript
// Development
config.serverBaseUrl = 'http://localhost:3000';

// Production
config.serverBaseUrl = 'https://your-domain.com';
```

### Enable/Disable Auto-Registration

```javascript
config.autoRegisterNewScripts = true;  // Auto-register new scripts
config.pollApprovalStatus = true;      // Poll for approval updates
```

### Set Monitoring Mode

```javascript
config.mode = 'report';   // Only report violations (recommended initially)
// or
config.mode = 'enforce';  // Block unauthorized scripts (use after testing)
```

## Common Commands

```bash
# Development server (with auto-reload)
npm run dev

# Production server
npm start

# Initialize/reset database
npm run db:init

# Check health
curl http://localhost:3000/health
```

## Verification Checklist

After setup, verify:

- [ ] Server starts without errors
- [ ] Admin panel loads and login works
- [ ] Dashboard shows statistics (may be zero initially)
- [ ] Test page detects scripts
- [ ] Scripts appear in pending approvals
- [ ] Can approve/reject scripts
- [ ] Violations are logged
- [ ] Database file exists at `./data/integrity-monitor.db`

## Next Steps

1. **Review Documentation**:
   - [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) - Complete workflow guide
   - [README.md](README.md) - Full documentation

2. **Configure for Your Environment**:
   - Update `baselineHashes` for your approved scripts
   - Configure `whitelistedSources` if needed
   - Set up email/Slack notifications

3. **Test Thoroughly**:
   - Test with your actual pages
   - Generate baseline hashes for all scripts
   - Test in staging environment first

4. **Production Deployment**:
   - Follow production checklist in README.md
   - Change all default credentials
   - Use PostgreSQL instead of SQLite
   - Set up SSL/TLS

## Troubleshooting

### Server won't start

**Check:**
- Node.js version (requires >= 14.0.0)
- All dependencies installed (`npm install`)
- Port 3000 not already in use
- Database file permissions

### Admin panel shows "Authentication required"

**Check:**
- Using correct API token
- Database was initialized (`npm run db:init`)
- Server is running
- No browser console errors

### Scripts not being detected

**Check:**
- Config loaded before monitor
- Monitor loaded before other scripts
- `serverBaseUrl` is correct
- Browser console for errors
- Network tab shows API calls

### Database errors

**Check:**
- Database file exists (`./data/integrity-monitor.db`)
- File permissions (read/write)
- Disk space available
- Schema is up to date

## Getting Help

1. Check the [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) troubleshooting section
2. Review browser console for client-side errors
3. Check server logs for backend errors
4. Verify configuration in `.env` and `script-integrity-config.js`

## Example Use Cases

### Use Case 1: E-Commerce Checkout

**Scenario:** Monitor payment page scripts

1. Add monitoring to checkout page
2. Detect Stripe.js, payment scripts
3. Approve with justification:
   - "Required for PCI-compliant payment processing"
4. Monitor for any unauthorized changes
5. Alert if payment scripts are modified

### Use Case 2: Third-Party Scripts

**Scenario:** Detect unauthorized tracking scripts

1. Monitor all pages
2. New analytics script detected
3. Review in admin panel
4. Reject if unauthorized
5. Investigate how it was added

### Use Case 3: CDN Script Updates

**Scenario:** CDN updates jQuery version

1. Hash mismatch detected (HASH_MISMATCH)
2. Violation logged
3. Review in admin panel
4. If legitimate update:
   - Generate new baseline hash
   - Update configuration
   - Approve new version
5. If unexpected:
   - Investigate cause
   - May indicate CDN compromise

## Security Best Practices

1. **Start in report mode** - Don't block scripts initially
2. **Generate accurate baselines** - Use actual production scripts
3. **Review regularly** - Check pending approvals daily
4. **Document approvals** - Provide detailed justifications
5. **Monitor violations** - Investigate all integrity issues
6. **Keep baselines updated** - When scripts change, update hashes
7. **Use HTTPS** - Always in production
8. **Change default credentials** - Before production deployment
9. **Backup database** - Regular backups of audit trail
10. **Review audit logs** - Periodic compliance reviews

---

**You're now ready to use the enhanced Script Integrity Monitor!**

For detailed information, see:
- [README.md](README.md) - Complete documentation
- [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) - Workflow guide
- [database-schema.sql](database-schema.sql) - Database structure

**Questions?** Review the troubleshooting sections or contact your security team.
