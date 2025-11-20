# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **PCI DSS v4.0 Requirement 6.4.3 compliant Script Integrity Monitoring solution** with automatic file detection and server-side approval workflow. It detects unauthorized changes to payment page scripts to prevent web skimming attacks.

**Key Components:**
- **Client-side monitor** (`script-integrity-monitor.js`) - Detects and hashes all scripts in browser
- **Server API** (`server-alert-handler.js`) - Handles registration, approval workflow, violations
- **Database layer** (`database-manager.js`) - Abstracts SQLite/PostgreSQL operations
- **Admin panel** (`public/admin-panel.html`) - Web UI for approving/rejecting scripts

## Essential Commands

### Development Workflow
```bash
# First-time setup
npm install
cp .env.example .env
npm run db:init              # Creates database + default admin (token: demo-token-12345)

# Development
npm run dev                  # Start with auto-reload (nodemon)
npm start                    # Production start

# Database
npm run db:init              # Initialize/reset database
```

### Testing
```bash
# Manual testing in browser
# Open: http://localhost:3000/test-auto-registration.html
# Open: http://localhost:3000/test-script-integrity.html
# Open: http://localhost:3000/admin-panel.html

# No automated test suite - tests are browser-based HTML files
npm test  # Just echoes instructions to open test-script-integrity.html
```

### Important URLs (when server running)
- **Admin Panel**: http://localhost:3000/admin-panel.html
- **Auto-Registration Test**: http://localhost:3000/test-auto-registration.html
- **Full Test Suite**: http://localhost:3000/test-script-integrity.html
- **Health Check**: http://localhost:3000/health

## Architecture

### Critical Execution Order
The monitor MUST load FIRST before any other scripts:
```html
<script src="script-integrity-config.js"></script>  <!-- 1. Config FIRST -->
<script src="script-integrity-monitor.js"></script> <!-- 2. Monitor SECOND -->
<script src="your-app.js"></script>                 <!-- 3. Everything else -->
```

### Request Flow
```
Browser → Detects Script → Calculate SHA-384 Hash
    ↓
Check baseline config: Known? Hash matches?
    ↓ NO or MISMATCH
Check server: POST /api/scripts/register (auto-register new)
    ↓
Server stores with status: pending_approval
    ↓
Admin reviews in panel → Approve/Reject
    ↓
Client polls GET /api/scripts/status/:hash every 30s
    ↓
Status updated → Allow or block execution
```

### Database Abstraction
**Database Manager Pattern**: `database-manager.js` abstracts SQLite vs PostgreSQL
- **Development**: Uses `sql.js` (pure JS, no compilation needed)
- **Production**: Supports PostgreSQL with connection pooling
- **Schema**: Database-specific schema files (`database-schema.sql` for SQLite, `database-schema-postgres.sql` for PostgreSQL)
- **Key Point**: Uses `sql.js` NOT `better-sqlite3` to avoid native compilation issues
- **Placeholder Conversion**: Automatically converts `?` placeholders (SQLite) to `$1, $2, $3` (PostgreSQL)
  - Write all queries with `?` placeholders
  - DatabaseManager handles conversion for PostgreSQL automatically
  - Example: `db.query('SELECT * FROM scripts WHERE id = ?', [123])`

### File Locations
- **Root**: Client scripts (`script-integrity-monitor.js`, `script-integrity-config.js`)
- **public/**: Served files (admin panel, client scripts copied here, test pages)
- **scripts/**: Utility scripts (`init-database.js`)
- **data/**: SQLite database (created on init, gitignored)

## Key Technical Details

### Auto-Detection & Registration
When a new script is detected:
1. Monitor calculates SHA-384 hash
2. Checks baseline config (`baselineHashes`) - if found and matches, allow
3. If not in baseline, calls `registerNewScript()` which POSTs to `/api/scripts/register`
4. Server stores as `pending_approval` in database
5. Client starts polling `/api/scripts/status/:hash` every 30s
6. Admin approves/rejects in admin panel
7. Client receives status update and takes action

### Script Blocking Behavior
**In enforce mode** (`mode: 'enforce'`), scripts are blocked based on violation type:

**Blocked Violations** (security threats and admin decisions):
- `HASH_MISMATCH` - Known script has been modified
- `SRI_MISMATCH` - Subresource Integrity attribute mismatch
- `REJECTED_BY_ADMIN` - Admin explicitly rejected the script
- `NO_BASELINE_HASH` - Script not in approved baseline
- `UNAUTHORIZED_SCRIPT` - Script from unauthorized source

**NOT Blocked** (allow time for review):
- `PENDING_APPROVAL` - Awaiting admin review
- `NEW_SCRIPT` - Newly discovered, auto-registered

**In report mode** (`mode: 'report'`), no scripts are blocked - violations are only reported to the server.

**Testing**:
- Run `node test-rejected-blocking.js` to verify blocking logic
- Open `http://localhost:3000/test-dynamic-injection.html` to test dynamic script injection blocking

### Dynamic Script Injection Protection
**DOM Method Overrides** are installed automatically to intercept dynamic script injection:

**Intercepted Methods:**
- `document.createElement('script')` - Catches script element creation
- `Element.prototype.appendChild()` - Catches script insertion
- `Element.prototype.insertBefore()` - Catches script insertion before reference node
- `Element.prototype.replaceChild()` - Catches script replacement
- `HTMLScriptElement.src` property setter - Catches src assignment
- `HTMLScriptElement.setAttribute('src')` - Catches src via setAttribute

**How It Works:**
1. Original DOM methods are stored in `this.originalMethods` to prevent bypass
2. Overrides intercept script creation/insertion before execution
3. `shouldBlockDynamicScript()` checks if script is in blocked list
4. Blocked scripts have their `type` changed to `blocked-by-integrity-monitor`
5. Scripts are marked with `data-integrity-status="blocked"` attribute
6. MutationObserver provides fallback detection for edge cases

**Coverage:**
- ✅ External scripts loaded via createElement
- ✅ Inline scripts created dynamically
- ✅ Scripts inserted via appendChild/insertBefore/replaceChild
- ✅ Scripts with src set via property or setAttribute
- ⚠️ Scripts in original HTML (handled by MutationObserver with race conditions)

**Limitations:**
- Overrides only affect scripts created AFTER monitor initialization
- Attacker with early code execution could save original methods before override
- Defense-in-depth: Combine with CSP for maximum protection

### Debug Logging
**Debug mode is ON by default** (`debug: true` unless explicitly disabled)
- All logs prefixed with `🔒 [SIM]` and timestamp
- Emojis indicate message type: 🌐 (API), ⚠️ (violation), ✅ (approved), 🔍 (detected)
- Structured data logged with `└─ Data:` for complex objects
- Look for these in browser console when testing

### Server URL Auto-Detection
In `script-integrity-config.js`:
```javascript
serverBaseUrl: (function() {
  // Auto-detects localhost/127.0.0.1/port 3000
  if (window.location.hostname === 'localhost' ||
      window.location.hostname === '127.0.0.1' ||
      window.location.port === '3000') {
    return window.location.origin;  // e.g., http://localhost:3000
  }
  return null;  // Manual config needed for production
})()
```

### CSP Configuration
**Critical for Admin Panel**: `helmet` CSP must allow inline scripts/event handlers
```javascript
helmet({
  contentSecurityPolicy: {
    directives: {
      scriptSrc: ["'self'", "'unsafe-inline'"],     // Inline <script> tags
      scriptSrcAttr: ["'unsafe-inline'"],           // onclick="..." attributes
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
})
```

## Common Pitfalls

### 1. File:// vs Server URLs
**Problem**: Opening `test-script-integrity.html` directly as `file://` won't work
**Why**: CORS blocks API calls, server URL detection fails
**Solution**: ALWAYS access via server: `http://localhost:3000/test-script-integrity.html`

### 2. Missing .env File
**Problem**: Admin login doesn't work, token mismatch
**Why**: Database initialized with random token because `.env` didn't exist
**Solution**: `cp .env.example .env` BEFORE running `npm run db:init`

### 3. Scripts in Root vs Public
**Important**: Client scripts exist in BOTH locations:
- `/script-integrity-monitor.js` - Source of truth
- `/public/script-integrity-monitor.js` - Copy for serving
**After editing root files**, copy to public: `cp script-*.js public/`

### 4. Admin Panel URLs
The admin panel expects to be served from the server at `/admin-panel.html`
- Correct: `http://localhost:3000/admin-panel.html`
- Wrong: Opening `public/admin-panel.html` as file

## Making Changes

### Modifying Client Monitor
1. Edit `/script-integrity-monitor.js` (root)
2. Copy to public: `cp script-integrity-monitor.js public/`
3. Restart server: `npm run dev`
4. Test in browser at `http://localhost:3000/test-auto-registration.html`
5. Check console for `🔒 [SIM]` debug logs

### Modifying Server API
1. Edit `server-alert-handler.js`
2. Server auto-restarts if using `npm run dev` (nodemon)
3. Test endpoints with curl or in admin panel
4. Check server console for `[Server]`, `[DB]`, `[Admin]` logs

### Database Schema Changes
1. Edit `database-schema.sql`
2. **Important**: Schema is applied on startup via `db.exec(schema)`
3. For existing databases, may need to drop and recreate: `rm data/*.db && npm run db:init`
4. Or implement proper migrations (not currently set up)

### Admin Panel Changes
1. Edit `public/admin-panel.html`
2. Refresh browser (may need hard refresh: Cmd+Shift+R / Ctrl+Shift+R)
3. Check browser console for errors
4. Verify CSP allows inline scripts (check for CSP errors)

## Configuration Files

### Environment Variables (.env)
Key settings:
- `DEFAULT_ADMIN_TOKEN=demo-token-12345` - Must match admin panel
- `DB_TYPE=sqlite` - Use 'postgres' for production
- `SQLITE_PATH=./data/integrity-monitor.db`
- `PORT=3000`
- `NODE_ENV=development`

### Client Config (script-integrity-config.js)
Key settings:
- `serverBaseUrl` - Auto-detected for localhost, manual for production
- `autoRegisterNewScripts: true` - Enable auto-registration
- `pollApprovalStatus: true` - Poll server for approval updates
- `pollInterval: 30000` - Poll every 30 seconds
- `mode: 'report'` - Start in report mode, use 'enforce' to block
- `baselineHashes: {}` - Known good script hashes

## PCI DSS Compliance Notes

This solution addresses PCI DSS v4.0 Requirement 6.4.3:
- **Script Authorization**: Admin approval workflow with business justification required
- **Integrity Verification**: SHA-384 cryptographic hashing
- **Inventory Maintenance**: Complete database of all scripts
- **Written Justification**: `business_justification` field in database
- **Audit Trail**: `approval_audit_log` table with 7-year retention

## Security Considerations

### Authentication
- Admin endpoints require `X-API-Token` header
- Token stored in `admin_users` table
- Default token: `demo-token-12345` (MUST change in production)

### Rate Limiting
- General: 100 req/15min per IP
- Registration: 200 req/hour per session
- Configured in `server-alert-handler.js`

### IP Privacy
- IP addresses hashed with salt before storage
- Salt in `.env` as `IP_SALT`

### SQL Injection Prevention
- All queries use parameterized statements
- Database manager handles escaping

## Debugging

### Client-Side Issues
1. Open browser DevTools Console (F12)
2. Look for `🔒 [SIM]` messages
3. Check for:
   - "✅ Auto-registration is ENABLED"
   - "🌐 📤 Sending registration request"
   - "✅ Script registered successfully"
4. If no logs, check `debug: true` in config

### Server-Side Issues
1. Check server console output
2. Look for:
   - `[DB]` - Database operations
   - `[Server]` - Server events
   - `[Admin]` - Admin actions
   - `[Auth]` - Authentication
3. Enable query logging: `LOG_QUERIES=true` in `.env`

### API Call Visibility
The test pages intercept `fetch()` calls and log them:
```
🌐 API Call: http://localhost:3000/api/scripts/register
   Method: POST
   Body: {...}
   Response: 200 OK
```

## Production Deployment

**Pre-deployment checklist** (see README.md for full list):
1. Change `DEFAULT_ADMIN_TOKEN` in `.env`
2. Set `DB_TYPE=postgres` and configure PostgreSQL
3. Set `NODE_ENV=production`
4. Configure specific `CORS_ORIGIN` (not `*`)
5. Set up SSL/TLS (use Nginx reverse proxy)
6. Configure email/Slack notifications
7. Update `IP_SALT` and `SESSION_SECRET`
8. Test disaster recovery

**Critical**: The solution uses `sql.js` (pure JavaScript SQLite) for development. For production with PostgreSQL, the same `database-manager.js` handles both via the abstraction layer.

## Additional Documentation

- `README.md` - Complete feature documentation and setup
- `APPROVAL-WORKFLOW.md` - Detailed workflow and API reference
- `SETUP.md` - Quick start guide and troubleshooting
- `database-schema.sql` - Complete schema with comments
- `.env.example` - All available configuration options
