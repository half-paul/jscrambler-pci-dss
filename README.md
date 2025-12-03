# Script Integrity Monitor - Enhanced Edition

Production-ready PCI DSS v4.0.1 Requirement 11.6.1 compliance solution with automatic file detection, server-side approval workflow, and comprehensive security monitoring.

## Features

### Core Monitoring
- Real-time script integrity verification using SHA-384 cryptographic hashes
- Detection of unauthorized script modifications
- Comprehensive script inventory with timestamps and metadata
- Monitoring of static, dynamic, and iframe scripts
- Support for both enforcement and report-only modes
- **DOM method overrides** to intercept dynamic script injection
- **HTTP header tampering detection** (NEW)
- **Network request monitoring** for unauthorized data exfiltration (NEW)

### Enhanced Auto-Detection
- **Automatic detection** of ALL new scripts (never seen before)
- **Intelligent categorization**: NEW, KNOWN-CHANGED, APPROVED
- **Auto-registration** with server for approval workflow
- **Client-side polling** for approval status updates
- **Real-time violation** reporting

### Server-Side Approval Workflow
- **Modular Express application** with organized routes
- **Database integration** (SQLite for dev, PostgreSQL for production)
- **Approval queue management** with admin panel
- **Business justification** tracking (PCI DSS requirement)
- **Complete audit trail** with 7-year retention
- **Role-based access control** for admin users
- **Multi-factor authentication (MFA)** support
- **Email/Slack notifications** for new scripts and violations

### Admin Dashboard (Refactored)
- **Modular JavaScript architecture** with 15 separate modules
- **Real-time statistics** (scripts, violations, compliance status)
- **Pending approval queue** with script details
- **Violation monitoring** across three domains:
  - Script integrity violations
  - HTTP header tampering
  - Network request violations
- **Search and filter** capabilities
- **Bulk operations** with multi-select checkboxes:
  - Bulk approve/reject scripts
  - Bulk resolve/false positive for violations
  - Bulk delete for cleanup
- **User management** with role assignment and MFA setup
- **Audit trail viewing** with advanced filtering

### PCI DSS 11.6.1 Compliance Features
- ✅ **Script Authorization**: Admin approval workflow with business justification
- ✅ **Integrity Verification**: SHA-384 cryptographic hashing
- ✅ **Inventory Maintenance**: Complete database of all scripts
- ✅ **Written Justification**: Required for each approved script
- ✅ **Audit Trail**: Complete logs with 7-year retention
- ✅ **Regular Review**: Admin dashboard for ongoing monitoring
- ✅ **HTTP Header Protection**: Detection of header manipulation
- ✅ **Data Exfiltration Prevention**: Network request monitoring and blocking

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

Open browser to: `http://localhost:3000/admin-panel-refactored.html`

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
  <script src="/script-integrity-config.js"></script>

  <!-- CRITICAL: Load monitors SECOND -->
  <script src="/script-integrity-monitor.js"></script>
  <script src="/http-header-monitor.js"></script>
  <script src="/network-request-monitor.js"></script>

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
│  │  - Intercepts dynamic script injection                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  http-header-monitor.js (NEW)                             │  │
│  │  - Monitors HTTP response headers                         │  │
│  │  - Detects header tampering                               │  │
│  │  - Validates security headers                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  network-request-monitor.js (NEW)                         │  │
│  │  - Intercepts fetch/XHR/sendBeacon                        │  │
│  │  - Detects unauthorized data exfiltration                 │  │
│  │  - Blocks suspicious network requests                     │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└────────────────────────┼─────────────────────────────────────────┘
                         │ HTTPS/POST
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SERVER (Node.js/Express)                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  src/server/app.js (Main Application)                     │  │
│  │  - Express setup with helmet, cors, rate limiting        │  │
│  │  - Route mounting and middleware configuration           │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│  ┌──────────────────▼──────────────────────────────────────┐  │
│  │  src/server/routes/ (Modular Routes)                     │  │
│  │  ├── scripts.js    - Script approval workflow            │  │
│  │  ├── violations.js - Violation management                │  │
│  │  ├── headers.js    - HTTP header monitoring (NEW)        │  │
│  │  ├── network.js    - Network violation tracking (NEW)    │  │
│  │  ├── auth.js       - Authentication & MFA                │  │
│  │  └── admin.js      - Admin operations                    │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│  ┌──────────────────▼──────────────────────────────────────┐  │
│  │  database-manager.js                                      │  │
│  │  - Database abstraction                                   │  │
│  │  - Query interface                                        │  │
│  │  - Transaction support                                    │  │
│  │  - Automatic placeholder conversion (? → $1, $2, $3)     │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└────────────────────────┼─────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DATABASE (SQLite/PostgreSQL)                │
│  - scripts: Script inventory with approval status              │
│  - integrity_violations: Script tampering detection            │
│  - header_violations: HTTP header tampering (NEW)              │
│  - network_violations: Data exfiltration attempts (NEW)        │
│  - approval_audit_log: Audit trail (7-year retention)          │
│  - admin_users: Authentication with MFA support                │
│  - notification_queue: Alert delivery queue                    │
└─────────────────────────────────────────────────────────────────┘
```

## File Structure

```
jscrambler/
├── src/
│   └── server/
│       ├── app.js                        # Main Express application (NEW)
│       ├── database-manager.js           # Database abstraction
│       └── routes/                       # Modular route handlers (NEW)
│           ├── admin.js                  # Admin operations
│           ├── auth.js                   # Authentication & MFA
│           ├── headers.js                # HTTP header monitoring
│           ├── network.js                # Network violation tracking
│           ├── scripts.js                # Script approval workflow
│           └── violations.js             # Violation management
├── public/                               # Served files
│   ├── admin-panel-refactored.html      # Refactored admin dashboard (NEW)
│   ├── css/                             # Stylesheets (NEW)
│   │   └── admin-panel.css
│   ├── js/                              # Modular JavaScript (NEW)
│   │   ├── admin-api.js                 # API client
│   │   ├── admin-auth.js                # Authentication logic
│   │   ├── admin-bulk-operations.js     # Bulk operations
│   │   ├── admin-config.js              # Configuration
│   │   ├── admin-data.js                # Data management
│   │   ├── admin-header-network.js      # Header/network monitoring UI
│   │   ├── admin-init.js                # Initialization
│   │   ├── admin-mfa.js                 # MFA setup
│   │   ├── admin-modals.js              # Modal dialogs
│   │   ├── admin-rendering.js           # UI rendering
│   │   ├── admin-script-details.js      # Script details modal
│   │   ├── admin-ui.js                  # UI helpers
│   │   ├── admin-users.js               # User management
│   │   ├── admin-utils.js               # Utilities
│   │   └── admin-audit.js               # Audit trail
│   ├── script-integrity-monitor.js      # Script integrity monitoring
│   ├── http-header-monitor.js           # HTTP header monitoring (NEW)
│   ├── network-request-monitor.js       # Network monitoring (NEW)
│   ├── script-integrity-config.js       # Client configuration
│   └── test-*.html                      # Test pages
├── scripts/
│   ├── init-database.js                 # Database initialization
│   └── seed-database.js                 # Sample data for testing
├── database-schema.sql                  # SQLite schema
├── database-schema-postgres.sql         # PostgreSQL schema
├── server.js                           # Server entry point
├── server-alert-handler.js             # Legacy monolithic server
├── .env.example                        # Environment template
├── .env                                # Your configuration (create from .env.example)
├── package.json                        # Dependencies
├── docs/                               # Additional documentation
│   ├── APPROVAL-WORKFLOW.md
│   ├── IP-TRACKING-FEATURE.md
│   ├── SCRIPT-BLOCKING-FEATURE.md
│   └── USER-MANAGEMENT-GUIDE.md
└── README.md                           # This file
```

## API Endpoints

### Public Endpoints (No Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scripts/register` | Register newly discovered script |
| GET | `/api/scripts/status/:hash` | Check script approval status |
| POST | `/api/scripts/violation` | Report integrity violation |
| POST | `/api/headers/violation` | Report HTTP header tampering (NEW) |
| POST | `/api/network/violation` | Report network violation (NEW) |
| GET | `/api/network/whitelist` | Get whitelisted domains (NEW) |
| GET | `/health` | Health check |

### Admin Endpoints (Authentication Required)

#### Script Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/dashboard` | Get statistics |
| GET | `/api/admin/scripts/pending` | Get pending approvals |
| POST | `/api/admin/scripts/:id/approve` | Approve a script |
| POST | `/api/admin/scripts/:id/reject` | Reject a script |
| POST | `/api/admin/scripts/bulk-approve` | Bulk approve multiple scripts |
| POST | `/api/admin/scripts/bulk-reject` | Bulk reject multiple scripts |
| GET | `/api/admin/violations` | Get script violations |
| GET | `/api/admin/scripts/search` | Search scripts |
| POST | `/api/admin/violations/:id/review` | Update violation review |
| POST | `/api/admin/violations/bulk-delete` | Bulk delete violations |

#### HTTP Header Monitoring (NEW)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/headers/violations` | Get header violations |
| POST | `/api/admin/headers/violations/:id/review` | Review header violation |
| POST | `/api/admin/headers/violations/bulk-resolve` | Bulk resolve header violations |
| POST | `/api/admin/headers/violations/bulk-false-positive` | Bulk mark as false positive |
| POST | `/api/admin/headers/violations/bulk-delete` | Bulk delete header violations |
| GET | `/api/admin/headers/baselines` | Get header baselines |
| POST | `/api/admin/headers/baselines` | Create header baseline |
| DELETE | `/api/admin/headers/baselines/:id` | Delete header baseline |

#### Network Monitoring (NEW)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/network/violations` | Get network violations |
| POST | `/api/admin/network/violations/:id/review` | Review network violation |
| POST | `/api/admin/network/violations/:id/whitelist` | Whitelist domain from violation |
| GET | `/api/admin/network/whitelist` | Get all whitelisted domains |
| DELETE | `/api/admin/network/whitelist/:id` | Remove domain from whitelist |
| POST | `/api/admin/network/violations/bulk-delete` | Bulk delete network violations |

#### Authentication & Users
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login with username/password |
| POST | `/api/auth/verify-mfa` | Verify MFA token |
| POST | `/api/auth/setup-mfa` | Setup MFA for user |
| GET | `/api/admin/users` | List all users |
| POST | `/api/admin/users` | Create new user |
| PUT | `/api/admin/users/:id` | Update user |
| DELETE | `/api/admin/users/:id` | Delete user |

## Configuration

### Client-Side (script-integrity-config.js)

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  // Hash algorithm
  hashAlgorithm: 'SHA-384',

  // Mode: 'report' (monitor only) or 'enforce' (block violations)
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
SESSION_SECRET=change-in-production

# Admin credentials
DEFAULT_ADMIN_TOKEN=demo-token-12345

# See .env.example for all options
```

## New Features

### HTTP Header Monitoring

The system now monitors HTTP response headers for tampering and security issues:

- **Baseline Management**: Define expected headers for your pages
- **Violation Detection**: Automatic detection of missing, modified, or unexpected headers
- **Security Headers**: Validate Content-Security-Policy, X-Frame-Options, etc.
- **Smart Reopening**: Violations marked as resolved/false positive are automatically reopened if they recur

**Test Page**: `http://localhost:3000/test-header-tampering.html`

### Network Request Monitoring

Monitor and block unauthorized data exfiltration attempts:

- **Request Interception**: Monitors fetch(), XMLHttpRequest, sendBeacon()
- **Domain Whitelisting**: Manage allowed external domains
- **Violation Tracking**: Complete audit trail of blocked requests
- **Smart Deduplication**: Groups similar violations into single records

**Test Page**: `http://localhost:3000/test-network-violations.html`

### Bulk Operations

Efficient workflow management with bulk operations:

- **Bulk Approve/Reject**: Process multiple scripts simultaneously
- **Bulk Resolve**: Mark multiple violations as resolved
- **Bulk False Positive**: Classify multiple violations as false positives
- **Bulk Delete**: Clean up old records efficiently
- **Multi-select UI**: Checkboxes with "Select All" functionality
- **Transaction Safety**: Atomic operations with rollback on failure

### Modular Architecture

The admin panel has been refactored into 15 modular JavaScript files:

- **Better Maintainability**: Each module has a single responsibility
- **Faster Load Times**: Modules can be loaded on demand
- **Easier Testing**: Individual modules can be tested in isolation
- **Code Reusability**: Common utilities shared across modules

## Dynamic Script Injection Protection

The Script Integrity Monitor includes **DOM method overrides** to intercept and block dynamic script injection attempts.

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

### Testing Dynamic Injection Blocking

```bash
# Start server
npm start

# Open test page in browser
http://localhost:3000/test-dynamic-injection.html
```

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

### Docker Deployment

The application can be deployed using Docker. See [DOCKER.md](DOCKER.md) for details.

```bash
# Using Docker Compose
docker-compose up -d
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
  "version": "1.0.0",
  "database": {
    "healthy": true,
    "type": "sqlite"
  },
  "timestamp": "2025-12-03T12:00:00.000Z"
}
```

### Logs

Monitor logs for:
- `[SIM]` - Client-side script monitoring events
- `[Header Monitor]` - HTTP header monitoring events
- `[Network Monitor]` - Network request monitoring events
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

**Problem: Network violations not recording**

Solution: Verify network-request-monitor.js is loaded, check browser console for errors

See [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) for detailed troubleshooting.

## Documentation

- [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) - Complete workflow documentation
- [IP-TRACKING-FEATURE.md](IP-TRACKING-FEATURE.md) - IP tracking and privacy
- [SCRIPT-BLOCKING-FEATURE.md](SCRIPT-BLOCKING-FEATURE.md) - Script blocking implementation
- [USER-MANAGEMENT-GUIDE.md](USER-MANAGEMENT-GUIDE.md) - User and role management
- [DOCKER.md](DOCKER.md) - Docker deployment guide
- [REFACTORING-ADMIN-PANEL.md](REFACTORING-ADMIN-PANEL.md) - Admin panel refactoring details
- [JAVASCRIPT-ERROR-FIXES.md](JAVASCRIPT-ERROR-FIXES.md) - JavaScript troubleshooting
- [database-schema.sql](database-schema.sql) - SQLite database structure
- [database-schema-postgres.sql](database-schema-postgres.sql) - PostgreSQL database structure
- [.env.example](.env.example) - Configuration options

## Testing

### Test Pages Available

- `test-auto-registration.html` - Test automatic script registration
- `test-script-blocking.html` - Test script blocking in enforce mode
- `test-dynamic-injection.html` - Test dynamic script injection protection
- `test-variations.html` - Test various script detection scenarios
- `test-header-tampering.html` - Test HTTP header monitoring
- `test-network-violations.html` - Test network request monitoring
- `test-index.html` - Test suite index

### Running Tests

```bash
# Start server
npm start

# Open test suite in browser
http://localhost:3000/test-index.html
```

## Recent Improvements

### Network Monitoring Fix (December 2025)
- Fixed "Illegal invocation" error in network-request-monitor.js
- Applied `.bind(window)` to fetch method reference for proper context
- Network violations now properly report to server and record in database

### Bulk Operations (December 2025)
- Added bulk resolve and false positive operations for header violations
- Implemented multi-select UI with checkboxes and dynamic counters
- Full audit logging for all bulk operations

### Admin Panel Refactoring (November 2025)
- Split monolithic admin panel into 15 modular JavaScript files
- Improved load times and maintainability
- Added comprehensive CSS organization

### Modular Server Architecture (November 2025)
- Reorganized server into modular Express routes
- Separated concerns: scripts, violations, headers, network, auth, admin
- Improved code maintainability and testability

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions:
- Review documentation in `docs/` directory
- Check troubleshooting section
- Contact your security team

## Version

**Version 1.0.0** - Current version with all enhancements

---

**⚠️ IMPORTANT SECURITY NOTES:**

1. **NEVER commit `.env` file** to version control
2. **Change all default credentials** before production deployment
3. **Use HTTPS** in production (HTTP is for development only)
4. **Review PCI DSS requirements** and ensure compliance
5. **Regularly update** baseline hashes when scripts change
6. **Monitor violations** and respond to alerts promptly
7. **Enable MFA** for all admin users
8. **Rotate API tokens** regularly

---

**PCI DSS v4.0.1 Requirement 11.6.1 Compliance Achieved ✓**
