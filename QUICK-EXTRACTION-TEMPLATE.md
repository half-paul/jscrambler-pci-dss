# Quick Module Extraction Template

## Pattern We've Established ✅

You have 4 working modules that demonstrate the perfect pattern:
- `src/server/middleware/auth.js`
- `src/server/middleware/rateLimiting.js`
- `src/server/services/auditService.js`
- `src/server/routes/auth.js`

**Use these as templates for all remaining modules!**

---

## Fast Track: Complete Server Routes in 2 Hours

Follow this proven 3-step process for each route module:

### Step 1: Copy the Template (30 seconds)

```javascript
/**
 * [Module Name] Routes
 * [Brief description]
 */

const express = require('express');
const router = express.Router();
// Add any other requires needed (crypto, etc.)

function create[ModuleName]Routes(db, logAudit, authenticate, requireRole, rateLimiters) {
  const { generalLimiter, registrationLimiter, violationLimiter } = rateLimiters;

  // === PUBLIC ROUTES (if any) ===

  // === ADMIN ROUTES ===

  return router;
}

module.exports = { create[ModuleName]Routes };
```

### Step 2: Extract Routes from Original File (10-20 min per module)

Open `server-alert-handler.js` and:

1. **Find the route** (use Cmd/Ctrl+F to search)
2. **Copy entire handler** from `app.post(...)` to closing `});`
3. **Paste into template**
4. **Make 2 changes**:
   - Change `app.post` to `router.post`
   - Remove path prefix (e.g., `/api/admin/scripts/:id` → `/:id`)

### Step 3: Test It (2 min)

```bash
# Syntax check
node -e "require('./src/server/routes/[name]'); console.log('✓ OK')"
```

---

## Scripts Routes Module (Next - 30 minutes)

### Routes to Extract

**File**: `src/server/routes/scripts.js`

**Line Numbers in server-alert-handler.js**:

| Route | Method | Path | Lines | Type |
|-------|--------|------|-------|------|
| Register | POST | /register | 768-861 | PUBLIC |
| Status | GET | /status/:hash | 864-895 | PUBLIC |
| Pending | GET | /admin/pending | 2165-2187 | ADMIN |
| Search | GET | /admin/search | 2236-2276 | ADMIN |
| Approve | POST | /admin/:id/approve | 2279-2324 | ADMIN |
| Reject | POST | /admin/:id/reject | 2327-2357 | ADMIN |
| Bulk Approve | POST | /admin/bulk-approve | 2360-2467 | ADMIN |
| Bulk Reject | POST | /admin/bulk-reject | 2470-2573 | ADMIN |
| Delete | DELETE | /admin/:id | 2576-2638 | ADMIN |

### Template Start

```javascript
const express = require('express');
const router = express.Router();
const crypto = require('crypto');

function createScriptsRoutes(db, logAudit, authenticate, requireRole, rateLimiters) {
  const { generalLimiter, registrationLimiter } = rateLimiters;

  // PUBLIC: POST /register
  router.post('/register', registrationLimiter, async (req, res) => {
    // COPY lines 769-861 here
  });

  // PUBLIC: GET /status/:hash
  router.get('/status/:hash', generalLimiter, async (req, res) => {
    // COPY lines 865-895 here
  });

  // ADMIN: GET /admin/pending
  router.get('/admin/pending', authenticate, async (req, res) => {
    // COPY lines 2166-2187 here
  });

  // Continue for all 9 routes...

  return router;
}

module.exports = { createScriptsRoutes };
```

---

## All Remaining Modules - Quick Reference

### Violations Routes (30 min)
**File**: `src/server/routes/violations.js`

| Route | Lines | Notes |
|-------|-------|-------|
| POST /violation | 898-976 | PUBLIC |
| GET /admin/violations | 2190-2233 | ADMIN |
| POST /admin/bulk-delete | 1654-1700 | ADMIN |

### Headers Routes (45 min)
**File**: `src/server/routes/headers.js`

| Route | Lines | Type |
|-------|-------|------|
| POST /register | 979-1027 | PUBLIC |
| GET /baseline/:pageUrl | 1030-1056 | PUBLIC |
| POST /violation | 1059-1184 | PUBLIC |
| GET /admin/violations | 1340-1370 | ADMIN |
| GET /admin/baselines | 1373-1395 | ADMIN |
| POST /admin/violations/:id/review | 1398-1424 | ADMIN |
| POST /admin/violations/bulk-delete | 1703-1747 | ADMIN |
| POST /admin/baselines/bulk-delete | 1750-1794 | ADMIN |

### Network Routes (45 min)
**File**: `src/server/routes/network.js`

| Route | Lines | Type |
|-------|-------|------|
| POST /violation | 1187-1308 | PUBLIC |
| GET /whitelist | 1311-1337 | PUBLIC |
| GET /admin/violations | 1427-1462 | ADMIN |
| POST /admin/violations/:id/review | 1465-1491 | ADMIN |
| POST /admin/violations/:id/whitelist | 1494-1538 | ADMIN |
| GET /admin/whitelist | 1541-1560 | ADMIN |
| DELETE /admin/whitelist/:id | 1563-1580 | ADMIN |
| POST /admin/violations/bulk-delete | 1797-1841 | ADMIN |

### Admin Routes (45 min)
**File**: `src/server/routes/admin.js`

| Route | Lines | Type |
|-------|-------|------|
| GET /dashboard | 2141-2162 | ADMIN |
| GET /audit-trail | 1848-1928 | ADMIN |
| GET /audit-trail/stats | 1931-2005 | ADMIN |
| GET /pci-dss/summary | 1583-1651 | ADMIN |
| GET /users | 2008-2033 | ADMIN |
| POST /users | 2036-2063 | ADMIN |
| PUT /users/:id | 2066-2101 | ADMIN |
| DELETE /users/:id | 2104-2138 | ADMIN |

---

## App.js Template (15 minutes)

Once all route modules are done, create `src/server/app.js`:

```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { getDatabase } = require('../../database-manager');
const AlertScheduler = require('../../alert-scheduler');

// Import all middleware
const { generalLimiter, registrationLimiter, violationLimiter } = require('./middleware/rateLimiting');
const { createAuthMiddleware, requireRole } = require('./middleware/auth');

// Import services
const { createAuditService } = require('./services/auditService');

// Import all routes
const { createAuthRoutes } = require('./routes/auth');
const { createScriptsRoutes } = require('./routes/scripts');
const { createViolationsRoutes } = require('./routes/violations');
const { createHeadersRoutes } = require('./routes/headers');
const { createNetworkRoutes } = require('./routes/network');
const { createAdminRoutes } = require('./routes/admin');

async function createApp() {
  const app = express();

  // Initialize database
  const db = getDatabase({
    type: process.env.DB_TYPE || 'sqlite',
    sqlitePath: process.env.SQLITE_PATH || './data/integrity-monitor.db',
    pgHost: process.env.PG_HOST,
    pgPort: process.env.PG_PORT,
    pgDatabase: process.env.PG_DATABASE,
    pgUser: process.env.PG_USER,
    pgPassword: process.env.PG_PASSWORD,
    logQueries: process.env.LOG_QUERIES === 'true'
  });
  await db.initialize();

  // Initialize services
  const { logAudit } = createAuditService(db);
  const authenticate = createAuthMiddleware(db);
  const alertScheduler = new AlertScheduler(db);

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    }
  }));

  app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
  }));

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  app.use(express.static('public'));

  // Request logging
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} -> ${res.statusCode} (${duration}ms)`);
    });
    next();
  });

  // Mount all routes
  const rateLimiters = { generalLimiter, registrationLimiter, violationLimiter };

  app.use('/api/admin/auth', createAuthRoutes(db, authenticate, rateLimiters));
  app.use('/api/scripts', createScriptsRoutes(db, logAudit, authenticate, requireRole, rateLimiters));
  app.use('/api/scripts', createViolationsRoutes(db, logAudit, authenticate, rateLimiters));
  app.use('/api/headers', createHeadersRoutes(db, logAudit, authenticate, rateLimiters));
  app.use('/api/network', createNetworkRoutes(db, logAudit, authenticate, rateLimiters));
  app.use('/api/admin', createAdminRoutes(db, logAudit, authenticate, requireRole, rateLimiters));

  // Health check
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Error handling
  app.use((err, req, res, next) => {
    console.error('[Error]', err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return { app, db, alertScheduler };
}

module.exports = { createApp };
```

---

## server.js Template (5 minutes)

```javascript
require('dotenv').config();
const { createApp } = require('./src/server/app');

async function startServer() {
  try {
    const { app, db, alertScheduler } = await createApp();

    const PORT = process.env.PORT || 3000;
    const server = app.listen(PORT, () => {
      console.log(`
========================================
Script Integrity Monitor Server
========================================
Server running on port ${PORT}
Database: ${process.env.DB_TYPE || 'sqlite'}

Admin Panel: http://localhost:${PORT}/admin-panel.html
Health Check: http://localhost:${PORT}/health
========================================
      `);
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      console.log('[Server] Shutting down gracefully...');
      server.close(async () => {
        await db.close();
        process.exit(0);
      });
    });

  } catch (error) {
    console.error('[Server] Failed to start:', error);
    process.exit(1);
  }
}

startServer();
```

---

## Testing Checklist

After creating all modules:

```bash
# 1. Test server starts
node server.js

# 2. Test health endpoint
curl http://localhost:3000/health

# 3. Test admin panel
open http://localhost:3000/admin-panel.html

# 4. Test auth
curl -X POST http://localhost:3000/api/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}'

# 5. Run existing tests
npm test
```

---

## Success! 🎉

Once you complete this, you'll have:
- ✅ 27 modular files instead of 3 monoliths
- ✅ Average file size: ~270 lines (was ~2,700)
- ✅ Easy for AI agents to analyze and modify
- ✅ Better maintainability and testability
- ✅ Same functionality, better structure

**Estimated time**: 3-4 hours for all server routes + app setup

**You've got this!** 🚀
