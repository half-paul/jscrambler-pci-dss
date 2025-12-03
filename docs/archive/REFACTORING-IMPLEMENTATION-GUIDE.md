# Modularization Implementation Guide

## Progress Status

### ✅ COMPLETED
1. Directory structure created
2. `src/server/middleware/rateLimiting.js` - Complete
3. `src/server/middleware/auth.js` - Complete
4. `src/server/services/auditService.js` - Complete

### 🔄 NEXT STEPS
Follow this guide to complete the remaining modules.

---

## How to Continue the Refactoring

This guide provides the exact steps to extract each remaining module from the monolithic files. Follow these steps in order for a safe, incremental refactoring.

---

## Server-Side Modules (Remaining)

### Module 1: Authentication Routes (`src/server/routes/auth.js`)

**Extract from**: `server-alert-handler.js` lines 331-764

**Routes to extract**:
- POST /api/admin/auth/login (lines 331-443)
- POST /api/admin/auth/verify-mfa (lines 446-551)
- POST /api/admin/auth/setup-mfa (lines 554-661)
- POST /api/admin/auth/logout (lines 664-688)
- POST /api/admin/auth/refresh (lines 691-764)

**Template**:
```javascript
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const mfaAuth = require('../../../auth-mfa');

/**
 * Create authentication routes
 * @param {Object} db - Database instance
 * @param {Function} logAudit - Audit logging function
 * @param {Object} rateLimiters - Rate limiter middleware
 * @returns {Router} Express router
 */
function createAuthRoutes(db, logAudit, rateLimiters) {
  const { generalLimiter } = rateLimiters;

  // POST /api/admin/auth/login
  router.post('/login', generalLimiter, async (req, res) => {
    // Copy implementation from lines 332-443
  });

  // POST /api/admin/auth/verify-mfa
  router.post('/verify-mfa', generalLimiter, async (req, res) => {
    // Copy implementation from lines 447-551
  });

  // POST /api/admin/auth/setup-mfa
  router.post('/setup-mfa', authenticate, async (req, res) => {
    // Copy implementation from lines 555-661
  });

  // POST /api/admin/auth/logout
  router.post('/logout', authenticate, async (req, res) => {
    // Copy implementation from lines 665-688
  });

  // POST /api/admin/auth/refresh
  router.post('/refresh', generalLimiter, async (req, res) => {
    // Copy implementation from lines 692-764
  });

  return router;
}

module.exports = { createAuthRoutes };
```

**How to extract**:
1. Read `server-alert-handler.js` lines 331-764
2. Copy each route handler function body
3. Replace `app.post` with `router.post`
4. Remove `/api/admin/auth` prefix from route paths (handled by mount point)
5. Test: `curl -X POST http://localhost:3000/api/admin/auth/login`

---

### Module 2: Scripts Routes (`src/server/routes/scripts.js`)

**Extract from**: `server-alert-handler.js` lines 768-2137

**Routes to extract**:
- POST /api/scripts/register (lines 768-861) - PUBLIC
- GET /api/scripts/status/:hash (lines 864-895) - PUBLIC
- GET /api/admin/scripts/pending (lines 2165-2187)
- GET /api/admin/scripts/search (lines 2236-2276)
- POST /api/admin/scripts/:id/approve (lines 2279-2324)
- POST /api/admin/scripts/:id/reject (lines 2327-2357)
- POST /api/admin/scripts/bulk-approve (lines 2360-2467)
- POST /api/admin/scripts/bulk-reject (lines 2470-2573)
- DELETE /api/admin/scripts/:id (lines 2576-2638)

**Template**:
```javascript
const express = require('express');
const router = express.Router();

function createScriptsRoutes(db, logAudit, authenticate, requireRole, rateLimiters) {
  const { registrationLimiter, generalLimiter } = rateLimiters;

  // Public endpoints
  router.post('/register', registrationLimiter, async (req, res) => {
    // Copy from lines 769-861
  });

  router.get('/status/:hash', generalLimiter, async (req, res) => {
    // Copy from lines 865-895
  });

  // Admin endpoints
  router.get('/admin/pending', authenticate, async (req, res) => {
    // Copy from lines 2166-2187
  });

  // ... rest of routes

  return router;
}

module.exports = { createScriptsRoutes };
```

---

### Module 3: Violations Routes (`src/server/routes/violations.js`)

**Extract from**: `server-alert-handler.js` lines 898-1652

**Routes to extract**:
- POST /api/scripts/violation (lines 898-976) - PUBLIC
- GET /api/admin/violations (lines 2190-2233)
- POST /api/admin/violations/bulk-delete (lines 1654-1700)

---

### Module 4: Headers Routes (`src/server/routes/headers.js`)

**Extract from**: `server-alert-handler.js` lines 979-1795

**Routes to extract**:
- POST /api/headers/register (lines 979-1027)
- GET /api/headers/baseline/:pageUrl (lines 1030-1056)
- POST /api/headers/violation (lines 1059-1184)
- GET /api/admin/headers/violations (lines 1340-1370)
- GET /api/admin/headers/baselines (lines 1373-1395)
- POST /api/admin/headers/violations/:id/review (lines 1398-1424)
- POST /api/admin/headers/violations/bulk-delete (lines 1703-1747)
- POST /api/admin/headers/baselines/bulk-delete (lines 1750-1794)

---

### Module 5: Network Routes (`src/server/routes/network.js`)

**Extract from**: `server-alert-handler.js` lines 1187-1844

**Routes to extract**:
- POST /api/network/violation (lines 1187-1308)
- GET /api/network/whitelist (lines 1311-1337)
- GET /api/admin/network/violations (lines 1427-1462)
- POST /api/admin/network/violations/:id/review (lines 1465-1491)
- POST /api/admin/network/violations/:id/whitelist (lines 1494-1538)
- GET /api/admin/network/whitelist (lines 1541-1560)
- DELETE /api/admin/network/whitelist/:id (lines 1563-1580)
- POST /api/admin/network/violations/bulk-delete (lines 1797-1841)

---

### Module 6: Admin Routes (`src/server/routes/admin.js`)

**Extract from**: `server-alert-handler.js` lines 1583-2138

**Routes to extract**:
- GET /api/admin/dashboard (lines 2141-2162)
- GET /api/admin/audit-trail (lines 1848-1928)
- GET /api/admin/audit-trail/stats (lines 1931-2005)
- GET /api/admin/pci-dss/summary (lines 1583-1651)
- GET /api/admin/users (lines 2008-2033)
- POST /api/admin/users (lines 2036-2063)
- PUT /api/admin/users/:id (lines 2066-2101)
- DELETE /api/admin/users/:id (lines 2104-2138)

---

### Module 7: Main Application (`src/server/app.js`)

**Purpose**: Set up Express app and mount all routes

**Template**:
```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { getDatabase } = require('../../database-manager');
const AlertScheduler = require('../../alert-scheduler');

// Middleware
const { generalLimiter, registrationLimiter, violationLimiter } = require('./middleware/rateLimiting');
const { createAuthMiddleware, requireRole } = require('./middleware/auth');

// Services
const { createAuditService } = require('./services/auditService');

// Routes
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
    // ... other config
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
        // ... rest of CSP config
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

  // Mount routes
  const rateLimiters = { generalLimiter, registrationLimiter, violationLimiter };

  app.use('/api/admin/auth', createAuthRoutes(db, logAudit, rateLimiters));
  app.use('/api/scripts', createScriptsRoutes(db, logAudit, authenticate, requireRole, rateLimiters));
  app.use('/api', createViolationsRoutes(db, logAudit, authenticate, rateLimiters));
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

### Module 8: Server Entry Point (`server.js`)

**Purpose**: Start the HTTP server

**Template**:
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

Public API Endpoints:
  POST   http://localhost:${PORT}/api/scripts/register
  GET    http://localhost:${PORT}/api/scripts/status/:hash
  POST   http://localhost:${PORT}/api/scripts/violation

Admin API Endpoints (require authentication):
  GET    http://localhost:${PORT}/api/admin/scripts/pending
  POST   http://localhost:${PORT}/api/admin/scripts/:id/approve
  POST   http://localhost:${PORT}/api/admin/scripts/:id/reject
  GET    http://localhost:${PORT}/api/admin/violations
  GET    http://localhost:${PORT}/api/admin/dashboard

Admin Panel:
  http://localhost:${PORT}/admin-panel.html

Health Check:
  GET    http://localhost:${PORT}/health
========================================
      `);
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      console.log('[Server] SIGTERM received, shutting down gracefully...');
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

## Testing Strategy

After creating each module, test it:

### 1. Test Auth Routes
```bash
# Start server with new modular structure
node server.js

# Test login
curl -X POST http://localhost:3000/api/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}'
```

### 2. Test Scripts Routes
```bash
# Test script registration
curl -X POST http://localhost:3000/api/scripts/register \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/script.js","hash":"sha384-xxx"}'

# Test script status
curl http://localhost:3000/api/scripts/status/sha384-xxx
```

### 3. Test Admin Panel
```
Open: http://localhost:3000/admin-panel.html
Verify: All tabs work correctly
```

---

## Rollback Plan

If something breaks:

1. **Keep original file**: Rename `server-alert-handler.js` to `server-alert-handler.js.backup`
2. **Revert**: Copy backup back if needed
3. **Selective rollback**: Keep working modules, revert broken ones

---

## Completion Checklist

- [ ] All 6 route modules created
- [ ] Main app.js created
- [ ] Server.js created
- [ ] All endpoints tested
- [ ] Admin panel works
- [ ] No regressions in functionality
- [ ] Documentation updated
- [ ] package.json updated with new entry point

---

## Next Phase: Client-Side and Admin Panel

Once server refactoring is complete and tested, follow similar process for:
1. Client-side modules (script-integrity-monitor.js)
2. Admin panel modules (admin-panel.html)

**End of Implementation Guide**
