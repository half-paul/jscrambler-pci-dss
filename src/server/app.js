/**
 * Express Application Setup
 * Sets up middleware, routes, and error handling for the Script Integrity Monitor server
 *
 * @version 2.0.0 - Modular Architecture
 */

'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { getDatabase } = require('../../database-manager');
const AlertScheduler = require('../../alert-scheduler');

// Import middleware
const { generalLimiter, registrationLimiter, violationLimiter } = require('./middleware/rateLimiting');
const { createAuthMiddleware, requireRole } = require('./middleware/auth');

// Import services
const { createAuditService } = require('./services/auditService');

// Import routes
const { createAuthRoutes } = require('./routes/auth');
const { createScriptsRoutes } = require('./routes/scripts');
const { createViolationsRoutes } = require('./routes/violations');
const { createHeadersRoutes } = require('./routes/headers');
const { createNetworkRoutes } = require('./routes/network');
const { createAdminRoutes } = require('./routes/admin');

/**
 * Create and configure Express application
 * @returns {Promise<{app: Express, db: Database, alertScheduler: AlertScheduler}>}
 */
async function createApp() {
  const app = express();

  // ============================================================================
  // DATABASE INITIALIZATION
  // ============================================================================

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
  console.log('[Server] Database initialized successfully');

  // Initialize alert scheduler
  const alertScheduler = new AlertScheduler(db);
  console.log('[Server] Alert scheduler initialized');

  // ============================================================================
  // SERVICES & MIDDLEWARE INITIALIZATION
  // ============================================================================

  const { logAudit } = createAuditService(db);
  const authenticate = createAuthMiddleware(db);

  // ============================================================================
  // SECURITY MIDDLEWARE
  // ============================================================================

  // Security headers with relaxed CSP for admin panel
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],    // Allow inline scripts for admin panel
        scriptSrcAttr: ["'unsafe-inline'"],          // Allow inline event handlers (onclick, etc.)
        styleSrc: ["'self'", "'unsafe-inline'"],     // Allow inline styles
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    }
  }));

  // CORS configuration
  app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
  }));

  // Body parser
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Static files (for admin panel)
  app.use(express.static('public'));

  // Request logging with response status
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} -> ${res.statusCode} (${duration}ms)`);
    });
    next();
  });

  // ============================================================================
  // ROUTE MOUNTING
  // ============================================================================

  const rateLimiters = { generalLimiter, registrationLimiter, violationLimiter };

  // Create route instances
  const scriptsRouter = createScriptsRoutes(db, logAudit, authenticate, requireRole, rateLimiters);
  const headersRouter = createHeadersRoutes(db, logAudit, authenticate, rateLimiters);
  const networkRouter = createNetworkRoutes(db, logAudit, authenticate, rateLimiters);

  // ============================================================================
  // PUBLIC API ROUTES
  // ============================================================================

  // Scripts public routes (registration, status check)
  app.use('/api/scripts', scriptsRouter);

  // Violations routes (script integrity violations)
  app.use('/api', createViolationsRoutes(db, logAudit, authenticate, rateLimiters));

  // Headers public routes (registration, baseline, violation reporting)
  app.use('/api/headers', headersRouter);

  // Network public routes (violation reporting, whitelist query)
  app.use('/api/network', networkRouter);

  // ============================================================================
  // ADMIN API ROUTES
  // ============================================================================

  // Authentication routes
  app.use('/api/admin/auth', createAuthRoutes(db, authenticate, rateLimiters));

  // Admin script management (mount admin routes from scripts router)
  app.use('/api/admin/scripts', scriptsRouter);

  // Admin header management (mount admin routes from headers router)
  app.use('/api/admin/headers', headersRouter);

  // Admin network management (mount admin routes from network router)
  app.use('/api/admin/network', networkRouter);

  // Admin dashboard, audit trail, user management
  app.use('/api/admin', createAdminRoutes(db, logAudit, authenticate, requireRole, rateLimiters));

  // ============================================================================
  // HEALTH CHECK
  // ============================================================================

  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      database: db.config.type
    });
  });

  // ============================================================================
  // ERROR HANDLING
  // ============================================================================

  // 404 handler
  app.use((req, res) => {
    console.log(`[404] Route not found: ${req.method} ${req.path}`);
    res.status(404).json({
      error: 'Route not found',
      method: req.method,
      path: req.path
    });
  });

  // Global error handler
  app.use((err, req, res, next) => {
    console.error('[Server Error]', err);
    res.status(500).json({
      error: 'Internal server error',
      message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  });

  return { app, db, alertScheduler };
}

module.exports = { createApp };
