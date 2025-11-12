/**
 * Enhanced Server-Side Alert Handler with Database Integration
 * PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * Features:
 * - Database integration (SQLite/PostgreSQL)
 * - Auto-discovery and registration workflow
 * - Approval queue management
 * - Integrity violation tracking
 * - Admin authentication
 * - Email/Slack notifications
 * - Comprehensive API endpoints
 *
 * @version 2.0.0
 */

'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { getDatabase } = require('./database-manager');

const app = express();

// ============================================================================
// MIDDLEWARE
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

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ============================================================================
// RATE LIMITING
// ============================================================================

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP'
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 200, // Max 200 script registrations per hour per session
  keyGenerator: (req) => req.headers['x-session-id'] || req.ip,
  message: 'Too many script registrations from this session'
});

const violationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.headers['x-session-id'] || req.ip,
  message: 'Too many violation reports from this session'
});

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

let db = null;

async function initializeDatabase() {
  try {
    db = getDatabase({
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
  } catch (error) {
    console.error('[Server] Database initialization failed:', error.message);
    throw error;
  }
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

async function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') ||
                req.headers['x-api-token'];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    // Verify token against database
    const admin = await db.queryOne(
      'SELECT * FROM admin_users WHERE api_token = ? AND is_active = 1',
      [token]
    );

    if (!admin) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Check if account is locked
    if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
      return res.status(403).json({ error: 'Account temporarily locked' });
    }

    // Attach admin to request
    req.admin = admin;

    // Update last login
    await db.query(
      'UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?',
      [admin.id]
    );

    next();
  } catch (error) {
    console.error('[Auth] Error:', error.message);
    res.status(500).json({ error: 'Authentication error' });
  }
}

// Permission check middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.admin || !roles.includes(req.admin.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// ============================================================================
// PUBLIC API ENDPOINTS (Client-Side Integration)
// ============================================================================

/**
 * POST /api/scripts/register
 * Register a newly discovered script
 */
app.post('/api/scripts/register', registrationLimiter, async (req, res) => {
  try {
    const {
      url,
      contentHash,
      scriptType,
      sizeBytes,
      contentPreview,
      pageUrl,
      discoveryContext
    } = req.body;

    // Validate required fields
    if (!url || !contentHash || !scriptType) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['url', 'contentHash', 'scriptType']
      });
    }

    // Register script in database
    const result = await db.registerScript({
      url,
      contentHash,
      scriptType,
      sizeBytes,
      contentPreview,
      pageUrl,
      discoveryContext
    });

    // Send notification if new script
    if (result.isNew) {
      await queueNotification({
        type: 'email',
        subject: 'New Script Pending Approval',
        message: `A new script has been discovered and requires approval:\n\nURL: ${url}\nPage: ${pageUrl}\nHash: ${contentHash}`,
        scriptId: result.scriptId
      });

      console.log(`[Registration] New script registered: ${url}`);
    }

    res.json({
      success: true,
      scriptId: result.scriptId,
      status: result.status,
      isNew: result.isNew
    });

  } catch (error) {
    console.error('[Registration] Error:', error.message);
    res.status(500).json({ error: 'Registration failed', message: error.message });
  }
});

/**
 * GET /api/scripts/status/:hash
 * Check approval status of a script by its hash
 */
app.get('/api/scripts/status/:hash', generalLimiter, async (req, res) => {
  try {
    const { hash } = req.params;

    const script = await db.getScriptStatus(hash);

    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }

    res.json({
      id: script.id,
      url: script.url,
      status: script.status,
      approvedAt: script.approved_at
    });

  } catch (error) {
    console.error('[Status Check] Error:', error.message);
    res.status(500).json({ error: 'Status check failed' });
  }
});

/**
 * POST /api/scripts/violation
 * Report an integrity violation
 */
app.post('/api/scripts/violation', violationLimiter, async (req, res) => {
  try {
    const {
      scriptUrl,
      oldHash,
      newHash,
      violationType,
      pageUrl,
      userSession,
      userAgent,
      severity,
      loadType,
      context
    } = req.body;

    // Validate required fields
    if (!scriptUrl || !newHash || !violationType) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['scriptUrl', 'newHash', 'violationType']
      });
    }

    // Hash IP address for privacy
    const ipAddress = hashIpAddress(req.ip);

    // Find script ID if exists
    const script = await db.queryOne(
      'SELECT id FROM scripts WHERE url = ? LIMIT 1',
      [scriptUrl]
    );

    // Log violation
    const violationId = await db.logViolation({
      scriptId: script?.id || null,
      scriptUrl,
      oldHash,
      newHash,
      violationType,
      pageUrl,
      userSession,
      userAgent,
      ipAddress,
      severity,
      loadType,
      context
    });

    // Send alert for critical violations
    if (severity === 'HIGH' || severity === 'CRITICAL') {
      await queueNotification({
        type: 'email',
        subject: `${severity} Integrity Violation Detected`,
        message: `Script integrity violation detected:\n\nScript: ${scriptUrl}\nType: ${violationType}\nPage: ${pageUrl}\nSeverity: ${severity}`,
        violationId
      });
    }

    console.log(`[Violation] ${severity} violation logged: ${scriptUrl} (${violationType})`);

    res.json({
      success: true,
      violationId,
      action: 'logged'
    });

  } catch (error) {
    console.error('[Violation] Error:', error.message);
    res.status(500).json({ error: 'Violation reporting failed' });
  }
});

// ============================================================================
// ADMIN API ENDPOINTS (Protected)
// ============================================================================

/**
 * GET /api/admin/scripts/pending
 * Get scripts pending approval
 */
app.get('/api/admin/scripts/pending', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const scripts = await db.getPendingApprovals(limit, offset);

    res.json({
      success: true,
      data: scripts,
      count: scripts.length,
      limit,
      offset
    });

  } catch (error) {
    console.error('[Admin] Error fetching pending scripts:', error.message);
    res.status(500).json({ error: 'Failed to fetch pending scripts' });
  }
});

/**
 * POST /api/admin/scripts/:id/approve
 * Approve a script
 */
app.post('/api/admin/scripts/:id/approve', authenticate, requireRole('reviewer', 'admin', 'super_admin'), async (req, res) => {
  try {
    const scriptId = parseInt(req.params.id);
    const {
      businessJustification,
      scriptPurpose,
      scriptOwner,
      riskLevel,
      approvalNotes
    } = req.body;

    // Validate required fields
    if (!businessJustification || !scriptPurpose) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['businessJustification', 'scriptPurpose']
      });
    }

    const success = await db.approveScript(scriptId, {
      approvedBy: req.admin.username,
      businessJustification,
      scriptPurpose,
      scriptOwner,
      riskLevel: riskLevel || 'medium',
      approvalNotes
    });

    if (!success) {
      return res.status(404).json({ error: 'Script not found' });
    }

    console.log(`[Admin] Script ${scriptId} approved by ${req.admin.username}`);

    res.json({
      success: true,
      message: 'Script approved successfully'
    });

  } catch (error) {
    console.error('[Admin] Approval error:', error.message);
    res.status(500).json({ error: 'Approval failed' });
  }
});

/**
 * POST /api/admin/scripts/:id/reject
 * Reject a script
 */
app.post('/api/admin/scripts/:id/reject', authenticate, requireRole('reviewer', 'admin', 'super_admin'), async (req, res) => {
  try {
    const scriptId = parseInt(req.params.id);
    const { rejectionReason, notes } = req.body;

    if (!rejectionReason) {
      return res.status(400).json({
        error: 'Rejection reason is required'
      });
    }

    const success = await db.rejectScript(scriptId, {
      rejectedBy: req.admin.username,
      rejectionReason,
      notes
    });

    if (!success) {
      return res.status(404).json({ error: 'Script not found' });
    }

    console.log(`[Admin] Script ${scriptId} rejected by ${req.admin.username}`);

    res.json({
      success: true,
      message: 'Script rejected successfully'
    });

  } catch (error) {
    console.error('[Admin] Rejection error:', error.message);
    res.status(500).json({ error: 'Rejection failed' });
  }
});

/**
 * GET /api/admin/violations
 * Get integrity violations
 */
app.get('/api/admin/violations', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const violations = await db.getRecentViolations(limit, offset);

    res.json({
      success: true,
      data: violations,
      count: violations.length,
      limit,
      offset
    });

  } catch (error) {
    console.error('[Admin] Error fetching violations:', error.message);
    res.status(500).json({ error: 'Failed to fetch violations' });
  }
});

/**
 * GET /api/admin/scripts/search
 * Search scripts (MUST be before /:id route)
 */
app.get('/api/admin/scripts/search', authenticate, async (req, res) => {
  try {
    const { q, status, type, limit, offset } = req.query;

    const scripts = await db.searchScripts({
      query: q,
      status,
      scriptType: type,
      limit: parseInt(limit) || 50,
      offset: parseInt(offset) || 0
    });

    res.json({
      success: true,
      data: scripts,
      count: scripts.length
    });

  } catch (error) {
    console.error('[Admin] Search error:', error.message);
    res.status(500).json({ error: 'Search failed' });
  }
});

/**
 * GET /api/admin/scripts/:id
 * Get script details
 */
app.get('/api/admin/scripts/:id', authenticate, async (req, res) => {
  try {
    const scriptId = parseInt(req.params.id);
    const script = await db.getScriptById(scriptId);

    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }

    // Get audit log
    const auditLog = await db.getScriptAuditLog(scriptId, 20);

    res.json({
      success: true,
      script,
      auditLog
    });

  } catch (error) {
    console.error('[Admin] Error fetching script:', error.message);
    res.status(500).json({ error: 'Failed to fetch script' });
  }
});

/**
 * POST /api/admin/violations/:id/review
 * Update violation review status
 */
app.post('/api/admin/violations/:id/review', authenticate, requireRole('reviewer', 'admin', 'super_admin'), async (req, res) => {
  try {
    const violationId = parseInt(req.params.id);
    const { reviewStatus, reviewNotes } = req.body;

    const validStatuses = ['investigating', 'resolved', 'false_positive', 'confirmed_attack'];
    if (!validStatuses.includes(reviewStatus)) {
      return res.status(400).json({
        error: 'Invalid review status',
        validStatuses
      });
    }

    const success = await db.updateViolationReview(violationId, {
      reviewStatus,
      reviewedBy: req.admin.username,
      reviewNotes
    });

    if (!success) {
      return res.status(404).json({ error: 'Violation not found' });
    }

    res.json({
      success: true,
      message: 'Violation review updated'
    });

  } catch (error) {
    console.error('[Admin] Review error:', error.message);
    res.status(500).json({ error: 'Review update failed' });
  }
});

/**
 * GET /api/admin/dashboard
 * Get dashboard statistics
 */
app.get('/api/admin/dashboard', authenticate, async (req, res) => {
  try {
    const [complianceSummary, violationStats] = await Promise.all([
      db.getComplianceSummary(),
      db.getViolationStatistics()
    ]);

    res.json({
      success: true,
      compliance: complianceSummary,
      violations: violationStats,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[Admin] Dashboard error:', error.message);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// ============================================================================
// HEALTH CHECK & STATUS
// ============================================================================

app.get('/health', async (req, res) => {
  const dbHealth = await db.healthCheck();

  res.json({
    status: dbHealth.healthy ? 'healthy' : 'unhealthy',
    service: 'script-integrity-monitor-server',
    version: '2.0.0',
    database: dbHealth,
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Hash IP address for privacy compliance
 */
function hashIpAddress(ip) {
  return crypto.createHash('sha256').update(ip + process.env.IP_SALT || 'default-salt').digest('hex');
}

/**
 * Queue notification for sending
 */
async function queueNotification(notification) {
  try {
    if (!db) return;

    // Get notification settings from config
    const emailConfig = await db.queryOne(
      "SELECT value FROM system_config WHERE key = 'violation_alert_email'"
    );

    if (emailConfig?.value) {
      await db.query(
        `INSERT INTO notification_queue (
          notification_type, recipient, subject, message, script_id, violation_id, priority
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          notification.type || 'email',
          emailConfig.value,
          notification.subject,
          notification.message,
          notification.scriptId || null,
          notification.violationId || null,
          notification.priority || 'normal'
        ]
      );

      console.log('[Notification] Queued:', notification.subject);
    }
  } catch (error) {
    console.error('[Notification] Queue error:', error.message);
  }
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[Server Error]', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    // Initialize database
    await initializeDatabase();

    // Start Express server
    app.listen(PORT, () => {
      console.log('\n========================================');
      console.log('Script Integrity Monitor Server');
      console.log('========================================');
      console.log(`Server running on port ${PORT}`);
      console.log(`Database: ${db.config.type}`);
      console.log('\nPublic API Endpoints:');
      console.log(`  POST   http://localhost:${PORT}/api/scripts/register`);
      console.log(`  GET    http://localhost:${PORT}/api/scripts/status/:hash`);
      console.log(`  POST   http://localhost:${PORT}/api/scripts/violation`);
      console.log('\nAdmin API Endpoints (require authentication):');
      console.log(`  GET    http://localhost:${PORT}/api/admin/scripts/pending`);
      console.log(`  POST   http://localhost:${PORT}/api/admin/scripts/:id/approve`);
      console.log(`  POST   http://localhost:${PORT}/api/admin/scripts/:id/reject`);
      console.log(`  GET    http://localhost:${PORT}/api/admin/violations`);
      console.log(`  GET    http://localhost:${PORT}/api/admin/dashboard`);
      console.log('\nAdmin Panel:');
      console.log(`  http://localhost:${PORT}/admin-panel.html`);
      console.log('\nHealth Check:');
      console.log(`  GET    http://localhost:${PORT}/health`);
      console.log('========================================\n');
    });

  } catch (error) {
    console.error('Failed to start server:', error.message);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n[Server] Shutting down gracefully...');
  if (db) {
    await db.close();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n[Server] Shutting down gracefully...');
  if (db) {
    await db.close();
  }
  process.exit(0);
});

// Start server
startServer();

module.exports = app;
