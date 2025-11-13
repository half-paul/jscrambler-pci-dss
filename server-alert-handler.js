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
const bcrypt = require('bcrypt');
const { getDatabase } = require('./database-manager');
const mfaAuth = require('./auth-mfa');

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
    // Try JWT token first (new MFA auth)
    try {
      const decoded = mfaAuth.verifyToken(token);

      // Check if session is valid and not revoked
      const session = await db.queryOne(
        'SELECT * FROM admin_sessions WHERE jwt_token = ? AND is_revoked = 0',
        [token]
      );

      if (session) {
        // Check if session expired
        if (new Date(session.expires_at) < new Date()) {
          return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
        }

        // Get admin user
        const admin = await db.queryOne(
          'SELECT * FROM admin_users WHERE id = ? AND is_active = 1',
          [decoded.id]
        );

        if (!admin) {
          return res.status(401).json({ error: 'User not found or inactive' });
        }

        // Check if account is locked
        if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
          return res.status(403).json({ error: 'Account temporarily locked' });
        }

        // Update last activity
        await db.query(
          'UPDATE admin_sessions SET last_activity = CURRENT_TIMESTAMP WHERE jwt_token = ?',
          [token]
        );

        // Attach admin to request
        req.admin = admin;
        return next();
      }
    } catch (jwtError) {
      // JWT verification failed, try legacy API token
      console.log('[Auth] JWT verification failed, trying legacy token');
    }

    // Fall back to legacy API token authentication
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

    // Update last login (legacy)
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
// AUTHENTICATION ENDPOINTS (MFA)
// ============================================================================

/**
 * POST /api/admin/auth/login
 * Step 1: Authenticate with username/password
 */
app.post('/api/admin/auth/login', generalLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Get admin user
    const admin = await db.queryOne(
      'SELECT * FROM admin_users WHERE username = ? AND is_active = 1',
      [username]
    );

    if (!admin) {
      console.log('[Auth] Login attempt for non-existent user:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
      return res.status(403).json({
        error: 'Account temporarily locked',
        lockedUntil: admin.locked_until
      });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, admin.password_hash);

    if (!passwordMatch) {
      // Increment failed login attempts
      await db.query(
        `UPDATE admin_users SET
          failed_login_attempts = failed_login_attempts + 1,
          locked_until = CASE
            WHEN failed_login_attempts + 1 >= ? THEN datetime('now', '+30 minutes')
            ELSE locked_until
          END
        WHERE id = ?`,
        [parseInt(process.env.MAX_FAILED_LOGIN_ATTEMPTS) || 5, admin.id]
      );

      console.log('[Auth] Failed login attempt for:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset failed login attempts on successful password verification
    await db.query(
      'UPDATE admin_users SET failed_login_attempts = 0 WHERE id = ?',
      [admin.id]
    );

    // Check if MFA is enabled
    if (admin.mfa_enabled) {
      // Return temporary token for MFA verification
      const tempToken = mfaAuth.generateTokens({ id: admin.id, temp: true });

      console.log('[Auth] Password verified for:', username, '- MFA required');
      return res.json({
        mfaRequired: true,
        tempToken: tempToken.accessToken,
        username: admin.username
      });
    }

    // No MFA - generate full session tokens
    const tokens = mfaAuth.generateTokens(admin);

    // Create session in database
    await db.query(
      `INSERT INTO admin_sessions (
        admin_id, jwt_token, refresh_token, expires_at, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?)`,
      [
        admin.id,
        tokens.accessToken,
        tokens.refreshToken,
        mfaAuth.calculateExpiryDate(process.env.JWT_EXPIRES_IN || '1h').toISOString(),
        req.ip,
        req.get('user-agent')
      ]
    );

    // Update last login
    await db.query(
      'UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?',
      [admin.id]
    );

    console.log('[Auth] Login successful (no MFA):', username);

    res.json({
      success: true,
      mfaRequired: false,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      admin: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    });

  } catch (error) {
    console.error('[Auth] Login error:', error.message);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

/**
 * POST /api/admin/auth/verify-mfa
 * Step 2: Verify MFA token after password authentication
 */
app.post('/api/admin/auth/verify-mfa', generalLimiter, async (req, res) => {
  try {
    const { tempToken, mfaCode, useBackupCode } = req.body;

    if (!tempToken || !mfaCode) {
      return res.status(400).json({ error: 'Temporary token and MFA code required' });
    }

    // Verify temporary token
    let decoded;
    try {
      decoded = mfaAuth.verifyToken(tempToken);
      if (!decoded.temp) {
        return res.status(401).json({ error: 'Invalid temporary token' });
      }
    } catch (error) {
      return res.status(401).json({ error: 'Invalid or expired temporary token' });
    }

    // Get admin user
    const admin = await db.queryOne(
      'SELECT * FROM admin_users WHERE id = ? AND is_active = 1',
      [decoded.id]
    );

    if (!admin || !admin.mfa_enabled) {
      return res.status(401).json({ error: 'MFA not enabled for this account' });
    }

    let mfaValid = false;

    if (useBackupCode) {
      // Verify backup code
      const backupCodes = JSON.parse(admin.mfa_backup_codes || '[]');
      const codeIndex = backupCodes.findIndex(hashedCode =>
        mfaAuth.verifyBackupCode(hashedCode, mfaCode)
      );

      if (codeIndex !== -1) {
        mfaValid = true;
        // Remove used backup code
        backupCodes.splice(codeIndex, 1);
        await db.query(
          'UPDATE admin_users SET mfa_backup_codes = ? WHERE id = ?',
          [JSON.stringify(backupCodes), admin.id]
        );
        console.log('[Auth] Backup code used for:', admin.username);
      }
    } else {
      // Verify TOTP
      mfaValid = mfaAuth.verifyTOTP(admin.mfa_secret, mfaCode);
    }

    if (!mfaValid) {
      console.log('[Auth] Invalid MFA code for:', admin.username);
      return res.status(401).json({ error: 'Invalid MFA code' });
    }

    // Generate full session tokens
    const tokens = mfaAuth.generateTokens(admin);

    // Create session in database
    await db.query(
      `INSERT INTO admin_sessions (
        admin_id, jwt_token, refresh_token, expires_at, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?) `,
      [
        admin.id,
        tokens.accessToken,
        tokens.refreshToken,
        mfaAuth.calculateExpiryDate(process.env.JWT_EXPIRES_IN || '1h').toISOString(),
        req.ip,
        req.get('user-agent')
      ]
    );


    // Update last login
    await db.query(
      'UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?',
      [admin.id]
    );

    console.log('[Auth] MFA verification successful:', admin.username);

    res.json({
      success: true,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      admin: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
        mfaEnabled: admin.mfa_enabled
      }
    });

  } catch (error) {
    console.error('[Auth] MFA verification error:', error.message);
    res.status(500).json({ error: 'MFA verification failed' });
  }
});

/**
 * POST /api/admin/auth/setup-mfa
 * Setup MFA for authenticated user
 */
app.post('/api/admin/auth/setup-mfa', authenticate, async (req, res) => {
  try {
    const { action, verificationCode } = req.body;

    if (action === 'generate') {
      // Generate new MFA secret and QR code
      const mfaData = await mfaAuth.generateMFASecret(req.admin.username);

      // Store secret temporarily (will be confirmed with verification)
      await db.query(
        'UPDATE admin_users SET mfa_secret = ? WHERE id = ?',
        [mfaData.secret, req.admin.id]
      );

      console.log('[Auth] MFA setup initiated for:', req.admin.username);

      res.json({
        success: true,
        secret: mfaData.secret,
        qrCode: mfaData.qrCode,
        otpauthUrl: mfaData.otpauthUrl
      });

    } else if (action === 'verify') {
      // Verify the TOTP code to confirm setup
      const admin = await db.queryOne(
        'SELECT mfa_secret FROM admin_users WHERE id = ?',
        [req.admin.id]
      );

      if (!admin.mfa_secret) {
        return res.status(400).json({ error: 'MFA setup not initiated' });
      }

      const isValid = mfaAuth.verifyTOTP(admin.mfa_secret, verificationCode);

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid verification code' });
      }

      // Generate backup codes
      const backupCodes = mfaAuth.generateBackupCodes(10);
      const hashedBackupCodes = backupCodes.map(code => mfaAuth.hashBackupCode(code));

      // Enable MFA
      await db.query(
        `UPDATE admin_users SET
          mfa_enabled = 1,
          mfa_backup_codes = ?,
          mfa_setup_at = CURRENT_TIMESTAMP
        WHERE id = ?`,
        [JSON.stringify(hashedBackupCodes), req.admin.id]
      );

      console.log('[Auth] MFA enabled for:', req.admin.username);

      res.json({
        success: true,
        backupCodes: backupCodes,
        message: 'MFA enabled successfully. Save your backup codes in a secure location.'
      });

    } else if (action === 'disable') {
      // Disable MFA (requires verification code)
      const admin = await db.queryOne(
        'SELECT mfa_secret, mfa_enabled FROM admin_users WHERE id = ?',
        [req.admin.id]
      );

      if (!admin.mfa_enabled) {
        return res.status(400).json({ error: 'MFA is not enabled' });
      }

      const isValid = mfaAuth.verifyTOTP(admin.mfa_secret, verificationCode);

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid verification code' });
      }

      // Disable MFA
      await db.query(
        `UPDATE admin_users SET
          mfa_enabled = 0,
          mfa_secret = NULL,
          mfa_backup_codes = NULL
        WHERE id = ?`,
        [req.admin.id]
      );

      console.log('[Auth] MFA disabled for:', req.admin.username);

      res.json({
        success: true,
        message: 'MFA disabled successfully'
      });

    } else {
      res.status(400).json({ error: 'Invalid action' });
    }

  } catch (error) {
    console.error('[Auth] MFA setup error:', error.message);
    res.status(500).json({ error: 'MFA setup failed' });
  }
});

/**
 * POST /api/admin/auth/logout
 * Logout and revoke session
 */
app.post('/api/admin/auth/logout', authenticate, async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '') ||
                  req.headers['x-api-token'];

    if (token) {
      // Revoke session
      await db.query(
        'UPDATE admin_sessions SET is_revoked = 1 WHERE jwt_token = ?',
        [token]
      );
    }

    console.log('[Auth] Logout:', req.admin.username);

    res.json({ success: true, message: 'Logged out successfully' });

  } catch (error) {
    console.error('[Auth] Logout error:', error.message);
    res.status(500).json({ error: 'Logout failed' });
  }
});

/**
 * POST /api/admin/auth/refresh
 * Refresh expired JWT token
 */
app.post('/api/admin/auth/refresh', generalLimiter, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = mfaAuth.verifyToken(refreshToken);
      if (decoded.type !== 'refresh') {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }
    } catch (error) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    // Check if session exists and is not revoked
    const session = await db.queryOne(
      'SELECT * FROM admin_sessions WHERE refresh_token = ? AND is_revoked = 0',
      [refreshToken]
    );

    if (!session) {
      return res.status(401).json({ error: 'Session not found or revoked' });
    }

    // Get admin user
    const admin = await db.queryOne(
      'SELECT * FROM admin_users WHERE id = ? AND is_active = 1',
      [decoded.id]
    );

    if (!admin) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    // Generate new access token
    const tokens = mfaAuth.generateTokens(admin);

    // Update session
    await db.query(
      `UPDATE admin_sessions SET
        jwt_token = ?,
        expires_at = ?,
        last_activity = CURRENT_TIMESTAMP
      WHERE refresh_token = ?`,
      [
        tokens.accessToken,
        mfaAuth.calculateExpiryDate(process.env.JWT_EXPIRES_IN || '1h').toISOString(),
        refreshToken
      ]
    );

    console.log('[Auth] Token refreshed for:', admin.username);

    res.json({
      success: true,
      accessToken: tokens.accessToken
    });

  } catch (error) {
    console.error('[Auth] Token refresh error:', error.message);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

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
      discoveryContext,
      scriptPosition  // NEW: Position of inline script
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
      discoveryContext,
      scriptPosition  // NEW: Pass position to database
    });

    // Send notification if new script (but not for variations - only truly new scripts)
    if (result.isNew && !result.isVariation) {
      await queueNotification({
        type: 'email',
        subject: 'New Script Pending Approval',
        message: `A new script has been discovered and requires approval:\n\nURL: ${url}\nPage: ${pageUrl}\nHash: ${contentHash}`,
        scriptId: result.scriptId
      });

      console.log(`[Registration] New script registered: ${url}`);
    } else if (result.isVariation) {
      console.log(`[Registration] Inline script variation detected: ${url} (variation #${result.variationNumber}, parent: ${result.parentScriptId})`);
    } else {
      console.log(`[Registration] Script re-detected: ${url} (access count: ${result.accessCount})`);
    }

    res.json({
      success: true,
      scriptId: result.scriptId,
      status: result.status,
      isNew: result.isNew,
      isVariation: result.isVariation || false,
      accessCount: result.accessCount || 1,
      parentScriptId: result.parentScriptId || null,
      variationNumber: result.variationNumber || null
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

    // Check if script exists to provide accurate 404 feedback
    const scriptExists = await db.queryOne('SELECT id FROM scripts WHERE id = ?', [scriptId]);
    if (!scriptExists) {
      return res.status(404).json({ error: 'Script not found or does not exist.' });
    }

    await db.approveScript(scriptId, {
      approvedBy: req.admin.username,
      businessJustification,
      scriptPurpose,
      scriptOwner,
      riskLevel: riskLevel || 'medium',
      approvalNotes
    });

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
    console.log('[Admin] Reject endpoint hit for script:', req.params.id);
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
 * PUT /api/admin/scripts/:id/update
 * Update script properties (except dates)
 */
app.put('/api/admin/scripts/:id/update', authenticate, requireRole('reviewer', 'admin', 'super_admin'), async (req, res) => {
  try {
    console.log('[Admin] Update endpoint hit for script:', req.params.id);
    const scriptId = parseInt(req.params.id);
    const {
      status,
      businessJustification,
      scriptPurpose,
      scriptOwner,
      riskLevel,
      approvalNotes,
      rejectionReason
    } = req.body;

    // Get current script
    const currentScript = await db.getScriptById(scriptId);
    if (!currentScript) {
      return res.status(404).json({ error: 'Script not found' });
    }

    // Build update query
    const updates = [];
    const params = [];

    if (status !== undefined) {
      const validStatuses = ['pending_approval', 'approved', 'rejected', 'flagged'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          error: 'Invalid status',
          validStatuses
        });
      }
      updates.push('status = ?');
      params.push(status);

      // If changing to approved/rejected, update approved_at and approved_by
      if ((status === 'approved' || status === 'rejected') && currentScript.status !== status) {
        updates.push('approved_at = CURRENT_TIMESTAMP');
        updates.push('approved_by = ?');
        params.push(req.admin.username);
      }
    }

    if (businessJustification !== undefined) {
      updates.push('business_justification = ?');
      params.push(businessJustification);
    }

    if (scriptPurpose !== undefined) {
      updates.push('script_purpose = ?');
      params.push(scriptPurpose);
    }

    if (scriptOwner !== undefined) {
      updates.push('script_owner = ?');
      params.push(scriptOwner);
    }

    if (riskLevel !== undefined) {
      const validRiskLevels = ['low', 'medium', 'high', 'critical'];
      if (riskLevel && !validRiskLevels.includes(riskLevel)) {
        return res.status(400).json({
          error: 'Invalid risk level',
          validRiskLevels
        });
      }
      updates.push('risk_level = ?');
      params.push(riskLevel || null);
    }

    if (approvalNotes !== undefined) {
      updates.push('approval_notes = ?');
      params.push(approvalNotes);
    }

    if (rejectionReason !== undefined) {
      updates.push('rejection_reason = ?');
      params.push(rejectionReason);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    // Execute update
    params.push(scriptId);
    const sql = `UPDATE scripts SET ${updates.join(', ')} WHERE id = ?`;
    const result = await db.query(sql, params);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Script not found' });
    }

    console.log(`[Admin] Script ${scriptId} updated by ${req.admin.username}`);

    res.json({
      success: true,
      message: 'Script updated successfully'
    });

  } catch (error) {
    console.error('[Admin] Update error:', error.message);
    res.status(500).json({ error: 'Update failed' });
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
// 404 HANDLER (must be last route)
// ============================================================================

app.use((req, res) => {
  console.log(`[404] Route not found: ${req.method} ${req.path}`);
  res.status(404).json({
    error: 'Route not found',
    method: req.method,
    path: req.path
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
