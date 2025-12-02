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
const AlertScheduler = require('./alert-scheduler');

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
let alertScheduler = null;

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

    // Initialize alert scheduler
    alertScheduler = new AlertScheduler(db);
    console.log('[Server] Alert scheduler initialized');

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
        'SELECT * FROM admin_sessions WHERE jwt_token = ? AND is_revoked = false',
        [token]
      );

      if (session) {
        // Check if session expired
        if (new Date(session.expires_at) < new Date()) {
          return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
        }

        // Get admin user
        const admin = await db.queryOne(
          'SELECT * FROM admin_users WHERE id = ? AND is_active = true',
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
      'SELECT * FROM admin_users WHERE api_token = ? AND is_active = true',
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
// AUDIT TRAIL LOGGING
// ============================================================================

/**
 * Log an action to the audit trail
 * @param {Object} options - Audit log options
 * @param {Object} options.req - Express request object (for IP, user-agent, etc.)
 * @param {Object} options.admin - Admin user object (from req.admin)
 * @param {string} options.actionType - Type of action (must match CHECK constraint in schema)
 * @param {string} options.entityType - Type of entity acted upon
 * @param {string|string[]} options.entityId - ID(s) of entity (can be array for bulk)
 * @param {string} options.actionDescription - Human-readable description
 * @param {string} [options.actionReason] - Optional reason provided by user
 * @param {Object} [options.oldValues] - Old values (for updates)
 * @param {Object} [options.newValues] - New values (for updates)
 * @param {boolean} [options.success=true] - Whether action succeeded
 * @param {string} [options.errorMessage] - Error message if failed
 */
async function logAudit(options) {
  try {
    const {
      req,
      admin,
      actionType,
      entityType,
      entityId,
      actionDescription,
      actionReason,
      oldValues,
      newValues,
      success = true,
      errorMessage
    } = options;

    // Handle bulk entity IDs
    const entityIdStr = Array.isArray(entityId) ? entityId.join(',') : String(entityId || '');
    const entityCount = Array.isArray(entityId) ? entityId.length : 1;

    // Hash IP address for privacy
    const ipAddress = req?.ip || req?.connection?.remoteAddress || '';
    const hashedIp = ipAddress ? crypto.createHash('sha256')
      .update(ipAddress + (process.env.IP_SALT || 'default-salt'))
      .digest('hex').substring(0, 64) : null;

    // Calculate retention date (12 months retention policy)
    const retentionDate = new Date();
    retentionDate.setMonth(retentionDate.getMonth() + 12);

    await db.query(
      `INSERT INTO audit_trail (
        timestamp, user_id, username, user_role,
        action_type, entity_type, entity_id, entity_count,
        action_description, action_reason,
        ip_address, user_agent, request_method, request_path,
        old_values, new_values,
        success, error_message, retention_until
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        new Date().toISOString(),
        admin?.id || null,
        admin?.username || 'system',
        admin?.role || null,
        actionType,
        entityType,
        entityIdStr,
        entityCount,
        actionDescription,
        actionReason || null,
        hashedIp,
        req?.headers['user-agent'] || null,
        req?.method || null,
        req?.path || null,
        oldValues ? JSON.stringify(oldValues) : null,
        newValues ? JSON.stringify(newValues) : null,
        success ? 1 : 0,
        errorMessage || null,
        retentionDate.toISOString()
      ]
    );

    console.log(`[Audit] ${actionType} by ${admin?.username || 'system'}: ${actionDescription}`);
  } catch (error) {
    // Don't fail the main operation if audit logging fails
    console.error('[Audit] Failed to log audit trail:', error.message);
  }
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
      'SELECT * FROM admin_users WHERE username = ? AND is_active = true',
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
                role: admin.role,
                mfa_enabled: admin.mfa_enabled
              }    });

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
      'SELECT * FROM admin_users WHERE id = ? AND is_active = true',
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
        mfa_enabled: admin.mfa_enabled
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
          mfa_enabled = true,
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
          mfa_enabled = false,
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
        'UPDATE admin_sessions SET is_revoked = true WHERE jwt_token = ?',
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
      'SELECT * FROM admin_sessions WHERE refresh_token = ? AND is_revoked = false',
      [refreshToken]
    );

    if (!session) {
      return res.status(401).json({ error: 'Session not found or revoked' });
    }

    // Get admin user
    const admin = await db.queryOne(
      'SELECT * FROM admin_users WHERE id = ? AND is_active = true',
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

    // Get client IP address (with privacy hashing if configured)
    let clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
                   req.headers['x-real-ip'] ||
                   req.socket.remoteAddress ||
                   req.connection.remoteAddress;
    
    // Normalize IPv6 localhost to IPv4
    if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
      clientIp = '127.0.0.1';
    }
    
    // Remove IPv6 prefix if present
    if (clientIp && clientIp.startsWith('::ffff:')) {
      clientIp = clientIp.substring(7);
    }
    
    // Only use if we have a valid IP
    if (!clientIp || clientIp.trim() === '') {
      clientIp = null;
    } else {
      clientIp = clientIp.trim();
    }
    
    console.log('[Registration] Client IP:', clientIp || 'NOT CAPTURED');

    // Register script in database
    const result = await db.registerScript({
      url,
      contentHash,
      scriptType,
      sizeBytes,
      contentPreview,
      pageUrl,
      discoveryContext,
      scriptPosition,  // NEW: Pass position to database
      clientIp         // NEW: Pass client IP for tracking
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

    // This now atomically increments the access count and returns the status
    const script = await db.incrementAccessCountAndGetStatus(hash);

    if (!script) {
      // This is not an error, it just means the script is not registered yet.
      // The client-side monitor will proceed to register it.
      return res.status(404).json({ error: 'Script not found' });
    }

    // Log the access for audit purposes
    console.log(`[Status Check] Script accessed: ${script.url} (new access count: ${script.access_count})`);

    res.json({
      id: script.id,
      url: script.url,
      status: script.status,
      approvedAt: script.approved_at,
      accessCount: script.access_count // Return the new access count
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
    console.log('[Violation] Received violation report:', req.body); // Add this line
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
// PCI DSS 11.6.1 - HTTP HEADER MONITORING ENDPOINTS
// ============================================================================

/**
 * POST /api/headers/register
 * Register baseline headers for a page
 */
app.post('/api/headers/register', generalLimiter, async (req, res) => {
  try {
    const { pageUrl, headers, sessionId, userAgent } = req.body;

    if (!pageUrl || !headers) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['pageUrl', 'headers']
      });
    }

    // Check if baseline already exists
    const existing = await db.queryOne(
      'SELECT id FROM http_headers_baseline WHERE page_url = ?',
      [pageUrl]
    );

    if (existing) {
      // Update existing baseline
      await db.query(
        `UPDATE http_headers_baseline SET
          headers_json = ?,
          session_id = ?,
          user_agent = ?,
          last_verified = CURRENT_TIMESTAMP
        WHERE page_url = ?`,
        [JSON.stringify(headers), sessionId, userAgent, pageUrl]
      );
      console.log(`[Headers] Updated baseline for: ${pageUrl}`);
    } else {
      // Create new baseline
      await db.query(
        `INSERT INTO http_headers_baseline (page_url, headers_json, session_id, user_agent)
         VALUES (?, ?, ?, ?)`,
        [pageUrl, JSON.stringify(headers), sessionId, userAgent]
      );
      console.log(`[Headers] Created baseline for: ${pageUrl}`);
    }

    res.json({ success: true, message: 'Headers baseline registered' });

  } catch (error) {
    console.error('[Headers] Register error:', error.message);
    res.status(500).json({ error: 'Failed to register headers' });
  }
});

/**
 * GET /api/headers/baseline/:pageUrl
 * Get baseline headers for a page
 */
app.get('/api/headers/baseline/:pageUrl', generalLimiter, async (req, res) => {
  try {
    const pageUrl = decodeURIComponent(req.params.pageUrl);

    const baseline = await db.queryOne(
      'SELECT headers_json, last_verified FROM http_headers_baseline WHERE page_url = ?',
      [pageUrl]
    );

    if (baseline) {
      res.json({
        success: true,
        headers: JSON.parse(baseline.headers_json),
        lastVerified: baseline.last_verified
      });
    } else {
      res.status(404).json({ error: 'No baseline found for this page' });
    }

  } catch (error) {
    console.error('[Headers] Baseline fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch baseline' });
  }
});

/**
 * POST /api/headers/violation
 * Report a header tampering violation
 */
app.post('/api/headers/violation', violationLimiter, async (req, res) => {
  try {
    const { pageUrl, violation, sessionId, userAgent } = req.body;

    if (!pageUrl || !violation) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['pageUrl', 'violation']
      });
    }

    // Hash IP for privacy
    const ipAddress = hashIpAddress(req.ip);

    // Check if a similar violation already exists (same page, header, type)
    // Include resolved/false_positive to prevent re-creating known violations
    const existing = await db.queryOne(
      `SELECT id, detected_at, review_status FROM header_violations
       WHERE page_url = ?
       AND header_name = ?
       AND violation_type = ?
       AND review_status IN ('pending', 'false_positive', 'resolved')
       ORDER BY detected_at DESC
       LIMIT 1`,
      [pageUrl, violation.headerName, violation.type]
    );

    let result;
    let isNew = false;

    if (existing) {
      // If the violation was previously resolved/false_positive but is occurring again,
      // reset it to pending and notify admin
      const shouldReopen = existing.review_status !== 'pending';

      await db.query(
        `UPDATE header_violations SET
          expected_value = ?,
          actual_value = ?,
          severity = ?,
          detected_at = CURRENT_TIMESTAMP,
          session_id = ?,
          user_agent = ?,
          ip_address = ?,
          review_status = ?
        WHERE id = ?`,
        [
          violation.expectedValue,
          violation.actualValue,
          violation.severity || 'HIGH',
          sessionId,
          userAgent,
          ipAddress,
          shouldReopen ? 'pending' : existing.review_status,
          existing.id
        ]
      );

      result = { lastID: existing.id, insertId: existing.id };

      if (shouldReopen) {
        console.log(`[Headers] REOPENED ${violation.severity} violation: ${violation.headerName} on ${pageUrl} (was: ${existing.review_status}, ID: ${existing.id})`);

        // Send alert for reopened violations
        await queueNotification({
          type: 'email',
          subject: `ALERT: Previously ${existing.review_status.toUpperCase()} Violation Recurring`,
          message: `A header violation that was marked as "${existing.review_status}" is occurring again:\n\nPage: ${pageUrl}\nHeader: ${violation.headerName}\nType: ${violation.type}\nSeverity: ${violation.severity}\n\nThis may indicate:\n- The issue was not properly fixed\n- A new attack is underway\n- Configuration changed\n\nPlease review immediately.`,
          priority: 'high'
        });
      } else {
        console.log(`[Headers] Updated existing ${violation.severity} violation: ${violation.headerName} on ${pageUrl} (ID: ${existing.id})`);
      }
    } else {
      // Insert new violation
      result = await db.query(
        `INSERT INTO header_violations (
          page_url, header_name, violation_type, expected_value, actual_value,
          severity, session_id, user_agent, ip_address
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          pageUrl,
          violation.headerName,
          violation.type,
          violation.expectedValue,
          violation.actualValue,
          violation.severity || 'HIGH',
          sessionId,
          userAgent,
          ipAddress
        ]
      );

      isNew = true;
      console.log(`[Headers] New ${violation.severity} violation: ${violation.headerName} on ${pageUrl}`);

      // Queue alert only for NEW critical violations (not updates)
      if (violation.severity === 'CRITICAL') {
        await queueNotification({
          type: 'email',
          subject: 'CRITICAL Header Tampering Detected',
          message: `Critical header violation detected:\n\nPage: ${pageUrl}\nHeader: ${violation.headerName}\nType: ${violation.type}\nExpected: ${violation.expectedValue}\nActual: ${violation.actualValue}`,
          priority: 'critical'
        });
      }
    }

    res.json({
      success: true,
      violationId: result.lastID || result.insertId,
      isNew: isNew,
      message: isNew ? 'New violation recorded' : 'Existing violation updated'
    });

  } catch (error) {
    console.error('[Headers] Violation report error:', error.message);
    res.status(500).json({ error: 'Failed to report violation' });
  }
});

// ============================================================================
// PCI DSS 11.6.1 - NETWORK REQUEST MONITORING ENDPOINTS
// ============================================================================

/**
 * POST /api/network/violation
 * Report an unauthorized network request
 */
app.post('/api/network/violation', violationLimiter, async (req, res) => {
  try {
    const { violation, sessionId, userAgent } = req.body;

    if (!violation || !violation.destinationUrl) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['violation.destinationUrl']
      });
    }

    // Hash IP for privacy
    const ipAddress = hashIpAddress(req.ip);

    // Check if a similar violation already exists (same page, destination, request type)
    // Include resolved/false_positive to prevent re-creating known violations
    const existing = await db.queryOne(
      `SELECT id, detected_at, review_status FROM network_violations
       WHERE page_url = ?
       AND destination_origin = ?
       AND request_type = ?
       AND review_status IN ('pending', 'false_positive', 'resolved', 'whitelisted')
       ORDER BY detected_at DESC
       LIMIT 1`,
      [violation.sourceUrl, violation.destinationOrigin, violation.requestType]
    );

    let result;
    let isNew = false;

    if (existing) {
      // If the violation was previously resolved/false_positive/whitelisted but is occurring again,
      // reset it to pending and notify admin
      const shouldReopen = existing.review_status !== 'pending';

      await db.query(
        `UPDATE network_violations SET
          destination_url = ?,
          severity = ?,
          blocked = ?,
          detected_at = CURRENT_TIMESTAMP,
          session_id = ?,
          user_agent = ?,
          ip_address = ?,
          review_status = ?
        WHERE id = ?`,
        [
          violation.destinationUrl,
          violation.severity || 'CRITICAL',
          violation.blocked ? 1 : 0,
          sessionId,
          userAgent,
          ipAddress,
          shouldReopen ? 'pending' : existing.review_status,
          existing.id
        ]
      );

      result = { lastID: existing.id, insertId: existing.id };

      if (shouldReopen) {
        console.log(`[Network] REOPENED violation: ${violation.requestType} to ${violation.destinationOrigin} (was: ${existing.review_status}, ID: ${existing.id})`);

        // Send alert for reopened violations (especially if it was whitelisted!)
        await queueNotification({
          type: 'email',
          subject: `ALERT: Previously ${existing.review_status.toUpperCase()} Network Violation Recurring`,
          message: `A network violation that was marked as "${existing.review_status}" is occurring again:\n\nSource: ${violation.sourceUrl}\nDestination: ${violation.destinationOrigin}\nType: ${violation.requestType}\nBlocked: ${violation.blocked ? 'YES' : 'NO'}\n\nThis may indicate:\n- The issue was not properly fixed\n- Whitelist needs review\n- A new attack is underway\n\nPlease investigate immediately.`,
          priority: existing.review_status === 'whitelisted' ? 'critical' : 'high'
        });
      } else {
        console.log(`[Network] Updated existing violation: ${violation.requestType} to ${violation.destinationOrigin} (ID: ${existing.id})`);
      }
    } else {
      // Insert new violation
      result = await db.query(
        `INSERT INTO network_violations (
          page_url, request_type, destination_url, destination_origin,
          severity, blocked, session_id, user_agent, ip_address
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          violation.sourceUrl,
          violation.requestType,
          violation.destinationUrl,
          violation.destinationOrigin,
          violation.severity || 'CRITICAL',
          violation.blocked ? 1 : 0,
          sessionId,
          userAgent,
          ipAddress
        ]
      );

      isNew = true;
      console.log(`[Network] New violation: ${violation.blocked ? 'BLOCKED' : 'Reported'} ${violation.requestType} to: ${violation.destinationOrigin}`);

      // Queue alert only for NEW blocked requests (not updates)
      if (violation.blocked) {
        await queueNotification({
          type: 'email',
          subject: 'Blocked Data Exfiltration Attempt',
          message: `Unauthorized network request blocked:\n\nSource: ${violation.sourceUrl}\nDestination: ${violation.destinationUrl}\nType: ${violation.requestType}`,
          priority: 'critical'
        });
      }
    }

    res.json({
      success: true,
      violationId: result.lastID || result.insertId,
      isNew: isNew,
      message: isNew ? 'New violation recorded' : 'Existing violation updated'
    });

  } catch (error) {
    console.error('[Network] Violation report error:', error.message);
    res.status(500).json({ error: 'Failed to report violation' });
  }
});

/**
 * GET /api/network/whitelist
 * Get whitelisted domains (for client-side reference)
 */
app.get('/api/network/whitelist', generalLimiter, async (req, res) => {
  try {
    const whitelist = await db.query(
      `SELECT domain, pattern_type FROM network_whitelist
       WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`
    );

    res.json({
      success: true,
      domains: whitelist.map(w => ({
        domain: w.domain,
        patternType: w.pattern_type
      }))
    });

  } catch (error) {
    console.error('[Network] Whitelist fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch whitelist' });
  }
});

// ============================================================================
// PCI DSS 11.6.1 - ADMIN ENDPOINTS FOR HEADER/NETWORK MONITORING
// ============================================================================

/**
 * GET /api/admin/headers/violations
 * Get header violations for admin panel
 */
app.get('/api/admin/headers/violations', authenticate, async (req, res) => {
  try {
    const { status, limit = 100 } = req.query;

    let query = `SELECT * FROM header_violations`;
    const params = [];

    if (status) {
      query += ' WHERE review_status = ?';
      params.push(status);
    }

    query += ' ORDER BY detected_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const violations = await db.query(query, params);

    res.json({
      success: true,
      data: violations,
      count: violations.length
    });

  } catch (error) {
    console.error('[Admin] Header violations fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch header violations' });
  }
});

/**
 * GET /api/admin/headers/baselines
 * Get all header baselines
 */
app.get('/api/admin/headers/baselines', authenticate, async (req, res) => {
  try {
    const baselines = await db.query(
      'SELECT * FROM http_headers_baseline ORDER BY created_at DESC'
    );

    res.json({
      success: true,
      data: baselines.map(b => ({
        ...b,
        headers: JSON.parse(b.headers_json)
      })),
      count: baselines.length
    });

  } catch (error) {
    console.error('[Admin] Baselines fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch baselines' });
  }
});

/**
 * POST /api/admin/headers/violations/:id/review
 * Review a header violation
 */
app.post('/api/admin/headers/violations/:id/review', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    await db.query(
      `UPDATE header_violations SET
        review_status = ?,
        reviewed_by = ?,
        reviewed_at = CURRENT_TIMESTAMP,
        review_notes = ?
      WHERE id = ?`,
      [status, req.admin.username, notes, id]
    );

    console.log(`[Admin] Header violation ${id} reviewed by ${req.admin.username}: ${status}`);

    res.json({ success: true, message: 'Violation reviewed' });

  } catch (error) {
    console.error('[Admin] Header review error:', error.message);
    res.status(500).json({ error: 'Failed to review violation' });
  }
});

/**
 * GET /api/admin/network/violations
 * Get network violations for admin panel
 */
app.get('/api/admin/network/violations', authenticate, async (req, res) => {
  try {
    const { status, blocked, limit = 100 } = req.query;

    let query = 'SELECT * FROM network_violations WHERE 1=1';
    const params = [];

    if (status) {
      query += ' AND review_status = ?';
      params.push(status);
    }

    if (blocked !== undefined) {
      query += ' AND blocked = ?';
      params.push(blocked === 'true' ? 1 : 0);
    }

    query += ' ORDER BY detected_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const violations = await db.query(query, params);

    res.json({
      success: true,
      data: violations,
      count: violations.length
    });

  } catch (error) {
    console.error('[Admin] Network violations fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch network violations' });
  }
});

/**
 * POST /api/admin/network/violations/:id/review
 * Review a network violation
 */
app.post('/api/admin/network/violations/:id/review', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    await db.query(
      `UPDATE network_violations SET
        review_status = ?,
        reviewed_by = ?,
        reviewed_at = CURRENT_TIMESTAMP,
        review_notes = ?
      WHERE id = ?`,
      [status, req.admin.username, notes, id]
    );

    console.log(`[Admin] Network violation ${id} reviewed by ${req.admin.username}: ${status}`);

    res.json({ success: true, message: 'Violation reviewed' });

  } catch (error) {
    console.error('[Admin] Network review error:', error.message);
    res.status(500).json({ error: 'Failed to review violation' });
  }
});

/**
 * POST /api/admin/network/violations/:id/whitelist
 * Whitelist a domain from a network violation
 */
app.post('/api/admin/network/violations/:id/whitelist', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { businessJustification } = req.body;

    // Get the violation to extract domain
    const violation = await db.queryOne(
      'SELECT destination_origin FROM network_violations WHERE id = ?',
      [id]
    );

    if (!violation) {
      return res.status(404).json({ error: 'Violation not found' });
    }

    // Add to whitelist
    await db.query(
      `INSERT OR REPLACE INTO network_whitelist (domain, business_justification, added_by)
       VALUES (?, ?, ?)`,
      [violation.destination_origin, businessJustification, req.admin.username]
    );

    // Update violation status
    await db.query(
      `UPDATE network_violations SET
        review_status = 'whitelisted',
        reviewed_by = ?,
        reviewed_at = CURRENT_TIMESTAMP,
        review_notes = ?
      WHERE id = ?`,
      [req.admin.username, `Whitelisted: ${businessJustification}`, id]
    );

    console.log(`[Admin] Domain whitelisted: ${violation.destination_origin} by ${req.admin.username}`);

    res.json({ success: true, message: 'Domain whitelisted' });

  } catch (error) {
    console.error('[Admin] Whitelist error:', error.message);
    res.status(500).json({ error: 'Failed to whitelist domain' });
  }
});

/**
 * GET /api/admin/network/whitelist
 * Get all whitelisted domains
 */
app.get('/api/admin/network/whitelist', authenticate, async (req, res) => {
  try {
    const whitelist = await db.query(
      'SELECT * FROM network_whitelist ORDER BY added_at DESC'
    );

    res.json({
      success: true,
      data: whitelist,
      count: whitelist.length
    });

  } catch (error) {
    console.error('[Admin] Whitelist fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch whitelist' });
  }
});

/**
 * DELETE /api/admin/network/whitelist/:id
 * Remove a domain from whitelist
 */
app.delete('/api/admin/network/whitelist/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    await db.query('DELETE FROM network_whitelist WHERE id = ?', [id]);

    console.log(`[Admin] Whitelist entry ${id} removed by ${req.admin.username}`);

    res.json({ success: true, message: 'Domain removed from whitelist' });

  } catch (error) {
    console.error('[Admin] Whitelist delete error:', error.message);
    res.status(500).json({ error: 'Failed to remove from whitelist' });
  }
});

/**
 * GET /api/admin/pci-dss/summary
 * Get PCI DSS 11.6.1 compliance summary
 */
app.get('/api/admin/pci-dss/summary', authenticate, async (req, res) => {
  try {
    // Get script violations summary
    const scriptStats = await db.getViolationStatistics();

    // Get header violations stats
    const headerStats = await db.queryOne(`
      SELECT
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical,
        COALESCE(SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END), 0) as pending
      FROM header_violations
    `);

    // Get network violations stats
    const networkStats = await db.queryOne(`
      SELECT
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0) as blocked,
        COALESCE(SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END), 0) as pending
      FROM network_violations
    `);

    // Get header baselines count
    const baselineCount = await db.queryOne(
      'SELECT COUNT(*) as count FROM http_headers_baseline'
    );

    // Get whitelist count
    const whitelistCount = await db.queryOne(
      'SELECT COUNT(*) as count FROM network_whitelist WHERE is_active = 1'
    );

    res.json({
      success: true,
      summary: {
        scriptIntegrity: scriptStats,
        httpHeaders: {
          baselines: baselineCount?.count || 0,
          violations: {
            total: headerStats?.total || 0,
            critical: headerStats?.critical || 0,
            pending: headerStats?.pending || 0
          }
        },
        networkMonitoring: {
          whitelistedDomains: whitelistCount?.count || 0,
          violations: {
            total: networkStats?.total || 0,
            blocked: networkStats?.blocked || 0,
            pending: networkStats?.pending || 0
          }
        }
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[Admin] PCI DSS summary error:', error.message);
    res.status(500).json({ error: 'Failed to fetch PCI DSS summary' });
  }
});

// ============================================================================
// BULK DELETE ENDPOINTS
// ============================================================================

/**
 * POST /api/admin/violations/bulk-delete
 * Bulk delete script violations
 */
app.post('/api/admin/violations/bulk-delete', authenticate, async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Invalid or empty ids array' });
    }

    const placeholders = ids.map(() => '?').join(',');
    await db.query(
      `DELETE FROM violations WHERE id IN (${placeholders})`,
      ids
    );

    // Log to audit trail
    await logAudit({
      req,
      admin: req.admin,
      actionType: 'violations_bulk_deleted',
      entityType: 'violation',
      entityId: ids,
      actionDescription: `Bulk deleted ${ids.length} script violation(s)`
    });

    console.log(`[Admin] Bulk deleted ${ids.length} violations by ${req.admin.username}`);
    res.json({ success: true, deleted: ids.length });
  } catch (error) {
    console.error('[Admin] Bulk delete violations error:', error.message);

    // Log failure
    await logAudit({
      req,
      admin: req.admin,
      actionType: 'violations_bulk_deleted',
      entityType: 'violation',
      entityId: req.body.ids,
      actionDescription: `Failed to bulk delete ${req.body.ids?.length || 0} violation(s)`,
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({ error: 'Failed to delete violations' });
  }
});

/**
 * POST /api/admin/headers/violations/bulk-delete
 * Bulk delete header violations
 */
app.post('/api/admin/headers/violations/bulk-delete', authenticate, async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Invalid or empty ids array' });
    }

    const placeholders = ids.map(() => '?').join(',');
    await db.query(
      `DELETE FROM header_violations WHERE id IN (${placeholders})`,
      ids
    );

    await logAudit({
      req,
      admin: req.admin,
      actionType: 'header_violations_bulk_deleted',
      entityType: 'header_violation',
      entityId: ids,
      actionDescription: `Bulk deleted ${ids.length} header violation(s)`
    });

    console.log(`[Admin] Bulk deleted ${ids.length} header violations by ${req.admin.username}`);
    res.json({ success: true, deleted: ids.length });
  } catch (error) {
    console.error('[Admin] Bulk delete header violations error:', error.message);

    await logAudit({
      req,
      admin: req.admin,
      actionType: 'header_violations_bulk_deleted',
      entityType: 'header_violation',
      entityId: req.body.ids,
      actionDescription: `Failed to bulk delete ${req.body.ids?.length || 0} header violation(s)`,
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({ error: 'Failed to delete header violations' });
  }
});

/**
 * POST /api/admin/headers/baselines/bulk-delete
 * Bulk delete header baselines
 */
app.post('/api/admin/headers/baselines/bulk-delete', authenticate, async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Invalid or empty ids array' });
    }

    const placeholders = ids.map(() => '?').join(',');
    await db.query(
      `DELETE FROM http_headers_baseline WHERE id IN (${placeholders})`,
      ids
    );

    await logAudit({
      req,
      admin: req.admin,
      actionType: 'header_baselines_bulk_deleted',
      entityType: 'header_baseline',
      entityId: ids,
      actionDescription: `Bulk deleted ${ids.length} header baseline(s)`
    });

    console.log(`[Admin] Bulk deleted ${ids.length} header baselines by ${req.admin.username}`);
    res.json({ success: true, deleted: ids.length });
  } catch (error) {
    console.error('[Admin] Bulk delete header baselines error:', error.message);

    await logAudit({
      req,
      admin: req.admin,
      actionType: 'header_baselines_bulk_deleted',
      entityType: 'header_baseline',
      entityId: req.body.ids,
      actionDescription: `Failed to bulk delete ${req.body.ids?.length || 0} header baseline(s)`,
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({ error: 'Failed to delete header baselines' });
  }
});

/**
 * POST /api/admin/network/violations/bulk-delete
 * Bulk delete network violations
 */
app.post('/api/admin/network/violations/bulk-delete', authenticate, async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Invalid or empty ids array' });
    }

    const placeholders = ids.map(() => '?').join(',');
    await db.query(
      `DELETE FROM network_violations WHERE id IN (${placeholders})`,
      ids
    );

    await logAudit({
      req,
      admin: req.admin,
      actionType: 'network_violations_bulk_deleted',
      entityType: 'network_violation',
      entityId: ids,
      actionDescription: `Bulk deleted ${ids.length} network violation(s)`
    });

    console.log(`[Admin] Bulk deleted ${ids.length} network violations by ${req.admin.username}`);
    res.json({ success: true, deleted: ids.length });
  } catch (error) {
    console.error('[Admin] Bulk delete network violations error:', error.message);

    await logAudit({
      req,
      admin: req.admin,
      actionType: 'network_violations_bulk_deleted',
      entityType: 'network_violation',
      entityId: req.body.ids,
      actionDescription: `Failed to bulk delete ${req.body.ids?.length || 0} network violation(s)`,
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({ error: 'Failed to delete network violations' });
  }
});

// ============================================================================
// AUDIT TRAIL ENDPOINTS
// ============================================================================

/**
 * GET /api/admin/audit-trail
 * Get audit trail logs with pagination and filtering
 */
app.get('/api/admin/audit-trail', authenticate, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      actionType,
      username,
      entityType,
      startDate,
      endDate,
      success,
      keyword
    } = req.query;

    const offset = (page - 1) * limit;
    let whereConditions = [];
    let params = [];

    // Build WHERE clause based on filters
    if (actionType) {
      whereConditions.push('action_type = ?');
      params.push(actionType);
    }
    if (username) {
      whereConditions.push('username LIKE ?');
      params.push(`%${username}%`);
    }
    if (entityType) {
      whereConditions.push('entity_type = ?');
      params.push(entityType);
    }
    if (startDate) {
      whereConditions.push('timestamp >= ?');
      params.push(startDate);
    }
    if (endDate) {
      whereConditions.push('timestamp <= ?');
      params.push(endDate);
    }
    if (success !== undefined) {
      whereConditions.push('success = ?');
      params.push(success === 'true' ? 1 : 0);
    }
    if (keyword) {
      whereConditions.push('(action_description LIKE ? OR action_reason LIKE ? OR entity_id LIKE ?)');
      params.push(`%${keyword}%`, `%${keyword}%`, `%${keyword}%`);
    }

    const whereClause = whereConditions.length > 0
      ? 'WHERE ' + whereConditions.join(' AND ')
      : '';

    // Get total count
    const countResult = await db.queryOne(
      `SELECT COUNT(*) as count FROM audit_trail ${whereClause}`,
      params
    );

    // Get paginated results
    const logs = await db.query(
      `SELECT * FROM audit_trail ${whereClause}
       ORDER BY timestamp DESC
       LIMIT ? OFFSET ?`,
      [...params, parseInt(limit), parseInt(offset)]
    );

    res.json({
      logs,
      total: countResult.count,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(countResult.count / limit)
    });
  } catch (error) {
    console.error('[Admin] Audit trail fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch audit trail' });
  }
});

/**
 * GET /api/admin/audit-trail/stats
 * Get audit trail statistics
 */
app.get('/api/admin/audit-trail/stats', authenticate, async (req, res) => {
  try {
    const stats = {
      totalLogs: 0,
      last24Hours: 0,
      last7Days: 0,
      failedActions: 0,
      actionsByType: [],
      topUsers: []
    };

    // Total logs
    const total = await db.queryOne('SELECT COUNT(*) as count FROM audit_trail');
    stats.totalLogs = total.count;

    // Last 24 hours
    const last24h = await db.queryOne(
      "SELECT COUNT(*) as count FROM audit_trail WHERE timestamp >= datetime('now', '-1 day')"
    );
    stats.last24Hours = last24h.count;

    // Last 7 days
    const last7d = await db.queryOne(
      "SELECT COUNT(*) as count FROM audit_trail WHERE timestamp >= datetime('now', '-7 days')"
    );
    stats.last7Days = last7d.count;

    // Failed actions
    const failed = await db.queryOne(
      'SELECT COUNT(*) as count FROM audit_trail WHERE success = 0'
    );
    stats.failedActions = failed.count;

    // Actions by type (top 10)
    const byType = await db.query(
      `SELECT action_type, COUNT(*) as count
       FROM audit_trail
       GROUP BY action_type
       ORDER BY count DESC
       LIMIT 10`
    );
    stats.actionsByType = byType;

    // Top users (top 10)
    const topUsers = await db.query(
      `SELECT username, COUNT(*) as action_count
       FROM audit_trail
       WHERE username != 'system'
       GROUP BY username
       ORDER BY action_count DESC
       LIMIT 10`
    );
    stats.topUsers = topUsers;

    res.json(stats);
  } catch (error) {
    console.error('[Admin] Audit trail stats error:', error.message);
    res.status(500).json({ error: 'Failed to fetch audit trail statistics' });
  }
});

// ============================================================================

// ADMIN API ENDPOINTS (Protected)

// ============================================================================



/**

 * GET /api/admin/users

 * Get all admin users

 */

app.get('/api/admin/users', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {

  try {

    const users = await db.getUsers();

    res.json({ success: true, data: users });

  } catch (error) {

    console.error('[Admin] Error fetching users:', error.message);

    res.status(500).json({ error: 'Failed to fetch users' });

  }

});



/**

 * POST /api/admin/users

 * Create a new admin user

 */

app.post('/api/admin/users', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {

  try {

    const { username, email, password, role, is_active } = req.body;

    const newUser = await db.createUser({ username, email, password, role, is_active });

    res.status(201).json({ success: true, data: newUser });

  } catch (error) {

    console.error('[Admin] Error creating user:', error.message);

    res.status(500).json({ error: 'Failed to create user' });

  }

});



/**

 * PUT /api/admin/users/:id

 * Update an admin user

 */

app.put('/api/admin/users/:id', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {

  try {

    const userId = parseInt(req.params.id);

    const { username, email, password, role, is_active } = req.body;

    const updatedUser = await db.updateUser(userId, { username, email, password, role, is_active });

    if (!updatedUser) {

      return res.status(404).json({ error: 'User not found' });

    }

    res.json({ success: true, data: updatedUser });

  } catch (error) {

    console.error('[Admin] Error updating user:', error.message);

    res.status(500).json({ error: 'Failed to update user' });

  }

});



/**

 * DELETE /api/admin/users/:id

 * Delete an admin user

 */

app.delete('/api/admin/users/:id', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {

  try {

    const userId = parseInt(req.params.id);

    const success = await db.deleteUser(userId);

    if (!success) {

      return res.status(404).json({ error: 'User not found' });

    }

    res.json({ success: true, message: 'User deleted successfully' });

  } catch (error) {

    console.error('[Admin] Error deleting user:', error.message);

    res.status(500).json({ error: 'Failed to delete user' });

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

/**
 * GET /api/admin/scripts/pending
 * Get all scripts pending approval
 */
app.get('/api/admin/scripts/pending', authenticate, async (req, res) => {
  try {
    const scripts = await db.query(
      `SELECT * FROM scripts
       WHERE status = 'pending_approval'
       ORDER BY first_seen DESC
       LIMIT 100`
    );

    res.json({
      success: true,
      data: scripts,
      count: scripts.length
    });

  } catch (error) {
    console.error('[Admin] Pending scripts error:', error.message);
    res.status(500).json({ error: 'Failed to fetch pending scripts' });
  }
});

/**
 * GET /api/admin/violations
 * Get integrity violations grouped by script_url (same logic as script inventory)
 */
app.get('/api/admin/violations', authenticate, async (req, res) => {
  try {
    // Group violations by script_url and count them, similar to script inventory logic
    // Get the most recent violation details for each script
    // Use correlated subqueries that work for both SQLite and PostgreSQL
    const violations = await db.query(
      `SELECT 
        script_url,
        COUNT(*) as violation_count,
        MAX(detected_at) as last_detected_at,
        (SELECT violation_type FROM integrity_violations v2 
         WHERE v2.script_url = integrity_violations.script_url 
         ORDER BY detected_at DESC LIMIT 1) as last_violation_type,
        (SELECT severity FROM integrity_violations v2 
         WHERE v2.script_url = integrity_violations.script_url 
         ORDER BY detected_at DESC LIMIT 1) as highest_severity,
        (SELECT review_status FROM integrity_violations v2 
         WHERE v2.script_url = integrity_violations.script_url 
         ORDER BY detected_at DESC LIMIT 1) as review_status,
        (SELECT page_url FROM integrity_violations v2 
         WHERE v2.script_url = integrity_violations.script_url 
         ORDER BY detected_at DESC LIMIT 1) as last_page_url
      FROM integrity_violations
      GROUP BY script_url
      ORDER BY last_detected_at DESC
      LIMIT 100`
    );

    console.log('[Admin] Fetched grouped violations:', violations.length);

    res.json({
      success: true,
      data: violations,
      count: violations.length
    });

  } catch (error) {
    console.error('[Admin] Violations error:', error.message);
    res.status(500).json({ error: 'Failed to fetch violations' });
  }
});

/**
 * GET /api/admin/scripts/search
 * Search/filter scripts in inventory
 */
app.get('/api/admin/scripts/search', authenticate, async (req, res) => {
  try {
    const { q, status, type, limit = 100 } = req.query;

    let query = 'SELECT * FROM scripts WHERE 1=1';
    const params = [];

    if (q) {
      query += ' AND (url LIKE ? OR content_preview LIKE ?)';
      params.push(`%${q}%`, `%${q}%`);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (type) {
      query += ' AND script_type = ?';
      params.push(type);
    }

    query += ' ORDER BY first_seen DESC LIMIT ?';
    params.push(parseInt(limit));

    const scripts = await db.query(query, params);

    res.json({
      success: true,
      data: scripts,
      count: scripts.length
    });

  } catch (error) {
    console.error('[Admin] Search error:', error.message);
    res.status(500).json({ error: 'Failed to search scripts' });
  }
});

/**
 * POST /api/admin/scripts/:id/approve
 * Approve a script
 */
app.post('/api/admin/scripts/:id/approve', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes } = req.body;

    // Get script URL before updating (needed to clean up violations)
    const script = await db.queryOne('SELECT url FROM scripts WHERE id = ?', [id]);

    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }

    await db.query(
      `UPDATE scripts SET
        status = 'approved',
        business_justification = ?,
        script_purpose = ?,
        script_owner = ?,
        risk_level = ?,
        approval_notes = ?,
        approved_by = ?,
        approved_at = CURRENT_TIMESTAMP
      WHERE id = ?`,
      [businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes, req.admin.username, id]
    );

    // Clean up violations for approved script
    const violationResult = await db.query(
      'DELETE FROM integrity_violations WHERE script_url = ?',
      [script.url]
    );
    const violationsRemoved = violationResult?.changes || 0;

    console.log(`[Admin] Script ${id} approved by ${req.admin.username}${violationsRemoved > 0 ? ` (${violationsRemoved} violations cleared)` : ''}`);

    res.json({
      success: true,
      message: 'Script approved successfully',
      violationsCleared: violationsRemoved
    });

  } catch (error) {
    console.error('[Admin] Approve error:', error.message);
    res.status(500).json({ error: 'Failed to approve script' });
  }
});

/**
 * POST /api/admin/scripts/:id/reject
 * Reject a script
 */
app.post('/api/admin/scripts/:id/reject', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { rejectionReason, notes } = req.body;

    await db.query(
      `UPDATE scripts SET
        status = 'rejected',
        rejection_reason = ?,
        approval_notes = ?,
        approved_by = ?,
        approved_at = CURRENT_TIMESTAMP
      WHERE id = ?`,
      [rejectionReason, notes, req.admin.username, id]
    );

    console.log(`[Admin] Script ${id} rejected by ${req.admin.username}`);

    res.json({ success: true, message: 'Script rejected successfully' });

  } catch (error) {
    console.error('[Admin] Reject error:', error.message);
    res.status(500).json({ error: 'Failed to reject script' });
  }
});

/**
 * POST /api/admin/scripts/bulk-approve
 * Bulk approve multiple scripts
 */
app.post('/api/admin/scripts/bulk-approve', authenticate, async (req, res) => {
  try {
    const { scriptIds, businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes } = req.body;

    if (!Array.isArray(scriptIds) || scriptIds.length === 0) {
      return res.status(400).json({ error: 'scriptIds must be a non-empty array' });
    }

    if (scriptIds.length > 100) {
      return res.status(400).json({ error: 'Cannot approve more than 100 scripts at once' });
    }

    // Validate all IDs are integers
    const invalidIds = scriptIds.filter(id => !Number.isInteger(id) || id <= 0);
    if (invalidIds.length > 0) {
      return res.status(400).json({ error: 'All script IDs must be positive integers' });
    }

    // Get script URLs before updating (needed to clean up violations)
    const scripts = await db.query(
      `SELECT id, url FROM scripts WHERE id IN (${scriptIds.map(() => '?').join(',')})`,
      scriptIds
    );

    const scriptUrlMap = {};
    scripts.forEach(script => {
      scriptUrlMap[script.id] = script.url;
    });

    // Use transactions for PostgreSQL (ensures atomicity)
    // Skip for SQLite (single-threaded, transaction support is limited)
    const useTransaction = db.isPostgreSQL();
    let transaction = null;

    try {
      if (useTransaction) {
        transaction = await db.beginTransaction();
      }

      let successCount = 0;
      let failedIds = [];
      const approvedUrls = [];

      for (const id of scriptIds) {
        try {
          const result = await db.query(
            `UPDATE scripts SET
              status = 'approved',
              business_justification = ?,
              script_purpose = ?,
              script_owner = ?,
              risk_level = ?,
              approval_notes = ?,
              approved_by = ?,
              approved_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'pending_approval'`,
            [businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes, req.admin.username, id]
          );

          if (result.changes > 0) {
            successCount++;
            if (scriptUrlMap[id]) {
              approvedUrls.push(scriptUrlMap[id]);
            }
          } else {
            failedIds.push(id);
          }
        } catch (error) {
          console.error(`[Admin] Failed to approve script ${id}:`, error.message);
          failedIds.push(id);
        }
      }

      // Clean up violations for all approved scripts
      let totalViolationsRemoved = 0;
      for (const url of approvedUrls) {
        const violationResult = await db.query(
          'DELETE FROM integrity_violations WHERE script_url = ?',
          [url]
        );
        totalViolationsRemoved += violationResult?.changes || 0;
      }

      if (useTransaction && transaction) {
        await transaction.commit();
      }

      console.log(`[Admin] Bulk approved ${successCount} scripts by ${req.admin.username}${totalViolationsRemoved > 0 ? ` (${totalViolationsRemoved} violations cleared)` : ''}`);

      res.json({
        success: true,
        message: `Successfully approved ${successCount} out of ${scriptIds.length} scripts`,
        approved: successCount,
        failed: failedIds.length,
        failedIds,
        violationsCleared: totalViolationsRemoved
      });

    } catch (error) {
      if (useTransaction && transaction) {
        await transaction.rollback();
      }
      console.error('[Admin] Bulk approve error:', error);
      throw error;
    }

  } catch (error) {
    console.error('[Admin] Bulk approve error:', error.message);
    console.error('[Admin] Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to bulk approve scripts' });
  }
});

/**
 * POST /api/admin/scripts/bulk-reject
 * Bulk reject multiple scripts
 */
app.post('/api/admin/scripts/bulk-reject', authenticate, async (req, res) => {
  try {
    const { scriptIds, rejectionReason, notes } = req.body;

    if (!Array.isArray(scriptIds) || scriptIds.length === 0) {
      return res.status(400).json({ error: 'scriptIds must be a non-empty array' });
    }

    if (scriptIds.length > 100) {
      return res.status(400).json({ error: 'Cannot reject more than 100 scripts at once' });
    }

    // Validate all IDs are integers
    const invalidIds = scriptIds.filter(id => !Number.isInteger(id) || id <= 0);
    if (invalidIds.length > 0) {
      return res.status(400).json({ error: 'All script IDs must be positive integers' });
    }

    // Use transactions for PostgreSQL (ensures atomicity)
    // Skip for SQLite (single-threaded, transaction support is limited)
    const useTransaction = db.isPostgreSQL();
    let transaction = null;

    try {
      if (useTransaction) {
        transaction = await db.beginTransaction();
      }

      let successCount = 0;
      let failedIds = [];

      for (const id of scriptIds) {
        try {
          const result = await db.query(
            `UPDATE scripts SET
              status = 'rejected',
              rejection_reason = ?,
              approval_notes = ?,
              approved_by = ?,
              approved_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'pending_approval'`,
            [rejectionReason, notes, req.admin.username, id]
          );

          if (result.changes > 0) {
            successCount++;
          } else {
            failedIds.push(id);
          }
        } catch (error) {
          console.error(`[Admin] Failed to reject script ${id}:`, error.message);
          failedIds.push(id);
        }
      }

      if (useTransaction && transaction) {
        await transaction.commit();
      }

      console.log(`[Admin] Bulk rejected ${successCount} scripts by ${req.admin.username}`);

      res.json({
        success: true,
        message: `Successfully rejected ${successCount} out of ${scriptIds.length} scripts`,
        rejected: successCount,
        failed: failedIds.length,
        failedIds
      });

    } catch (error) {
      if (useTransaction && transaction) {
        await transaction.rollback();
      }
      console.error('[Admin] Bulk reject error:', error);
      throw error;
    }

  } catch (error) {
    console.error('[Admin] Bulk reject error:', error.message);
    res.status(500).json({ error: 'Failed to bulk reject scripts' });
  }
});

/**
 * GET /api/admin/scripts/:id
 * Get script details
 */
app.get('/api/admin/scripts/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const script = await db.queryOne('SELECT * FROM scripts WHERE id = ?', [id]);

    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }

    const auditLog = await db.query(
      'SELECT * FROM approval_audit_log WHERE script_id = ? ORDER BY performed_at DESC',
      [id]
    );

    res.json({
      success: true,
      script,
      auditLog
    });

  } catch (error) {
    console.error('[Admin] Get script error:', error.message);
    res.status(500).json({ error: 'Failed to fetch script details' });
  }
});

/**
 * PUT /api/admin/scripts/:id/update
 * Update script details
 */
app.put('/api/admin/scripts/:id/update', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes, rejectionReason } = req.body;

    await db.query(
      `UPDATE scripts SET
        status = ?,
        business_justification = ?,
        script_purpose = ?,
        script_owner = ?,
        risk_level = ?,
        approval_notes = ?,
        rejection_reason = ?
      WHERE id = ?`,
      [status, businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes, rejectionReason, id]
    );

    console.log(`[Admin] Script ${id} updated by ${req.admin.username}`);

    res.json({ success: true, message: 'Script updated successfully' });

  } catch (error) {
    console.error('[Admin] Update error:', error.message);
    res.status(500).json({ error: 'Failed to update script' });
  }
});

/**
 * DELETE /api/admin/scripts/:id
 * Delete a single script from inventory
 */
app.delete('/api/admin/scripts/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const adminUsername = req.admin.username;

    // Check if script exists
    const script = await db.queryOne('SELECT * FROM scripts WHERE id = ?', [id]);

    if (!script) {
      return res.status(404).json({ error: 'Script not found' });
    }

    // Log the deletion in audit log before deleting (using valid action type)
    await db.query(
      `INSERT INTO approval_audit_log
       (script_id, action, previous_status, new_status, performed_by, notes, performed_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
      [id, 'status_changed', script.status, 'deleted', adminUsername, `Script deleted from inventory: ${script.url}`]
    );

    // Delete related records first (violations don't have foreign key cascade)
    await db.query('DELETE FROM integrity_violations WHERE script_url = ?', [script.url]);

    // Delete the script (this will cascade delete audit logs via ON DELETE CASCADE)
    await db.query('DELETE FROM scripts WHERE id = ?', [id]);

    console.log(`[Admin] Script ${id} deleted by ${adminUsername}`);

    res.json({
      success: true,
      message: 'Script deleted successfully',
      deletedId: id
    });

  } catch (error) {
    console.error('[Admin] Delete script error:', error.message);
    res.status(500).json({ error: 'Failed to delete script' });
  }
});

/**
 * POST /api/admin/scripts/bulk-delete
 * Delete multiple scripts from inventory
 */
app.post('/api/admin/scripts/bulk-delete', authenticate, async (req, res) => {
  try {
    const { scriptIds, deletionReason } = req.body;
    const adminUsername = req.admin.username;

    if (!scriptIds || !Array.isArray(scriptIds) || scriptIds.length === 0) {
      return res.status(400).json({ error: 'Script IDs array is required' });
    }

    if (!deletionReason || deletionReason.trim() === '') {
      return res.status(400).json({ error: 'Deletion reason is required' });
    }

    const deleted = [];
    const failed = [];

    for (const id of scriptIds) {
      try {
        // Check if script exists
        const script = await db.queryOne('SELECT * FROM scripts WHERE id = ?', [id]);

        if (!script) {
          failed.push({ id, reason: 'Script not found' });
          continue;
        }

        // Log the deletion in audit log before deleting (using valid action type)
        await db.query(
          `INSERT INTO approval_audit_log
           (script_id, action, previous_status, new_status, performed_by, notes, performed_at)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
          [id, 'status_changed', script.status, 'deleted', adminUsername, `Bulk deletion: ${deletionReason}`]
        );

        // Delete related records first (violations don't have foreign key cascade)
        await db.query('DELETE FROM integrity_violations WHERE script_url = ?', [script.url]);

        // Delete the script (this will cascade delete audit logs via ON DELETE CASCADE)
        await db.query('DELETE FROM scripts WHERE id = ?', [id]);

        deleted.push(id);
        console.log(`[Admin] Script ${id} deleted by ${adminUsername} (bulk operation)`);

      } catch (error) {
        console.error(`[Admin] Failed to delete script ${id}:`, error.message);
        failed.push({ id, reason: error.message });
      }
    }

    res.json({
      success: true,
      message: `Successfully deleted ${deleted.length} script${deleted.length !== 1 ? 's' : ''}`,
      deleted: deleted.length,
      deletedIds: deleted,
      failed: failed.length,
      failedIds: failed
    });

  } catch (error) {
    console.error('[Admin] Bulk delete error:', error.message);
    res.status(500).json({ error: 'Failed to perform bulk delete operation' });
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
  res.
  status(404).json({ error: 'Endpoint not found' });
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

    // Start alert scheduler
    await alertScheduler.start();

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
