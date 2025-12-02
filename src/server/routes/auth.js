/**
 * Authentication Routes
 * Handles user login, MFA, logout, and token refresh
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const mfaAuth = require('../../../auth-mfa');

/**
 * Create authentication routes
 * @param {Object} db - Database instance
 * @param {Function} authenticate - Authentication middleware
 * @param {Object} rateLimiters - Rate limiter middleware
 * @returns {Router} Express router with auth routes
 */
function createAuthRoutes(db, authenticate, rateLimiters) {
  const { generalLimiter } = rateLimiters;

  /**
   * POST /api/admin/auth/login
   * Step 1: Authenticate with username/password
   */
  router.post('/login', generalLimiter, async (req, res) => {
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
  router.post('/verify-mfa', generalLimiter, async (req, res) => {
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
  router.post('/setup-mfa', authenticate, async (req, res) => {
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
  router.post('/logout', authenticate, async (req, res) => {
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
  router.post('/refresh', generalLimiter, async (req, res) => {
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

  return router;
}

module.exports = { createAuthRoutes };
