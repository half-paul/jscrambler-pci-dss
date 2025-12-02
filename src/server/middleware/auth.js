/**
 * Authentication Middleware
 * Handles JWT and legacy token authentication
 */

const mfaAuth = require('../../../auth-mfa');

/**
 * Authentication middleware
 * Supports both JWT tokens (new MFA auth) and legacy API tokens
 * @param {Object} db - Database instance
 * @returns {Function} Express middleware function
 */
function createAuthMiddleware(db) {
  return async function authenticate(req, res, next) {
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
  };
}

/**
 * Role-based access control middleware
 * @param {...string} roles - Allowed roles
 * @returns {Function} Express middleware function
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.admin || !roles.includes(req.admin.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

module.exports = {
  createAuthMiddleware,
  requireRole
};
