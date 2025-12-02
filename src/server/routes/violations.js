/**
 * Violations Routes
 * Handles script integrity violation reporting and management
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

/**
 * Hash IP address for privacy compliance
 */
function hashIpAddress(ip) {
  return crypto.createHash('sha256').update(ip + process.env.IP_SALT || 'default-salt').digest('hex');
}

/**
 * Queue notification for sending
 */
async function queueNotification(db, notification) {
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

/**
 * Create violations routes
 * @param {Object} db - Database instance
 * @param {Function} logAudit - Audit logging function
 * @param {Function} authenticate - Authentication middleware
 * @param {Object} rateLimiters - Rate limiter middleware
 * @returns {Router} Express router with violations routes
 */
function createViolationsRoutes(db, logAudit, authenticate, rateLimiters) {
  const { violationLimiter } = rateLimiters;

  // ============================================================================
  // PUBLIC ROUTES
  // ============================================================================

  /**
   * POST /api/scripts/violation
   * Report an integrity violation
   */
  router.post('/scripts/violation', violationLimiter, async (req, res) => {
    try {
      console.log('[Violation] Received violation report:', req.body);
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
        await queueNotification(db, {
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
  // ADMIN ROUTES
  // ============================================================================

  /**
   * GET /api/admin/violations
   * Get integrity violations grouped by script_url
   */
  router.get('/admin/violations', authenticate, async (req, res) => {
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
   * POST /api/admin/violations/bulk-delete
   * Bulk delete script violations
   */
  router.post('/admin/violations/bulk-delete', authenticate, async (req, res) => {
    try {
      const { ids } = req.body;

      if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'Invalid or empty ids array' });
      }

      const placeholders = ids.map(() => '?').join(',');
      await db.query(
        `DELETE FROM integrity_violations WHERE id IN (${placeholders})`,
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

  return router;
}

module.exports = { createViolationsRoutes };
