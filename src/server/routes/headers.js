/**
 * Headers Routes
 * Handles HTTP header baseline registration and tampering violation detection
 * Part of PCI DSS 11.6.1 compliance
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

/**
 * Hash IP address for privacy compliance
 */
function hashIpAddress(ip) {
  return crypto.createHash('sha256').update(ip + (process.env.IP_SALT || 'default-salt')).digest('hex');
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
 * Create headers routes
 * @param {Object} db - Database instance
 * @param {Function} logAudit - Audit logging function
 * @param {Function} authenticate - Authentication middleware
 * @param {Object} rateLimiters - Rate limiter middleware
 * @returns {Router} Express router with headers routes
 */
function createHeadersRoutes(db, logAudit, authenticate, rateLimiters) {
  const { generalLimiter, violationLimiter } = rateLimiters;

  // ============================================================================
  // PUBLIC ROUTES
  // ============================================================================

  /**
   * POST /api/headers/register
   * Register baseline headers for a page
   */
  router.post('/register', generalLimiter, async (req, res) => {
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
  router.get('/baseline/:pageUrl', generalLimiter, async (req, res) => {
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
  router.post('/violation', violationLimiter, async (req, res) => {
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
          await queueNotification(db, {
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
          await queueNotification(db, {
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
  // ADMIN ROUTES
  // ============================================================================

  /**
   * GET /api/admin/headers/violations
   * Get header violations for admin panel
   */
  router.get('/violations', authenticate, async (req, res) => {
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
  router.get('/baselines', authenticate, async (req, res) => {
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
  router.post('/violations/:id/review', authenticate, async (req, res) => {
    try {
      const { id } = req.params;
      const { status, notes } = req.body;

      // Get violation details before updating
      const violation = await db.queryOne(
        'SELECT page_url, header_name, review_status FROM header_violations WHERE id = ?',
        [id]
      );

      if (!violation) {
        return res.status(404).json({ error: 'Violation not found' });
      }

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

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'header_violation_reviewed',
        entityType: 'header_violation',
        entityId: id,
        actionDescription: `Reviewed header violation: ${violation.header_name} on ${violation.page_url}`,
        previousValue: violation.review_status,
        newValue: status
      });

      res.json({ success: true, message: 'Violation reviewed' });

    } catch (error) {
      console.error('[Admin] Header review error:', error.message);
      res.status(500).json({ error: 'Failed to review violation' });
    }
  });

  /**
   * POST /api/admin/headers/violations/bulk-delete
   * Bulk delete header violations
   */
  router.post('/violations/bulk-delete', authenticate, async (req, res) => {
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
  router.post('/baselines/bulk-delete', authenticate, async (req, res) => {
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

  return router;
}

module.exports = { createHeadersRoutes };
