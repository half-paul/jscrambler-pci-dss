/**
 * Network Routes
 * Handles network request monitoring and unauthorized data exfiltration detection
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
 * Create network routes
 * @param {Object} db - Database instance
 * @param {Function} logAudit - Audit logging function
 * @param {Function} authenticate - Authentication middleware
 * @param {Object} rateLimiters - Rate limiter middleware
 * @returns {Router} Express router with network routes
 */
function createNetworkRoutes(db, logAudit, authenticate, rateLimiters) {
  const { generalLimiter, violationLimiter } = rateLimiters;

  // ============================================================================
  // PUBLIC ROUTES
  // ============================================================================

  /**
   * POST /api/network/violation
   * Report an unauthorized network request
   */
  router.post('/violation', violationLimiter, async (req, res) => {
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
          await queueNotification(db, {
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
          await queueNotification(db, {
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
  router.get('/whitelist', generalLimiter, async (req, res) => {
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
  // ADMIN ROUTES
  // ============================================================================

  /**
   * GET /api/admin/network/violations
   * Get network violations for admin panel
   */
  router.get('/violations', authenticate, async (req, res) => {
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
  router.post('/violations/:id/review', authenticate, async (req, res) => {
    try {
      const { id } = req.params;
      const { status, notes } = req.body;

      // Get violation details before updating
      const violation = await db.queryOne(
        'SELECT destination_origin, request_type, review_status FROM network_violations WHERE id = ?',
        [id]
      );

      if (!violation) {
        return res.status(404).json({ error: 'Violation not found' });
      }

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

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'network_violation_reviewed',
        entityType: 'network_violation',
        entityId: id,
        actionDescription: `Reviewed network violation: ${violation.request_type} to ${violation.destination_origin}`,
        previousValue: violation.review_status,
        newValue: status
      });

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
  router.post('/violations/:id/whitelist', authenticate, async (req, res) => {
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

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'domain_whitelisted',
        entityType: 'network_whitelist',
        entityId: id,
        actionDescription: `Whitelisted domain: ${violation.destination_origin}`,
        actionReason: businessJustification,
        previousValue: null,
        newValue: 'whitelisted'
      });

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
  router.get('/whitelist', authenticate, async (req, res) => {
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
  router.delete('/whitelist/:id', authenticate, async (req, res) => {
    try {
      const { id } = req.params;

      // Get whitelist entry before deleting
      const entry = await db.queryOne(
        'SELECT domain FROM network_whitelist WHERE id = ?',
        [id]
      );

      if (!entry) {
        return res.status(404).json({ error: 'Whitelist entry not found' });
      }

      await db.query('DELETE FROM network_whitelist WHERE id = ?', [id]);

      console.log(`[Admin] Whitelist entry ${id} removed by ${req.admin.username}`);

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'domain_removed_from_whitelist',
        entityType: 'network_whitelist',
        entityId: id,
        actionDescription: `Removed domain from whitelist: ${entry.domain}`,
        previousValue: 'whitelisted',
        newValue: null
      });

      res.json({ success: true, message: 'Domain removed from whitelist' });

    } catch (error) {
      console.error('[Admin] Whitelist delete error:', error.message);
      res.status(500).json({ error: 'Failed to remove from whitelist' });
    }
  });

  /**
   * POST /api/admin/network/violations/bulk-delete
   * Bulk delete network violations
   */
  router.post('/violations/bulk-delete', authenticate, async (req, res) => {
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

  return router;
}

module.exports = { createNetworkRoutes };
