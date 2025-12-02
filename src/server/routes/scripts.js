/**
 * Scripts Routes
 * Handles script registration, approval workflow, and script inventory management
 */

const express = require('express');
const router = express.Router();

/**
 * Create scripts routes
 * @param {Object} db - Database instance
 * @param {Function} logAudit - Audit logging function
 * @param {Function} authenticate - Authentication middleware
 * @param {Function} requireRole - Role requirement middleware
 * @param {Object} rateLimiters - Rate limiter middleware
 * @returns {Router} Express router with scripts routes
 */
function createScriptsRoutes(db, logAudit, authenticate, requireRole, rateLimiters) {
  const { registrationLimiter, generalLimiter } = rateLimiters;

  // ============================================================================
  // PUBLIC ROUTES
  // ============================================================================

  /**
   * POST /api/scripts/register
   * Register a new script or re-detect an existing one
   */
  router.post('/register', registrationLimiter, async (req, res) => {
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
        // Note: Notification queue integration point
        // await queueNotification({ type: 'email', subject: 'New Script Pending Approval', ... });
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
  router.get('/status/:hash', generalLimiter, async (req, res) => {
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

  // ============================================================================
  // ADMIN ROUTES
  // ============================================================================

  /**
   * GET /api/scripts/admin/pending
   * Get all scripts pending approval
   */
  router.get('/pending', authenticate, async (req, res) => {
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
   * GET /api/scripts/admin/search
   * Search scripts with filters
   */
  router.get('/search', authenticate, async (req, res) => {
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
   * POST /api/scripts/admin/:id/approve
   * Approve a script
   */
  router.post('/:id/approve', authenticate, async (req, res) => {
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

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'script_approved',
        entityType: 'script',
        entityId: id,
        actionDescription: `Approved script: ${script.url}`,
        previousValue: 'pending_approval',
        newValue: 'approved'
      });

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
   * POST /api/scripts/admin/:id/reject
   * Reject a script
   */
  router.post('/:id/reject', authenticate, async (req, res) => {
    try {
      const { id } = req.params;
      const { rejectionReason, notes } = req.body;

      // Get script info before updating
      const script = await db.queryOne('SELECT url FROM scripts WHERE id = ?', [id]);

      if (!script) {
        return res.status(404).json({ error: 'Script not found' });
      }

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

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'script_rejected',
        entityType: 'script',
        entityId: id,
        actionDescription: `Rejected script: ${script.url}`,
        actionReason: rejectionReason,
        previousValue: 'pending_approval',
        newValue: 'rejected'
      });

      res.json({ success: true, message: 'Script rejected successfully' });

    } catch (error) {
      console.error('[Admin] Reject error:', error.message);
      res.status(500).json({ error: 'Failed to reject script' });
    }
  });

  /**
   * POST /api/scripts/admin/bulk-approve
   * Bulk approve multiple scripts
   */
  router.post('/bulk-approve', authenticate, async (req, res) => {
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

        // Log to audit trail
        if (successCount > 0) {
          await logAudit({
            req,
            admin: req.admin,
            actionType: 'scripts_bulk_approved',
            entityType: 'script',
            entityId: scriptIds,
            actionDescription: `Bulk approved ${successCount} script(s)`,
            previousValue: 'pending_approval',
            newValue: 'approved'
          });
        }

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
   * POST /api/scripts/admin/bulk-reject
   * Bulk reject multiple scripts
   */
  router.post('/bulk-reject', authenticate, async (req, res) => {
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

        // Log to audit trail
        if (successCount > 0) {
          await logAudit({
            req,
            admin: req.admin,
            actionType: 'scripts_bulk_rejected',
            entityType: 'script',
            entityId: scriptIds,
            actionDescription: `Bulk rejected ${successCount} script(s)`,
            actionReason: rejectionReason,
            previousValue: 'pending_approval',
            newValue: 'rejected'
          });
        }

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
   * GET /api/scripts/admin/:id
   * Get script details with audit log
   */
  router.get('/:id', authenticate, async (req, res) => {
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
   * PUT /api/scripts/admin/:id/update
   * Update script details
   */
  router.put('/:id/update', authenticate, async (req, res) => {
    try {
      const { id } = req.params;
      const { status, businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes, rejectionReason } = req.body;

      // Get script info before updating
      const script = await db.queryOne('SELECT url, status as old_status FROM scripts WHERE id = ?', [id]);

      if (!script) {
        return res.status(404).json({ error: 'Script not found' });
      }

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

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'script_updated',
        entityType: 'script',
        entityId: id,
        actionDescription: `Updated script: ${script.url}`,
        previousValue: script.old_status,
        newValue: status
      });

      res.json({ success: true, message: 'Script updated successfully' });

    } catch (error) {
      console.error('[Admin] Update error:', error.message);
      res.status(500).json({ error: 'Failed to update script' });
    }
  });

  /**
   * DELETE /api/scripts/admin/:id
   * Delete a single script from inventory
   */
  router.delete('/:id', authenticate, async (req, res) => {
    try {
      const { id } = req.params;
      const adminUsername = req.admin.username;

      // Check if script exists
      const script = await db.queryOne('SELECT * FROM scripts WHERE id = ?', [id]);

      if (!script) {
        return res.status(404).json({ error: 'Script not found' });
      }

      // Delete related records first (violations don't have foreign key cascade)
      await db.query('DELETE FROM integrity_violations WHERE script_url = ?', [script.url]);

      // Delete the script (this will cascade delete audit logs via ON DELETE CASCADE)
      await db.query('DELETE FROM scripts WHERE id = ?', [id]);

      console.log(`[Admin] Script ${id} deleted by ${adminUsername}`);

      // Log to audit trail
      await logAudit({
        req,
        admin: req.admin,
        actionType: 'script_deleted',
        entityType: 'script',
        entityId: id,
        actionDescription: `Deleted script: ${script.url}`,
        previousValue: script.status,
        newValue: 'deleted'
      });

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

  return router;
}

module.exports = { createScriptsRoutes };
