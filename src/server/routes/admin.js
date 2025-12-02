/**
 * Admin Routes
 * Handles admin dashboard, user management, audit trail, and PCI DSS compliance reporting
 */

const express = require('express');
const router = express.Router();

/**
 * Create admin routes
 * @param {Object} db - Database instance
 * @param {Function} logAudit - Audit logging function
 * @param {Function} authenticate - Authentication middleware
 * @param {Function} requireRole - Role requirement middleware
 * @param {Object} rateLimiters - Rate limiter middleware
 * @returns {Router} Express router with admin routes
 */
function createAdminRoutes(db, logAudit, authenticate, requireRole, rateLimiters) {
  // All admin routes require authentication

  /**
   * GET /api/admin/dashboard
   * Get dashboard statistics
   */
  router.get('/dashboard', authenticate, async (req, res) => {
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
   * GET /api/admin/pci-dss/summary
   * Get PCI DSS 11.6.1 compliance summary
   */
  router.get('/pci-dss/summary', authenticate, async (req, res) => {
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

  /**
   * GET /api/admin/audit-trail
   * Get audit trail logs with pagination and filtering
   */
  router.get('/audit-trail', authenticate, async (req, res) => {
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
        // Add one day to endDate to make it inclusive (< nextDay instead of <= endDate)
        // This ensures logs from the entire endDate day are included
        const endDateTime = new Date(endDate);
        endDateTime.setDate(endDateTime.getDate() + 1);
        whereConditions.push('timestamp < ?');
        params.push(endDateTime.toISOString().split('T')[0]); // YYYY-MM-DD format
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
  router.get('/audit-trail/stats', authenticate, async (req, res) => {
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

  /**
   * GET /api/admin/users
   * Get all admin users
   */
  router.get('/users', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {
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
  router.post('/users', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {
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
  router.put('/users/:id', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {
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
  router.delete('/users/:id', authenticate, requireRole('admin', 'super_admin'), async (req, res) => {
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

  return router;
}

module.exports = { createAdminRoutes };
