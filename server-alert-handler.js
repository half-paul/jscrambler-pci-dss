/**
 * Server-Side Alert Handler for Script Integrity Monitor
 * PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * Example implementation for receiving and processing script integrity violations
 * This example uses Node.js with Express, but can be adapted to any backend
 *
 * Features:
 * - Receives violation alerts from frontend monitor
 * - Validates and sanitizes alert data
 * - Logs to security monitoring system
 * - Triggers incident response for critical violations
 * - Stores violations in database for audit trail
 * - Sends notifications to security team
 * - Generates compliance reports
 *
 * @version 1.0.0
 */

const express = require('express');
const app = express();

// Middleware
app.use(express.json({ limit: '10mb' }));

// Helmet for security headers
const helmet = require('helmet');
app.use(helmet());

// Rate limiting to prevent abuse
const rateLimit = require('express-rate-limit');
const alertLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many violation reports from this IP'
});

/**
 * Script Integrity Violation Handler
 * POST /api/security/script-violations
 *
 * Receives violation alerts from the frontend monitor
 */
app.post('/api/security/script-violations', alertLimiter, async (req, res) => {
  try {
    const alert = req.body;

    // Validate alert data
    if (!isValidAlert(alert)) {
      return res.status(400).json({
        error: 'Invalid alert format',
        received: false
      });
    }

    // Extract metadata
    const metadata = {
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection.remoteAddress,
      timestamp: new Date(),
      sessionId: req.headers['x-session-id'] || null,
      userId: req.headers['x-user-id'] || null
    };

    // Log to console (in production, use proper logging)
    console.error('=== SCRIPT INTEGRITY VIOLATION ===');
    console.error('Timestamp:', metadata.timestamp);
    console.error('IP:', metadata.ip);
    console.error('User Agent:', metadata.userAgent);
    console.error('Alert:', JSON.stringify(alert, null, 2));

    // Process based on severity
    if (alert.severity === 'HIGH' || alert.severity === 'CRITICAL') {
      await handleCriticalViolation(alert, metadata);
    } else {
      await handleStandardViolation(alert, metadata);
    }

    // Log to security monitoring system
    await logToSecuritySystem(alert, metadata);

    // Store in database for audit trail
    await storeViolation(alert, metadata);

    // Send notifications
    await sendNotifications(alert, metadata);

    // Generate response
    res.status(200).json({
      received: true,
      alertId: generateAlertId(alert, metadata),
      timestamp: metadata.timestamp,
      action: 'processed'
    });

  } catch (error) {
    console.error('Error processing violation alert:', error);
    res.status(500).json({
      error: 'Failed to process alert',
      received: false
    });
  }
});

/**
 * Get violation statistics
 * GET /api/security/violations/stats
 */
app.get('/api/security/violations/stats', async (req, res) => {
  try {
    // In production, query from database
    const stats = await getViolationStatistics();

    res.json(stats);
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

/**
 * Get compliance report
 * GET /api/security/compliance/report
 */
app.get('/api/security/compliance/report', async (req, res) => {
  try {
    const startDate = req.query.startDate ? new Date(req.query.startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = req.query.endDate ? new Date(req.query.endDate) : new Date();

    const report = await generateComplianceReport(startDate, endDate);

    res.json(report);
  } catch (error) {
    console.error('Error generating compliance report:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

/**
 * Validate alert structure
 */
function isValidAlert(alert) {
  if (!alert || typeof alert !== 'object') {
    return false;
  }

  // Check required fields
  const requiredFields = ['severity', 'title', 'message'];
  for (const field of requiredFields) {
    if (!(field in alert)) {
      return false;
    }
  }

  // Validate severity
  const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  if (!validSeverities.includes(alert.severity)) {
    return false;
  }

  return true;
}

/**
 * Handle critical violations
 * Requires immediate attention and incident response
 */
async function handleCriticalViolation(alert, metadata) {
  console.error('=== CRITICAL VIOLATION - IMMEDIATE ACTION REQUIRED ===');

  // Log to critical alerts channel
  await logCriticalAlert(alert, metadata);

  // Trigger incident response
  await triggerIncidentResponse(alert, metadata);

  // Send immediate notifications
  await sendImmediateNotification(alert, metadata);

  // In enforce mode, consider blocking user session
  if (alert.action === 'BLOCKED') {
    await blockUserSession(metadata.sessionId, metadata.ip);
  }
}

/**
 * Handle standard violations
 */
async function handleStandardViolation(alert, metadata) {
  console.warn('Script integrity violation detected');

  // Log to standard monitoring
  await logStandardAlert(alert, metadata);

  // Queue for review
  await queueForReview(alert, metadata);
}

/**
 * Log to security monitoring system
 * Example: Splunk, ELK, Datadog, etc.
 */
async function logToSecuritySystem(alert, metadata) {
  // Example: Send to Splunk
  // await splunkLogger.log({
  //   sourcetype: 'script_integrity_violation',
  //   event: {
  //     severity: alert.severity,
  //     violation: alert.violation,
  //     metadata: metadata
  //   }
  // });

  // Example: Send to ELK
  // await elasticsearchClient.index({
  //   index: 'security-violations',
  //   body: {
  //     type: 'script_integrity',
  //     alert: alert,
  //     metadata: metadata,
  //     timestamp: new Date()
  //   }
  // });

  console.log('[Security System] Alert logged');
}

/**
 * Store violation in database
 * Maintain audit trail for PCI DSS compliance
 */
async function storeViolation(alert, metadata) {
  // Example: MongoDB
  // await db.collection('violations').insertOne({
  //   alert: alert,
  //   metadata: metadata,
  //   createdAt: new Date(),
  //   status: 'open',
  //   reviewedAt: null,
  //   reviewedBy: null,
  //   resolution: null
  // });

  // Example: PostgreSQL
  // await db.query(
  //   `INSERT INTO script_violations
  //    (severity, script_id, violation_type, user_agent, ip_address, created_at)
  //    VALUES ($1, $2, $3, $4, $5, $6)`,
  //   [
  //     alert.severity,
  //     alert.violation?.scriptId,
  //     alert.violation?.violationType,
  //     metadata.userAgent,
  //     metadata.ip,
  //     metadata.timestamp
  //   ]
  // );

  console.log('[Database] Violation stored');
}

/**
 * Send notifications to security team
 */
async function sendNotifications(alert, metadata) {
  // Example: Send email for high severity
  if (alert.severity === 'HIGH' || alert.severity === 'CRITICAL') {
    // await emailService.send({
    //   to: 'security-team@company.com',
    //   subject: `[ALERT] Script Integrity Violation - ${alert.severity}`,
    //   body: formatAlertEmail(alert, metadata)
    // });
  }

  // Example: Send Slack notification
  // await slackClient.sendMessage({
  //   channel: '#security-alerts',
  //   text: formatSlackMessage(alert, metadata)
  // });

  // Example: Send PagerDuty alert for critical
  // if (alert.severity === 'CRITICAL') {
  //   await pagerDuty.trigger({
  //     incident_key: generateAlertId(alert, metadata),
  //     description: alert.message,
  //     details: { alert, metadata }
  //   });
  // }

  console.log('[Notifications] Alerts sent');
}

/**
 * Log critical alert
 */
async function logCriticalAlert(alert, metadata) {
  console.error('[CRITICAL] Script integrity violation');
  console.error('Script:', alert.violation?.scriptId);
  console.error('Type:', alert.violation?.violationType);
  console.error('IP:', metadata.ip);
  console.error('User Agent:', metadata.userAgent);
}

/**
 * Trigger incident response
 */
async function triggerIncidentResponse(alert, metadata) {
  console.log('[Incident Response] Creating incident...');

  // Example: Create incident in incident management system
  // await incidentManagement.createIncident({
  //   title: 'Script Integrity Violation',
  //   severity: 'high',
  //   category: 'security',
  //   description: alert.message,
  //   metadata: {
  //     alert: alert,
  //     context: metadata
  //   }
  // });
}

/**
 * Send immediate notification
 */
async function sendImmediateNotification(alert, metadata) {
  console.log('[Immediate Notification] Sending...');

  // Example: SMS to on-call engineer
  // await smsService.send({
  //   to: '+1234567890',
  //   message: `CRITICAL: Script integrity violation detected. Check security dashboard immediately.`
  // });
}

/**
 * Block user session
 */
async function blockUserSession(sessionId, ip) {
  if (!sessionId && !ip) {
    return;
  }

  console.log('[Session Block] Blocking session:', sessionId, 'IP:', ip);

  // Example: Add to blocklist
  // await redis.sadd('blocked_sessions', sessionId);
  // await redis.sadd('blocked_ips', ip);
  // await redis.expire('blocked_sessions', 3600); // 1 hour
}

/**
 * Log standard alert
 */
async function logStandardAlert(alert, metadata) {
  console.warn('[Standard Alert] Script violation logged');
}

/**
 * Queue for review
 */
async function queueForReview(alert, metadata) {
  console.log('[Review Queue] Alert queued for manual review');

  // Example: Add to review queue
  // await redis.lpush('violation_review_queue', JSON.stringify({
  //   alert: alert,
  //   metadata: metadata,
  //   queuedAt: new Date()
  // }));
}

/**
 * Generate unique alert ID
 */
function generateAlertId(alert, metadata) {
  const data = `${alert.violation?.scriptId}-${metadata.timestamp.getTime()}-${metadata.ip}`;
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

/**
 * Get violation statistics
 */
async function getViolationStatistics() {
  // Example: Query from database
  // const totalViolations = await db.collection('violations').countDocuments();
  // const last24Hours = await db.collection('violations').countDocuments({
  //   createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
  // });

  return {
    totalViolations: 0,
    last24Hours: 0,
    last7Days: 0,
    last30Days: 0,
    byType: {},
    bySeverity: {},
    topScripts: []
  };
}

/**
 * Generate PCI DSS compliance report
 */
async function generateComplianceReport(startDate, endDate) {
  // Example: Query violations from database
  // const violations = await db.collection('violations').find({
  //   createdAt: { $gte: startDate, $lte: endDate }
  // }).toArray();

  return {
    reportDate: new Date(),
    period: {
      start: startDate,
      end: endDate
    },
    pciDssRequirement: '6.4.3',
    summary: {
      totalViolations: 0,
      criticalViolations: 0,
      highViolations: 0,
      mediumViolations: 0,
      lowViolations: 0
    },
    complianceStatus: 'COMPLIANT',
    recommendations: [
      'Continue monitoring for unauthorized scripts',
      'Review and update baseline hashes regularly',
      'Maintain script inventory documentation',
      'Conduct quarterly security reviews'
    ]
  };
}

/**
 * Format alert email
 */
function formatAlertEmail(alert, metadata) {
  return `
Script Integrity Violation Detected

Severity: ${alert.severity}
Title: ${alert.title}
Message: ${alert.message}

Violation Details:
- Script: ${alert.violation?.scriptId || 'N/A'}
- Type: ${alert.violation?.violationType || 'N/A'}
- Timestamp: ${metadata.timestamp}

Request Details:
- IP Address: ${metadata.ip}
- User Agent: ${metadata.userAgent}
- Session ID: ${metadata.sessionId || 'N/A'}

Action: ${alert.action || 'REPORTED'}

Please review immediately and take appropriate action.

---
This is an automated alert from the Script Integrity Monitoring system.
  `.trim();
}

/**
 * Format Slack message
 */
function formatSlackMessage(alert, metadata) {
  return {
    text: `Script Integrity Violation: ${alert.severity}`,
    attachments: [
      {
        color: alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'danger' : 'warning',
        fields: [
          { title: 'Script', value: alert.violation?.scriptId || 'N/A', short: false },
          { title: 'Type', value: alert.violation?.violationType || 'N/A', short: true },
          { title: 'IP', value: metadata.ip, short: true },
          { title: 'Action', value: alert.action || 'REPORTED', short: true }
        ],
        footer: 'Script Integrity Monitor',
        ts: Math.floor(metadata.timestamp.getTime() / 1000)
      }
    ]
  };
}

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'script-integrity-alert-handler' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Script Integrity Alert Handler listening on port ${PORT}`);
  console.log(`POST /api/security/script-violations - Receive violation alerts`);
  console.log(`GET  /api/security/violations/stats - Get statistics`);
  console.log(`GET  /api/security/compliance/report - Get compliance report`);
});

module.exports = app;
