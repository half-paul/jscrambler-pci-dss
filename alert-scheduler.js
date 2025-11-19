/**
 * Alert Scheduler Service
 * Batches and sends periodic alerts for violations and new pending scripts
 *
 * Features:
 * - Batches alerts over configurable intervals (default: 15 minutes)
 * - Sends to multiple email addresses
 * - Sends to Slack webhooks
 * - Separate toggles for violations vs new scripts
 * - Rich formatting for both email and Slack
 *
 * @version 1.0.0
 */

'use strict';

const nodemailer = require('nodemailer');

class AlertScheduler {
  constructor(db) {
    this.db = db;
    this.intervalId = null;
    this.isRunning = false;
    this.emailTransporter = null;
  }

  /**
   * Start the alert scheduler
   */
  async start() {
    if (this.isRunning) {
      console.log('[Alerts] Alert scheduler already running');
      return;
    }

    console.log('[Alerts] Starting alert scheduler...');

    // Get configuration
    const config = await this.getConfig();

    if (!config.violationsEnabled && !config.newScriptsEnabled) {
      console.log('[Alerts] All alerts disabled, scheduler not started');
      return;
    }

    // Initialize email transporter if email is configured
    if (config.emailAddresses && config.emailAddresses.length > 0) {
      this.initializeEmailTransporter();
    }

    this.isRunning = true;

    // Run immediately on start
    await this.checkAndSendAlerts();

    // Schedule periodic checks
    const intervalMs = config.intervalMinutes * 60 * 1000;
    this.intervalId = setInterval(async () => {
      await this.checkAndSendAlerts();
    }, intervalMs);

    console.log(`[Alerts] Scheduler started (interval: ${config.intervalMinutes} minutes)`);
  }

  /**
   * Stop the alert scheduler
   */
  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.isRunning = false;
    console.log('[Alerts] Alert scheduler stopped');
  }

  /**
   * Get alert configuration from database
   */
  async getConfig() {
    const configRows = await this.db.query(
      `SELECT key, value FROM system_config WHERE key IN (?, ?, ?, ?, ?, ?, ?)`,
      [
        'alert_batch_interval_minutes',
        'alert_violations_enabled',
        'alert_new_scripts_enabled',
        'violation_alert_email',
        'violation_alert_slack',
        'alert_last_sent_violations',
        'alert_last_sent_new_scripts'
      ]
    );

    const config = {};
    for (const row of configRows) {
      config[row.key] = row.value;
    }

    return {
      intervalMinutes: parseInt(config.alert_batch_interval_minutes || '15'),
      violationsEnabled: config.alert_violations_enabled === 'true',
      newScriptsEnabled: config.alert_new_scripts_enabled === 'true',
      emailAddresses: config.violation_alert_email
        ? config.violation_alert_email.split(',').map(e => e.trim()).filter(e => e.length > 0)
        : [],
      slackWebhook: config.violation_alert_slack || null,
      lastSentViolations: config.alert_last_sent_violations || null,
      lastSentNewScripts: config.alert_last_sent_new_scripts || null
    };
  }

  /**
   * Initialize email transporter
   */
  initializeEmailTransporter() {
    const smtpConfig = {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
      auth: process.env.SMTP_USER && process.env.SMTP_PASSWORD ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      } : undefined
    };

    // Only create transporter if SMTP is configured
    if (smtpConfig.host) {
      this.emailTransporter = nodemailer.createTransporter(smtpConfig);
      console.log('[Alerts] Email transporter initialized');
    } else {
      console.log('[Alerts] SMTP not configured, email alerts disabled');
    }
  }

  /**
   * Check for new violations and scripts, send alerts if needed
   */
  async checkAndSendAlerts() {
    try {
      console.log('[Alerts] Checking for alerts to send...');

      const config = await this.getConfig();
      const now = new Date();

      // Check violations
      if (config.violationsEnabled) {
        const violations = await this.getRecentViolations(config.lastSentViolations);
        if (violations.length > 0) {
          console.log(`[Alerts] Found ${violations.length} new violations`);
          await this.sendViolationAlerts(violations, config);
          await this.updateLastSent('alert_last_sent_violations', now);
        }
      }

      // Check new pending scripts
      if (config.newScriptsEnabled) {
        const newScripts = await this.getRecentNewScripts(config.lastSentNewScripts);
        if (newScripts.length > 0) {
          console.log(`[Alerts] Found ${newScripts.length} new pending scripts`);
          await this.sendNewScriptAlerts(newScripts, config);
          await this.updateLastSent('alert_last_sent_new_scripts', now);
        }
      }

    } catch (error) {
      console.error('[Alerts] Error checking/sending alerts:', error.message);
    }
  }

  /**
   * Get recent violations since last alert
   */
  async getRecentViolations(lastSentTimestamp) {
    const sinceTime = lastSentTimestamp || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const violations = await this.db.query(
      `SELECT
        iv.id,
        iv.script_url,
        iv.violation_type,
        iv.severity,
        iv.detected_at,
        iv.page_url,
        iv.old_hash,
        iv.new_hash,
        s.url as full_script_url,
        s.script_type
      FROM integrity_violations iv
      LEFT JOIN scripts s ON iv.script_id = s.id
      WHERE iv.detected_at > ?
        AND iv.violation_type NOT IN ('PENDING_APPROVAL', 'NEW_SCRIPT')
      ORDER BY iv.detected_at DESC
      LIMIT 100`,
      [sinceTime]
    );

    return violations;
  }

  /**
   * Get recent new pending scripts since last alert
   */
  async getRecentNewScripts(lastSentTimestamp) {
    const sinceTime = lastSentTimestamp || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const scripts = await this.db.query(
      `SELECT
        id,
        url,
        content_hash,
        script_type,
        size_bytes,
        first_seen,
        page_url,
        content_preview,
        last_registered_ip
      FROM scripts
      WHERE status = 'pending_approval'
        AND first_seen > ?
      ORDER BY first_seen DESC
      LIMIT 50`,
      [sinceTime]
    );

    return scripts;
  }

  /**
   * Send violation alerts
   */
  async sendViolationAlerts(violations, config) {
    const subject = `[Script Integrity] ${violations.length} Violation${violations.length > 1 ? 's' : ''} Detected`;
    const htmlBody = this.formatViolationsHTML(violations);
    const slackBody = this.formatViolationsSlack(violations);

    // Send email
    if (config.emailAddresses.length > 0 && this.emailTransporter) {
      await this.sendEmail(config.emailAddresses, subject, htmlBody);
    }

    // Send Slack
    if (config.slackWebhook) {
      await this.sendSlack(config.slackWebhook, slackBody);
    }
  }

  /**
   * Send new script alerts
   */
  async sendNewScriptAlerts(scripts, config) {
    const subject = `[Script Integrity] ${scripts.length} New Script${scripts.length > 1 ? 's' : ''} Awaiting Approval`;
    const htmlBody = this.formatNewScriptsHTML(scripts);
    const slackBody = this.formatNewScriptsSlack(scripts);

    // Send email
    if (config.emailAddresses.length > 0 && this.emailTransporter) {
      await this.sendEmail(config.emailAddresses, subject, htmlBody);
    }

    // Send Slack
    if (config.slackWebhook) {
      await this.sendSlack(config.slackWebhook, slackBody);
    }
  }

  /**
   * Format violations for email (HTML)
   */
  formatViolationsHTML(violations) {
    const rows = violations.map(v => `
      <tr>
        <td style="padding: 8px; border: 1px solid #ddd;">${new Date(v.detected_at).toLocaleString()}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${v.violation_type}</td>
        <td style="padding: 8px; border: 1px solid #ddd; color: ${this.getSeverityColor(v.severity)};"><strong>${v.severity}</strong></td>
        <td style="padding: 8px; border: 1px solid #ddd;">${this.escapeHtml(v.script_url)}</td>
        <td style="padding: 8px; border: 1px solid #ddd; font-size: 11px;">${this.escapeHtml(v.page_url)}</td>
      </tr>
    `).join('');

    return `
      <html>
        <body style="font-family: Arial, sans-serif;">
          <h2 style="color: #d32f2f;">Script Integrity Violations Detected</h2>
          <p><strong>${violations.length}</strong> violation${violations.length > 1 ? 's have' : ' has'} been detected since the last alert.</p>

          <table style="border-collapse: collapse; width: 100%; margin-top: 20px;">
            <thead>
              <tr style="background-color: #f5f5f5;">
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Detected At</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Type</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Severity</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Script URL</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Page URL</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>

          <p style="margin-top: 20px; font-size: 12px; color: #666;">
            This is an automated alert from the Script Integrity Monitoring System.
          </p>
        </body>
      </html>
    `;
  }

  /**
   * Format new scripts for email (HTML)
   */
  formatNewScriptsHTML(scripts) {
    const rows = scripts.map(s => `
      <tr>
        <td style="padding: 8px; border: 1px solid #ddd;">${new Date(s.first_seen).toLocaleString()}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${s.script_type}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${this.escapeHtml(s.url)}</td>
        <td style="padding: 8px; border: 1px solid #ddd; font-size: 11px;">${this.escapeHtml(s.page_url)}</td>
        <td style="padding: 8px; border: 1px solid #ddd; font-size: 10px;">${s.content_hash.substring(0, 16)}...</td>
      </tr>
    `).join('');

    return `
      <html>
        <body style="font-family: Arial, sans-serif;">
          <h2 style="color: #1976d2;">New Scripts Awaiting Approval</h2>
          <p><strong>${scripts.length}</strong> new script${scripts.length > 1 ? 's have' : ' has'} been detected and require${scripts.length === 1 ? 's' : ''} approval.</p>

          <table style="border-collapse: collapse; width: 100%; margin-top: 20px;">
            <thead>
              <tr style="background-color: #f5f5f5;">
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Detected At</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Type</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Script URL</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Page URL</th>
                <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Hash</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>

          <p style="margin-top: 20px; font-size: 12px; color: #666;">
            This is an automated alert from the Script Integrity Monitoring System.<br>
            Please review and approve/reject these scripts in the admin panel.
          </p>
        </body>
      </html>
    `;
  }

  /**
   * Format violations for Slack
   */
  formatViolationsSlack(violations) {
    const fields = violations.slice(0, 10).map(v => ({
      type: "mrkdwn",
      text: `*${v.violation_type}* (${v.severity})\n${v.script_url}\nPage: ${v.page_url}\n_${new Date(v.detected_at).toLocaleString()}_`
    }));

    const moreCount = violations.length - 10;

    return {
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: `🚨 ${violations.length} Script Integrity Violation${violations.length > 1 ? 's' : ''} Detected`
          }
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*${violations.length}* violation${violations.length > 1 ? 's have' : ' has'} been detected since the last alert.`
          }
        },
        {
          type: "divider"
        },
        ...violations.slice(0, 10).map(v => ({
          type: "section",
          fields: [
            {
              type: "mrkdwn",
              text: `*Type:*\n${v.violation_type}`
            },
            {
              type: "mrkdwn",
              text: `*Severity:*\n${v.severity}`
            },
            {
              type: "mrkdwn",
              text: `*Script:*\n${v.script_url}`
            },
            {
              type: "mrkdwn",
              text: `*Page:*\n${v.page_url.substring(0, 50)}${v.page_url.length > 50 ? '...' : ''}`
            }
          ]
        })),
        ...(moreCount > 0 ? [{
          type: "context",
          elements: [{
            type: "mrkdwn",
            text: `_...and ${moreCount} more violation${moreCount > 1 ? 's' : ''}_`
          }]
        }] : [])
      ]
    };
  }

  /**
   * Format new scripts for Slack
   */
  formatNewScriptsSlack(scripts) {
    return {
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: `📝 ${scripts.length} New Script${scripts.length > 1 ? 's' : ''} Awaiting Approval`
          }
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*${scripts.length}* new script${scripts.length > 1 ? 's have' : ' has'} been detected and require${scripts.length === 1 ? 's' : ''} approval.`
          }
        },
        {
          type: "divider"
        },
        ...scripts.slice(0, 10).map(s => ({
          type: "section",
          fields: [
            {
              type: "mrkdwn",
              text: `*Type:*\n${s.script_type}`
            },
            {
              type: "mrkdwn",
              text: `*Detected:*\n${new Date(s.first_seen).toLocaleString()}`
            },
            {
              type: "mrkdwn",
              text: `*Script:*\n${s.url}`
            },
            {
              type: "mrkdwn",
              text: `*Page:*\n${s.page_url.substring(0, 50)}${s.page_url.length > 50 ? '...' : ''}`
            }
          ]
        })),
        ...(scripts.length > 10 ? [{
          type: "context",
          elements: [{
            type: "mrkdwn",
            text: `_...and ${scripts.length - 10} more script${scripts.length - 10 > 1 ? 's' : ''}_`
          }]
        }] : [])
      ]
    };
  }

  /**
   * Send email alert
   */
  async sendEmail(recipients, subject, htmlBody) {
    if (!this.emailTransporter) {
      console.log('[Alerts] Email transporter not configured, skipping email');
      return;
    }

    try {
      const info = await this.emailTransporter.sendMail({
        from: process.env.SMTP_FROM || '"Script Integrity Monitor" <noreply@example.com>',
        to: recipients.join(', '),
        subject: subject,
        html: htmlBody
      });

      console.log(`[Alerts] Email sent to ${recipients.length} recipient(s): ${info.messageId}`);
    } catch (error) {
      console.error('[Alerts] Failed to send email:', error.message);
    }
  }

  /**
   * Send Slack alert
   */
  async sendSlack(webhookUrl, payload) {
    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        console.log('[Alerts] Slack notification sent successfully');
      } else {
        console.error(`[Alerts] Slack notification failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('[Alerts] Failed to send Slack notification:', error.message);
    }
  }

  /**
   * Update last sent timestamp
   */
  async updateLastSent(key, timestamp) {
    await this.db.query(
      'UPDATE system_config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?',
      [timestamp.toISOString(), key]
    );
  }

  /**
   * Get severity color for HTML
   */
  getSeverityColor(severity) {
    const colors = {
      'CRITICAL': '#d32f2f',
      'HIGH': '#f57c00',
      'MEDIUM': '#fbc02d',
      'LOW': '#388e3c'
    };
    return colors[severity] || '#666';
  }

  /**
   * Escape HTML special characters
   */
  escapeHtml(text) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  }
}

module.exports = AlertScheduler;
