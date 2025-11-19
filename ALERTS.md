# Batched Alert System

Comprehensive guide for configuring and using the batched alert system for integrity violations and new pending scripts.

## Overview

The alert system sends **batched notifications** via Email and Slack when:
- **Integrity violations** are detected (unauthorized script changes, hash mismatches)
- **New pending scripts** are registered and awaiting approval

Alerts are **batched** over configurable intervals (default: 15 minutes) to prevent alert fatigue. All violations/scripts detected within the interval are included in a single alert.

## Features

✅ **Batched Alerts**: Group violations/scripts over time intervals
✅ **Multiple Email Recipients**: Send to comma-separated email addresses
✅ **Slack Integration**: Post formatted messages to Slack channels
✅ **Separate Toggles**: Enable/disable violations vs new scripts independently
✅ **Rich Formatting**: HTML emails and formatted Slack blocks
✅ **Auto-Scheduling**: Background job runs automatically
✅ **Database Configuration**: Change settings without server restart

## Quick Start

### 1. Configure SMTP (for Email)

Add to your `.env` file:

```bash
# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM="Script Integrity Monitor" <noreply@your-domain.com>
```

**Gmail Users**: Use an [App Password](https://support.google.com/accounts/answer/185833), not your regular password.

### 2. Configure Alert Settings

Update the database configuration:

```sql
-- Enable violation alerts
UPDATE system_config SET value = 'true' WHERE key = 'alert_violations_enabled';

-- Enable new script alerts
UPDATE system_config SET value = 'true' WHERE key = 'alert_new_scripts_enabled';

-- Set email recipients (comma-separated)
UPDATE system_config
SET value = 'security@example.com,devops@example.com,admin@example.com'
WHERE key = 'violation_alert_email';

-- Set Slack webhook (optional)
UPDATE system_config
SET value = 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
WHERE key = 'violation_alert_slack';

-- Set batch interval (minutes)
UPDATE system_config SET value = '15' WHERE key = 'alert_batch_interval_minutes';
```

### 3. Restart Server

```bash
npm restart
```

The alert scheduler starts automatically on server startup.

## Configuration Reference

All alert settings are stored in the `system_config` database table:

| Key | Default | Description |
|-----|---------|-------------|
| `alert_batch_interval_minutes` | `15` | How often to check and send batched alerts (in minutes) |
| `alert_violations_enabled` | `false` | Enable/disable violation alerts |
| `alert_new_scripts_enabled` | `false` | Enable/disable new pending script alerts |
| `violation_alert_email` | `` | Email addresses for alerts (comma-separated) |
| `violation_alert_slack` | `` | Slack webhook URL for alerts |
| `alert_last_sent_violations` | `` | Internal: Timestamp of last violation alert |
| `alert_last_sent_new_scripts` | `` | Internal: Timestamp of last new script alert |

## Email Configuration

### SMTP Environment Variables

Required environment variables in `.env`:

```bash
SMTP_HOST=smtp.gmail.com          # SMTP server hostname
SMTP_PORT=587                      # SMTP port (587 for TLS, 465 for SSL)
SMTP_SECURE=false                  # true for 465, false for other ports
SMTP_USER=your-email@example.com  # SMTP username
SMTP_PASSWORD=your-password        # SMTP password or app password
SMTP_FROM="Monitor" <noreply@your-domain.com>  # From address
```

### Common SMTP Providers

**Gmail:**
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password  # Generate at https://myaccount.google.com/apppasswords
```

**SendGrid:**
```bash
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=apikey
SMTP_PASSWORD=your-sendgrid-api-key
```

**AWS SES:**
```bash
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-ses-smtp-username
SMTP_PASSWORD=your-ses-smtp-password
```

**Mailgun:**
```bash
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=postmaster@your-domain.mailgun.org
SMTP_PASSWORD=your-mailgun-password
```

## Slack Configuration

### 1. Create a Slack Incoming Webhook

1. Go to https://api.slack.com/apps
2. Click "Create New App" → "From scratch"
3. Name your app (e.g., "Script Integrity Monitor")
4. Select your workspace
5. Navigate to "Incoming Webhooks"
6. Toggle "Activate Incoming Webhooks" to ON
7. Click "Add New Webhook to Workspace"
8. Select the channel to post to
9. Copy the webhook URL

### 2. Configure the Webhook

```sql
UPDATE system_config
SET value = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX'
WHERE key = 'violation_alert_slack';
```

## Alert Format

### Violation Email Example

```
Subject: [Script Integrity] 3 Violations Detected

Script Integrity Violations Detected

3 violations have been detected since the last alert.

┌─────────────────────┬──────────────┬──────────┬─────────────────┬────────────────┐
│ Detected At         │ Type         │ Severity │ Script URL      │ Page URL       │
├─────────────────────┼──────────────┼──────────┼─────────────────┼────────────────┤
│ 2025-01-19 10:30 AM │ HASH_MISMATCH│ HIGH     │ /js/payment.js  │ /checkout.html │
│ 2025-01-19 10:32 AM │ UNAUTHORIZED │ CRITICAL │ /js/unknown.js  │ /checkout.html │
│ 2025-01-19 10:35 AM │ SRI_MISMATCH │ HIGH     │ /js/vendor.js   │ /cart.html     │
└─────────────────────┴──────────────┴──────────┴─────────────────┴────────────────┘

This is an automated alert from the Script Integrity Monitoring System.
```

### New Scripts Email Example

```
Subject: [Script Integrity] 2 New Scripts Awaiting Approval

New Scripts Awaiting Approval

2 new scripts have been detected and require approval.

┌─────────────────────┬──────────┬─────────────────┬────────────────┬──────────────┐
│ Detected At         │ Type     │ Script URL      │ Page URL       │ Hash         │
├─────────────────────┼──────────┼─────────────────┼────────────────┼──────────────┤
│ 2025-01-19 10:40 AM │ external │ /js/analytics.js│ /dashboard.html│ sha384-Pq9h...│
│ 2025-01-19 10:42 AM │ inline   │ inline-script-0 │ /home.html     │ sha384-8Xd2...│
└─────────────────────┴──────────┴─────────────────┴────────────────┴──────────────┘

This is an automated alert from the Script Integrity Monitoring System.
Please review and approve/reject these scripts in the admin panel.
```

### Slack Message Example

```
🚨 3 Script Integrity Violations Detected

3 violations have been detected since the last alert.

━━━━━━━━━━━━━━━━━━━━━━━━

Type:                Severity:
HASH_MISMATCH        HIGH

Script:              Page:
/js/payment.js       /checkout.html

━━━━━━━━━━━━━━━━━━━━━━━━

[... additional violations ...]

━━━━━━━━━━━━━━━━━━━━━━━━

...and 1 more violation
```

## Alert Timing

### How Batching Works

1. **Alert scheduler runs every X minutes** (configured by `alert_batch_interval_minutes`)
2. **Queries for new violations/scripts** since last alert was sent
3. **If violations/scripts found**, sends a single batched alert
4. **Updates last sent timestamp** to prevent duplicate alerts
5. **Repeats** on the next interval

### Example Timeline

```
10:00 AM - Scheduler starts, interval: 15 minutes
10:05 AM - Violation detected (queued)
10:10 AM - Another violation detected (queued)
10:15 AM - Scheduler runs → Sends alert with 2 violations
10:20 AM - New violation detected (queued)
10:30 AM - Scheduler runs → Sends alert with 1 violation
10:45 AM - Scheduler runs → No new violations, no alert sent
```

## Troubleshooting

### No Alerts Being Sent

**Check if alerts are enabled:**
```sql
SELECT key, value FROM system_config
WHERE key IN ('alert_violations_enabled', 'alert_new_scripts_enabled');
```

**Check if email/Slack is configured:**
```sql
SELECT key, value FROM system_config
WHERE key IN ('violation_alert_email', 'violation_alert_slack');
```

**Check server logs:**
```bash
# Look for alert scheduler messages
grep "\[Alerts\]" logs/app.log

# Example output:
# [Alerts] Starting alert scheduler...
# [Alerts] Scheduler started (interval: 15 minutes)
# [Alerts] Checking for alerts to send...
# [Alerts] Found 3 new violations
# [Alerts] Email sent to 2 recipient(s)
```

### Email Not Sending

**Test SMTP configuration:**
```bash
# Check environment variables
env | grep SMTP

# Test connection (from Node.js)
node -e "
const nodemailer = require('nodemailer');
const transport = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
});
transport.verify().then(console.log).catch(console.error);
"
```

**Common Issues:**
- **Gmail**: Use App Password, not regular password
- **Firewall**: Ensure ports 587/465 are open
- **Authentication**: Check username/password are correct
- **TLS**: Set `SMTP_SECURE=false` for port 587, `true` for 465

### Slack Not Posting

**Test webhook:**
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message from Script Integrity Monitor"}' \
  YOUR_WEBHOOK_URL
```

**Common Issues:**
- **Invalid URL**: Webhook URL must start with `https://hooks.slack.com/services/`
- **Revoked Webhook**: Recreate webhook in Slack app settings
- **Wrong Channel**: Webhook posts to the channel it was created for

### Changing Alert Interval

To change how often alerts are sent:

```sql
-- Send alerts every 30 minutes
UPDATE system_config SET value = '30' WHERE key = 'alert_batch_interval_minutes';
```

**Note**: Requires server restart for interval change to take effect.

## Security Considerations

### Email Security

- **Use TLS/SSL**: Always configure `SMTP_SECURE` appropriately
- **App Passwords**: Use app-specific passwords, not account passwords
- **Restrict From Address**: Configure SPF/DKIM for your from domain
- **Rate Limiting**: Monitor for excessive emails (potential DoS)

### Slack Security

- **Webhook Security**: Keep webhook URLs secret (treat like passwords)
- **Channel Permissions**: Restrict who can see the alert channel
- **Webhook Rotation**: Periodically rotate webhooks
- **Audit Logs**: Review Slack audit logs for unauthorized access

### Data Privacy

- **Email Content**: Contains script URLs and page URLs
- **PII Concerns**: Script URLs may contain user identifiers
- **Encryption**: Use TLS for email transmission
- **Retention**: Emails stored by recipients, plan retention policies

## Performance

### Resource Usage

- **Scheduler Overhead**: Minimal (~10ms per check)
- **Database Queries**: 2 queries per interval (violations + scripts)
- **Email Sending**: Async, doesn't block server
- **Slack Posting**: Async HTTP request
- **Memory**: ~1MB for scheduler instance

### Scaling Recommendations

| Scripts/Day | Violations/Day | Recommended Interval |
|-------------|----------------|---------------------|
| < 100       | < 50           | 15 minutes          |
| 100-1000    | 50-500         | 30 minutes          |
| 1000-10000  | 500-2000       | 60 minutes          |
| > 10000     | > 2000         | Custom batching     |

## API for Manual Alerts

While alerts are automatic, you can trigger manual checks:

```javascript
// In server code or admin endpoint
await alertScheduler.checkAndSendAlerts();
```

## Future Enhancements

Potential improvements for future versions:

- [ ] Admin panel UI for alert configuration
- [ ] Alert templates and customization
- [ ] Per-violation severity thresholds
- [ ] Digest mode (daily/weekly summaries)
- [ ] SMS alerts via Twilio
- [ ] PagerDuty integration
- [ ] Alert muting/snoozing
- [ ] Alert escalation rules
- [ ] Webhook alerts for custom integrations

## Support

For issues or questions:
- Check server logs: `[Alerts]` prefix
- Review database config: `SELECT * FROM system_config WHERE key LIKE 'alert_%';`
- Test email: Send test email via SMTP provider
- Test Slack: Use webhook test endpoint

## Related Documentation

- [README.md](README.md) - Project overview and setup
- [APPROVAL-WORKFLOW.md](APPROVAL-WORKFLOW.md) - Script approval process
- [DOCKER.md](DOCKER.md) - Docker deployment
- [.env.example](.env.example) - Environment configuration
