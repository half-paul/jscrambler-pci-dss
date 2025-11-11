# Script Integrity Monitoring Solution
## PCI DSS v4.0 Requirement 6.4.3 Compliance

A production-ready JavaScript solution for monitoring and validating script integrity on payment pages and other security-sensitive web applications.

---

## Table of Contents

1. [Overview](#overview)
2. [PCI DSS 6.4.3 Requirements](#pci-dss-643-requirements)
3. [Features](#features)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [API Reference](#api-reference)
8. [Compliance Guide](#compliance-guide)
9. [Troubleshooting](#troubleshooting)
10. [Security Considerations](#security-considerations)

---

## Overview

This Script Integrity Monitoring (SIM) solution provides real-time detection and prevention of unauthorized JavaScript modifications on web pages, specifically designed to meet PCI DSS v4.0 requirement 6.4.3.

### How It Works

1. **Early Loading**: Loads before any other scripts on the page
2. **Hash Calculation**: Calculates cryptographic hashes (SHA-256/SHA-384) of all scripts
3. **Integrity Verification**: Compares calculated hashes against known baseline values
4. **Continuous Monitoring**: Uses MutationObserver to detect dynamically added scripts
5. **Violation Detection**: Alerts when unauthorized scripts are detected
6. **Comprehensive Logging**: Maintains detailed inventory of all scripts

---

## PCI DSS 6.4.3 Requirements

**PCI DSS v4.0 Requirement 6.4.3** states:

> *"All payment page scripts that are loaded and executed in the consumer's browser are managed as follows:*
> - *A method is implemented to confirm that each script is authorized*
> - *A method is implemented to assure the integrity of each script*
> - *An inventory of all scripts is maintained with written justification as to why each is necessary"*

### How This Solution Addresses Each Requirement

| Requirement | Solution Component |
|-------------|-------------------|
| **Script Authorization** | Baseline hash verification + whitelist validation |
| **Script Integrity** | SHA-256/SHA-384 cryptographic hash comparison |
| **Script Inventory** | Comprehensive logging with timestamps and metadata |
| **Written Justification** | Configuration file with documented scripts |

---

## Features

### Core Capabilities

- **Cryptographic Hash Verification**: SHA-256 or SHA-384 hashing using Web Crypto API
- **Real-Time Monitoring**: Detects scripts at page load and dynamically added scripts
- **Multiple Script Types**: Monitors inline, external, and dynamically loaded scripts
- **Iframe Support**: Monitors scripts within same-origin iframes
- **Subresource Integrity (SRI)**: Validates SRI attributes when present
- **Violation Alerting**: Multiple alert channels (console, API endpoint, callback)
- **Enforcement Modes**: Report-only or enforce (blocking) mode
- **Performance Optimized**: Non-blocking, minimal overhead
- **Comprehensive Logging**: Detailed inventory with timestamps and context

### Monitoring Coverage

- ✅ External scripts (`<script src="...">`)
- ✅ Inline scripts (`<script>code</script>`)
- ✅ Dynamically added scripts (via JavaScript)
- ✅ Scripts in iframes (same-origin only)
- ✅ Scripts with SRI attributes
- ✅ Async and defer scripts
- ✅ Module scripts (`type="module"`)

---

## Installation

### Step 1: Download Files

Place both files in your web server's JavaScript directory:

```
/js/
  ├── script-integrity-config.js
  └── script-integrity-monitor.js
```

### Step 2: Add to HTML

**CRITICAL**: Load in the correct order - configuration first, monitor second, BEFORE all other scripts:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Payment Page</title>

  <!-- 1. Load configuration FIRST -->
  <script src="/js/script-integrity-config.js"></script>

  <!-- 2. Load monitor SECOND (before any other scripts) -->
  <script src="/js/script-integrity-monitor.js"></script>

  <!-- 3. Now load your application scripts - they will be monitored -->
  <script src="/js/app.js"></script>
  <script src="https://cdn.example.com/library.js"
          integrity="sha384-..."
          crossorigin="anonymous"></script>
</head>
<body>
  <!-- Page content -->
</body>
</html>
```

### Step 3: Configure CSP Headers (Recommended)

Add Content Security Policy headers to reinforce script security:

```http
Content-Security-Policy:
  script-src 'self' https://cdn.example.com;
  require-sri-for script;
```

---

## Configuration

### Basic Configuration

Edit `script-integrity-config.js`:

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  // Hash algorithm: 'SHA-256' or 'SHA-384'
  hashAlgorithm: 'SHA-384',

  // Mode: 'report' (log only) or 'enforce' (block unauthorized)
  mode: 'report',

  // Baseline hashes for authorized scripts
  baselineHashes: {
    'https://yourdomain.com/js/app.js': 'sha384-abc123...',
    'https://cdn.example.com/library.js': 'sha384-def456...'
  },

  // Alert endpoint for violations
  alertEndpoint: 'https://yourdomain.com/api/security/violations',

  // Enable console alerts
  consoleAlerts: true,

  // Debug mode
  debug: false
};
```

### Generating Baseline Hashes

#### Method 1: Using Browser Console

1. Load your page in a browser
2. Open Developer Console
3. Run:
   ```javascript
   SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()
   ```
4. Copy the output to your configuration

#### Method 2: Using OpenSSL (Command Line)

```bash
# SHA-384 (recommended)
cat script.js | openssl dgst -sha384 -binary | openssl base64 -A

# SHA-256
cat script.js | openssl dgst -sha256 -binary | openssl base64 -A
```

#### Method 3: Using Node.js

```javascript
const crypto = require('crypto');
const fs = require('fs');

function generateHash(filePath, algorithm = 'sha384') {
  const content = fs.readFileSync(filePath, 'utf8');
  const hash = crypto.createHash(algorithm).update(content).digest('base64');
  return `${algorithm}-${hash}`;
}

console.log(generateHash('./app.js'));
```

### Advanced Configuration Options

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  // Core settings
  hashAlgorithm: 'SHA-384',
  mode: 'report',

  // Baseline hashes
  baselineHashes: { /* ... */ },

  // Whitelisted sources (use cautiously)
  whitelistedSources: [
    /^https:\/\/yourdomain\.com\//,
    /^https:\/\/trusted-cdn\.com\//
  ],

  // Monitoring options
  monitorInlineScripts: true,
  monitorExternalScripts: true,
  monitorDynamicScripts: true,
  monitorIframes: true,

  // Alert configuration
  alertEndpoint: 'https://yourdomain.com/api/violations',
  alertCallback: function(alert) {
    // Custom alert handling
    if (window.analytics) {
      window.analytics.track('Script Violation', alert);
    }
  },
  consoleAlerts: true,
  batchAlerts: false,
  batchInterval: 5000,

  // Debug
  debug: false
};
```

---

## Usage

### Basic Usage

Once configured, the monitor runs automatically. Access the API through the global object:

```javascript
// Get script inventory
const inventory = window.ScriptIntegrityMonitor.getInventory();
console.log('Total scripts:', inventory.length);

// Get violations
const violations = window.ScriptIntegrityMonitor.getViolations();
console.log('Violations detected:', violations.length);

// Get summary
const summary = window.ScriptIntegrityMonitor.getSummary();
console.log(summary);

// Generate compliance report
const report = window.ScriptIntegrityMonitor.generateReport();
console.log(report);

// Export as JSON
const json = window.ScriptIntegrityMonitor.exportInventory();
```

### Monitoring Lifecycle

1. **Initialization**: Monitor loads and scans existing scripts
2. **Hash Calculation**: Calculates hashes for all scripts
3. **Verification**: Compares against baseline hashes
4. **Continuous Monitoring**: Watches for new scripts via MutationObserver
5. **Violation Detection**: Alerts when unauthorized scripts detected
6. **Reporting**: Logs and sends alerts via configured channels

### Example: Accessing Reports

```javascript
// Wait for page load
window.addEventListener('load', function() {
  // Get compliance report
  const report = window.ScriptIntegrityMonitor.generateReport();

  // Send to your analytics
  fetch('/api/compliance/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(report)
  });

  // Display summary
  console.table(report.summary);

  // Check compliance status
  if (report.complianceStatus === 'COMPLIANT') {
    console.log('✓ All scripts authorized');
  } else {
    console.error('✗ Violations detected:', report.violations.length);
  }
});
```

---

## API Reference

### Global Objects

#### `window.ScriptIntegrityMonitor`

Public API for accessing monitor functionality.

##### Methods

**`getInventory()`**
- Returns: `Array<Object>` - Complete script inventory
- Description: Returns all detected scripts with metadata

```javascript
const scripts = window.ScriptIntegrityMonitor.getInventory();
// [
//   {
//     id: "https://example.com/script.js",
//     src: "https://example.com/script.js",
//     inline: false,
//     hash: "sha384-abc123...",
//     authorized: true,
//     timestamp: 1699747200000,
//     ...
//   }
// ]
```

**`getViolations()`**
- Returns: `Array<Object>` - All integrity violations
- Description: Returns all detected violations

```javascript
const violations = window.ScriptIntegrityMonitor.getViolations();
// [
//   {
//     timestamp: 1699747200000,
//     scriptId: "https://malicious.com/script.js",
//     violationType: "NO_BASELINE_HASH",
//     ...
//   }
// ]
```

**`getSummary()`**
- Returns: `Object` - Inventory summary
- Description: Returns high-level statistics

```javascript
const summary = window.ScriptIntegrityMonitor.getSummary();
// {
//   totalScripts: 15,
//   authorizedScripts: 14,
//   unauthorizedScripts: 1,
//   inlineScripts: 2,
//   externalScripts: 13
// }
```

**`generateReport()`**
- Returns: `Object` - PCI DSS compliance report
- Description: Generates complete compliance report

```javascript
const report = window.ScriptIntegrityMonitor.generateReport();
// {
//   reportDate: "2025-11-11T12:00:00.000Z",
//   pciDssRequirement: "6.4.3",
//   complianceStatus: "COMPLIANT",
//   summary: {...},
//   scriptInventory: [...],
//   violations: [...]
// }
```

**`exportInventory()`**
- Returns: `String` - JSON string
- Description: Exports inventory as formatted JSON

```javascript
const json = window.ScriptIntegrityMonitor.exportInventory();
// Download or send to server
const blob = new Blob([json], { type: 'application/json' });
const url = URL.createObjectURL(blob);
```

**`destroy()`**
- Returns: `void`
- Description: Cleanup and stop monitoring

```javascript
window.ScriptIntegrityMonitor.destroy();
```

### Configuration Helper

**`SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()`**
- Returns: `Promise<Object>` - Map of script IDs to hashes
- Description: Generates hashes for all current page scripts

```javascript
await SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes();
// Console output:
// 'https://example.com/script.js': 'sha384-abc123...',
// 'inline-script-0': 'sha384-def456...',
```

---

## Compliance Guide

### PCI DSS 6.4.3 Compliance Checklist

#### ✅ Method to Confirm Script Authorization

- [ ] Baseline hashes configured for all scripts
- [ ] Whitelist configured for trusted sources (optional)
- [ ] Verification occurs on every page load
- [ ] Dynamic scripts are monitored

#### ✅ Method to Assure Script Integrity

- [ ] Cryptographic hashing (SHA-256 or SHA-384)
- [ ] Hash comparison on every script load
- [ ] SRI attributes validated when present
- [ ] Violations detected and logged

#### ✅ Script Inventory Maintenance

- [ ] Automated inventory tracking
- [ ] Timestamps for each script
- [ ] Written justification documented (in config)
- [ ] Regular inventory reviews scheduled

### Documentation Requirements

Maintain the following documentation for PCI DSS audits:

1. **Script Inventory**
   ```javascript
   // Generate and save regularly
   const inventory = window.ScriptIntegrityMonitor.exportInventory();
   // Save to file: script-inventory-YYYY-MM-DD.json
   ```

2. **Written Justification**
   - Document why each script is necessary
   - Include business justification
   - Note data access/functionality
   - Example in config file comments

3. **Change Management**
   - Log all script updates
   - Update baseline hashes
   - Document review and approval
   - Maintain audit trail

4. **Review Process**
   - Quarterly inventory reviews
   - Validation of justifications
   - Removal of unnecessary scripts
   - Hash updates for changed scripts

### Deployment Workflow

#### Phase 1: Testing (Report Mode)

```javascript
// Configuration
mode: 'report',
debug: true,
consoleAlerts: true
```

1. Deploy to staging environment
2. Generate baseline hashes
3. Test all user flows
4. Review violation logs
5. Adjust configuration as needed
6. Document all scripts

#### Phase 2: Production (Report Mode)

```javascript
// Configuration
mode: 'report',
debug: false,
alertEndpoint: 'https://yourdomain.com/api/violations'
```

1. Deploy to production
2. Monitor for 1-2 weeks
3. Review violations
4. Validate no false positives
5. Establish alert procedures

#### Phase 3: Enforcement

```javascript
// Configuration
mode: 'enforce',
debug: false
```

1. Enable enforce mode
2. Monitor closely for 24-48 hours
3. Have rollback plan ready
4. Establish incident response
5. Regular compliance reviews

---

## Troubleshooting

### Common Issues

#### Issue: "No baseline hash" violations for known scripts

**Cause**: Script hashes not configured

**Solution**:
```javascript
// Generate hashes
SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()

// Copy output to configuration
baselineHashes: {
  'https://example.com/script.js': 'sha384-...'
}
```

#### Issue: Hash mismatch for CDN scripts

**Cause**: CDN updated script version

**Solution**:
- Regenerate hash for updated script
- Consider using version-locked CDN URLs
- Example: `https://cdn.com/library@1.2.3/script.js`

#### Issue: Inline script hash keeps changing

**Cause**: Dynamic content in inline scripts

**Solution**:
- Move dynamic code to external file
- Use data attributes instead of inline scripts
- Add to whitelist (less secure)

#### Issue: Performance impact on page load

**Cause**: Large number of scripts or large script files

**Solution**:
```javascript
// Enable batch alerts
batchAlerts: true,
batchInterval: 5000
```

### Debug Mode

Enable detailed logging:

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  debug: true,
  consoleAlerts: true
};
```

View detailed logs in console:
- Script detection events
- Hash calculations
- Verification results
- Violation details

### Verification Testing

Test the monitor is working:

```javascript
// Add unauthorized script dynamically
const script = document.createElement('script');
script.src = 'https://unauthorized-domain.com/malicious.js';
document.head.appendChild(script);

// Check for violation
setTimeout(() => {
  const violations = window.ScriptIntegrityMonitor.getViolations();
  console.log('Violations:', violations);
}, 1000);
```

---

## Security Considerations

### Best Practices

1. **Use SHA-384**: Stronger than SHA-256, recommended for SRI
2. **HTTPS Only**: Only load scripts over HTTPS
3. **SRI Attributes**: Add integrity attributes to all external scripts
4. **CSP Headers**: Implement Content Security Policy
5. **Regular Updates**: Keep baseline hashes current
6. **Minimize Inline**: Avoid inline scripts when possible
7. **Whitelist Caution**: Use whitelists sparingly
8. **Alert Monitoring**: Set up real-time alerts
9. **Incident Response**: Have procedures for violations
10. **Regular Audits**: Review script inventory quarterly

### Content Security Policy (CSP)

Recommended CSP headers:

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://trusted-cdn.com;
  require-sri-for script;
  report-uri /api/csp-violations;
```

### Subresource Integrity (SRI)

Always include SRI attributes for external scripts:

```html
<script src="https://cdn.example.com/library.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

Generate SRI hash:
```bash
curl https://cdn.example.com/library.js | openssl dgst -sha384 -binary | openssl base64 -A
```

### Limitations

**Cross-Origin Scripts**:
- Cannot read content of cross-origin scripts without CORS
- Use SRI attributes as fallback verification
- Monitor via src URL matching

**Already-Executed Scripts**:
- Monitor detects but cannot prevent already-executed inline scripts
- Load monitor as first script to minimize gap
- Consider CSP for additional protection

**Dynamic eval/Function**:
- Cannot monitor code executed via eval() or Function()
- Avoid these patterns entirely
- CSP can block eval with `'unsafe-eval'` restriction

**Web Workers**:
- Separate context, not monitored by default
- Implement separate monitoring if workers used
- Consider worker-specific integrity checks

---

## Advanced Topics

### Custom Alert Handling

```javascript
alertCallback: function(alert) {
  // Send to SIEM
  if (window.splunk) {
    splunk.log({
      severity: alert.severity,
      event: 'script_violation',
      details: alert
    });
  }

  // Trigger incident response
  if (alert.severity === 'HIGH') {
    incidentResponse.create({
      type: 'security',
      category: 'script-integrity',
      alert: alert
    });
  }

  // Block user session (enforce mode)
  if (SCRIPT_INTEGRITY_CONFIG.mode === 'enforce') {
    // Optionally prevent form submission
    disablePaymentForms();
    showSecurityWarning();
  }
}
```

### Server-Side Alert Endpoint

Example Node.js/Express endpoint:

```javascript
const express = require('express');
const app = express();

app.post('/api/security/violations', express.json(), async (req, res) => {
  const alert = req.body;

  // Log to security system
  await securityLogger.log({
    level: 'error',
    type: 'script_integrity_violation',
    alert: alert,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
    timestamp: new Date()
  });

  // Send notification
  if (alert.severity === 'HIGH') {
    await notificationService.sendAlert({
      channel: 'security-team',
      message: `Script violation on ${req.hostname}`,
      details: alert
    });
  }

  // Store in database for audit
  await db.violations.create({
    ...alert,
    userAgent: req.headers['user-agent'],
    ip: req.ip
  });

  res.status(200).json({ received: true });
});
```

### Automated Compliance Reporting

```javascript
// Schedule daily compliance report
setInterval(() => {
  const report = window.ScriptIntegrityMonitor.generateReport();

  fetch('/api/compliance/daily-report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(report)
  });
}, 24 * 60 * 60 * 1000); // Daily
```

---

## Support and Maintenance

### Regular Maintenance Tasks

**Daily**:
- Monitor violation alerts
- Review security logs

**Weekly**:
- Check false positive rates
- Review new script additions

**Monthly**:
- Update baseline hashes for changed scripts
- Review script justifications
- Clean up obsolete scripts

**Quarterly**:
- Full compliance audit
- Documentation review
- Penetration testing
- Configuration review

### Version History

- **v1.0.0** (2025-11-11): Initial release
  - PCI DSS 6.4.3 compliance
  - SHA-256/SHA-384 support
  - Report and enforce modes
  - Comprehensive monitoring

---

## License

MIT License - See LICENSE file for details

---

## Additional Resources

- [PCI DSS v4.0 Requirements](https://www.pcisecuritystandards.org/)
- [Subresource Integrity (SRI) - MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [Content Security Policy - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Web Crypto API - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

---

**For questions or support, contact your security team.**
