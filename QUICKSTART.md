# Quick Start Guide
## Script Integrity Monitor - PCI DSS 6.4.3

Get up and running in 5 minutes!

---

## Step 1: Files Overview

You should have these files:

```
script-integrity-monitor.js       - Main monitoring script (load first!)
script-integrity-config.js        - Configuration with baseline hashes
example-payment-page.html         - Example payment page implementation
test-script-integrity.html        - Test suite for validation
server-alert-handler.js           - Backend alert handler (Node.js)
package.json                      - Dependencies for server
README-SCRIPT-INTEGRITY.md        - Complete documentation
```

---

## Step 2: Basic HTML Setup

Add to your payment page HTML (CRITICAL: order matters!):

```html
<!DOCTYPE html>
<html>
<head>
  <!-- 1. Configuration FIRST -->
  <script src="/js/script-integrity-config.js"></script>

  <!-- 2. Monitor SECOND -->
  <script src="/js/script-integrity-monitor.js"></script>

  <!-- 3. Other scripts (will be monitored) -->
  <script src="/js/app.js"></script>
</head>
<body>
  <!-- Your content -->
</body>
</html>
```

---

## Step 3: Generate Baseline Hashes

### Method A: Using Browser Console (Easiest)

1. Load your payment page in a browser
2. Open Developer Console (F12)
3. Run:
   ```javascript
   SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()
   ```
4. Copy the output

### Method B: Using Command Line

```bash
# SHA-384 (recommended)
cat your-script.js | openssl dgst -sha384 -binary | openssl base64 -A

# SHA-256
cat your-script.js | openssl dgst -sha256 -binary | openssl base64 -A
```

---

## Step 4: Configure Baseline Hashes

Edit `script-integrity-config.js`:

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  hashAlgorithm: 'SHA-384',
  mode: 'report', // Start with 'report', switch to 'enforce' after testing

  baselineHashes: {
    // ADD YOUR HASHES HERE (from Step 3)
    'https://yourdomain.com/js/app.js': 'sha384-abc123...',
    'https://yourdomain.com/js/payment.js': 'sha384-def456...',
    // ... etc
  },

  alertEndpoint: null, // Set to your endpoint: 'https://yourdomain.com/api/violations'
  consoleAlerts: true,
  debug: true // Set to false in production
};
```

---

## Step 5: Test the Monitor

### Option A: Open Test Page

1. Open `test-script-integrity.html` in a browser
2. Click "Run All Tests"
3. Verify all tests pass
4. Click "Test Violation" to see violation detection

### Option B: Check Your Payment Page

1. Open your payment page in a browser
2. Open Developer Console
3. Check for initialization message:
   ```
   [SIM] Initializing Script Integrity Monitor
   ```
4. View inventory:
   ```javascript
   window.ScriptIntegrityMonitor.getInventory()
   ```
5. Check summary:
   ```javascript
   window.ScriptIntegrityMonitor.getSummary()
   ```

---

## Step 6: Review Results

### Check for Violations

```javascript
// Get all violations
const violations = window.ScriptIntegrityMonitor.getViolations();
console.log('Violations:', violations);

// Generate full report
const report = window.ScriptIntegrityMonitor.generateReport();
console.log('Report:', report);
```

### Expected Results (Initial Setup)

If you see violations with type `NO_BASELINE_HASH`:
- ✅ **Good!** Monitor is working
- 📝 Add those scripts to your `baselineHashes` config

If all scripts are authorized:
- ✅ **Perfect!** You're ready for production

---

## Step 7: Set Up Backend (Optional but Recommended)

### Install Dependencies

```bash
npm install
```

### Start Alert Handler

```bash
npm start
# Server runs on http://localhost:3000
```

### Update Config

```javascript
// In script-integrity-config.js
alertEndpoint: 'http://localhost:3000/api/security/script-violations'
```

---

## Step 8: Production Deployment

### Pre-Deployment Checklist

- [ ] All baseline hashes configured
- [ ] Tested in report mode for 1-2 weeks
- [ ] No false positives detected
- [ ] Alert endpoint configured
- [ ] Monitoring dashboard set up
- [ ] Incident response procedures documented
- [ ] Debug mode disabled

### Production Config

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  hashAlgorithm: 'SHA-384',
  mode: 'enforce', // Switch to enforce after thorough testing
  baselineHashes: { /* all your hashes */ },
  alertEndpoint: 'https://yourdomain.com/api/security/violations',
  consoleAlerts: false, // Disable console logs in production
  debug: false
};
```

### Deploy Steps

1. **Deploy to Staging**
   - Mode: `'report'`
   - Debug: `true`
   - Test all user flows

2. **Deploy to Production (Report Mode)**
   - Mode: `'report'`
   - Debug: `false`
   - Monitor for 1-2 weeks
   - Review violations

3. **Enable Enforcement**
   - Mode: `'enforce'`
   - Monitor closely for 24-48 hours
   - Have rollback plan ready

---

## Common Commands

```javascript
// View all detected scripts
window.ScriptIntegrityMonitor.getInventory()

// View violations
window.ScriptIntegrityMonitor.getViolations()

// Get summary statistics
window.ScriptIntegrityMonitor.getSummary()

// Generate PCI DSS compliance report
window.ScriptIntegrityMonitor.generateReport()

// Export as JSON
window.ScriptIntegrityMonitor.exportInventory()

// Regenerate baseline hashes
SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()
```

---

## Troubleshooting

### Issue: "No baseline hash" for all scripts

**Solution**: Generate and add baseline hashes to config (Step 3-4)

### Issue: Hash mismatch for CDN scripts

**Solution**: CDN may have updated. Regenerate hash or use version-locked URLs

### Issue: Monitor not loading

**Solution**:
1. Check script order (config → monitor → other scripts)
2. Check browser console for errors
3. Verify files are accessible

### Issue: Performance problems

**Solution**: Enable batch alerts in config:
```javascript
batchAlerts: true,
batchInterval: 5000
```

---

## Quick Example: Complete Setup

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Payment Page</title>

  <!-- Script Integrity Monitor -->
  <script>
    window.SCRIPT_INTEGRITY_CONFIG = {
      hashAlgorithm: 'SHA-384',
      mode: 'report',
      baselineHashes: {
        'https://code.jquery.com/jquery-3.7.1.min.js':
          'sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs',
        'https://yourdomain.com/js/app.js':
          'sha384-YOUR_HASH_HERE'
      },
      alertEndpoint: 'https://yourdomain.com/api/violations',
      consoleAlerts: true,
      debug: true
    };
  </script>
  <script src="/js/script-integrity-monitor.js"></script>

  <!-- Your scripts (monitored) -->
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"
          integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs"
          crossorigin="anonymous"></script>
  <script src="/js/app.js"></script>
</head>
<body>
  <h1>Payment Page</h1>
  <!-- Your content -->
</body>
</html>
```

---

## PCI DSS Compliance

### Required Documentation

For PCI DSS 6.4.3 compliance, maintain:

1. **Script Inventory**
   ```javascript
   // Export regularly
   const json = window.ScriptIntegrityMonitor.exportInventory();
   // Save as: script-inventory-YYYY-MM-DD.json
   ```

2. **Written Justification**
   - Document why each script is necessary
   - Include business justification
   - Keep in configuration comments

3. **Change Log**
   - Log all script updates
   - Update baseline hashes
   - Document review and approval

4. **Review Schedule**
   - Quarterly inventory reviews
   - Validation of justifications
   - Hash updates for changed scripts

---

## Next Steps

1. ✅ Complete basic setup (Steps 1-5)
2. ✅ Generate baseline hashes
3. ✅ Test thoroughly
4. ✅ Set up backend alert handler
5. ✅ Deploy to staging
6. ✅ Monitor and adjust
7. ✅ Deploy to production
8. ✅ Enable enforcement mode
9. ✅ Maintain documentation

---

## Support

- 📖 Full documentation: `README-SCRIPT-INTEGRITY.md`
- 🧪 Test suite: `test-script-integrity.html`
- 💡 Example: `example-payment-page.html`

---

**Ready to go? Load `example-payment-page.html` or `test-script-integrity.html` in your browser to see it in action!**
