/**
 * Script Integrity Monitor Configuration
 * PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * This configuration file defines:
 * 1. Baseline script hashes for authorized scripts
 * 2. Whitelisted sources for trusted CDNs and domains
 * 3. Monitoring and alerting settings
 * 4. Operational mode (enforce vs report-only)
 *
 * IMPORTANT: Load this configuration BEFORE the monitor script:
 * <script src="script-integrity-config.js"></script>
 * <script src="script-integrity-monitor.js"></script>
 *
 * @version 1.0.0
 */

(function() {
  'use strict';

  /**
   * Generate baseline hashes for your scripts:
   *
   * Method 1: Using OpenSSL (command line)
   * ----------------------------------------
   * SHA-384: cat script.js | openssl dgst -sha384 -binary | openssl base64 -A
   * SHA-256: cat script.js | openssl dgst -sha256 -binary | openssl base64 -A
   *
   * Method 2: Using browser console
   * --------------------------------
   * async function generateHash(url) {
   *   const response = await fetch(url);
   *   const content = await response.text();
   *   const encoder = new TextEncoder();
   *   const data = encoder.encode(content);
   *   const hashBuffer = await crypto.subtle.digest('SHA-384', data);
   *   const hashArray = Array.from(new Uint8Array(hashBuffer));
   *   const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));
   *   return 'sha384-' + hashBase64;
   * }
   * generateHash('https://example.com/script.js').then(console.log);
   *
   * Method 3: Using the monitor's built-in function (after page load)
   * ------------------------------------------------------------------
   * window.ScriptIntegrityMonitor.getInventory()
   *   .forEach(script => console.log(script.id, script.hash));
   */

  window.SCRIPT_INTEGRITY_CONFIG = {
    /**
     * Hash Algorithm
     * Options: 'SHA-256' or 'SHA-384'
     * SHA-384 is recommended for stronger security (used by default in SRI)
     */
    hashAlgorithm: 'SHA-384',

    /**
     * Monitoring Mode
     * - 'report': Only log violations (recommended for initial deployment)
     * - 'enforce': Attempt to block unauthorized scripts (use after testing)
     */
    mode: 'report',

    /**
     * Baseline Hashes
     * Map of script identifiers to their expected hash values
     * Format: { 'script-identifier': 'sha384-hash...' }
     *
     * For external scripts, use the full URL as the identifier
     * For inline scripts, use the format: 'inline-script-<index>-<timestamp>'
     *
     * Example entries:
     */
    baselineHashes: {
      // External scripts (CDN libraries)
      'https://cdn.example.com/jquery-3.6.0.min.js': 'sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK',
      'https://cdn.example.com/bootstrap.min.js': 'sha384-cn7l7gDp0eyniUwwAZgrzD06kc/tftFf19TOAs2zVinnD/C7E91j9yyk5//jjpt/',

      // Your application scripts
      'https://yourdomain.com/js/app.js': 'sha384-REPLACE_WITH_ACTUAL_HASH',
      'https://yourdomain.com/js/payment.js': 'sha384-REPLACE_WITH_ACTUAL_HASH',
      'https://yourdomain.com/js/checkout.js': 'sha384-REPLACE_WITH_ACTUAL_HASH',

      // Inline scripts (if you have authorized inline scripts)
      // Note: These are harder to track - consider moving to external files
      // 'inline-script-0': 'sha384-...'
    },

    /**
     * Whitelisted Sources
     * Array of trusted domains/patterns that are allowed without hash verification
     * Use RegExp for pattern matching
     *
     * WARNING: Use whitelist cautiously - hash verification is more secure
     * Only whitelist sources you completely trust (e.g., your own CDN)
     */
    whitelistedSources: [
      // Example: Allow all scripts from your domain
      /^https:\/\/yourdomain\.com\//,

      // Example: Allow specific trusted CDN
      // /^https:\/\/cdn\.jsdelivr\.net\//,

      // Example: Allow localhost for development
      /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//
    ],

    /**
     * Monitoring Options
     * Enable/disable monitoring for different script types
     */
    monitorInlineScripts: true,      // Monitor <script>inline code</script>
    monitorExternalScripts: true,    // Monitor <script src="..."></script>
    monitorDynamicScripts: true,     // Monitor scripts added via JavaScript
    monitorIframes: true,            // Monitor scripts within iframes (same-origin only)

    /**
     * Alert Configuration
     * Configure how and where to send integrity violation alerts
     */

    // API endpoint for receiving alerts (POST requests)
    // The monitor will send JSON payload with violation details
    alertEndpoint: null, // Example: 'https://yourdomain.com/api/security/script-violations'

    /**
     * Server Endpoints Configuration
     * Configure endpoints for auto-discovery and approval workflow
     */

    // Base URL for API endpoints
    // Auto-detect: Uses window.location.origin if running on same domain as server
    // Manual: Set to 'https://yourdomain.com' for different domain
    serverBaseUrl: (function() {
      // Auto-detect if running on localhost or has /api endpoint
      if (window.location.hostname === 'localhost' ||
          window.location.hostname === '127.0.0.1' ||
          window.location.port === '3000') {
        return window.location.origin;
      }
      // For production, uncomment and set your domain:
      // return 'https://yourdomain.com';
      return null;
    })(),

    // Auto-registration endpoint for newly discovered scripts
    registerScriptEndpoint: '/api/scripts/register',

    // Check script approval status endpoint
    checkStatusEndpoint: '/api/scripts/status',

    // Report integrity violation endpoint
    reportViolationEndpoint: '/api/scripts/violation',

    // Auto-registration mode
    autoRegisterNewScripts: true,           // Automatically register new scripts with server

    // Polling configuration for approval status
    pollApprovalStatus: true,               // Poll server for approval status updates
    pollInterval: 30000,                    // Poll every 30 seconds (30000ms)
    pollTimeout: 300000,                    // Stop polling after 5 minutes (300000ms)

    // Behavior when server is unreachable
    fallbackMode: 'report',                 // 'report' or 'block' when server unavailable
    serverTimeoutMs: 5000,                  // Timeout for server requests

    // Custom callback function for handling alerts
    // Receives alert object as parameter
    alertCallback: function(alert) {
      // Example: Send to your analytics/monitoring service
      // if (window.analytics) {
      //   window.analytics.track('Script Integrity Violation', alert);
      // }

      // Example: Send to Sentry
      // if (window.Sentry) {
      //   window.Sentry.captureMessage('Script Integrity Violation', {
      //     level: 'error',
      //     extra: alert
      //   });
      // }

      // Example: Display user notification (be careful with UX)
      // if (alert.severity === 'HIGH') {
      //   console.error('Security Alert:', alert.message);
      // }
    },

    // Log alerts to browser console
    consoleAlerts: true,

    // Batch multiple alerts together (reduces alert noise)
    batchAlerts: false,
    batchInterval: 5000, // milliseconds (only used if batchAlerts is true)

    /**
     * Debug Mode
     * Enable verbose logging for troubleshooting
     * Set to false in production
     */
    debug: true, // Set to false in production

    /**
     * Additional Configuration Options
     */

    // Environment-specific settings
    environment: 'development', // 'development', 'staging', 'production'

    // PCI DSS compliance metadata
    pciDss: {
      requirement: '6.4.3',
      description: 'Script management on payment pages',
      version: '4.0',
      lastReviewDate: '2025-11-11',
      reviewer: 'Security Team'
    }
  };

  /**
   * Environment-specific configuration overrides
   * Adjust settings based on environment
   */
  (function applyEnvironmentConfig() {
    const config = window.SCRIPT_INTEGRITY_CONFIG;
    const hostname = window.location.hostname;

    // Production environment
    if (hostname === 'yourdomain.com' || hostname === 'www.yourdomain.com') {
      config.environment = 'production';
      config.debug = false;
      config.mode = 'enforce'; // Enable enforcement in production after testing
      config.serverBaseUrl = 'https://yourdomain.com';
      config.alertEndpoint = 'https://yourdomain.com/api/security/script-violations';
    }

    // Staging environment
    else if (hostname === 'staging.yourdomain.com') {
      config.environment = 'staging';
      config.debug = true;
      config.mode = 'report';
      config.serverBaseUrl = 'https://staging.yourdomain.com';
      config.alertEndpoint = 'https://staging.yourdomain.com/api/security/script-violations';
    }

    // Development/localhost
    else {
      config.environment = 'development';
      config.debug = true;
      config.mode = 'report';
      config.serverBaseUrl = 'http://localhost:3000';
      config.alertEndpoint = null; // Use serverBaseUrl endpoints in development
    }

    console.info('[SIM Config] Environment:', config.environment);
  })();

  /**
   * Configuration validation
   * Validates the configuration and provides warnings
   */
  (function validateConfiguration() {
    const config = window.SCRIPT_INTEGRITY_CONFIG;
    const warnings = [];

    // Check if baseline hashes are configured
    if (Object.keys(config.baselineHashes).length === 0) {
      warnings.push('No baseline hashes configured - all scripts will be unauthorized');
    }

    // Check hash algorithm
    if (!['SHA-256', 'SHA-384'].includes(config.hashAlgorithm)) {
      warnings.push('Invalid hash algorithm - must be SHA-256 or SHA-384');
    }

    // Check mode
    if (!['report', 'enforce'].includes(config.mode)) {
      warnings.push('Invalid mode - must be "report" or "enforce"');
    }

    // Warn if enforce mode is enabled without proper testing
    if (config.mode === 'enforce' && config.environment === 'production') {
      console.warn('[SIM Config] WARNING: Enforce mode is enabled in production - ensure thorough testing');
    }

    // Display warnings
    if (warnings.length > 0) {
      console.warn('[SIM Config] Configuration warnings:');
      warnings.forEach(warning => console.warn(`  - ${warning}`));
    }
  })();

  /**
   * Helper function to generate baseline hashes for current page scripts
   * Call this function in browser console to generate hashes for your scripts:
   *
   * Usage:
   * ------
   * SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()
   *
   * Copy the output and add to your baselineHashes configuration
   */
  window.SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes = async function() {
    console.log('Generating baseline hashes for all scripts on current page...');
    console.log('Please wait...\n');

    const scripts = document.querySelectorAll('script');
    const hashes = {};

    for (let i = 0; i < scripts.length; i++) {
      const script = scripts[i];
      let content = '';
      let identifier = '';

      try {
        if (script.src) {
          // External script
          identifier = script.src;
          const response = await fetch(script.src);
          content = await response.text();
        } else {
          // Inline script
          identifier = `inline-script-${i}`;
          content = script.textContent || script.innerHTML;
        }

        if (content) {
          const encoder = new TextEncoder();
          const data = encoder.encode(content);
          const hashBuffer = await crypto.subtle.digest('SHA-384', data);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));
          const hash = 'sha384-' + hashBase64;

          hashes[identifier] = hash;
          console.log(`'${identifier}': '${hash}',`);
        }
      } catch (error) {
        console.error(`Error processing script ${identifier}:`, error.message);
      }
    }

    console.log('\nCopy the above lines to your baselineHashes configuration.');
    console.log('Total scripts processed:', Object.keys(hashes).length);

    return hashes;
  };

})();

/**
 * DEPLOYMENT CHECKLIST
 * ====================
 *
 * Before deploying to production:
 *
 * 1. Generate Baseline Hashes
 *    - Load your payment pages in a browser
 *    - Open developer console
 *    - Run: SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()
 *    - Copy the output to baselineHashes configuration
 *
 * 2. Configure Alert Endpoint
 *    - Set up a secure API endpoint to receive violation alerts
 *    - Implement proper authentication and logging
 *    - Configure alertEndpoint with your endpoint URL
 *
 * 3. Test in Report Mode
 *    - Deploy with mode: 'report' first
 *    - Monitor alerts and logs for false positives
 *    - Adjust whitelist and baseline hashes as needed
 *    - Test all user flows and payment scenarios
 *
 * 4. Update Regularly
 *    - When updating scripts, regenerate baseline hashes
 *    - Document all authorized script changes
 *    - Maintain inventory of all scripts (PCI DSS requirement)
 *
 * 5. Enable Enforce Mode
 *    - After thorough testing, switch to mode: 'enforce'
 *    - Monitor closely for the first 24-48 hours
 *    - Have rollback plan ready
 *
 * 6. PCI DSS Documentation
 *    - Maintain written justification for each script
 *    - Document script functionality and business necessity
 *    - Keep audit trail of all script changes
 *    - Regular compliance reviews
 *
 * 7. Monitoring and Alerting
 *    - Set up real-time alerts for violations
 *    - Integrate with SIEM or security monitoring tools
 *    - Establish incident response procedures
 *    - Regular review of violation logs
 *
 * INTEGRATION EXAMPLES
 * ====================
 *
 * HTML Integration:
 * -----------------
 * <!DOCTYPE html>
 * <html>
 * <head>
 *   <meta charset="UTF-8">
 *   <title>Payment Page</title>
 *
 *   <!-- CRITICAL: Load configuration FIRST -->
 *   <script src="/js/script-integrity-config.js"></script>
 *
 *   <!-- CRITICAL: Load monitor SECOND (before any other scripts) -->
 *   <script src="/js/script-integrity-monitor.js"></script>
 *
 *   <!-- Now load other scripts - they will be monitored -->
 *   <script src="https://cdn.example.com/jquery.min.js"
 *           integrity="sha384-..."
 *           crossorigin="anonymous"></script>
 * </head>
 * <body>
 *   <!-- Your payment page content -->
 * </body>
 * </html>
 *
 * API Endpoint Example (Node.js/Express):
 * ----------------------------------------
 * app.post('/api/security/script-violations', express.json(), (req, res) => {
 *   const alert = req.body;
 *
 *   // Log to security monitoring system
 *   securityLogger.error('Script integrity violation', {
 *     severity: alert.severity,
 *     violation: alert.violation,
 *     userAgent: req.headers['user-agent'],
 *     ip: req.ip,
 *     timestamp: new Date()
 *   });
 *
 *   // Trigger incident response if critical
 *   if (alert.severity === 'HIGH') {
 *     incidentResponse.trigger('script-integrity-violation', alert);
 *   }
 *
 *   res.status(200).json({ received: true });
 * });
 *
 * Accessing Reports via JavaScript:
 * ----------------------------------
 * // Get current script inventory
 * const inventory = window.ScriptIntegrityMonitor.getInventory();
 * console.log('Total scripts:', inventory.length);
 *
 * // Get all violations
 * const violations = window.ScriptIntegrityMonitor.getViolations();
 * console.log('Violations:', violations);
 *
 * // Generate PCI DSS compliance report
 * const report = window.ScriptIntegrityMonitor.generateReport();
 * console.log(report);
 *
 * // Export inventory as JSON
 * const json = window.ScriptIntegrityMonitor.exportInventory();
 * // Send to server or download
 */
