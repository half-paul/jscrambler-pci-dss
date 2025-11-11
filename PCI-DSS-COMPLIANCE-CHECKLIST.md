# PCI DSS v4.0 Requirement 6.4.3 Compliance Checklist
## Script Integrity Monitoring Implementation

Use this checklist to ensure full compliance with PCI DSS v4.0 requirement 6.4.3.

---

## Overview

**PCI DSS v4.0 Requirement 6.4.3** states:

> All payment page scripts that are loaded and executed in the consumer's browser are managed as follows:
> - A method is implemented to confirm that each script is authorized
> - A method is implemented to assure the integrity of each script
> - An inventory of all scripts is maintained with written justification as to why each is necessary

---

## Phase 1: Initial Setup

### 1.1 File Deployment
- [ ] `script-integrity-config.js` deployed to web server
- [ ] `script-integrity-monitor.js` deployed to web server
- [ ] Files are accessible via HTTPS only (not HTTP)
- [ ] Files have proper cache headers configured
- [ ] Files are served with correct Content-Type (text/javascript)

### 1.2 HTML Integration
- [ ] Configuration script loaded FIRST in HTML `<head>`
- [ ] Monitor script loaded SECOND (before any other scripts)
- [ ] Script tags are in correct order on all payment pages
- [ ] No scripts load before the monitor
- [ ] Verified on all payment page templates

### 1.3 Configuration
- [ ] `hashAlgorithm` set to 'SHA-384' (recommended) or 'SHA-256'
- [ ] `mode` initially set to 'report' for testing
- [ ] `consoleAlerts` enabled during testing
- [ ] `debug` enabled during initial setup
- [ ] Environment-specific settings configured

---

## Phase 2: Script Inventory

### 2.1 Script Discovery
- [ ] Generated list of all scripts on payment pages
- [ ] Identified all external scripts (CDN, third-party)
- [ ] Identified all inline scripts
- [ ] Identified all dynamically loaded scripts
- [ ] Checked scripts in iframes (if applicable)
- [ ] Documented script load sequence

### 2.2 Baseline Hash Generation
- [ ] Generated SHA-384 hashes for all external scripts
- [ ] Generated SHA-384 hashes for all inline scripts
- [ ] Verified hash format (sha384-base64string)
- [ ] Hashes added to `baselineHashes` in config
- [ ] Used consistent method (browser console or CLI)
- [ ] Documented hash generation date

**Hash Generation Command Reference:**
```bash
# Using OpenSSL
cat script.js | openssl dgst -sha384 -binary | openssl base64 -A

# Using browser console
SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()
```

### 2.3 Written Justification (PCI DSS Required)
- [ ] Documented purpose of each script
- [ ] Documented business justification for each script
- [ ] Documented what data each script accesses
- [ ] Documented script vendor/source
- [ ] Documented who authorized each script
- [ ] Documented review date
- [ ] Stored documentation securely

**Example Justification Template:**
```
Script: https://cdn.example.com/payment-form.js
Purpose: Payment form validation and formatting
Business Need: Required for PCI-compliant payment processing
Data Access: Card number formatting (no storage)
Vendor: Example Payment Gateway
Authorized By: Security Team, 2025-11-11
Review Date: 2025-11-11
Hash: sha384-abc123...
```

---

## Phase 3: Testing

### 3.1 Functional Testing
- [ ] Opened `test-script-integrity.html` in browser
- [ ] All 10 tests pass
- [ ] Monitor initializes without errors
- [ ] Scripts are detected and inventoried
- [ ] Hashes are calculated correctly
- [ ] Configuration loads properly
- [ ] API methods work correctly

### 3.2 Integration Testing
- [ ] Tested on all payment pages
- [ ] Tested with all supported browsers (Chrome, Firefox, Safari, Edge)
- [ ] Tested on mobile devices
- [ ] Tested all payment flows (checkout, subscription, etc.)
- [ ] Tested with browser developer tools open
- [ ] No console errors or warnings (except expected violations)

### 3.3 Violation Detection Testing
- [ ] Tested unauthorized script detection
- [ ] Tested hash mismatch detection
- [ ] Tested dynamic script addition
- [ ] Violations are logged correctly
- [ ] Console alerts appear for violations
- [ ] Verified violation details are accurate

### 3.4 Performance Testing
- [ ] Page load time impact measured (should be minimal)
- [ ] No blocking of page rendering
- [ ] Hash calculation completes quickly
- [ ] MutationObserver performance acceptable
- [ ] Memory usage is reasonable
- [ ] No performance issues under load

---

## Phase 4: Alert Configuration

### 4.1 Backend Setup
- [ ] Alert endpoint implemented (`server-alert-handler.js` or custom)
- [ ] Endpoint accepts POST requests
- [ ] Endpoint validates alert data
- [ ] Endpoint logs violations to security system
- [ ] Endpoint stores violations in database
- [ ] Endpoint has proper error handling
- [ ] Endpoint has rate limiting configured
- [ ] Endpoint requires authentication (recommended)

### 4.2 Alert Testing
- [ ] `alertEndpoint` configured in config file
- [ ] Test alert sent successfully
- [ ] Alert appears in security logs
- [ ] Alert stored in database
- [ ] Alert format is correct
- [ ] Alert contains all required metadata
- [ ] Tested alert for violation scenarios

### 4.3 Notification Setup
- [ ] Email notifications configured (for HIGH severity)
- [ ] Slack/Teams notifications configured (optional)
- [ ] SIEM integration configured (recommended)
- [ ] PagerDuty integration configured (for CRITICAL)
- [ ] On-call team notified of alert setup
- [ ] Tested notification delivery

---

## Phase 5: Staging Deployment

### 5.1 Pre-Deployment
- [ ] All baseline hashes configured
- [ ] Configuration reviewed by security team
- [ ] Documentation complete
- [ ] Rollback plan prepared
- [ ] Monitoring dashboard prepared

### 5.2 Staging Deployment
- [ ] Deployed to staging environment
- [ ] Mode set to 'report'
- [ ] Debug enabled
- [ ] Alert endpoint configured
- [ ] Verified initialization on staging
- [ ] Tested all payment flows on staging

### 5.3 Staging Validation
- [ ] Monitored for 1 week minimum
- [ ] Reviewed all violations
- [ ] Resolved false positives
- [ ] Updated baseline hashes as needed
- [ ] Updated whitelist if necessary
- [ ] No unexpected issues
- [ ] Performance acceptable

---

## Phase 6: Production Deployment (Report Mode)

### 6.1 Pre-Production
- [ ] Staging testing complete
- [ ] All false positives resolved
- [ ] Change request approved
- [ ] Deployment window scheduled
- [ ] Stakeholders notified
- [ ] Rollback plan confirmed

### 6.2 Production Deployment
- [ ] Deployed to production
- [ ] Mode set to 'report' (not 'enforce' yet)
- [ ] Debug disabled
- [ ] Console alerts disabled or minimized
- [ ] Alert endpoint production URL configured
- [ ] Verified deployment successful

### 6.3 Production Monitoring (Report Mode)
- [ ] Monitored for 2 weeks minimum
- [ ] Reviewed daily violation reports
- [ ] Analyzed violation patterns
- [ ] Resolved any false positives
- [ ] Updated configuration as needed
- [ ] No business impact from monitoring
- [ ] Performance metrics acceptable

---

## Phase 7: Enforcement Mode

### 7.1 Pre-Enforcement
- [ ] Report mode monitoring complete (2+ weeks)
- [ ] Zero false positives
- [ ] Team trained on violation response
- [ ] Incident response procedures documented
- [ ] Rollback procedure tested
- [ ] Change request for enforcement approved

### 7.2 Enable Enforcement
- [ ] Updated config to `mode: 'enforce'`
- [ ] Deployed configuration change
- [ ] Verified enforcement active
- [ ] Monitored closely for 24 hours
- [ ] No legitimate scripts blocked
- [ ] No customer impact

### 7.3 Post-Enforcement Validation
- [ ] Monitored for 1 week intensively
- [ ] Reviewed all blocked scripts
- [ ] Confirmed legitimate blocks only
- [ ] No customer complaints
- [ ] Business operations normal
- [ ] Performance metrics unchanged

---

## Phase 8: Operational Procedures

### 8.1 Daily Operations
- [ ] Monitor violation dashboard
- [ ] Review new violations
- [ ] Investigate unauthorized scripts
- [ ] Update incident tracking
- [ ] Respond to alerts within SLA

### 8.2 Weekly Maintenance
- [ ] Review violation trends
- [ ] Check for new scripts
- [ ] Verify monitoring health
- [ ] Update documentation if needed
- [ ] Team sync on any issues

### 8.3 Monthly Reviews
- [ ] Generate compliance report
- [ ] Review script inventory
- [ ] Validate all justifications still current
- [ ] Check for obsolete scripts
- [ ] Update baseline hashes for changed scripts
- [ ] Review and update whitelist
- [ ] Performance review

### 8.4 Quarterly Audits
- [ ] Full script inventory audit
- [ ] Validate written justifications
- [ ] Review authorization for all scripts
- [ ] Remove unnecessary scripts
- [ ] Update all documentation
- [ ] Security team review
- [ ] Compliance team review

---

## Phase 9: Change Management

### 9.1 Adding New Script
- [ ] Business justification documented
- [ ] Security review completed
- [ ] Script source verified
- [ ] Generate baseline hash
- [ ] Add to configuration
- [ ] Update documentation
- [ ] Test in staging
- [ ] Deploy to production
- [ ] Verify monitoring

### 9.2 Updating Existing Script
- [ ] Change documented
- [ ] Security review if needed
- [ ] Generate new baseline hash
- [ ] Update configuration
- [ ] Update documentation
- [ ] Test in staging
- [ ] Deploy to production
- [ ] Verify new hash

### 9.3 Removing Script
- [ ] Removal justified and documented
- [ ] Remove from baseline hashes
- [ ] Update documentation
- [ ] Test in staging
- [ ] Deploy to production
- [ ] Verify removal

---

## Phase 10: PCI DSS Documentation

### 10.1 Script Inventory
- [ ] Complete list of all scripts
- [ ] Script sources documented
- [ ] Script purposes documented
- [ ] Business justifications documented
- [ ] Baseline hashes recorded
- [ ] Authorization documented
- [ ] Review dates recorded
- [ ] Inventory stored securely
- [ ] Inventory updated regularly

**Export Inventory:**
```javascript
const inventory = window.ScriptIntegrityMonitor.exportInventory();
// Save as: script-inventory-YYYY-MM-DD.json
```

### 10.2 Method Documentation - Authorization
- [ ] Documented how scripts are authorized
- [ ] Baseline hash verification process documented
- [ ] Whitelist validation process documented
- [ ] Authorization workflow documented
- [ ] Escalation procedure documented

### 10.3 Method Documentation - Integrity
- [ ] Documented hash algorithm (SHA-384)
- [ ] Hash calculation process documented
- [ ] Hash comparison process documented
- [ ] Integrity verification workflow documented
- [ ] Violation detection process documented

### 10.4 Audit Trail
- [ ] All script changes logged
- [ ] All violations logged
- [ ] All configuration changes logged
- [ ] Logs stored securely
- [ ] Logs retained per policy
- [ ] Logs available for audit

### 10.5 Procedures
- [ ] Violation response procedure documented
- [ ] Script change procedure documented
- [ ] Emergency response procedure documented
- [ ] Audit procedure documented
- [ ] Training materials created

---

## Phase 11: Incident Response

### 11.1 Violation Response Plan
- [ ] Violation severity levels defined
- [ ] Response procedures for each severity
- [ ] Escalation paths defined
- [ ] Communication plan established
- [ ] Containment procedures defined
- [ ] Investigation procedures defined
- [ ] Resolution procedures defined

### 11.2 Response Procedures
**For HIGH/CRITICAL Violations:**
- [ ] Immediate notification to security team
- [ ] Incident created in tracking system
- [ ] Affected pages identified
- [ ] Investigation initiated
- [ ] Containment actions taken
- [ ] Root cause analysis performed
- [ ] Resolution implemented
- [ ] Post-incident review completed

### 11.3 Communication
- [ ] Security team contact list
- [ ] Escalation contact list
- [ ] Stakeholder notification list
- [ ] Customer communication plan
- [ ] Regulator notification plan (if needed)

---

## Phase 12: Training

### 12.1 Team Training
- [ ] Security team trained on monitor
- [ ] Development team trained on adding scripts
- [ ] Operations team trained on monitoring
- [ ] Incident response team trained
- [ ] Management briefed on compliance

### 12.2 Documentation
- [ ] User guide created
- [ ] Operations runbook created
- [ ] Troubleshooting guide created
- [ ] FAQ document created
- [ ] Training materials available

---

## Phase 13: Continuous Compliance

### 13.1 Regular Activities
- [ ] Daily monitoring
- [ ] Weekly reviews
- [ ] Monthly reports
- [ ] Quarterly audits
- [ ] Annual security reviews

### 13.2 Compliance Verification
- [ ] All three requirements met:
  - [ ] Method to confirm authorization (baseline hashes)
  - [ ] Method to assure integrity (SHA-384 verification)
  - [ ] Inventory maintained (automated + documented)
- [ ] Documentation current
- [ ] Procedures followed
- [ ] Violations addressed
- [ ] Audit trail complete

### 13.3 Metrics
- [ ] Total scripts monitored
- [ ] Authorized vs unauthorized
- [ ] Violations detected
- [ ] Mean time to detection (MTTD)
- [ ] Mean time to response (MTTR)
- [ ] False positive rate
- [ ] Compliance status

---

## Compliance Evidence for Auditors

### Required Evidence

1. **Method for Authorization**
   - Configuration file showing `baselineHashes`
   - Whitelist configuration
   - Authorization workflow documentation
   - Proof of hash verification process

2. **Method for Integrity**
   - Monitor source code
   - Hash algorithm documentation (SHA-384)
   - Verification process documentation
   - Violation detection examples

3. **Script Inventory**
   - Exported inventory JSON file
   - Written justification for each script
   - Authorization records
   - Review history

4. **Operational Evidence**
   - Violation logs
   - Response records
   - Change management records
   - Audit reports
   - Training records

---

## Final Compliance Checklist

### Core Requirements
- [x] Script Integrity Monitor implemented
- [ ] All payment pages protected
- [ ] Configuration complete with baseline hashes
- [ ] Written justification for all scripts
- [ ] Authorization method documented
- [ ] Integrity verification method documented
- [ ] Complete script inventory maintained
- [ ] Violation detection working
- [ ] Alert system operational
- [ ] Incident response procedures established
- [ ] Team trained
- [ ] Documentation complete
- [ ] Regular reviews scheduled

### Ongoing Compliance
- [ ] Daily monitoring active
- [ ] Violations reviewed promptly
- [ ] Inventory updated regularly
- [ ] Quarterly audits scheduled
- [ ] Documentation maintained
- [ ] Training current
- [ ] Procedures followed

---

## Sign-Off

### Implementation Sign-Off

```
Project: Script Integrity Monitoring - PCI DSS 6.4.3
Implementation Date: _______________

Security Team: _________________ Date: _______
Development Team: ______________ Date: _______
Compliance Team: _______________ Date: _______
Management: ___________________ Date: _______
```

### Quarterly Review Sign-Off

```
Review Period: Q___ 20___
Review Date: _______________

All requirements verified: [ ] Yes [ ] No
Script inventory current: [ ] Yes [ ] No
Documentation current: [ ] Yes [ ] No
Violations addressed: [ ] Yes [ ] No
Compliance status: [ ] Compliant [ ] Non-compliant

Reviewer: _____________________ Date: _______
Security Lead: ________________ Date: _______
```

---

## Quick Reference

### Daily Checklist
- [ ] Check violation dashboard
- [ ] Review new alerts
- [ ] Investigate anomalies

### Weekly Checklist
- [ ] Review violation trends
- [ ] Verify monitoring health
- [ ] Update documentation

### Monthly Checklist
- [ ] Generate compliance report
- [ ] Review script inventory
- [ ] Update baseline hashes

### Quarterly Checklist
- [ ] Full inventory audit
- [ ] Security review
- [ ] Compliance verification
- [ ] Documentation update

---

**Status**: [ ] Not Started [ ] In Progress [ ] Testing [ ] Deployed [ ] Compliant

**Last Updated**: _______________

**Next Review**: _______________
