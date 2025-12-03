# PCI DSS v4.0.1 Requirement 11.6.1 Compliance Gap Analysis

**Date:** 2025-01-20
**Requirement:** 11.6.1 - Tamper/Change Detection on Payment Pages (TRA)
**Current Status:** ⚠️ PARTIALLY COMPLIANT

---

## Executive Summary

The Script Integrity Monitor application provides **strong script-level protection** but has **significant gaps** in meeting the full requirements of PCI DSS v4.0.1 section 11.6.1. The application excels at script monitoring but lacks HTTP header monitoring, payment form integrity checks, and network request monitoring.

**Compliance Score:** 60% (3 of 5 required components implemented)

---

## PCI DSS 11.6.1 Requirement Overview

**Full Requirement Text:**
> "A change- and tamper-detection mechanism is deployed as follows:
> - To alert personnel to unauthorized modification (including indicators of compromise, changes, additions, and deletions) to the **HTTP headers** and the **contents of payment pages** as received by the consumer browser.
> - The mechanism is configured to evaluate the received **HTTP headers** and **payment page**.
> - The mechanism functions are performed as follows:
>   • At least once every **seven days**
>   OR
>   • Periodically (at the frequency defined in the entity's **targeted risk analysis**, which is performed according to all elements specified in Requirement 12.3.1)."

**Key Components:**
1. HTTP header monitoring
2. Payment page content monitoring
3. Alert mechanism
4. Frequency: ≥ weekly OR per TRA
5. Evaluation of both headers and page content

---

## Current Implementation Analysis

### ✅ What IS Implemented (Strong Areas)

#### 1. Script Content Monitoring (EXCELLENT)
- **Real-time detection** of all script elements on payment pages
- **SHA-384 cryptographic hashing** for integrity verification
- **Change detection** via hash comparison against baseline
- **Auto-discovery** of new scripts with automatic registration
- **Dynamic script injection protection** via DOM method overrides
- **Inline and external** script monitoring
- **Coverage:** External scripts, inline scripts, dynamically added scripts, iframes

**Files:** `script-integrity-monitor.js`

#### 2. Alert Mechanism (EXCELLENT)
- **Server-side API** for violation reporting (`/api/scripts/violation`)
- **Real-time alerts** sent immediately upon detection
- **Batch alert support** to reduce noise
- **Database storage** of all violations with severity levels
- **Admin dashboard** for violation monitoring
- **Email/Slack notification queue** (infrastructure exists)

**Files:** `server-alert-handler.js`, `database-manager.js`

#### 3. Monitoring Frequency (EXCEEDS REQUIREMENT)
- **Continuous real-time monitoring** (far exceeds 7-day minimum)
- **MutationObserver** for instant detection of DOM changes
- **Event-driven architecture** ensures immediate response
- **Polling mechanism** for approval status (every 30 seconds)

**Assessment:** COMPLIANT - Exceeds minimum requirement

#### 4. Approval Workflow (EXCELLENT)
- **Database-backed approval system** with pending/approved/rejected status
- **Business justification** required per PCI DSS
- **Complete audit trail** with 7-year retention
- **Admin panel** with bulk approval/rejection
- **Role-based access control** for admin users

**Files:** `server-alert-handler.js`, `database-schema.sql`, `public/admin-panel.html`

#### 5. Inventory Maintenance (EXCELLENT)
- **Complete script inventory** in database
- **Metadata tracking:** URL, hash, type, size, first seen, page URL
- **Status tracking:** pending, approved, rejected
- **Audit log** for all approval decisions

**Assessment:** COMPLIANT - Meets PCI DSS 6.4.3 inventory requirements

---

### ❌ What IS NOT Implemented (Gaps)

#### Gap 1: HTTP Response Header Monitoring (CRITICAL)

**PCI DSS Requirement:**
> "detect unauthorized modification to HTTP headers"

**Current Status:** ❌ NOT IMPLEMENTED

**What's Missing:**
- No monitoring of HTTP response headers from payment pages
- Cannot detect if security headers are removed or modified
- No baseline for expected security headers
- No alerts when headers change

**Security Headers That Should Be Monitored:**
1. `Content-Security-Policy` - XSS protection
2. `X-Frame-Options` - Clickjacking protection
3. `X-Content-Type-Options` - MIME sniffing protection
4. `Strict-Transport-Security` - HTTPS enforcement
5. `Referrer-Policy` - Information leakage protection
6. `Permissions-Policy` - Feature access control
7. `Content-Type` - Ensures correct MIME type
8. Custom security headers specific to payment processor

**Attack Scenarios Enabled by This Gap:**
- Attacker removes CSP header → enables XSS attacks
- Attacker modifies X-Frame-Options → enables clickjacking
- Attacker weakens security headers → reduces protection

**Compliance Impact:** CRITICAL - Explicitly required by 11.6.1

---

#### Gap 2: Payment Form Integrity Monitoring (HIGH)

**PCI DSS Requirement:**
> "detect unauthorized modification to contents of payment pages"

**Current Status:** ⚠️ PARTIALLY IMPLEMENTED (scripts only)

**What's Missing:**
- No monitoring of payment form structure
- Cannot detect if form fields are added/removed
- No verification of form action URL
- No monitoring of input field attributes
- Cannot detect hidden field injection

**Payment Form Elements That Should Be Monitored:**
1. **Form structure:**
   - Form action URL (where data is submitted)
   - Form method (POST vs GET)
   - Form target (frame/window)
   - Number and type of input fields

2. **Input fields:**
   - Field names (cardNumber, cvv, expiryDate, etc.)
   - Field IDs and autocomplete attributes
   - Input types (text, password, number)
   - Placeholder text and labels
   - Required/optional status

3. **Hidden fields:**
   - Merchant ID fields
   - Session tokens
   - Transaction identifiers

4. **Submit buttons:**
   - Button text and styling
   - Event handlers
   - Form submission behavior

**Attack Scenarios Enabled by This Gap:**
- Attacker adds hidden field to capture CVV
- Attacker changes form action to rogue endpoint
- Attacker modifies autocomplete to enable card caching
- Attacker injects additional payment fields for skimming

**Compliance Impact:** HIGH - "Contents of payment pages" includes forms

---

#### Gap 3: Network Request Monitoring (HIGH)

**PCI DSS Requirement:**
> "detect unauthorized modification including additions"

**Current Status:** ❌ NOT IMPLEMENTED

**What's Missing:**
- No monitoring of where payment data is sent
- Cannot detect rogue form submissions
- No tracking of XHR/fetch requests from payment pages
- Cannot detect data exfiltration attempts

**Network Activity That Should Be Monitored:**
1. **Form submissions:**
   - Destination URL validation
   - POST data inspection (without capturing sensitive data)
   - Multiple submission detection

2. **AJAX/Fetch requests:**
   - API endpoints called from payment page
   - Third-party API calls
   - Data being sent to external domains

3. **WebSocket connections:**
   - Real-time connections from payment page
   - Data streaming to external services

4. **Beacon/sendBeacon:**
   - Analytics beacons
   - Tracking pixels
   - Data collection endpoints

**Attack Scenarios Enabled by This Gap:**
- Malicious script sends card data to attacker's server
- Skimmer exfiltrates data via image beacon
- Form submission duplicated to rogue endpoint
- WebSocket streams payment data in real-time

**Compliance Impact:** HIGH - Critical for detecting data exfiltration

---

#### Gap 4: DOM Element Integrity Beyond Scripts (MEDIUM)

**PCI DSS Requirement:**
> "detect unauthorized modification to contents of payment pages"

**Current Status:** ⚠️ SCRIPTS ONLY

**What's Missing:**
- No monitoring of non-script DOM elements
- Cannot detect visual changes that mislead users
- No verification of payment page structure
- Cannot detect element hiding/showing manipulations

**DOM Elements That Should Be Monitored:**
1. **Critical visual elements:**
   - Payment buttons and links
   - Security badges and trust indicators
   - Price displays and total amounts
   - Terms and conditions text

2. **Iframes:**
   - Payment iframe src URLs
   - Iframe sandbox attributes
   - Iframe visibility and positioning

3. **Images and media:**
   - Logo images (phishing detection)
   - Security badge images
   - Background images

4. **Styles and CSS:**
   - CSS that could hide elements
   - Styles that overlay payment forms
   - Visual obfuscation techniques

**Attack Scenarios Enabled by This Gap:**
- Attacker overlays fake payment form on real form
- Malicious CSS hides security warnings
- Payment button redirected to phishing site
- Iframe replaced with attacker-controlled version

**Compliance Impact:** MEDIUM - Improves overall tamper detection

---

#### Gap 5: Targeted Risk Analysis (TRA) Documentation (MEDIUM)

**PCI DSS Requirement:**
> "Periodically (at the frequency defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1)"

**Current Status:** ⚠️ FREQUENCY EXCEEDS REQUIREMENT, BUT NO TRA DOCUMENTATION

**What's Missing:**
- No formal TRA document defining monitoring frequency
- No risk assessment for payment page tampering
- No documented rationale for real-time monitoring
- Missing TRA per Requirement 12.3.1 elements

**TRA Documentation Should Include:**
1. Risk assessment methodology
2. Identified threats to payment pages
3. Likelihood and impact analysis
4. Rationale for monitoring frequency (real-time)
5. Compensating controls
6. Review and approval signatures
7. Annual review schedule

**Compliance Impact:** MEDIUM - Documentation requirement, not technical

---

## Compliance Score Breakdown

| Component | Required | Implemented | Status | Weight | Score |
|-----------|----------|-------------|--------|--------|-------|
| Script Monitoring | Yes | ✅ Yes | Excellent | 20% | 100% |
| HTTP Header Monitoring | Yes | ❌ No | Missing | 25% | 0% |
| Form Integrity | Yes | ⚠️ Partial | Scripts Only | 25% | 40% |
| Network Monitoring | Yes | ❌ No | Missing | 20% | 0% |
| Alert Mechanism | Yes | ✅ Yes | Excellent | 10% | 100% |
| **OVERALL** | - | - | **Partial** | **100%** | **60%** |

---

## Required Changes for Full Compliance

### Priority 1: HTTP Header Monitoring (CRITICAL)

**Implementation Requirements:**

1. **Capture Initial Headers:**
   ```javascript
   class HTTPHeaderMonitor {
     constructor() {
       this.baselineHeaders = {};
       this.criticalHeaders = [
         'content-security-policy',
         'x-frame-options',
         'x-content-type-options',
         'strict-transport-security',
         'referrer-policy',
         'permissions-policy'
       ];
     }

     async captureHeaders() {
       const response = await fetch(window.location.href, { method: 'HEAD' });
       const headers = {};
       for (const [key, value] of response.headers.entries()) {
         headers[key.toLowerCase()] = value;
       }
       return headers;
     }
   }
   ```

2. **Periodic Verification:**
   - Capture headers on page load
   - Compare against baseline stored in database
   - Re-check headers every 60 seconds (or configurable)
   - Alert on changes to critical security headers

3. **Database Schema:**
   ```sql
   CREATE TABLE http_headers (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     page_url TEXT NOT NULL,
     header_name TEXT NOT NULL,
     header_value TEXT,
     baseline_value TEXT,
     first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     last_verified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     status TEXT DEFAULT 'approved', -- approved, flagged, changed
     UNIQUE(page_url, header_name)
   );

   CREATE TABLE header_violations (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     page_url TEXT NOT NULL,
     header_name TEXT NOT NULL,
     expected_value TEXT,
     actual_value TEXT,
     detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     severity TEXT DEFAULT 'HIGH',
     review_status TEXT DEFAULT 'pending'
   );
   ```

4. **Server API Endpoints:**
   ```
   POST /api/headers/register - Register baseline headers
   GET /api/headers/baseline/:pageUrl - Get expected headers
   POST /api/headers/violation - Report header tampering
   GET /api/admin/headers/violations - Review header violations
   ```

5. **Admin Panel Updates:**
   - New "HTTP Headers" tab
   - Display baseline headers per page
   - Show header violations
   - Approve/flag header changes

**Estimated Effort:** 3-4 days

---

### Priority 2: Payment Form Integrity Monitoring (HIGH)

**Implementation Requirements:**

1. **Form Structure Hashing:**
   ```javascript
   class PaymentFormMonitor {
     constructor() {
       this.monitoredForms = new Map();
     }

     hashFormStructure(form) {
       const structure = {
         action: form.action,
         method: form.method,
         target: form.target,
         fields: Array.from(form.elements).map(el => ({
           name: el.name,
           type: el.type,
           id: el.id,
           autocomplete: el.autocomplete,
           required: el.required
         }))
       };
       return this.calculateHash(JSON.stringify(structure));
     }

     detectFormChanges(form) {
       const currentHash = this.hashFormStructure(form);
       const baselineHash = this.monitoredForms.get(form.id);

       if (baselineHash && currentHash !== baselineHash) {
         this.reportFormViolation(form, 'FORM_STRUCTURE_CHANGED');
       }
     }
   }
   ```

2. **Form Field Monitoring:**
   - Monitor card number, CVV, expiry date fields
   - Detect new hidden fields
   - Verify form action URL against whitelist
   - Check autocomplete attributes (should be 'off' for sensitive fields)

3. **MutationObserver for Forms:**
   ```javascript
   const formObserver = new MutationObserver((mutations) => {
     mutations.forEach((mutation) => {
       if (mutation.type === 'childList') {
         mutation.addedNodes.forEach((node) => {
           if (node.tagName === 'INPUT' || node.tagName === 'FORM') {
             paymentFormMonitor.verifyElement(node);
           }
         });
       }
       if (mutation.type === 'attributes') {
         if (mutation.target.tagName === 'FORM') {
           paymentFormMonitor.detectFormChanges(mutation.target);
         }
       }
     });
   });
   ```

4. **Database Schema:**
   ```sql
   CREATE TABLE payment_forms (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     page_url TEXT NOT NULL,
     form_id TEXT,
     form_name TEXT,
     action_url TEXT NOT NULL,
     structure_hash TEXT NOT NULL,
     field_count INTEGER,
     first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     status TEXT DEFAULT 'approved',
     UNIQUE(page_url, form_id)
   );

   CREATE TABLE form_violations (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     page_url TEXT NOT NULL,
     form_id TEXT,
     violation_type TEXT NOT NULL, -- STRUCTURE_CHANGED, FIELD_ADDED, ACTION_CHANGED
     details TEXT,
     detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     severity TEXT DEFAULT 'HIGH'
   );
   ```

**Estimated Effort:** 4-5 days

---

### Priority 3: Network Request Monitoring (HIGH)

**Implementation Requirements:**

1. **Intercept Fetch/XHR:**
   ```javascript
   class NetworkMonitor {
     constructor() {
       this.originalFetch = window.fetch;
       this.originalXHR = window.XMLHttpRequest;
       this.setupInterceptors();
     }

     setupInterceptors() {
       const self = this;

       // Override fetch
       window.fetch = function(...args) {
         self.inspectRequest('fetch', args[0], args[1]);
         return self.originalFetch.apply(this, args);
       };

       // Override XMLHttpRequest
       const originalOpen = XMLHttpRequest.prototype.open;
       XMLHttpRequest.prototype.open = function(method, url, ...rest) {
         self.inspectRequest('xhr', url, { method });
         return originalOpen.apply(this, [method, url, ...rest]);
       };
     }

     inspectRequest(type, url, options) {
       // Check if request is to payment processor domain
       // Alert if request goes to unauthorized domain
       // Log all payment-related requests for audit
       if (this.isUnauthorizedDestination(url)) {
         this.reportNetworkViolation(type, url, options);
       }
     }
   }
   ```

2. **Form Submission Monitoring:**
   ```javascript
   document.addEventListener('submit', (event) => {
     const form = event.target;
     if (isPaymentForm(form)) {
       const actionUrl = form.action;
       if (!isWhitelistedDestination(actionUrl)) {
         event.preventDefault();
         reportViolation('UNAUTHORIZED_FORM_SUBMISSION', { actionUrl });
         alert('Payment form submission blocked - unauthorized destination');
       }
     }
   }, true);
   ```

3. **Whitelist Configuration:**
   ```javascript
   networkWhitelist: {
     allowedDomains: [
       'https://payment.example.com',
       'https://api.paymentprocessor.com'
     ],
     allowedEndpoints: [
       '/api/payment/process',
       '/api/payment/validate'
     ]
   }
   ```

4. **Database Schema:**
   ```sql
   CREATE TABLE network_violations (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     page_url TEXT NOT NULL,
     request_type TEXT NOT NULL, -- fetch, xhr, form, beacon
     destination_url TEXT NOT NULL,
     method TEXT,
     detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     severity TEXT DEFAULT 'CRITICAL',
     blocked BOOLEAN DEFAULT 0
   );
   ```

**Estimated Effort:** 3-4 days

---

### Priority 4: Enhanced DOM Element Monitoring (MEDIUM)

**Implementation Requirements:**

1. **Critical Element Registry:**
   ```javascript
   criticalElements: {
     paymentButton: {
       selector: '#submit-payment',
       attributes: ['onclick', 'href', 'action'],
       textContent: 'Pay Now'
     },
     securityBadge: {
       selector: '.security-badge',
       attributes: ['src', 'alt']
     },
     priceDisplay: {
       selector: '#total-amount',
       textContent: true
     }
   }
   ```

2. **Element Integrity Monitoring:**
   ```javascript
   monitorCriticalElements() {
     for (const [name, config] of Object.entries(this.criticalElements)) {
       const element = document.querySelector(config.selector);
       if (element) {
         const baseline = this.getElementBaseline(name);
         if (!this.verifyElement(element, baseline)) {
           this.reportElementViolation(name, element, baseline);
         }
       }
     }
   }
   ```

3. **CSS Monitoring:**
   ```javascript
   // Detect CSS that hides payment forms or overlays content
   const suspiciousCSSPatterns = [
     /opacity:\s*0/,
     /display:\s*none/,
     /position:\s*absolute.*z-index:\s*9999/,
     /visibility:\s*hidden/
   ];
   ```

**Estimated Effort:** 2-3 days

---

### Priority 5: TRA Documentation (MEDIUM)

**Implementation Requirements:**

1. **Create TRA Document:**
   - Template: `PCI-DSS-TRA-11.6.1.md`
   - Sections: Scope, Risk Assessment, Threat Analysis, Monitoring Frequency Justification
   - Include risk matrix and control mapping
   - Document real-time monitoring rationale

2. **TRA Content:**
   ```markdown
   # Targeted Risk Analysis - Requirement 11.6.1

   ## Scope
   - All payment pages on e-commerce site
   - Scripts, headers, forms, network requests

   ## Identified Threats
   1. Magecart/web skimming attacks (Likelihood: Medium, Impact: Critical)
   2. XSS injection (Likelihood: High, Impact: High)
   3. Form manipulation (Likelihood: Medium, Impact: High)

   ## Monitoring Frequency Decision
   Real-time monitoring chosen (exceeds 7-day minimum) because:
   - JavaScript-based attacks occur instantly
   - 7-day interval insufficient for detecting web skimming
   - Real-time detection minimizes exposure window
   - Technical capability available with acceptable performance

   ## Review Schedule
   - Annual TRA review
   - Ad-hoc review after significant changes
   ```

**Estimated Effort:** 1-2 days (documentation)

---

## Implementation Roadmap

### Phase 1: Critical Compliance (Weeks 1-2)
- ✅ HTTP Header Monitoring (Priority 1)
- ✅ Network Request Monitoring (Priority 3)
- ⚠️ TRA Documentation (Priority 5)

**Deliverables:** Basic compliance achieved, documentation complete

### Phase 2: Full Coverage (Weeks 3-4)
- ✅ Payment Form Integrity (Priority 2)
- ✅ Enhanced DOM Monitoring (Priority 4)
- ✅ Admin panel updates for new monitoring types

**Deliverables:** Comprehensive tamper detection across all page components

### Phase 3: Testing & Validation (Week 5)
- ✅ Penetration testing with simulated attacks
- ✅ False positive tuning
- ✅ Performance optimization
- ✅ Documentation review

**Deliverables:** Production-ready, validated solution

---

## Estimated Total Effort

| Phase | Duration | Complexity |
|-------|----------|------------|
| HTTP Header Monitoring | 3-4 days | Medium |
| Form Integrity Monitoring | 4-5 days | High |
| Network Monitoring | 3-4 days | Medium-High |
| DOM Element Monitoring | 2-3 days | Medium |
| TRA Documentation | 1-2 days | Low |
| Testing & Integration | 3-4 days | Medium |
| **TOTAL** | **16-22 days** | **3-4 weeks** |

**Team:** 1 senior developer + 1 security engineer

---

## Compliance Validation Checklist

After implementation, verify:

- [ ] HTTP response headers monitored on all payment pages
- [ ] Security headers (CSP, X-Frame-Options, etc.) validated against baseline
- [ ] Payment form structure hashed and verified
- [ ] Form action URLs validated against whitelist
- [ ] Network requests monitored and unauthorized destinations blocked
- [ ] Alert mechanism sends notifications for all violation types
- [ ] Admin panel displays all monitoring data (scripts, headers, forms, network)
- [ ] Database stores complete audit trail for all changes
- [ ] Monitoring runs continuously (real-time, exceeds 7-day requirement)
- [ ] TRA document completed and approved per Requirement 12.3.1
- [ ] Annual TRA review process established
- [ ] Penetration testing validates detection capabilities

---

## Alternative: Magecart-Specific Solutions

If internal development is not feasible, consider:

1. **Third-Party Solutions:**
   - Akamai Page Integrity Manager
   - Cloudflare Page Shield
   - PerimeterX Code Defender
   - Jscrambler Page Monitoring

2. **Managed Services:**
   - PCI compliance monitoring services
   - SOC-as-a-Service with 11.6.1 coverage

**Note:** Third-party solutions still require TRA documentation and integration.

---

## Recommendation

**Immediate Action:**
1. Implement Priority 1 (HTTP Headers) and Priority 3 (Network Monitoring) within 2 weeks
2. Complete TRA documentation within 1 week
3. Plan Phase 2 implementation for form integrity monitoring

**Justification:**
- Current 60% compliance is insufficient for PCI DSS audit
- HTTP header and network monitoring are explicitly required
- Script monitoring alone does not constitute "contents of payment pages"
- Missing capabilities enable critical attack vectors (data exfiltration, form manipulation)

**Timeline to Full Compliance:** 4-5 weeks with dedicated resources

---

## Conclusion

The Script Integrity Monitor provides an **excellent foundation** for PCI DSS 11.6.1 compliance with industry-leading script monitoring capabilities. However, **full compliance requires expansion** to include HTTP header monitoring, payment form integrity, and network request monitoring.

**Current State:** PARTIALLY COMPLIANT (60%)
**Required Investment:** 3-4 weeks development
**Risk if Not Addressed:** PCI DSS audit failure, exposure to Magecart attacks, potential compliance fines

**Next Steps:**
1. Review and approve this gap analysis
2. Allocate development resources
3. Prioritize implementation per roadmap
4. Complete TRA documentation
5. Schedule follow-up PCI DSS audit after implementation

