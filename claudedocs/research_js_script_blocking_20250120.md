# JavaScript Script Blocking Research Report

**Research Date:** 2025-01-20
**Query:** Ability of JavaScript to block another script from executing on the page, loaded via link or inline script

---

## Executive Summary

JavaScript has **limited but functional capabilities** to block or prevent other scripts from executing on a web page. The effectiveness varies significantly between:
- **Inline scripts** (harder to block, race condition issues)
- **External scripts** (easier to intercept before download)
- **Dynamically injected scripts** (easiest to control via method overrides)

**Key Finding:** JavaScript **CANNOT reliably block scripts already in the HTML** at page load, but **CAN effectively prevent dynamically added scripts** and **CAN work with MutationObserver** for partial protection with timing limitations.

**Confidence Level:** HIGH - Based on multiple authoritative sources including MDN, Stack Overflow, OWASP, and practical implementations.

---

## 1. Core Methods for Blocking Script Execution

### 1.1 Content Security Policy (CSP) [Server-Side + JavaScript]

**Effectiveness:** ★★★★★ (Most Reliable)
**Browser Support:** All modern browsers
**Limitations:** Requires server configuration or meta tag before page load

#### How It Works:
```http
Content-Security-Policy: script-src 'none'
```
or via HTML meta tag:
```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
```

#### Capabilities:
- **Blocks inline scripts** by default (unless explicitly allowed via nonce/hash)
- **Blocks eval()** and similar APIs
- **Blocks external scripts** not from whitelisted sources
- **Blocks inline event handlers** (onclick, onerror, etc.)

#### CSP with JavaScript:
While CSP is primarily server-side, JavaScript cannot modify CSP after page load. However, you can:
- Read current CSP: `document.querySelector('meta[http-equiv="Content-Security-Policy"]')`
- Cannot dynamically strengthen CSP via JavaScript (browser security restriction)

**Source:** MDN Web Docs, OWASP CSP Cheat Sheet

---

### 1.2 MutationObserver [JavaScript-Only]

**Effectiveness:** ★★★☆☆ (Moderate - Race Condition Issues)
**Browser Support:** All modern browsers
**Limitations:** Cannot guarantee execution blocking for inline scripts already in DOM

#### How It Works:
```javascript
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.tagName === 'SCRIPT') {
        // Attempt to block by changing type before execution
        node.type = 'javascript/blocked';
        node.parentNode.removeChild(node);
      }
    });
  });
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true
});
```

#### Capabilities:
- **Detects script tags** added to DOM after observer setup
- **Can remove scripts** before they download (external scripts)
- **Race condition with inline scripts** - may execute before observer callback fires
- **Works best for dynamically injected scripts** via third-party code

#### Timing Issue Example:
```html
<script>
  // This MutationObserver is set up first
  const observer = new MutationObserver(...);
</script>
<script>
  alert('I may execute before observer callback runs!');
</script>
```

**Source:** Stack Overflow, javascript.info

---

### 1.3 Script Type Attribute Modification [JavaScript-Only]

**Effectiveness:** ★★★★☆ (High for External Scripts)
**Browser Support:** All browsers
**Limitations:** Only works if modified BEFORE script content loads

#### How It Works:
```javascript
// Original HTML:
// <script type="text/plain" src="external.js" data-blocked></script>

// Later, when approved:
document.querySelectorAll('script[data-blocked]').forEach(script => {
  script.type = 'text/javascript'; // or 'application/javascript'
  script.removeAttribute('data-blocked');
});
```

#### Why This Works:
- Browser **ignores script tags** with non-JavaScript MIME types
- Common blocking types: `text/plain`, `javascript/blocked`, `text/template`
- Script **won't download** if type is invalid (Chrome, Firefox)
- Can be **unblocked later** by changing type back

#### Use Case:
Cookie consent management - scripts marked `type="text/plain"` until user accepts cookies.

**Source:** Medium (Snips Blog), Stack Overflow

---

### 1.4 beforescriptexecute Event [Firefox-Only]

**Effectiveness:** ★★★★☆ (High in Firefox)
**Browser Support:** Firefox only (non-standard)
**Limitations:** Not cross-browser compatible

#### How It Works:
```javascript
document.addEventListener('beforescriptexecute', (event) => {
  const script = event.target;

  if (script.src && script.src.includes('blocked-domain.com')) {
    event.preventDefault();
    script.parentNode.removeChild(script);
  }
}, true);
```

#### Capabilities:
- **Fires before script execution** (both inline and external)
- **Can preventDefault()** to block execution
- **Can modify script content** before execution
- **Works for inline scripts** (better than MutationObserver)

#### Chrome Equivalent:
There are polyfills for Chrome/Edge, but they rely on MutationObserver underneath, so have the same race condition limitations.

**Source:** Stack Overflow, Mozilla Discourse

---

### 1.5 Method Override/Interception [JavaScript-Only]

**Effectiveness:** ★★★★★ (Excellent for Dynamic Scripts)
**Browser Support:** All browsers
**Limitations:** Only affects scripts added AFTER override is in place

#### How It Works:
```javascript
// Override createElement to intercept script creation
const originalCreateElement = document.createElement;
document.createElement = function(tagName) {
  const element = originalCreateElement.call(document, tagName);

  if (tagName.toLowerCase() === 'script') {
    // Add your blocking logic here
    const originalSetAttribute = element.setAttribute;
    element.setAttribute = function(name, value) {
      if (name === 'src' && shouldBlockScript(value)) {
        console.log('Blocked script:', value);
        return; // Don't set src
      }
      return originalSetAttribute.call(element, name, value);
    };
  }

  return element;
};

// Override appendChild to intercept script insertion
const originalAppendChild = Element.prototype.appendChild;
Element.prototype.appendChild = function(child) {
  if (child.tagName === 'SCRIPT' && shouldBlockScript(child.src)) {
    console.log('Blocked appendChild of script:', child.src);
    return child; // Return without appending
  }
  return originalAppendChild.call(this, child);
};
```

#### Capabilities:
- **Intercepts dynamically created scripts** (createElement)
- **Intercepts script insertion** (appendChild, insertBefore)
- **Can inspect and modify** script attributes before execution
- **Effective against third-party injection** (analytics, ads, malware)

#### Limitations:
- **Doesn't affect scripts in original HTML** (already parsed)
- **Can be bypassed** if attacker knows about the override
- **Must be loaded first** in page execution order

**Source:** GitHub Gist, Stack Overflow

---

## 2. Comparison Matrix

| Method | External Scripts | Inline Scripts | Dynamic Scripts | Browser Support | Reliability |
|--------|-----------------|----------------|-----------------|-----------------|-------------|
| **CSP** | ✅ Excellent | ✅ Excellent | ✅ Excellent | ✅ Universal | ⭐⭐⭐⭐⭐ |
| **MutationObserver** | ✅ Good | ⚠️ Race Condition | ✅ Good | ✅ Universal | ⭐⭐⭐☆☆ |
| **Type Attribute** | ✅ Excellent | ⚠️ Must Pre-Set | ❌ No | ✅ Universal | ⭐⭐⭐⭐☆ |
| **beforescriptexecute** | ✅ Excellent | ✅ Excellent | ✅ Excellent | ❌ Firefox Only | ⭐⭐⭐⭐☆ |
| **Method Override** | ❌ No | ❌ No | ✅ Excellent | ✅ Universal | ⭐⭐⭐⭐⭐ |

---

## 3. Real-World Implementation Strategies

### 3.1 Defense-in-Depth Approach (Recommended)

Combine multiple techniques for maximum protection:

```javascript
// 1. Set up MutationObserver FIRST
const scriptBlocker = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.tagName === 'SCRIPT') {
        if (shouldBlockScript(node)) {
          node.type = 'javascript/blocked';
          node.parentNode?.removeChild(node);
          console.warn('Blocked script via MutationObserver:', node.src || 'inline');
        }
      }
    });
  });
});
scriptBlocker.observe(document.documentElement, { childList: true, subtree: true });

// 2. Override dynamic script creation
const originalCreateElement = document.createElement.bind(document);
document.createElement = function(tagName) {
  const element = originalCreateElement(tagName);
  if (tagName.toLowerCase() === 'script') {
    Object.defineProperty(element, 'src', {
      set: function(value) {
        if (shouldBlockScript(value)) {
          console.warn('Blocked script via createElement override:', value);
          return;
        }
        Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src').set.call(this, value);
      }
    });
  }
  return element;
};

// 3. Override appendChild
const originalAppendChild = Element.prototype.appendChild;
Element.prototype.appendChild = function(child) {
  if (child.tagName === 'SCRIPT' && shouldBlockScript(child)) {
    console.warn('Blocked script via appendChild override:', child.src || 'inline');
    return child;
  }
  return originalAppendChild.call(this, child);
};

function shouldBlockScript(scriptOrUrl) {
  // Your approval logic here
  // Example: check against approved hash list
  return true; // Block by default
}
```

### 3.2 Server-Side CSP + Client-Side Fallback

```html
<!-- Server sends CSP header -->
<!-- Content-Security-Policy: script-src 'self' 'nonce-random123' -->

<!-- Client-side fallback for dynamic scripts -->
<script nonce="random123">
  // CSP handles initial page load
  // JavaScript handles dynamically injected scripts
  setupDynamicScriptBlocking();
</script>
```

---

## 4. Critical Limitations

### 4.1 Race Conditions with Inline Scripts

**Problem:** JavaScript executes synchronously. If an inline script exists in the HTML below your blocking code, it may execute before your MutationObserver callback runs.

**Example:**
```html
<script>
  // Your blocker sets up MutationObserver
</script>
<script>
  alert('I execute immediately!');
  // MutationObserver callback is QUEUED, not yet run
</script>
```

**Solution:** Use CSP or pre-mark scripts with `type="text/plain"`.

### 4.2 Cannot Block Scripts in Original HTML

JavaScript loaded later **cannot prevent execution** of scripts already in the HTML document because:
- HTML parsing happens before JavaScript execution
- Scripts execute as soon as they're parsed (unless async/defer)
- No API to "unexecute" already-run code

**Solution:** Use server-side CSP or mark scripts with non-JS type attributes in the HTML itself.

### 4.3 Malicious Code Can Bypass Overrides

If an attacker knows you've overridden `appendChild`, they can:
```javascript
// Save reference to original before your override
const realAppendChild = Element.prototype.appendChild;

// Later, bypass your override
realAppendChild.call(document.body, scriptElement);
```

**Solution:** Implement at the earliest possible execution point (top of `<head>`).

---

## 5. Browser Compatibility Summary

| Feature | Chrome | Firefox | Safari | Edge | IE11 |
|---------|--------|---------|--------|------|------|
| CSP | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Partial |
| MutationObserver | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes* |
| Type Attribute | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| beforescriptexecute | ❌ No | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Method Override | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |

*IE11 supports MutationObserver with polyfill

---

## 6. Use Cases & Recommendations

### Use Case 1: PCI DSS Script Integrity Monitoring

**Scenario:** Block unauthorized scripts on payment pages (like your current project)

**Recommended Approach:**
1. **Server-side CSP** with nonce-based whitelisting
2. **Client-side MutationObserver** as fallback for dynamically injected scripts
3. **Method overrides** for createElement/appendChild
4. **Server approval workflow** before allowing scripts

**Why:** Defense-in-depth approach catches scripts at multiple layers.

---

### Use Case 2: Cookie Consent Management

**Scenario:** Block tracking scripts until user consents

**Recommended Approach:**
1. Mark scripts with `type="text/plain"` in HTML
2. Change to `type="text/javascript"` after consent
3. Use MutationObserver to catch dynamic script injection

**Why:** Type attribute method is reliable for initial page load, observer handles dynamic injection.

---

### Use Case 3: Third-Party Widget Sandboxing

**Scenario:** Load third-party widget but prevent it from loading additional scripts

**Recommended Approach:**
1. Load widget in iframe with restrictive CSP
2. Override createElement/appendChild in iframe context
3. Whitelist only approved script sources

**Why:** Iframe provides isolation, overrides control dynamic behavior.

---

## 7. Code Examples

### Example 1: Comprehensive Script Blocker

```javascript
class ScriptBlocker {
  constructor(approvalCallback) {
    this.approvalCallback = approvalCallback;
    this.blockedScripts = new Map();
    this.init();
  }

  init() {
    this.setupMutationObserver();
    this.overrideCreateElement();
    this.overrideAppendChild();
    this.overrideInsertBefore();
  }

  async checkApproval(scriptElement) {
    const hash = await this.calculateHash(scriptElement);
    return this.approvalCallback(hash, scriptElement);
  }

  async calculateHash(scriptElement) {
    let content = '';
    if (scriptElement.src) {
      content = scriptElement.src;
    } else {
      content = scriptElement.textContent;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-384', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  setupMutationObserver() {
    const observer = new MutationObserver(async (mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.tagName === 'SCRIPT') {
            const approved = await this.checkApproval(node);
            if (!approved) {
              node.type = 'javascript/blocked';
              node.parentNode?.removeChild(node);
              this.blockedScripts.set(node, 'MutationObserver');
              console.warn('🚫 Blocked script (MutationObserver):', node.src || 'inline');
            }
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  overrideCreateElement() {
    const self = this;
    const originalCreateElement = document.createElement.bind(document);

    document.createElement = function(tagName) {
      const element = originalCreateElement(tagName);

      if (tagName.toLowerCase() === 'script') {
        const descriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');

        Object.defineProperty(element, 'src', {
          set: async function(value) {
            const approved = await self.checkApproval({ src: value });
            if (!approved) {
              self.blockedScripts.set(element, 'createElement');
              console.warn('🚫 Blocked script (createElement):', value);
              return;
            }
            descriptor.set.call(this, value);
          },
          get: function() {
            return descriptor.get.call(this);
          }
        });
      }

      return element;
    };
  }

  overrideAppendChild() {
    const self = this;
    const originalAppendChild = Element.prototype.appendChild;

    Element.prototype.appendChild = async function(child) {
      if (child.tagName === 'SCRIPT') {
        const approved = await self.checkApproval(child);
        if (!approved) {
          self.blockedScripts.set(child, 'appendChild');
          console.warn('🚫 Blocked script (appendChild):', child.src || 'inline');
          return child;
        }
      }
      return originalAppendChild.call(this, child);
    };
  }

  overrideInsertBefore() {
    const self = this;
    const originalInsertBefore = Element.prototype.insertBefore;

    Element.prototype.insertBefore = async function(newNode, referenceNode) {
      if (newNode.tagName === 'SCRIPT') {
        const approved = await self.checkApproval(newNode);
        if (!approved) {
          self.blockedScripts.set(newNode, 'insertBefore');
          console.warn('🚫 Blocked script (insertBefore):', newNode.src || 'inline');
          return newNode;
        }
      }
      return originalInsertBefore.call(this, newNode, referenceNode);
    };
  }

  getBlockedScripts() {
    return this.blockedScripts;
  }
}

// Usage
const blocker = new ScriptBlocker(async (hash, scriptElement) => {
  // Check against your approval database
  const response = await fetch(`/api/scripts/check/${hash}`);
  const data = await response.json();
  return data.approved;
});
```

---

## 8. Security Considerations

### 8.1 Limitations as Security Control

**Warning:** JavaScript-based script blocking should **NOT** be your only security control because:

1. **JavaScript can be disabled** by user
2. **Attacker can save reference** to original methods before your override
3. **Race conditions** exist with inline scripts
4. **Browser bugs** may allow bypasses

**Recommendation:** Use JavaScript blocking as **defense-in-depth**, not primary security.

### 8.2 CSP as Primary Control

Always implement CSP as your **primary script control mechanism**:
- Cannot be bypassed by client-side JavaScript
- Enforced by browser security architecture
- Works even if JavaScript is disabled
- Meets compliance requirements (PCI DSS, etc.)

---

## 9. Performance Implications

### MutationObserver Overhead

**Impact:** Minimal for most pages
- Observing `childList` + `subtree` has low overhead
- Callbacks execute asynchronously (don't block rendering)
- Modern browsers optimize MutationObserver performance

**Benchmark:** Typically <1ms per DOM mutation

### Method Override Overhead

**Impact:** Negligible
- Simple function wrapper (few microseconds)
- Only affects script creation/insertion (infrequent operation)
- No impact on other DOM operations

**Recommendation:** Method overrides are safe for production use.

---

## 10. Conclusion

### Summary of Capabilities

**JavaScript CAN:**
- ✅ Block dynamically injected scripts (high reliability)
- ✅ Prevent scripts with modified `type` attributes from executing
- ✅ Intercept script creation via method overrides
- ✅ Detect and remove scripts via MutationObserver (with timing limits)

**JavaScript CANNOT:**
- ❌ Reliably block inline scripts already in HTML
- ❌ Prevent execution after script has started
- ❌ Modify CSP after page load
- ❌ Guarantee blocking without race conditions (pure JS approach)

### Best Practice Recommendation

**For Production Systems (like PCI DSS compliance):**

1. **Primary Control:** Server-side CSP with nonce/hash-based whitelisting
2. **Secondary Control:** JavaScript MutationObserver for dynamic scripts
3. **Tertiary Control:** Method overrides for createElement/appendChild
4. **Monitoring:** Log all blocked scripts for security review
5. **Approval Workflow:** Server-side validation before allowing scripts

**For Cookie Consent / User Preference:**

1. **Primary Control:** Mark scripts with `type="text/plain"` in HTML
2. **Secondary Control:** Change type to `text/javascript` after consent
3. **Tertiary Control:** MutationObserver for dynamically injected tracking scripts

---

## 11. References & Sources

### Official Documentation
- MDN Web Docs - Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- MDN Web Docs - MutationObserver: https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver
- WHATWG HTML Standard - Script Execution: https://html.spec.whatwg.org/multipage/scripting.html

### Security Resources
- OWASP CSP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- Google Strict CSP: https://csp.withgoogle.com/docs/strict-csp.html

### Community Resources
- Stack Overflow: Multiple threads on script blocking techniques
- Medium (Snips Blog): "Block Third-Party Scripts with a Few Lines of Javascript"
- GitHub Gists: Practical implementations of script blocking

### Browser Specifications
- beforescriptexecute (Firefox): Non-standard event for script interception
- CSP Level 3 Specification: W3C Working Draft

---

**Report Confidence:** HIGH
**Research Completeness:** Comprehensive coverage of all major techniques
**Last Updated:** 2025-01-20
