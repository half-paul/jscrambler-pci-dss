# Modularization Refactoring Plan

## Overview
This document outlines the plan to refactor three large monolithic files into a modular architecture:
- **script-integrity-monitor.js** (1,485 lines) → Client-side modules
- **server-alert-handler.js** (2,893 lines) → Server-side modules
- **admin-panel.html** (3,731 lines) → Separate HTML/JS/CSS

**Total**: 8,109 lines across 3 files

## Current Progress

### ✅ Completed
1. Created directory structure:
   - `/src/client/core/`, `/src/client/monitors/`, `/src/client/utils/`
   - `/src/server/routes/`, `/src/server/middleware/`, `/src/server/services/`
   - `/public/js/admin/`, `/public/css/`

2. Created middleware modules:
   - `src/server/middleware/rateLimiting.js` ✓
   - `src/server/middleware/auth.js` ✓

### 🔄 In Progress
Server-side refactoring

### ⏳ Pending
- Client-side refactoring
- Admin panel refactoring
- Entry point creation
- Testing
- Documentation updates

---

## Detailed Refactoring Plan

### Part 1: Server-Side Refactoring (server-alert-handler.js → 11 modules)

#### A. Middleware (2 files) - ✅ COMPLETED
- [x] `src/server/middleware/rateLimiting.js` - Rate limiters
- [x] `src/server/middleware/auth.js` - Authentication & authorization

#### B. Services (1 file)
- [ ] `src/server/services/auditService.js`
  - Extract `logAudit()` function (lines 254-328)
  - Handles audit trail logging for all admin actions

#### C. Routes (6 files)
- [ ] `src/server/routes/auth.js` - Authentication routes
  - POST /api/admin/auth/login
  - POST /api/admin/auth/verify-mfa
  - POST /api/admin/auth/setup-mfa
  - POST /api/admin/auth/logout
  - POST /api/admin/auth/refresh

- [ ] `src/server/routes/scripts.js` - Script management
  - POST /api/scripts/register (public)
  - GET /api/scripts/status/:hash (public)
  - GET /api/admin/scripts/pending
  - GET /api/admin/scripts/search
  - POST /api/admin/scripts/:id/approve
  - POST /api/admin/scripts/:id/reject
  - POST /api/admin/scripts/bulk-approve
  - POST /api/admin/scripts/bulk-reject
  - DELETE /api/admin/scripts/:id

- [ ] `src/server/routes/violations.js` - Violation management
  - POST /api/scripts/violation (public)
  - GET /api/admin/violations
  - POST /api/admin/violations/bulk-delete

- [ ] `src/server/routes/headers.js` - HTTP header monitoring
  - POST /api/headers/register (public)
  - GET /api/headers/baseline/:pageUrl (public)
  - POST /api/headers/violation (public)
  - GET /api/admin/headers/violations
  - GET /api/admin/headers/baselines
  - POST /api/admin/headers/violations/:id/review
  - POST /api/admin/headers/violations/bulk-delete
  - POST /api/admin/headers/baselines/bulk-delete

- [ ] `src/server/routes/network.js` - Network request monitoring
  - POST /api/network/violation (public)
  - GET /api/network/whitelist (public)
  - GET /api/admin/network/violations
  - POST /api/admin/network/violations/:id/review
  - POST /api/admin/network/violations/:id/whitelist
  - GET /api/admin/network/whitelist
  - DELETE /api/admin/network/whitelist/:id
  - POST /api/admin/network/violations/bulk-delete

- [ ] `src/server/routes/admin.js` - Admin dashboard & management
  - GET /api/admin/dashboard
  - GET /api/admin/audit-trail
  - GET /api/admin/audit-trail/stats
  - GET /api/admin/pci-dss/summary
  - GET /api/admin/users
  - POST /api/admin/users
  - PUT /api/admin/users/:id
  - DELETE /api/admin/users/:id

#### D. Main Application (2 files)
- [ ] `src/server/app.js`
  - Express app setup
  - Middleware configuration (helmet, cors, body-parser)
  - Database initialization
  - Route registration
  - Error handling

- [ ] `server.js` (root)
  - Entry point
  - Imports app from src/server/app.js
  - Starts HTTP server
  - Handles graceful shutdown

---

### Part 2: Client-Side Refactoring (script-integrity-monitor.js → 6 modules)

#### A. Core Modules (2 files)
- [ ] `src/client/core/MonitorCore.js` (~300 lines)
  - ScriptIntegrityMonitor class
  - Configuration management
  - Script inventory
  - Violation tracking
  - Session management

- [ ] `src/client/core/HashCalculator.js` (~150 lines)
  - SHA-384 hash calculation
  - Subresource Integrity generation
  - Hash comparison utilities

#### B. Monitor Modules (2 files)
- [ ] `src/client/monitors/DOMProtection.js` (~250 lines)
  - DOM method override protection
  - createElement interception
  - appendChild/insertBefore/replaceChild interception
  - Script blocking logic
  - Blocked scripts tracking

- [ ] `src/client/monitors/MutationMonitor.js` (~200 lines)
  - MutationObserver setup
  - Script detection in mutations
  - Inline script monitoring
  - Dynamic script detection

#### C. Utilities (1 file)
- [ ] `src/client/utils/ServerAPI.js` (~300 lines)
  - Script registration API
  - Status polling
  - Violation reporting
  - Server communication utilities
  - Retry logic
  - Timeout handling

#### D. Entry Point (1 file)
- [ ] `src/client/integrity-monitor.js` (~200 lines)
  - Module imports
  - Global initialization
  - Config loading
  - Monitor instantiation
  - IIFE wrapper for browser compatibility

---

### Part 3: Admin Panel Refactoring (admin-panel.html → 10 modules)

#### A. HTML Structure (1 file)
- [ ] `public/admin-panel.html` (~300 lines)
  - Minimal HTML shell
  - Tab structure
  - Container elements
  - Script imports (new modular JS files)
  - CSS import

#### B. JavaScript Modules (8 files)
- [ ] `public/js/admin/utils.js` (~300 lines)
  - apiCall() function
  - escapeHtml() function
  - formatDate() utilities
  - Badge generation
  - Common UI helpers

- [ ] `public/js/admin/auth.js` (~300 lines)
  - Login logic
  - MFA setup and verification
  - Token management
  - Session handling
  - Logout functionality

- [ ] `public/js/admin/dashboard.js` (~400 lines)
  - Dashboard rendering
  - Statistics loading
  - Chart generation (if any)
  - Real-time updates
  - Tab switching

- [ ] `public/js/admin/scripts.js` (~500 lines)
  - Script inventory display
  - Approval queue management
  - Approve/reject actions
  - Bulk operations
  - Script search and filtering

- [ ] `public/js/admin/violations.js` (~400 lines)
  - Violation list display
  - Violation review
  - Bulk deletion
  - Filtering and pagination

- [ ] `public/js/admin/auditTrail.js` (~400 lines)
  - Audit trail display
  - Statistics cards
  - Filtering (date, action type, user)
  - Pagination
  - 30-day default range

- [ ] `public/js/admin/headers.js` (~300 lines)
  - Header baseline management
  - Header violation display
  - Review and approval

- [ ] `public/js/admin/network.js` (~300 lines)
  - Network violation display
  - Whitelist management
  - Bulk operations

#### C. Styles (1 file)
- [ ] `public/css/admin.css` (~500 lines)
  - Extract all `<style>` content
  - Organize by component
  - Add comments for sections

---

## Implementation Strategy

### Phase 1: Server Modules (Week 1)
1. ✅ Create middleware modules
2. Create service modules
3. Create route modules (one at a time)
4. Create main app.js
5. Test each route as it's created
6. Verify all endpoints work

### Phase 2: Client Modules (Week 2)
1. Create core modules
2. Create monitor modules
3. Create utility modules
4. Create entry point
5. Test in browser
6. Verify all monitoring features work

### Phase 3: Admin Panel (Week 3)
1. Extract CSS
2. Create utility module
3. Extract JavaScript modules (one tab at a time)
4. Update HTML to use new modules
5. Test each tab
6. Verify all admin features work

### Phase 4: Integration & Testing (Week 4)
1. Integration testing
2. End-to-end testing
3. Performance testing
4. Documentation updates
5. Migration guide
6. Deployment planning

---

## Migration Steps

### For Server Code:
```bash
# Old way
node server-alert-handler.js

# New way
node server.js
```

### For Client Code:
```html
<!-- Old way -->
<script src="script-integrity-monitor.js"></script>

<!-- New way -->
<script src="src/client/integrity-monitor.js"></script>
```

### For Admin Panel:
```
http://localhost:3000/admin-panel.html
# (Same URL, but using modular JS/CSS)
```

---

## Benefits

### Maintainability
- Each module has a single, clear responsibility
- Easier to find and modify specific functionality
- Reduced cognitive load when reading code

### Testing
- Can unit test individual modules
- Easier to mock dependencies
- Better test coverage

### Collaboration
- Multiple developers can work on different modules
- Reduced merge conflicts
- Clear module boundaries

### AI Agent Efficiency
- Files are within AI context windows
- Easier to analyze and modify
- Better code suggestions
- Faster refactoring

### Code Reusability
- Modules can be imported where needed
- No code duplication
- Consistent implementations

---

## File Size Comparison

### Before
- server-alert-handler.js: 2,893 lines
- script-integrity-monitor.js: 1,485 lines
- admin-panel.html: 3,731 lines

### After
- Server modules: 11 files averaging ~250 lines each
- Client modules: 6 files averaging ~250 lines each
- Admin modules: 10 files averaging ~300 lines each

**Average file size reduction**: From ~2,700 lines to ~270 lines (90% reduction)

---

## Next Steps

1. **Review this plan** and approve/modify as needed
2. **Prioritize modules** to refactor first
3. **Set up testing strategy** before making changes
4. **Create backup** of current working code
5. **Implement incrementally** - one module at a time
6. **Test continuously** after each module
7. **Document** as you go

---

## Notes

- This is a **pure refactoring** - no functionality changes
- All existing features must continue to work
- Backward compatibility maintained where possible
- Original files can be kept as `.backup` during transition
- Gradual migration allows for rollback if issues arise

---

## Questions to Consider

1. Should we keep both old and new structures during transition?
2. What's the testing strategy for each module?
3. How do we handle the database instance sharing across modules?
4. Should we add build/bundling step for client-side code?
5. Version to tag before starting refactoring?

---

**Status**: Plan Created - Awaiting Approval
**Created**: 2025-12-01
**Last Updated**: 2025-12-01
