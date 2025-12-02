# Routing Fix Required

## Problem Identified

The modular server has a route mounting issue where admin routes are not accessible at the expected URLs.

### Current Implementation Issue:

When we mount a single router at multiple paths:
```javascript
const scriptsRouter = createScriptsRoutes(...);
app.use('/api/scripts', scriptsRouter);        // Public routes
app.use('/api/admin/scripts', scriptsRouter);  // Admin routes (doesn't work as expected)
```

The router with path `/admin/pending` becomes:
- `/api/scripts/admin/pending` ✓ (works)
- `/api/admin/scripts/admin/pending` ❌ (not what we want)

But the client expects `/api/admin/scripts/pending`.

### Root Cause:

Express routers cannot be cleanly mounted at multiple base paths when the route definitions contain nested paths like `/admin/...`. The router paths are relative to the first mount point.

### Solution Options:

**Option 1: Split Public and Admin Routes into Separate Modules** (Recommended)
- Create `scripts-public.js` and `scripts-admin.js`
- Mount at correct base paths
- Clean separation, easy to maintain
- Requires refactoring route modules

**Option 2: Remove `/admin` Prefix from Route Definitions**
- Change `/admin/pending` to `/pending` in route modules
- Mount entire router at `/api/admin/scripts` for admin routes
- Mount at `/api/scripts` for public routes
- Less code changes, but routes become ambiguous

**Option 3: Create Wrapper Routers**
- Keep original route modules
- Create thin wrapper routers that re-export specific routes
- Mount wrappers at correct paths
- More code, but preserves original structure

## Recommended Fix: Option 2 (Minimal Changes)

Change route definitions to remove `/admin` prefix, then mount at appropriate base:

### In `src/server/routes/scripts.js`:
```javascript
// Change from:
router.get('/admin/pending', ...)
router.get('/admin/search', ...)
router.post('/admin/:id/approve', ...)

// To:
router.get('/pending', ...)
router.get('/search', ...)
router.post('/:id/approve', ...)
```

### In `src/server/app.js`:
```javascript
// Public routes (register, status)
app.use('/api/scripts', scriptsRouter);

// Admin routes (pending, approve, reject, etc.)
app.use('/api/admin/scripts', scriptsRouter);
```

This creates both:
- `/api/scripts/register` ✓
- `/api/scripts/status/:hash` ✓
- `/api/admin/scripts/pending` ✓
- `/api/admin/scripts/:id/approve` ✓

Same pattern applies to headers and network routes.

## Impact

- 3 route files need updates (scripts.js, headers.js, network.js)
- 1 app.js already updated (mounting correct)
- Admin panel will work correctly
- Client-side monitors will continue working
- All 43 endpoints will be accessible

## Files to Modify:

1. `src/server/routes/scripts.js` - Remove `/admin` from all admin route paths
2. `src/server/routes/headers.js` - Remove `/admin` from all admin route paths
3. `src/server/routes/network.js` - Remove `/admin` from all admin route paths
4. `src/server/app.js` - Already updated correctly

Total changes: ~15-20 lines across 3 files.
