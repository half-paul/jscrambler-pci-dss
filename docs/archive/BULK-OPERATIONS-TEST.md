# Bulk Operations Testing Guide

## Test Setup

1. **Server is running**: Port 3000
2. **Sample data added**: 3 pending scripts, 2 approved scripts
3. **Admin credentials**: username: `admin`, password: `admin123`

## Test URL

Open: http://localhost:3000/admin-panel.html

## Quick Manual Test

1. Log in to admin panel
2. Click "Pending Approvals" tab
3. You should see 3 pending scripts with checkboxes
4. Click a checkbox - bulk actions bar should appear
5. Click "Select All" - all 3 should be selected
6. Click "Bulk Approve" - follow prompts
7. Verify scripts are approved and list refreshes

## Success Criteria

✅ Checkboxes appear in pending approvals table
✅ Bulk actions bar shows when scripts selected
✅ "Select All" selects all checkboxes
✅ "Select None" clears all checkboxes
✅ Header checkbox works (check/uncheck all)
✅ Bulk Approve works and refreshes list
✅ Bulk Reject works and refreshes list
✅ Selection count updates correctly
✅ No console errors

Test completed successfully! ✅
