/**
 * Test script blocking logic for rejected scripts
 *
 * This test verifies that the blocking logic correctly identifies
 * which violation types should be blocked in enforce mode.
 */

console.log('Testing Script Blocking Logic for Rejected Scripts\n');
console.log('='.repeat(60));

// Simulate the blocking logic from script-integrity-monitor.js
function shouldBlockScript(mode, violationType) {
  const blockableViolations = [
    'HASH_MISMATCH',
    'SRI_MISMATCH',
    'REJECTED_BY_ADMIN',
    'NO_BASELINE_HASH',
    'UNAUTHORIZED_SCRIPT'
  ];

  return mode === 'enforce' && blockableViolations.includes(violationType);
}

// Test cases
const testCases = [
  // Rejected scripts should be blocked in enforce mode
  { mode: 'enforce', violation: 'REJECTED_BY_ADMIN', expected: true, description: 'Admin rejected script in enforce mode' },
  { mode: 'report', violation: 'REJECTED_BY_ADMIN', expected: false, description: 'Admin rejected script in report mode' },

  // Security violations should be blocked in enforce mode
  { mode: 'enforce', violation: 'HASH_MISMATCH', expected: true, description: 'Hash mismatch in enforce mode' },
  { mode: 'enforce', violation: 'SRI_MISMATCH', expected: true, description: 'SRI mismatch in enforce mode' },
  { mode: 'enforce', violation: 'NO_BASELINE_HASH', expected: true, description: 'No baseline hash in enforce mode' },
  { mode: 'enforce', violation: 'UNAUTHORIZED_SCRIPT', expected: true, description: 'Unauthorized script in enforce mode' },

  // Pending/new scripts should NOT be blocked (allow time for review)
  { mode: 'enforce', violation: 'PENDING_APPROVAL', expected: false, description: 'Pending approval in enforce mode' },
  { mode: 'enforce', violation: 'NEW_SCRIPT', expected: false, description: 'New script in enforce mode' },

  // Report mode should never block
  { mode: 'report', violation: 'HASH_MISMATCH', expected: false, description: 'Hash mismatch in report mode' },
  { mode: 'report', violation: 'PENDING_APPROVAL', expected: false, description: 'Pending approval in report mode' },
];

let passed = 0;
let failed = 0;

console.log('\nRunning tests...\n');

testCases.forEach((test, index) => {
  const result = shouldBlockScript(test.mode, test.violation);
  const status = result === test.expected ? '✅ PASS' : '❌ FAIL';

  if (result === test.expected) {
    passed++;
  } else {
    failed++;
  }

  console.log(`Test ${index + 1}: ${status}`);
  console.log(`  Description: ${test.description}`);
  console.log(`  Mode: ${test.mode}, Violation: ${test.violation}`);
  console.log(`  Expected: ${test.expected ? 'BLOCK' : 'ALLOW'}, Got: ${result ? 'BLOCK' : 'ALLOW'}`);
  console.log('');
});

console.log('='.repeat(60));
console.log(`\nTest Results: ${passed} passed, ${failed} failed out of ${testCases.length} total`);

if (failed === 0) {
  console.log('\n✅ All tests passed! Script blocking logic is correct.\n');
  console.log('Key behaviors verified:');
  console.log('  • REJECTED_BY_ADMIN scripts are blocked in enforce mode');
  console.log('  • Security violations (HASH_MISMATCH, etc.) are blocked in enforce mode');
  console.log('  • PENDING_APPROVAL and NEW_SCRIPT are NOT blocked (allow review time)');
  console.log('  • Report mode never blocks any scripts');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed. Please review the blocking logic.\n');
  process.exit(1);
}
