/**
 * Test Placeholder Conversion
 * Verifies that ? placeholders are correctly converted to $1, $2, $3 for PostgreSQL
 */

// Test the conversion function
function convertPlaceholders(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => {
    index++;
    return `$${index}`;
  });
}

// Test cases
const testCases = [
  {
    name: 'Simple SELECT',
    input: 'SELECT * FROM scripts WHERE id = ?',
    expected: 'SELECT * FROM scripts WHERE id = $1',
    params: [123]
  },
  {
    name: 'Multiple parameters',
    input: 'SELECT * FROM scripts WHERE status = ? AND script_type = ?',
    expected: 'SELECT * FROM scripts WHERE status = $1 AND script_type = $2',
    params: ['pending_approval', 'external']
  },
  {
    name: 'INSERT with multiple values',
    input: 'INSERT INTO scripts (url, content_hash, status) VALUES (?, ?, ?)',
    expected: 'INSERT INTO scripts (url, content_hash, status) VALUES ($1, $2, $3)',
    params: ['/test.js', 'abc123', 'approved']
  },
  {
    name: 'UPDATE with WHERE',
    input: 'UPDATE scripts SET status = ?, approved_by = ? WHERE id = ?',
    expected: 'UPDATE scripts SET status = $1, approved_by = $2 WHERE id = $3',
    params: ['approved', 'admin', 456]
  },
  {
    name: 'Complex query with IN clause',
    input: 'SELECT * FROM scripts WHERE status IN (?, ?, ?) AND first_seen > ?',
    expected: 'SELECT * FROM scripts WHERE status IN ($1, $2, $3) AND first_seen > $4',
    params: ['pending_approval', 'approved', 'rejected', '2025-01-01']
  },
  {
    name: 'No placeholders',
    input: 'SELECT COUNT(*) FROM scripts',
    expected: 'SELECT COUNT(*) FROM scripts',
    params: []
  }
];

console.log('Testing Placeholder Conversion\n');
console.log('='.repeat(80));

let passed = 0;
let failed = 0;

testCases.forEach((test, index) => {
  const result = convertPlaceholders(test.input);
  const success = result === test.expected;

  if (success) {
    passed++;
    console.log(`\n✅ Test ${index + 1}: ${test.name}`);
  } else {
    failed++;
    console.log(`\n❌ Test ${index + 1}: ${test.name}`);
    console.log(`   Input:    ${test.input}`);
    console.log(`   Expected: ${test.expected}`);
    console.log(`   Got:      ${result}`);
  }

  if (success && process.env.VERBOSE) {
    console.log(`   SQLite:     ${test.input}`);
    console.log(`   PostgreSQL: ${result}`);
    console.log(`   Params:     [${test.params.join(', ')}]`);
  }
});

console.log('\n' + '='.repeat(80));
console.log(`\nResults: ${passed} passed, ${failed} failed out of ${testCases.length} tests`);

if (failed === 0) {
  console.log('\n✅ All tests passed! Placeholder conversion works correctly.');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed. Please review the conversion logic.');
  process.exit(1);
}
