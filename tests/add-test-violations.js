const { DatabaseManager } = require('./database-manager');

async function addViolations() {
  const db = new DatabaseManager();
  await db.initialize();

  console.log('Adding test violations...');

  // Add violations for script ID 1 (jquery)
  await db.query(
    `INSERT INTO integrity_violations 
     (script_url, violation_type, old_hash, new_hash, page_url, severity)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      'https://cdn.example.com/jquery-3.6.0.min.js',
      'HASH_MISMATCH',
      'sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK',
      'sha384-DIFFERENT_HASH_12345',
      'https://example.com/checkout',
      'HIGH'
    ]
  );

  await db.query(
    `INSERT INTO integrity_violations 
     (script_url, violation_type, old_hash, new_hash, page_url, severity)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      'https://cdn.example.com/jquery-3.6.0.min.js',
      'HASH_MISMATCH',
      'sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK',
      'sha384-ANOTHER_HASH_67890',
      'https://example.com/checkout',
      'HIGH'
    ]
  );

  // Add violations for script ID 2 (payment-widget)
  await db.query(
    `INSERT INTO integrity_violations 
     (script_url, violation_type, new_hash, page_url, severity)
     VALUES (?, ?, ?, ?, ?)`,
    [
      'https://cdn.example.com/payment-widget.js',
      'NEW_SCRIPT',
      'sha384-AbCdEf1234567890aBcDeF1234567890AbCdEf1234567890aBcDeF1234567890',
      'https://example.com/checkout',
      'MEDIUM'
    ]
  );

  console.log('✓ Added 3 test violations');
  
  await db.close();
}

addViolations().catch(console.error);
