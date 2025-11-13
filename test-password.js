const bcrypt = require('bcrypt');
const { getDatabase } = require('./database-manager');

async function testPassword() {
  const db = getDatabase({
    type: 'sqlite',
    sqlitePath: './data/integrity-monitor.db'
  });

  await db.initialize();

  // Get the admin user
  const admin = await db.queryOne('SELECT * FROM admin_users WHERE username = ?', ['admin']);

  console.log('Admin user:', {
    username: admin.username,
    email: admin.email,
    password_hash_preview: admin.password_hash.substring(0, 20) + '...'
  });

  // Test password
  const testPassword = 'admin123';
  console.log('\nTesting password:', testPassword);

  const match = await bcrypt.compare(testPassword, admin.password_hash);
  console.log('Password match:', match);

  if (!match) {
    console.log('\nGenerating new hash for comparison...');
    const newHash = await bcrypt.hash(testPassword, 10);
    console.log('New hash:', newHash.substring(0, 20) + '...');
    const newMatch = await bcrypt.compare(testPassword, newHash);
    console.log('New hash match:', newMatch);
  }

  await db.close();
}

testPassword().catch(console.error);
