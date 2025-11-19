/**
 * Wait for PostgreSQL to be ready
 * Simple connection check using pg package
 */

const { Pool } = require('pg');

const config = {
  host: process.env.PG_HOST || 'localhost',
  port: parseInt(process.env.PG_PORT || '5432'),
  database: process.env.PG_DATABASE || 'script_integrity',
  user: process.env.PG_USER || 'postgres',
  password: process.env.PG_PASSWORD || 'postgres',
  connectionTimeoutMillis: 2000
};

async function waitForPostgres(maxAttempts = 30) {
  const pool = new Pool(config);
  
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const client = await pool.connect();
      await client.query('SELECT NOW()');
      client.release();
      await pool.end();
      console.log('PostgreSQL is ready!');
      return;
    } catch (error) {
      if (i < maxAttempts - 1) {
        console.log(`PostgreSQL is unavailable (attempt ${i + 1}/${maxAttempts}) - waiting...`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      } else {
        console.error('PostgreSQL failed to become ready:', error.message);
        await pool.end();
        process.exit(1);
      }
    }
  }
}

waitForPostgres().catch(error => {
  console.error('Error waiting for PostgreSQL:', error.message);
  process.exit(1);
});

