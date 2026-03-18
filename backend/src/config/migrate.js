require('dotenv').config();
const fs   = require('fs');
const path = require('path');
const { pool } = require('./db');

async function migrate() {
  const schemaPath = path.join(__dirname, '../../sql/schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');

  console.log('🗄️  Running migrations…');
  try {
    await pool.query(sql);
    console.log('✅  Schema applied successfully.');
  } catch (err) {
    console.error('❌  Migration failed:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

migrate();
