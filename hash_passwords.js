const bcrypt = require('bcrypt');
const db = require('./db');

async function hashAllPasswords() {
  try {
    const [admins] = await db.pool.query('SELECT id, username, plaintext_password FROM admins WHERE plaintext_password IS NOT NULL');
    console.log('Admins to update:', admins);

    for (const admin of admins) {
      if (admin.plaintext_password) {
        const hashedPassword = await bcrypt.hash(admin.plaintext_password, 10);
        await db.pool.query('UPDATE admins SET password = ? WHERE id = ?', [hashedPassword, admin.id]);
        console.log(`Updated hashed password for ${admin.username}: ${hashedPassword}`);
      }
    }

    console.log('All passwords hashed successfully.');
    process.exit(0);
  } catch (err) {
    console.error('Error hashing passwords:', err);
    process.exit(1);
  }
}

hashAllPasswords();