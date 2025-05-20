const bcrypt = require('bcrypt');
const db = require('./db');

async function hashAdmin3Password() {
  try {
    const [admins] = await db.pool.query('SELECT id, username, plaintext_password FROM admins WHERE id = 3');
    if (admins.length === 0) {
      console.log('Admin with ID 3 not found.');
      process.exit(1);
    }

    const admin = admins[0];
    if (!admin.plaintext_password) {
      console.log('No plaintext password set for admin with ID 3.');
      process.exit(1);
    }

    const hashedPassword = await bcrypt.hash(admin.plaintext_password, 10);
    await db.pool.query('UPDATE admins SET password = ? WHERE id = ?', [hashedPassword, admin.id]);
    console.log(`Updated hashed password for admin with ID 3: ${hashedPassword}`);

    process.exit(0);
  } catch (err) {
    console.error('Error hashing password:', err);
    process.exit(1);
  }
}

hashAdmin3Password();