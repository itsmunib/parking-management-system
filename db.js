const mysql = require('mysql2');
require('dotenv').config();

// Parse CLEARDB_DATABASE_URL if available (Heroku), otherwise use local .env variables
const parseDatabaseUrl = (url) => {
  if (!url) return null;
  const regex = /mysql:\/\/([^:]+):([^@]+)@([^/]+)\/(.+)\?.*/;
  const match = url.match(regex);
  if (match) {
    return {
      user: match[1],
      password: match[2],
      host: match[3],
      database: match[4]
    };
  }
  return null;
};

// Use CLEARDB_DATABASE_URL if available and in production, otherwise fall back to .env
const dbConfig = process.env.NODE_ENV === 'production' && process.env.CLEARDB_DATABASE_URL
  ? parseDatabaseUrl(process.env.CLEARDB_DATABASE_URL)
  : {
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASS || '',
      database: process.env.DB_NAME || 'parking_system'
    };

// Only log in development for debugging
if (process.env.NODE_ENV !== 'production') {
  console.log('Database Configuration:', {
    host: dbConfig.host,
    user: dbConfig.user,
    database: dbConfig.database
  });
}

const pool = mysql.createPool(dbConfig);

// Set the database time zone to PKT (UTC+5)
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Failed to connect to database:', err.message);
    return;
  }
  console.log('Successfully connected to database');

  // Set time zone to PKT
  connection.query("SET time_zone = '+05:00';", (err) => {
    if (err) {
      console.error('Error setting database time zone to PKT:', err.message);
      connection.release();
      return;
    }
    console.log('Database time zone set to PKT (UTC+5)');
    connection.release();
  });
});

// Wrapper to handle tenant-specific queries
const tenantQuery = async (sql, params, lotId) => {
  let modifiedSql = sql;
  let modifiedParams = params || [];

  if (lotId) {
    // Determine the type of query
    const queryType = sql.trim().split(/\s+/)[0].toUpperCase();

    // For SELECT, UPDATE, DELETE: Add lot_id condition
    if (['SELECT', 'UPDATE', 'DELETE'].includes(queryType)) {
      if (sql.includes('vehicle_categories') || sql.includes('entries') || sql.includes('exits')) {
        const whereIndex = sql.toLowerCase().indexOf('where');
        if (whereIndex !== -1) {
          modifiedSql = `${sql.substring(0, whereIndex + 5)} lot_id = ? AND ${sql.substring(whereIndex + 6)}`;
        } else {
          modifiedSql = `${sql} WHERE lot_id = ?`;
        }
        modifiedParams = [lotId, ...modifiedParams];
      }
    }
    // For INSERT: lot_id should already be in params, so no modification needed
    // Ensure the caller includes lot_id in the params list
  }

  try {
    return await pool.promise().query(modifiedSql, modifiedParams);
  } catch (err) {
    console.error('Database query error:', err.message);
    throw err;
  }
};

module.exports = {
  query: tenantQuery,
  pool: pool.promise()
};