const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');
const fs = require('fs');
const webPush = require('web-push');
const activeSessions = new Map(); // Map<userId, Set<sessionId>>
require('dotenv').config();
// Set Node.js time zone to Karachi (PKT, UTC+5)
process.env.TZ = 'Asia/Karachi';

const app = express();

// VAPID keys for Web Push (generate these once and reuse)
const vapidKeys = {
  publicKey: process.env.VAPID_PUBLIC_KEY || 'your-vapid-public-key',
  privateKey: process.env.VAPID_PRIVATE_KEY || 'your-vapid-private-key'
};

webPush.setVapidDetails(
  'mailto:your-email@example.com',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'default-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (requires HTTPS)
      httpOnly: true, // Prevent client-side access to cookies
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  })
);

app.use((req, res, next) => {
  if (req.session && req.session.admin && req.session.admin.id) {
    const userId = req.session.admin.id.toString();
    const sessionId = req.sessionID;
    if (!activeSessions.has(userId)) {
      activeSessions.set(userId, new Set());
    }
    activeSessions.get(userId).add(sessionId);
    // Clean up on session destroy
    res.on('finish', () => {
      if (req.session && req.session.destroyed) {
        activeSessions.get(userId)?.delete(sessionId);
        if (activeSessions.get(userId)?.size === 0) {
          activeSessions.delete(userId);
        }
      }
    });
  }
  next();
});

// Authentication middleware
const isAuthenticated = async (req, res, next) => {
  console.log('isAuthenticated middleware called', { sessionAdmin: req.session.admin, sessionId: req.sessionID });
  if (req.session.admin) {
    try {
      const userId = req.session.admin.id.toString();
      const sessionId = req.sessionID;
      console.log('Checking session validity:', { userId, sessionId, activeSessionsForUser: activeSessions.has(userId) ? Array.from(activeSessions.get(userId)) : null });
      // Check if this session is still valid
      if (activeSessions.has(userId) && activeSessions.get(userId).has(sessionId)) {
        // Fetch the latest admin data from the database
        const [admins] = await db.pool.query('SELECT * FROM admins WHERE id = ?', [req.session.admin.id]);
        console.log('Fetched admin from database:', admins);
        if (admins.length === 0) {
          console.log('Admin no longer exists, destroying session');
          req.session.destroy(err => {
            if (err) {
              console.error('Error destroying session:', err);
            }
            activeSessions.get(userId)?.delete(sessionId);
            if (activeSessions.get(userId)?.size === 0) {
              activeSessions.delete(userId);
            }
            res.redirect('/login');
          });
          return;
        }

        const admin = admins[0];
        // Check if username or password has changed
        const usernameMatches = admin.username === req.session.admin.username;
        let passwordMatches = true; // Default to true to avoid immediate invalidation after login
        if (req.session.admin.plaintext_password) {
          // If plaintext_password exists in the session, verify it against the database
          passwordMatches = await bcrypt.compare(req.session.admin.plaintext_password, admin.password);
        } else {
          // If plaintext_password is not set, assume credentials are invalid
          passwordMatches = false;
        }
        console.log('Credential check:', { usernameMatches, passwordMatches });
        if (!usernameMatches || !passwordMatches) {
          console.log(`Session invalidated for admin ID ${userId} due to ${!usernameMatches ? 'username' : ''}${!usernameMatches && !passwordMatches ? ' and ' : ''}${!passwordMatches ? 'password' : ''} change`);
          req.session.destroy(err => {
            if (err) {
              console.error('Error destroying session:', err);
            }
            activeSessions.get(userId)?.delete(sessionId);
            if (activeSessions.get(userId)?.size === 0) {
              activeSessions.delete(userId);
            }
            res.redirect('/login');
          });
          return;
        }

        // Update the session with the latest admin data, but preserve plaintext_password
        const plaintextPassword = req.session.admin.plaintext_password;
        req.session.admin = admin;
        req.session.admin.plaintext_password = plaintextPassword;
        if (typeof req.session.admin.permissions === 'string') {
          try {
            req.session.admin.permissions = JSON.parse(req.session.admin.permissions);
          } catch (err) {
            console.error('Error parsing permissions:', err);
            req.session.admin.permissions = { entry: false, exit: false, manage: false, profile: false, add_admin: false };
          }
        } else if (!req.session.admin.permissions) {
          req.session.admin.permissions = { entry: false, exit: false, manage: false, profile: false, add_admin: false };
        }
        console.log('Authenticated user:', { username: req.session.admin.username, permissions: req.session.admin.permissions });
        next();
      } else {
        console.log('Session not found in activeSessions, destroying session');
        req.session.destroy(err => {
          if (err) {
            console.error('Error destroying session:', err);
          }
          res.redirect('/login');
        });
      }
    } catch (err) {
      console.error('Error in isAuthenticated middleware:', err);
      fs.writeFileSync('server.log', `Error in isAuthenticated middleware: ${err}\n`, { flag: 'a' });
      req.session.destroy(err => {
        if (err) {
          console.error('Error destroying session:', err);
        }
        res.redirect('/login');
      });
    }
  } else {
    console.log('No admin session found, redirecting to login');
    res.redirect('/login');
  }
};

// Permission middleware
const hasPermission = (permission) => (req, res, next) => {
  const user = req.session.admin;
  const permissions = user.permissions || {};
  console.log('Checking permission:', { user: user.username, permission, permissions });

  // Allow super admin to access all routes regardless of permissions
  if (user.username === 'superadmin') {
    console.log('Super admin access granted for:', { user: user.username, permission });
    next();
    return;
  }

  // Enforce permission check for other users
  if (permissions[permission] === true) {
    next();
  } else {
    console.log('Permission denied, redirecting to /dashboard');
    res.redirect('/dashboard');
  }
};

const invalidateUserSessions = (userId, currentSessionId) => {
  userId = userId.toString();
  if (activeSessions.has(userId)) {
    const sessionIds = activeSessions.get(userId);
    sessionIds.forEach(sessionId => {
      if (sessionId !== currentSessionId) { // Don't invalidate the super admin's session
        sessionIds.delete(sessionId);
      }
    });
    if (sessionIds.size === 0) {
      activeSessions.delete(userId);
    }
  }
};

// Validation Functions
const validateUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9]{3,20}$/;
  if (!usernameRegex.test(username)) {
    return 'Username must be 3-20 characters and contain only letters and numbers';
  }
  return null;
};

const validatePassword = (password) => {
  if (password.length < 8) {
    return 'Password must be at least 8 characters long';
  }
  return null;
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return 'Invalid email format';
  }
  return null;
};

const validateCategoryName = (name) => {
  const nameRegex = /^[a-zA-Z0-9\s]{1,50}$/;
  if (!nameRegex.test(name)) {
    return 'Category name must be 1-50 characters and contain only letters, numbers, and spaces';
  }
  return null;
};

const validateTotalSpaces = (total_spaces) => {
  const num = Number(total_spaces);
  if (!Number.isInteger(num) || num < 1) {
    return 'Total spaces must be a positive integer';
  }
  return null;
};

const validateSpacesPerVehicle = (spaces_per_vehicle) => {
  const num = Number(spaces_per_vehicle);
  if (!Number.isInteger(num) || num < 1) {
    return 'Spaces per vehicle must be a positive integer';
  }
  return null;
};

const validatePricingType = (pricing_type) => {
  if (!['hourly', 'per-entry'].includes(pricing_type)) {
    return 'Pricing type must be "hourly" or "per-entry"';
  }
  return null;
};

const validatePrice = (price) => {
  const num = Number(price);
  if (isNaN(num) || num < 0) {
    return 'Price must be a positive number';
  }
  return null;
};

const validateNumberPlate = (number_plate) => {
  const plateRegex = /^[A-Z0-9]{3,10}$/;
  if (!plateRegex.test(number_plate)) {
    return 'Number plate must be 3-10 characters and contain only uppercase letters and numbers (e.g., ABC123)';
  }
  return null;
};

const validateOwnerName = (owner_name) => {
  if (owner_name && owner_name.length > 0) {
    const nameRegex = /^[a-zA-Z\s]{1,50}$/;
    if (!nameRegex.test(owner_name)) {
      return 'Owner name must be 1-50 characters and contain only letters and spaces';
    }
  }
  return null;
};

const validatePhone = (phone) => {
  if (phone && phone.length > 0) {
    const phoneRegex = /^\d{10,15}$/;
    if (!phoneRegex.test(phone)) {
      return 'Phone number must be 10-15 digits';
    }
  }
  return null;
};

// Redirect root URL to /dashboard
app.get('/', isAuthenticated, (req, res) => {
  console.log('GET / - Redirecting to /dashboard');
  res.redirect('/dashboard');
});

// Login Routes
app.get('/login', (req, res) => {
  console.log('GET /login');
  res.render('login', { error: null, success: null, user: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('POST /login:', { username, password: password ? '[REDACTED]' : 'Not provided' });
  try {
    const [rows] = await db.pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    console.log('Database user:', rows);
    if (rows.length > 0) {
      const match = await bcrypt.compare(password, rows[0].password);
      console.log('Password match result:', match);
      if (match) {
        if (typeof rows[0].permissions === 'string') {
          rows[0].permissions = JSON.parse(rows[0].permissions);
        }
        console.log('Parsed permissions:', rows[0].permissions);
        // Store the plaintext password in the session and database
        rows[0].plaintext_password = password;
        req.session.admin = rows[0];
        console.log('Session admin set:', req.session.admin);
        // Update the plaintext_password in the database
        await db.pool.query('UPDATE admins SET plaintext_password = ? WHERE id = ?', [password, rows[0].id]);
        console.log('Updated plaintext_password in database for user:', username);
        // Explicitly save the session before redirecting
        req.session.save(err => {
          if (err) {
            console.error('Error saving session:', err);
            fs.writeFileSync('server.log', `Error saving session: ${err}\n`, { flag: 'a' });
            res.render('login', { error: 'Server error', success: null, user: null });
          } else {
            res.redirect('/');
          }
        });
      } else {
        console.log('Invalid credentials for:', username);
        res.render('login', { error: 'Invalid credentials', success: null, user: null });
      }
    } else {
      console.log('User not found:', username);
      res.render('login', { error: 'Invalid credentials', success: null, user: null });
    }
  } catch (err) {
    console.error('Login error:', err);
    fs.writeFileSync('server.log', `Login error: ${err}\n`, { flag: 'a' });
    res.render('login', { error: 'Server error', success: null, user: null });
  }
});

// Dashboard Route
app.get('/dashboard', isAuthenticated, async (req, res) => {
  console.log('GET /dashboard');
  try {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');

    const user = req.session.admin;
    const filter = req.query.filter || 'today';
    let dateCondition = '';
    let graphLabels = [];
    let vehiclesData = [];
    let earningsData = [];
    let earningsChange = 0;
    let recentActivity = [];
    let quickStats = { avgEarningsPerVehicle: 0, busiestPeriod: 'N/A', busiestCount: 0 };

    // Set current date and time in PKT (Node.js is already in PKT)
    const currentTime = new Date(); // 06:56 AM PKT on May 23, 2025
    const year = currentTime.getFullYear();
    const month = String(currentTime.getMonth() + 1).padStart(2, '0');
    const day = String(currentTime.getDate()).padStart(2, '0');
    const todayPKTDateStr = `${year}-${month}-${day}`; // e.g., "2025-05-23"
    console.log('Current date and time (PKT):', currentTime);

    // Adjust date condition and prepare graph data
    if (filter === 'weekly') {
      dateCondition = `>= DATE_SUB('${todayPKTDateStr}', INTERVAL 7 DAY)`;
      // Generate labels for the past 7 days (e.g., "May 17", "May 18", ..., "May 23")
      for (let i = 6; i >= 0; i--) {
        const date = new Date(currentTime);
        date.setDate(currentTime.getDate() - i);
        const label = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        graphLabels.push(label);
      }
      // Fetch daily vehicle counts (non-exited + exited)
      for (let i = 6; i >= 0; i--) {
        const date = new Date(currentTime);
        date.setDate(currentTime.getDate() - i);
        const dateStr = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
        const dailyCondition = `BETWEEN '${dateStr} 00:00:00' AND '${dateStr} 23:59:59'`;
        const [nonExited] = await db.pool.query(
          `SELECT COUNT(*) as count FROM entries WHERE entry_time ${dailyCondition}`
        );
        const [exited] = await db.pool.query(
          `SELECT COUNT(*) as count FROM exits WHERE exit_time ${dailyCondition}`
        );
        const [dailyEarnings] = await db.pool.query(
          `SELECT COALESCE(SUM(cost), 0) as total FROM exits WHERE exit_time ${dailyCondition}`
        );
        vehiclesData.push((nonExited[0].count || 0) + (exited[0].count || 0));
        earningsData.push(Number(dailyEarnings[0].total) || 0);
      }
      // Calculate earnings for the previous 7-day period (May 10–16)
      const prevStartDate = new Date(currentTime);
      prevStartDate.setDate(currentTime.getDate() - 13);
      const prevEndDate = new Date(currentTime);
      prevEndDate.setDate(currentTime.getDate() - 7);
      const prevStartStr = `${prevStartDate.getFullYear()}-${String(prevStartDate.getMonth() + 1).padStart(2, '0')}-${String(prevStartDate.getDate()).padStart(2, '0')}`;
      const prevEndStr = `${prevEndDate.getFullYear()}-${String(prevEndDate.getMonth() + 1).padStart(2, '0')}-${String(prevEndDate.getDate()).padStart(2, '0')}`;
      const prevCondition = `BETWEEN '${prevStartStr} 00:00:00' AND '${prevEndStr} 23:59:59'`;
      const [prevEarnings] = await db.pool.query(
        `SELECT COALESCE(SUM(cost), 0) as total FROM exits WHERE exit_time ${prevCondition}`
      );
      const currentEarnings = earningsData.reduce((sum, val) => sum + val, 0);
      const prevEarningsValue = Number(prevEarnings[0].total) || 0;
      earningsChange = prevEarningsValue > 0 ? ((currentEarnings - prevEarningsValue) / prevEarningsValue) * 100 : currentEarnings > 0 ? 100 : 0;

      // Find the busiest day (most vehicles)
      let maxVehicles = 0;
      let busiestDay = 'N/A';
      for (let i = 0; i < graphLabels.length; i++) {
        if (vehiclesData[i] > maxVehicles) {
          maxVehicles = vehiclesData[i];
          busiestDay = graphLabels[i];
        }
      }
      quickStats.busiestPeriod = busiestDay;
      quickStats.busiestCount = maxVehicles;
    } else if (filter === 'monthly') {
      dateCondition = `>= DATE_SUB('${todayPKTDateStr}', INTERVAL 30 DAY)`;
      // Generate labels for the past 30 days (e.g., "Apr 24", "Apr 25", ..., "May 23")
      for (let i = 29; i >= 0; i--) {
        const date = new Date(currentTime);
        date.setDate(currentTime.getDate() - i);
        const label = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        graphLabels.push(label);
      }
      // Fetch daily vehicle counts
      for (let i = 29; i >= 0; i--) {
        const date = new Date(currentTime);
        date.setDate(currentTime.getDate() - i);
        const dateStr = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
        const dailyCondition = `BETWEEN '${dateStr} 00:00:00' AND '${dateStr} 23:59:59'`;
        const [nonExited] = await db.pool.query(
          `SELECT COUNT(*) as count FROM entries WHERE entry_time ${dailyCondition}`
        );
        const [exited] = await db.pool.query(
          `SELECT COUNT(*) as count FROM exits WHERE exit_time ${dailyCondition}`
        );
        const [dailyEarnings] = await db.pool.query(
          `SELECT COALESCE(SUM(cost), 0) as total FROM exits WHERE exit_time ${dailyCondition}`
        );
        vehiclesData.push((nonExited[0].count || 0) + (exited[0].count || 0));
        earningsData.push(Number(dailyEarnings[0].total) || 0);
      }
      // Calculate earnings for the previous 30-day period (Mar 25–Apr 23)
      const prevStartDate = new Date(currentTime);
      prevStartDate.setDate(currentTime.getDate() - 59);
      const prevEndDate = new Date(currentTime);
      prevEndDate.setDate(currentTime.getDate() - 30);
      const prevStartStr = `${prevStartDate.getFullYear()}-${String(prevStartDate.getMonth() + 1).padStart(2, '0')}-${String(prevStartDate.getDate()).padStart(2, '0')}`;
      const prevEndStr = `${prevEndDate.getFullYear()}-${String(prevEndDate.getMonth() + 1).padStart(2, '0')}-${String(prevEndDate.getDate()).padStart(2, '0')}`;
      const prevCondition = `BETWEEN '${prevStartStr} 00:00:00' AND '${prevEndStr} 23:59:59'`;
      const [prevEarnings] = await db.pool.query(
        `SELECT COALESCE(SUM(cost), 0) as total FROM exits WHERE exit_time ${prevCondition}`
      );
      const currentEarnings = earningsData.reduce((sum, val) => sum + val, 0);
      const prevEarningsValue = Number(prevEarnings[0].total) || 0;
      earningsChange = prevEarningsValue > 0 ? ((currentEarnings - prevEarningsValue) / prevEarningsValue) * 100 : currentEarnings > 0 ? 100 : 0;

      // Find the busiest day
      let maxVehicles = 0;
      let busiestDay = 'N/A';
      for (let i = 0; i < graphLabels.length; i++) {
        if (vehiclesData[i] > maxVehicles) {
          maxVehicles = vehiclesData[i];
          busiestDay = graphLabels[i];
        }
      }
      quickStats.busiestPeriod = busiestDay;
      quickStats.busiestCount = maxVehicles;
    } else {
      // Past 24 hours: From 06:56 AM on May 22 to 06:56 AM on May 23
      const startTime = new Date(currentTime.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago
      const endTime = new Date(currentTime); // Current time

      // Format the date condition for the past 24 hours
      const startStr = `${startTime.getFullYear()}-${String(startTime.getMonth() + 1).padStart(2, '0')}-${String(startTime.getDate()).padStart(2, '0')} ${String(startTime.getHours()).padStart(2, '0')}:${String(startTime.getMinutes()).padStart(2, '0')}:${String(startTime.getSeconds()).padStart(2, '0')}`;
      const endStr = `${endTime.getFullYear()}-${String(endTime.getMonth() + 1).padStart(2, '0')}-${String(endTime.getDate()).padStart(2, '0')} ${String(endTime.getHours()).padStart(2, '0')}:${String(endTime.getMinutes()).padStart(2, '0')}:${String(endTime.getSeconds()).padStart(2, '0')}`;
      dateCondition = `BETWEEN '${startStr}' AND '${endStr}'`;

      // Generate labels for the past 24 hours
      for (let i = 23; i >= 0; i--) {
        const hour = new Date(currentTime.getTime() - i * 60 * 60 * 1000);
        const label = hour.toLocaleString('en-US', { 
          month: 'short', 
          day: 'numeric', 
          hour: '2-digit', 
          hour12: false 
        }).replace(',', '');
        graphLabels.push(label);
      }

      // Fetch hourly vehicle counts for the past 24 hours
      for (let i = 23; i >= 0; i--) {
        const hourStart = new Date(currentTime.getTime() - i * 60 * 60 * 1000);
        const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000 - 1000); // End of the hour
        const hourStartStr = `${hourStart.getFullYear()}-${String(hourStart.getMonth() + 1).padStart(2, '0')}-${String(hourStart.getDate()).padStart(2, '0')} ${String(hourStart.getHours()).padStart(2, '0')}:${String(hourStart.getMinutes()).padStart(2, '0')}:${String(hourStart.getSeconds()).padStart(2, '0')}`;
        const hourEndStr = `${hourEnd.getFullYear()}-${String(hourEnd.getMonth() + 1).padStart(2, '0')}-${String(hourEnd.getDate()).padStart(2, '0')} ${String(hourEnd.getHours()).padStart(2, '0')}:${String(hourEnd.getMinutes()).padStart(2, '0')}:${String(hourEnd.getSeconds()).padStart(2, '0')}`;
        const hourCondition = `BETWEEN '${hourStartStr}' AND '${hourEndStr}'`;
        const [nonExited] = await db.pool.query(
          `SELECT COUNT(*) as count FROM entries WHERE entry_time ${hourCondition}`
        );
        const [exited] = await db.pool.query(
          `SELECT COUNT(*) as count FROM exits WHERE exit_time ${hourCondition}`
        );
        const [hourlyEarnings] = await db.pool.query(
          `SELECT COALESCE(SUM(cost), 0) as total FROM exits WHERE exit_time ${hourCondition}`
        );
        vehiclesData.push((nonExited[0].count || 0) + (exited[0].count || 0));
        earningsData.push(Number(hourlyEarnings[0].total) || 0);
      }

      // Calculate earnings for the previous 24-hour period (May 21 06:56 to May 22 06:56)
      const prevStartTime = new Date(currentTime.getTime() - 48 * 60 * 60 * 1000); // 48 hours ago
      const prevEndTime = new Date(currentTime.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago
      const prevStartStr = `${prevStartTime.getFullYear()}-${String(prevStartTime.getMonth() + 1).padStart(2, '0')}-${String(prevStartTime.getDate()).padStart(2, '0')} ${String(prevStartTime.getHours()).padStart(2, '0')}:${String(prevStartTime.getMinutes()).padStart(2, '0')}:${String(prevStartTime.getSeconds()).padStart(2, '0')}`;
      const prevEndStr = `${prevEndTime.getFullYear()}-${String(prevEndTime.getMonth() + 1).padStart(2, '0')}-${String(prevEndTime.getDate()).padStart(2, '0')} ${String(prevEndTime.getHours()).padStart(2, '0')}:${String(prevEndTime.getMinutes()).padStart(2, '0')}:${String(prevEndTime.getSeconds()).padStart(2, '0')}`;
      const prevCondition = `BETWEEN '${prevStartStr}' AND '${prevEndStr}'`;
      const [prevEarnings] = await db.pool.query(
        `SELECT COALESCE(SUM(cost), 0) as total FROM exits WHERE exit_time ${prevCondition}`
      );
      const currentEarnings = earningsData.reduce((sum, val) => sum + val, 0);
      const prevEarningsValue = Number(prevEarnings[0].total) || 0;
      earningsChange = prevEarningsValue > 0 ? ((currentEarnings - prevEarningsValue) / prevEarningsValue) * 100 : currentEarnings > 0 ? 100 : 0;

      // Find the busiest hour
      let maxVehicles = 0;
      let busiestHour = 'N/A';
      for (let i = 0; i < graphLabels.length; i++) {
        if (vehiclesData[i] > maxVehicles) {
          maxVehicles = vehiclesData[i];
          busiestHour = graphLabels[i];
        }
      }
      quickStats.busiestPeriod = busiestHour;
      quickStats.busiestCount = maxVehicles;
    }

    // Debug: Fetch recent entries to verify entry_time
    const [recentEntries] = await db.pool.query(
      `SELECT entry_time FROM entries ORDER BY entry_time DESC LIMIT 5`
    );
    console.log('Recent entries:', recentEntries);

    // Debug: Fetch recent exits
    const [recentExits] = await db.pool.query(
      `SELECT number_plate, exit_time, cost FROM exits ORDER BY exit_time DESC LIMIT 5`
    );
    console.log('Recent exits:', recentExits);

    // Count non-exited entries for the selected period
    const [nonExitedVehicles] = await db.pool.query(
      `SELECT COUNT(*) as count FROM entries WHERE entry_time ${dateCondition}`
    );

    // Count exited vehicles by querying the exits table
    const [exitedVehicles] = await db.pool.query(
      `SELECT COUNT(*) as count FROM exits WHERE exit_time ${dateCondition}`
    );

    // Total vehicles = non-exited + exited
    const totalVehicles = (nonExitedVehicles[0].count || 0) + (exitedVehicles[0].count || 0);

    // Debug: Fetch entries and exits that should match the condition
    const [matchingEntries] = await db.pool.query(
      `SELECT entry_time FROM entries WHERE entry_time ${dateCondition}`
    );
    console.log('Non-exited entries matching filter:', matchingEntries);

    const [matchingExits] = await db.pool.query(
      `SELECT number_plate, exit_time FROM exits WHERE exit_time ${dateCondition}`
    );
    console.log('Exited entries matching filter:', matchingExits);

    // Fetch earnings for the selected period
    const [earnings] = await db.pool.query(
      `SELECT COALESCE(SUM(x.cost), 0) as total FROM exits x WHERE exit_time ${dateCondition}`
    );

    // Fetch currently parked vehicles (only non-exited entries remain in the table)
    const [parkedVehicles] = await db.pool.query(
      `SELECT e.category_id, vc.spaces_per_vehicle 
       FROM entries e 
       JOIN vehicle_categories vc ON e.category_id = vc.id
       WHERE e.status = 'Active'`
    );

    // Fetch total spaces from parking lot
    const [lot] = await db.pool.query('SELECT total_spaces FROM parking_lot WHERE id = 1');

    // Fetch recent activity (last 3 entries and exits combined)
    const [recentEntriesActivity] = await db.pool.query(
      `SELECT 'Entry' as action, number_plate as vehicle_number, entry_time as time, 'Entered' as details 
       FROM entries 
       ORDER BY entry_time DESC LIMIT 5`
    );
    const [recentExitsActivity] = await db.pool.query(
      `SELECT 'Exit' as action, number_plate as vehicle_number, exit_time as time, CONCAT('Cost: PKR ', cost) as details 
       FROM exits 
       ORDER BY exit_time DESC LIMIT 5`
    );
    // Combine and sort by time (descending), limit to 3
    recentActivity = [...recentEntriesActivity, ...recentExitsActivity]
      .sort((a, b) => new Date(b.time) - new Date(a.time))
      .slice(0, 3);

    // Calculate quick stats
    const totalEarnings = Number(earnings[0].total) || 0;
    quickStats.avgEarningsPerVehicle = totalVehicles > 0 ? (totalEarnings / totalVehicles).toFixed(2) : 0;

    const totalSpaces = lot.length > 0 ? Number(lot[0].total_spaces) || 0 : 0;
    const totalUsedSpaces = parkedVehicles.reduce((sum, vehicle) => {
      return sum + (Number(vehicle.spaces_per_vehicle) || 1);
    }, 0);
    const parkedCount = parkedVehicles.length;
    const available = totalSpaces - totalUsedSpaces;

    console.log('Dashboard queries:', { 
      totalVehicles, 
      nonExitedVehicles: nonExitedVehicles[0].count, 
      exitedVehicles: exitedVehicles[0].count, 
      earnings: earnings[0].total, 
      parkedCount, 
      totalUsedSpaces, 
      totalSpaces, 
      available,
      earningsChange,
      recentActivity,
      quickStats
    });

    const renderData = {
      vehicles: totalVehicles,
      earnings: totalEarnings,
      available,
      parked: parkedCount,
      totalSpaces,
      filter,
      error: null,
      success: null,
      user,
      graphData: {
        labels: graphLabels,
        vehicles: vehiclesData,
        earnings: earningsData
      },
      earningsChange: earningsChange.toFixed(1),
      recentActivity,
      quickStats
    };
    console.log('Rendering dashboard with:', renderData);

    res.render('dashboard', renderData);
  } catch (err) {
    console.error('Dashboard error:', err);
    fs.writeFileSync('server.log', `Dashboard error: ${err}\n`, { flag: 'a' });
    res.render('dashboard', {
      vehicles: 0,
      earnings: 0,
      available: 0,
      parked: 0,
      totalSpaces: 0,
      filter: 'today',
      error: 'Server error: ' + err.message,
      success: null,
      user: req.session.admin,
      hardRefresh: null,
      graphData: { labels: [], vehicles: [], earnings: [] },
      earningsChange: 0,
      recentActivity: [],
      quickStats: { avgEarningsPerVehicle: 0, busiestPeriod: 'N/A', busiestCount: 0 }
    });
  }
});

// Profile Routes
app.get('/profile', isAuthenticated, hasPermission('profile'), async (req, res) => {
  console.log('GET /profile');
  console.log('User accessing profile:', { username: req.session.admin.username, permissions: req.session.admin.permissions });
  try {
    const user = req.session.admin;
    res.render('profile', { admin: user, error: null, success: null, validationErrors: [], user });
  } catch (err) {
    console.error('Profile error:', err);
    fs.writeFileSync('server.log', `Profile error: ${err}\n`, { flag: 'a' });
    res.render('profile', { admin: req.session.admin, error: 'Server error: ' + err.message, success: null, validationErrors: [], user: req.session.admin });
  }
});

app.post('/profile', isAuthenticated, hasPermission('profile'), async (req, res) => {
  console.log('POST /profile');
  console.log('User accessing profile:', { username: req.session.admin.username, permissions: req.session.admin.permissions });
  const user = req.session.admin;
  const { username, email, password } = req.body;
  console.log('POST /profile:', { username, email, password: password ? '[REDACTED]' : 'Not provided' });

  const validationErrors = [];
  const usernameError = validateUsername(username);
  const emailError = validateEmail(email);
  let passwordError = null;
  if (password) {
    passwordError = validatePassword(password);
  }

  if (usernameError) validationErrors.push(usernameError);
  if (emailError) validationErrors.push(emailError);
  if (passwordError) validationErrors.push(passwordError);

  const [duplicateUsername] = await db.pool.query('SELECT id FROM admins WHERE username = ? AND id != ?', [username, user.id]);
  if (duplicateUsername.length > 0) {
    validationErrors.push('Username already exists');
  }
  const [duplicateEmail] = await db.pool.query('SELECT id FROM admins WHERE email = ? AND id != ?', [email, user.id]);
  if (duplicateEmail.length > 0) {
    validationErrors.push('Email already exists');
  }

  if (validationErrors.length > 0) {
    return res.render('profile', { admin: user, error: null, success: null, validationErrors, user });
  }

  try {
    let hashedPassword = user.password;
    let plaintextPassword = user.plaintext_password;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
      plaintextPassword = password;
    }

    await db.pool.query(
      'UPDATE admins SET username = ?, email = ?, password = ?, plaintext_password = ? WHERE id = ?',
      [username, email, hashedPassword, plaintextPassword, user.id]
    );

    // Refresh the session with updated admin data
    const [updatedAdmin] = await db.pool.query('SELECT * FROM admins WHERE id = ?', [user.id]);
    req.session.admin = updatedAdmin[0];
    if (typeof req.session.admin.permissions === 'string') {
      req.session.admin.permissions = JSON.parse(req.session.admin.permissions);
    }

    res.render('profile', { admin: req.session.admin, error: null, success: 'Profile updated successfully', validationErrors: [], user: req.session.admin });
  } catch (err) {
    console.error('Update profile error:', err);
    fs.writeFileSync('server.log', `Update profile error: ${err}\n`, { flag: 'a' });
    res.render('profile', { admin: req.session.admin, error: 'Failed to update profile: ' + err.message, success: null, validationErrors: [], user: req.session.admin });
  }
});

// Manage Routes
app.get('/manage', isAuthenticated, hasPermission('manage'), async (req, res) => {
  console.log('GET /manage');
  try {
    const user = req.session.admin;
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    console.log('Manage data:', { categories: formattedCategories });
    res.render('manage', { categories: formattedCategories, error: null, success: null, editCategory: null, validationErrors: [], user });
  } catch (err) {
    console.error('Manage error:', err);
    fs.writeFileSync('server.log', `Manage error: ${err}\n`, { flag: 'a' });
    res.render('manage', { categories: [], error: 'Server error', success: null, editCategory: null, validationErrors: [], user: req.session.admin });
  }
});

app.post('/manage/set-lot-spaces', isAuthenticated, hasPermission('manage'), async (req, res) => {
  const user = req.session.admin;
  const { total_spaces } = req.body;
  console.log('POST /manage/set-lot-spaces:', { total_spaces });

  const validationErrors = [];
  const spacesError = validateTotalSpaces(total_spaces);

  if (spacesError) validationErrors.push(spacesError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    return res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: null, 
      editCategory: null, 
      validationErrors,
      user
    });
  }

  let usedSpaces = 0;
  try {
    const [lot] = await db.pool.query('SELECT used_spaces FROM parking_lot WHERE id = 1');
    usedSpaces = lot.length > 0 && lot[0].used_spaces !== undefined ? Number(lot[0].used_spaces) || 0 : 0;
    const newTotalSpaces = Number(total_spaces);

    if (newTotalSpaces < usedSpaces) {
      const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
      const formattedCategories = categories.map(category => ({
        ...category,
        price: Number(category.price) || 0,
        spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
      }));
      validationErrors.push(`Total spaces (${newTotalSpaces}) cannot be less than used spaces (${usedSpaces})`);
      return res.render('manage', { 
        categories: formattedCategories, 
        error: null, 
        success: null, 
        editCategory: null, 
        validationErrors,
        user
      });
    }

    await db.pool.query(
      'INSERT INTO parking_lot (id, total_spaces, used_spaces) VALUES (1, ?, ?) ON DUPLICATE KEY UPDATE total_spaces = ?',
      [newTotalSpaces, usedSpaces, newTotalSpaces]
    );

    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: 'Total spaces updated successfully', 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  } catch (err) {
    console.error('Set lot spaces error:', err);
    fs.writeFileSync('server.log', `Set lot spaces error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to set total spaces: ' + err.message, 
      success: null, 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  }
});

app.post('/manage/add-category', isAuthenticated, hasPermission('manage'), async (req, res) => {
  const user = req.session.admin;
  const { name, spaces_per_vehicle, pricing_type, price } = req.body;
  console.log('POST /manage/add-category:', { name, spaces_per_vehicle, pricing_type, price });
  
  const validationErrors = [];
  const nameError = validateCategoryName(name);
  const spacesPerVehicleError = validateSpacesPerVehicle(spaces_per_vehicle);
  const pricingError = validatePricingType(pricing_type);
  const priceError = validatePrice(price);

  if (nameError) validationErrors.push(nameError);
  if (spacesPerVehicleError) validationErrors.push(spacesPerVehicleError);
  if (pricingError) validationErrors.push(pricingError);
  if (priceError) validationErrors.push(priceError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    return res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: null, 
      editCategory: null, 
      validationErrors,
      user
    });
  }

  try {
    await db.pool.query(
      'INSERT INTO vehicle_categories (name, spaces_per_vehicle, pricing_type, price) VALUES (?, ?, ?, ?)',
      [name, spaces_per_vehicle, pricing_type, price]
    );
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: 'Category added successfully', 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  } catch (err) {
    console.error('Add category error:', err);
    fs.writeFileSync('server.log', `Add category error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to add category', 
      success: null, 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  }
});

app.get('/manage/edit/:id', isAuthenticated, hasPermission('manage'), async (req, res) => {
  const user = req.session.admin;
  const { id } = req.params;
  console.log('GET /manage/edit/:id:', { id });
  try {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const [category] = await db.pool.query('SELECT * FROM vehicle_categories WHERE id = ?', [id]);
    if (category.length === 0) {
      const formattedCategories = categories.map(cat => ({
        ...cat,
        price: Number(cat.price) || 0,
        spaces_per_vehicle: Number(cat.spaces_per_vehicle) || 1
      }));
      return res.render('manage', { 
        categories: formattedCategories, 
        error: 'Category not found', 
        success: null, 
        editCategory: null, 
        validationErrors: [], 
        user
      });
    }
    const formattedCategories = categories.map(cat => ({
      ...cat,
      price: Number(cat.price) || 0,
      spaces_per_vehicle: Number(cat.spaces_per_vehicle) || 1
    }));
    const formattedCategory = { 
      ...category[0], 
      price: Number(category[0].price) || 0,
      spaces_per_vehicle: Number(category[0].spaces_per_vehicle) || 1
    };
    res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: null, 
      editCategory: formattedCategory, 
      validationErrors: [], 
      user
    });
  } catch (err) {
    console.error('Edit category fetch error:', err);
    fs.writeFileSync('server.log', `Edit category fetch error: ${err}\n`, { flag: 'a' });
    res.render('manage', { 
      categories: [], 
      error: 'Server error', 
      success: null, 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  }
});

app.post('/manage/edit/:id', isAuthenticated, hasPermission('manage'), async (req, res) => {
  const user = req.session.admin;
  const { id } = req.params;
  const { name, spaces_per_vehicle, pricing_type, price } = req.body;
  console.log('POST /manage/edit/:id:', { id, name, spaces_per_vehicle, pricing_type, price });

  const validationErrors = [];
  const nameError = validateCategoryName(name);
  const spacesPerVehicleError = validateSpacesPerVehicle(spaces_per_vehicle);
  const pricingError = validatePricingType(pricing_type);
  const priceError = validatePrice(price);

  if (nameError) validationErrors.push(nameError);
  if (spacesPerVehicleError) validationErrors.push(spacesPerVehicleError);
  if (pricingError) validationErrors.push(pricingError);
  if (priceError) validationErrors.push(priceError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    return res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: null, 
      editCategory: { id, name, spaces_per_vehicle, pricing_type, price: Number(price) || 0 }, 
      validationErrors,
      user
    });
  }

  try {
    await db.pool.query(
      'UPDATE vehicle_categories SET name = ?, spaces_per_vehicle = ?, pricing_type = ?, price = ? WHERE id = ?',
      [name, spaces_per_vehicle, pricing_type, price, id]
    );
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: 'Category updated successfully', 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  } catch (err) {
    console.error('Edit category update error:', err);
    fs.writeFileSync('server.log', `Edit category update error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to update category: ' + err.message, 
      success: null, 
      editCategory: { id, name, spaces_per_vehicle, pricing_type, price: Number(price) || 0 },
      validationErrors: [],
      user
    });
  }
});

app.post('/manage/delete/:id', isAuthenticated, hasPermission('manage'), async (req, res) => {
  const user = req.session.admin;
  const { id } = req.params;
  console.log('POST /manage/delete/:id:', { id });
  try {
    const [entries] = await db.pool.query(
      'SELECT * FROM entries WHERE category_id = ? AND CAST(id AS SIGNED) NOT IN (SELECT CAST(entry_id AS SIGNED) FROM exits WHERE entry_id IS NOT NULL)',
      [id]
    );
    console.log('Entries blocking deletion:', entries);
    if (entries.length > 0) {
      const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
      const formattedCategories = categories.map(category => ({
        ...category,
        price: Number(category.price) || 0,
        spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
      }));
      return res.render('manage', { 
        categories: formattedCategories, 
        error: 'Cannot delete category: it is in use by existing entries that have not exited', 
        success: null, 
        editCategory: null, 
        validationErrors: [], 
        user
      });
    }

    try {
      await db.pool.query('ALTER TABLE entries DROP FOREIGN KEY entries_ibfk_1');
      console.log('Dropped foreign key constraint entries_ibfk_1');
    } catch (err) {
      console.warn('Foreign key constraint entries_ibfk_1 may not exist:', err.message);
    }

    try {
      await db.pool.query('ALTER TABLE exits DROP FOREIGN KEY exits_ibfk_1');
      console.log('Dropped foreign key constraint exits_ibfk_1');
    } catch (err) {
      console.warn('Foreign key constraint exits_ibfk_1 may not exist:', err.message);
    }

    const [deleteEntriesResult] = await db.pool.query(
      'DELETE FROM entries WHERE category_id = ?',
      [id]
    );
    console.log('Deleted entries for category:', { category_id: id, affectedRows: deleteEntriesResult.affectedRows });

    const [deleteCategoryResult] = await db.pool.query('DELETE FROM vehicle_categories WHERE id = ?', [id]);
    console.log('Deleted category:', { category_id: id, affectedRows: deleteCategoryResult.affectedRows });

    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      success: 'Category deleted successfully', 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  } catch (err) {
    console.error('Delete category error:', err.message, err.stack);
    fs.writeFileSync('server.log', `Delete category error: ${err.message}\n${err.stack}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0,
      spaces_per_vehicle: Number(category.spaces_per_vehicle) || 1
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to delete category: ' + err.message, 
      success: null, 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  }
});

// Public Routes
app.get('/public', async (req, res) => {
  console.log('GET /public');
  try {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const [lot] = await db.pool.query('SELECT * FROM parking_lot WHERE id = 1');
    const formattedLot = lot.length > 0 ? {
      total_spaces: Number(lot[0].total_spaces) || 0,
      used_spaces: Number(lot[0].used_spaces) || 0
    } : { total_spaces: 0, used_spaces: 0 };
    const available = formattedLot.total_spaces - formattedLot.used_spaces;
    const lotDetails = { categories, available, totalSpaces: formattedLot.total_spaces };
    res.render('public-parking', { lots: [lotDetails], error: null, success: null, validationErrors: [], autofill: {}, user: null });
  } catch (err) {
    console.error('Public page error:', err);
    fs.writeFileSync('server.log', `Public page error: ${err}\n`, { flag: 'a' });
    res.render('public-parking', { lots: [], error: 'Server error', success: null, validationErrors: [], autofill: {}, user: null });
  }
});

app.post('/public/park', async (req, res) => {
  const { number_plate, owner_name, phone, category_id } = req.body;
  console.log('POST /public/park:', { number_plate, owner_name, phone, category_id });

  const validationErrors = [];
  const plateError = validateNumberPlate(number_plate);
  const ownerError = validateOwnerName(owner_name);
  const phoneError = validatePhone(phone);

  let categoryError = null;
  const [categoryCheck] = await db.pool.query('SELECT id, spaces_per_vehicle FROM vehicle_categories WHERE id = ?', [category_id]);
  const [lot] = await db.pool.query('SELECT total_spaces, used_spaces FROM parking_lot WHERE id = 1');
  if (categoryCheck.length === 0) {
    categoryError = 'Selected category does not exist';
  } else if (lot.length === 0) {
    categoryError = 'Parking lot configuration not found';
  } else {
    const spacesPerVehicle = Number(categoryCheck[0].spaces_per_vehicle) || 1;
    const totalSpaces = Number(lot[0].total_spaces) || 0;
    const usedSpaces = Number(lot[0].used_spaces) || 0;
    const availableSpaces = totalSpaces - usedSpaces;
    if (availableSpaces < spacesPerVehicle) {
      categoryError = `Not enough spaces available in the lot. Required: ${spacesPerVehicle}, Available: ${availableSpaces}`;
    }
  }

  if (plateError) validationErrors.push(plateError);
  if (ownerError) validationErrors.push(ownerError);
  if (phoneError) validationErrors.push(phoneError);
  if (categoryError) validationErrors.push(categoryError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const [lotData] = await db.pool.query('SELECT * FROM parking_lot WHERE id = 1');
    const formattedLot = lotData.length > 0 ? {
      total_spaces: Number(lotData[0].total_spaces) || 0,
      used_spaces: Number(lotData[0].used_spaces) || 0
    } : { total_spaces: 0, used_spaces: 0 };
    const available = formattedLot.total_spaces - formattedLot.used_spaces;
    const lotDetails = { categories, available, totalSpaces: formattedLot.total_spaces };
    return res.render('public-parking', { 
      lots: [lotDetails], 
      error: null, 
      success: null,
      validationErrors,
      autofill: { number_plate, owner_name, phone, category_id },
      user: null
    });
  }

  try {
    const connection = await db.pool.getConnection();
    try {
      await connection.beginTransaction();

      const [entryResult] = await connection.query(
        'INSERT INTO entries (number_plate, owner_name, phone, category_id, entry_time) VALUES (?, ?, ?, ?, NOW())',
        [number_plate, owner_name || null, phone || null, category_id]
      );
      const entryId = entryResult.insertId;

      const spacesPerVehicle = Number(categoryCheck[0].spaces_per_vehicle) || 1;
      await connection.query(
        'UPDATE parking_lot SET used_spaces = used_spaces + ? WHERE id = 1',
        [spacesPerVehicle]
      );

      await connection.commit();
      connection.release();

      if (req.session.subscription) {
        const payload = JSON.stringify({
          title: 'Vehicle Parked',
          body: `Your vehicle ${number_plate} has been parked.`
        });
        await webPush.sendNotification(req.session.subscription, payload);
      }

      const ticketContent = `
        <div style="text-align: center; font-family: Arial, sans-serif; padding: 20px;">
          <h2>Parking System</h2>
          <h4>Entry Ticket</h4>
          <p><strong>Vehicle Number:</strong> ${number_plate}</p>
          <p><strong>Entry Time:</strong> ${new Date().toLocaleString()}</p>
        </div>
      `;

      // Serve as HTML, let client-side script handle PDF generation
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Entry Ticket</title>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
        </head>
        <body>
          <div id="ticket">${ticketContent}</div>
          <script>
            const element = document.getElementById('ticket');
            html2pdf().from(element).save('entry_ticket_${number_plate}_${Date.now()}.pdf');
            setTimeout(() => { window.location.href = '/public'; }, 1000);
          </script>
        </body>
        </html>
      `);
    } catch (err) {
      await connection.rollback();
      connection.release();
      throw err;
    }
  } catch (err) {
    console.error('Public park error:', err);
    fs.writeFileSync('server.log', `Public park error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const [lotData] = await db.pool.query('SELECT * FROM parking_lot WHERE id = 1');
    const formattedLot = lotData.length > 0 ? {
      total_spaces: Number(lotData[0].total_spaces) || 0,
      used_spaces: Number(lotData[0].used_spaces) || 0
    } : { total_spaces: 0, used_spaces: 0 };
    const available = formattedLot.total_spaces - formattedLot.used_spaces;
    const lotDetails = { categories, available, totalSpaces: formattedLot.total_spaces };
    res.render('public-parking', { 
      lots: [lotDetails], 
      error: 'Failed to park vehicle: ' + err.message, 
      success: null,
      validationErrors: [],
      autofill: { number_plate, owner_name, phone, category_id },
      user: null
    });
  }
});

// Entry Routes
app.get('/entry', isAuthenticated, hasPermission('entry'), async (req, res) => {
  console.log('GET /entry');
  try {
    const [categories] = await db.pool.query('SELECT id, name, spaces_per_vehicle FROM vehicle_categories');
    
    // Calculate available spaces for each category
    const [parkedVehicles] = await db.pool.query(`
      SELECT e.category_id, vc.spaces_per_vehicle 
      FROM entries e 
      JOIN vehicle_categories vc ON e.category_id = vc.id
      WHERE e.status = 'Active'
    `);

    const usedSpacesByCategory = {};
    parkedVehicles.forEach(vehicle => {
      const catId = vehicle.category_id;
      usedSpacesByCategory[catId] = (usedSpacesByCategory[catId] || 0) + (Number(vehicle.spaces_per_vehicle) || 1);
    });

    const [lot] = await db.pool.query('SELECT total_spaces FROM parking_lot WHERE id = 1');
    const totalSpaces = lot.length > 0 ? Number(lot[0].total_spaces) || 0 : 0;

    const totalUsedSpaces = Object.values(usedSpacesByCategory).reduce((sum, spaces) => sum + spaces, 0);
    const totalAvailable = totalSpaces - totalUsedSpaces;

    categories.forEach(category => {
      const usedForThisCategory = usedSpacesByCategory[category.id] || 0;
      const maxVehiclesForCategory = Math.floor(totalAvailable / (Number(category.spaces_per_vehicle) || 1));
      category.available_spaces = Math.max(0, maxVehiclesForCategory);
    });

    res.render('entry', {
      categories,
      error: null,
      success: null,
      user: req.session.admin,
      validationErrors: [],
      autofill: { number_plate: '', owner_name: '', phone: '', category_id: '' },
      receipt: null
    });
  } catch (err) {
    console.error('Entry error:', err);
    fs.writeFileSync('server.log', `Entry error: ${err}\n`, { flag: 'a' });
    res.render('entry', {
      categories: [],
      error: 'Server error: ' + err.message,
      success: null,
      user: req.session.admin,
      validationErrors: [],
      autofill: { number_plate: '', owner_name: '', phone: '', category_id: '' },
      receipt: null
    });
  }
});

app.post('/entry', isAuthenticated, hasPermission('entry'), async (req, res) => {
  console.log('POST /entry');
  const { number_plate, owner_name, phone, category_id } = req.body;

  try {
    // Validate inputs
    const validationErrors = [];
    if (!number_plate || number_plate.trim() === '') {
      validationErrors.push('Number Plate is required');
    }
    if (!category_id || isNaN(category_id)) {
      validationErrors.push('Vehicle Category is required');
    }

    if (validationErrors.length > 0) {
      const [categories] = await db.pool.query('SELECT id, name, spaces_per_vehicle FROM vehicle_categories');
      
      // Calculate available spaces for each category
      const [parkedVehicles] = await db.pool.query(`
        SELECT e.category_id, vc.spaces_per_vehicle 
        FROM entries e 
        JOIN vehicle_categories vc ON e.category_id = vc.id
        WHERE e.status = 'Active'
      `);

      const usedSpacesByCategory = {};
      parkedVehicles.forEach(vehicle => {
        const catId = vehicle.category_id;
        usedSpacesByCategory[catId] = (usedSpacesByCategory[catId] || 0) + (Number(vehicle.spaces_per_vehicle) || 1);
      });

      const [lot] = await db.pool.query('SELECT total_spaces FROM parking_lot WHERE id = 1');
      const totalSpaces = lot.length > 0 ? Number(lot[0].total_spaces) || 0 : 0;

      const totalUsedSpaces = Object.values(usedSpacesByCategory).reduce((sum, spaces) => sum + spaces, 0);
      const totalAvailable = totalSpaces - totalUsedSpaces;

      categories.forEach(category => {
        const usedForThisCategory = usedSpacesByCategory[category.id] || 0;
        const maxVehiclesForCategory = Math.floor(totalAvailable / (Number(category.spaces_per_vehicle) || 1));
        category.available_spaces = Math.max(0, maxVehiclesForCategory);
      });

      return res.render('entry', {
        categories,
        error: null,
        success: null,
        user: req.session.admin,
        validationErrors,
        autofill: { number_plate, owner_name, phone, category_id },
        receipt: null
      });
    }

    // Fetch category details to check available spaces
    const [category] = await db.pool.query('SELECT name, spaces_per_vehicle FROM vehicle_categories WHERE id = ?', [category_id]);
    if (category.length === 0) {
      throw new Error('Category not found');
    }

    const { name: category_name, spaces_per_vehicle } = category[0];
    console.log('Category details:', { category_id, category_name, spaces_per_vehicle });

    // Fetch current parked vehicles to calculate used spaces
    const [parkedVehicles] = await db.pool.query(`
      SELECT e.category_id, vc.spaces_per_vehicle 
      FROM entries e 
      JOIN vehicle_categories vc ON e.category_id = vc.id
      WHERE e.status = 'Active'
    `);
    console.log('Parked vehicles:', parkedVehicles);
    console.log('Number of active entries:', parkedVehicles.length);

    const totalUsedSpaces = parkedVehicles.reduce((sum, vehicle) => {
      const spaces = Number(vehicle.spaces_per_vehicle) || 1;
      console.log('Vehicle spaces:', { category_id: vehicle.category_id, spaces });
      return sum + spaces;
    }, 0);
    console.log('Total used spaces:', totalUsedSpaces);

    const [lot] = await db.pool.query('SELECT total_spaces FROM parking_lot WHERE id = 1');
    const totalSpaces = lot.length > 0 ? Number(lot[0].total_spaces) || 0 : 0;
    console.log('Total spaces:', totalSpaces);

    const available = totalSpaces - totalUsedSpaces;
    console.log('Available spaces:', available);

    if (available < spaces_per_vehicle) {
      const [categories] = await db.pool.query('SELECT id, name, spaces_per_vehicle FROM vehicle_categories');

      // Recalculate available spaces for error case
      const [parkedVehiclesError] = await db.pool.query(`
        SELECT e.category_id, vc.spaces_per_vehicle 
        FROM entries e 
        JOIN vehicle_categories vc ON e.category_id = vc.id
        WHERE e.status = 'Active'
      `);

      const usedSpacesByCategoryError = {};
      parkedVehiclesError.forEach(vehicle => {
        const catId = vehicle.category_id;
        usedSpacesByCategoryError[catId] = (usedSpacesByCategoryError[catId] || 0) + (Number(vehicle.spaces_per_vehicle) || 1);
      });

      const totalUsedSpacesError = Object.values(usedSpacesByCategoryError).reduce((sum, spaces) => sum + spaces, 0);
      const totalAvailableError = totalSpaces - totalUsedSpacesError;

      categories.forEach(category => {
        const usedForThisCategory = usedSpacesByCategoryError[category.id] || 0;
        const maxVehiclesForCategory = Math.floor(totalAvailableError / (Number(category.spaces_per_vehicle) || 1));
        category.available_spaces = Math.max(0, maxVehiclesForCategory);
      });

      return res.render('entry', {
        categories,
        error: `Not enough parking spaces available. Total spaces (${totalSpaces}) cannot be less than used spaces (${totalUsedSpaces})`,
        success: null,
        user: req.session.admin,
        validationErrors: [],
        autofill: { number_plate, owner_name, phone, category_id },
        receipt: null
      });
    }

    // Insert the entry with all fields
    const entry_time = new Date();
    const added_by = req.session.admin.username;
    const [result] = await db.pool.query(
      'INSERT INTO entries (number_plate, entry_time, owner_name, phone, category_id, added_by, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [number_plate.trim().toUpperCase(), entry_time, owner_name || null, phone || null, category_id, added_by, 'Active']
    );

    const receiptNumber = result.insertId;

    const [categories] = await db.pool.query('SELECT id, name, spaces_per_vehicle FROM vehicle_categories');

    // Recalculate available spaces for success case
    const [parkedVehiclesSuccess] = await db.pool.query(`
      SELECT e.category_id, vc.spaces_per_vehicle 
      FROM entries e 
      JOIN vehicle_categories vc ON e.category_id = vc.id
      WHERE e.status = 'Active'
    `);

    const usedSpacesByCategorySuccess = {};
    parkedVehiclesSuccess.forEach(vehicle => {
      const catId = vehicle.category_id;
      usedSpacesByCategorySuccess[catId] = (usedSpacesByCategorySuccess[catId] || 0) + (Number(vehicle.spaces_per_vehicle) || 1);
    });

    const totalUsedSpacesSuccess = Object.values(usedSpacesByCategorySuccess).reduce((sum, spaces) => sum + spaces, 0);
    const totalAvailableSuccess = totalSpaces - totalUsedSpacesSuccess;

    categories.forEach(category => {
      const usedForThisCategory = usedSpacesByCategorySuccess[category.id] || 0;
      const maxVehiclesForCategory = Math.floor(totalAvailableSuccess / (Number(category.spaces_per_vehicle) || 1));
      category.available_spaces = Math.max(0, maxVehiclesForCategory);
    });

    // Prepare receipt data
    const receipt = {
      receipt_number: receiptNumber,
      date: entry_time.toLocaleString('en-US', { timeZone: 'Asia/Karachi' }),
      vehicle_number: number_plate.trim().toUpperCase(),
      entry_time: entry_time.toLocaleString('en-US', { timeZone: 'Asia/Karachi' }),
      category: category_name,
      owner_name: owner_name || 'N/A',
      phone: phone || 'N/A',
      added_by: added_by || 'Unknown'
    };

    console.log('Receipt data:', receipt);

    res.render('entry', {
      categories,
      error: null,
      success: 'Vehicle entry added successfully',
      user: req.session.admin,
      validationErrors: [],
      autofill: { number_plate: '', owner_name: '', phone: '', category_id: '' },
      receipt
    });
  } catch (err) {
    console.error('Entry error:', err);
    fs.writeFileSync('server.log', `Entry error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT id, name, spaces_per_vehicle FROM vehicle_categories');
    res.render('entry', {
      categories,
      error: 'Server error: ' + err.message,
      success: null,
      user: req.session.admin,
      validationErrors: [],
      autofill: { number_plate, owner_name, phone, category_id },
      receipt: null
    });
  }
});

// Exit Routes
app.get('/exit', isAuthenticated, hasPermission('exit'), async (req, res) => {
  console.log('GET /exit');
  try {
    const [entries] = await db.pool.query(`
      SELECT e.id, e.number_plate, e.entry_time, e.owner_name, e.phone, vc.name as category 
      FROM entries e 
      JOIN vehicle_categories vc ON e.category_id = vc.id
      WHERE e.status = 'Active'
    `);
    res.render('exit', { entries, error: null, success: null, user: req.session.admin, receipt: null });
  } catch (err) {
    console.error('Exit error:', err);
    fs.writeFileSync('server.log', `Exit error: ${err}\n`, { flag: 'a' });
    res.render('exit', { entries: [], error: 'Server error: ' + err.message, success: null, user: req.session.admin, receipt: null });
  }
});

app.get('/exit/download', isAuthenticated, hasPermission('exit'), async (req, res) => {
  console.log('GET /exit/download');
  try {
    const [exits] = await db.pool.query(`
      SELECT e.number_plate, e.entry_time, e.owner_name, e.phone, vc.name as category, x.exit_time, x.cost
      FROM exits x
      JOIN entries e ON x.entry_id = e.id
      JOIN vehicle_categories vc ON e.category_id = vc.id
    `);

    const csv = exits.map(exit => {
      return `${exit.number_plate},${exit.entry_time},${exit.owner_name || 'N/A'},${exit.phone || 'N/A'},${exit.category},${exit.exit_time},${exit.cost}`;
    }).join('\n');

    res.header('Content-Type', 'text/csv');
    res.attachment('exits.csv');
    res.send(`Number Plate,Entry Time,Owner Name,Phone,Category,Exit Time,Cost\n${csv}`);
  } catch (err) {
    console.error('Exit download error:', err);
    fs.writeFileSync('server.log', `Exit download error: ${err}\n`, { flag: 'a' });
    res.status(500).send('Server error: ' + err.message);
  }
});

app.post('/exit', isAuthenticated, hasPermission('exit'), async (req, res) => {
  console.log('POST /exit');
  const { entry_id } = req.body;

  try {
    // Fetch the entry
    console.log('Fetching entry with ID:', entry_id);
    const [entry] = await db.pool.query('SELECT number_plate, entry_time, category_id, owner_name, phone, added_by FROM entries WHERE id = ?', [entry_id]);
    if (entry.length === 0) {
      console.log('Entry not found for ID:', entry_id);
      return res.render('exit', { 
        entries: [], 
        error: 'Entry not found', 
        success: null, 
        user: req.session.admin,
        receipt: null
      });
    }

    const { number_plate, entry_time, category_id, owner_name, phone, added_by } = entry[0];
    const exit_time = new Date();

    // Fetch the pricing details for the category
    console.log('Fetching category with ID:', category_id);
    const [category] = await db.pool.query('SELECT name, pricing_type, price FROM vehicle_categories WHERE id = ?', [category_id]);
    if (category.length === 0) {
      console.log('Category not found for ID:', category_id);
      return res.render('exit', { 
        entries: [], 
        error: 'Category not found', 
        success: null, 
        user: req.session.admin,
        receipt: null
      });
    }

    const { name: category_name, pricing_type, price } = category[0];
    console.log('Pricing details:', { pricing_type, price, typeOfPrice: typeof price });

    // Validate price
    const parsedPrice = Number(price);
    if (isNaN(parsedPrice)) {
      console.log('Invalid price value:', price);
      throw new Error('Invalid price value in vehicle category');
    }

    let cost = 0;
    let durationHours = 0;

    // Calculate duration and cost
    const entryDate = new Date(entry_time);
    durationHours = Math.ceil((exit_time - entryDate) / (1000 * 60 * 60)); // Duration in hours
    if (pricing_type === 'hourly') {
      cost = durationHours * parsedPrice;
    } else {
      cost = parsedPrice;
    }

    console.log('Calculated cost:', cost, typeof cost);

    // Insert into exits table with number_plate
    console.log('Inserting into exits table:', { entry_id, number_plate, exit_time, cost });
    const [result] = await db.pool.query('INSERT INTO exits (entry_id, number_plate, exit_time, cost) VALUES (?, ?, ?, ?)', [entry_id, number_plate, exit_time, cost]);
    const receiptNumber = result.insertId; // Get the auto-incremented ID of the exit record

    // Update the entry status to 'Exited'
    console.log('Updating entry status to Exited for ID:', entry_id);
    await db.pool.query('UPDATE entries SET status = "Exited" WHERE id = ?', [entry_id]);

    // Fetch remaining active entries (status = 'Active')
    console.log('Fetching remaining active entries');
    const [entries] = await db.pool.query(`
      SELECT e.id, e.number_plate, e.entry_time, e.owner_name, e.phone, vc.name as category 
      FROM entries e 
      JOIN vehicle_categories vc ON e.category_id = vc.id
      WHERE e.status = 'Active'
    `);

    // Prepare receipt data with additional details
    const receipt = {
      receipt_number: receiptNumber,
      date: exit_time.toLocaleString('en-US', { timeZone: 'Asia/Karachi' }),
      vehicle_number: number_plate,
      entry_time: entryDate.toLocaleString('en-US', { timeZone: 'Asia/Karachi' }),
      exit_time: exit_time.toLocaleString('en-US', { timeZone: 'Asia/Karachi' }),
      duration: durationHours,
      cost: cost.toFixed(2),
      category: category_name,
      owner_name: owner_name || 'N/A',
      phone: phone || 'N/A',
      added_by: added_by || 'Unknown'
    };

    console.log('Receipt data:', receipt);

    res.render('exit', { 
      entries, 
      error: null, 
      success: 'Vehicle exit processed successfully', 
      user: req.session.admin,
      receipt
    });
  } catch (err) {
    console.error('Exit error:', err);
    fs.writeFileSync('server.log', `Exit error: ${err}\n`, { flag: 'a' });
    res.render('exit', { 
      entries: [], 
      error: 'Server error: ' + err.message, 
      success: null, 
      user: req.session.admin,
      receipt: null
    });
  }
});

// Add Admin Routes
app.get('/add-admin', isAuthenticated, hasPermission('add_admin'), (req, res) => {
  console.log('GET /add-admin');
  const user = req.session.admin;
  res.render('add-admin', { error: null, success: null, validationErrors: [], user });
});

app.post('/add-admin', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  const user = req.session.admin;
  const { username, password, email, can_entry, can_exit, can_manage, can_profile } = req.body;
  console.log('POST /add-admin:', { username, email, can_entry, can_exit, can_manage, can_profile });

  const validationErrors = [];
  const usernameError = validateUsername(username);
  const passwordError = validatePassword(password);
  const emailError = validateEmail(email);

  if (usernameError) validationErrors.push(usernameError);
  if (passwordError) validationErrors.push(passwordError);
  if (emailError) validationErrors.push(emailError);

  if (validationErrors.length > 0) {
    return res.render('add-admin', { error: null, success: null, validationErrors, user });
  }

  try {
    if (!username || !password || !email) {
      console.log('Missing fields');
      return res.render('add-admin', { error: 'All fields are required', success: null, validationErrors: [], user });
    }

    const [existing] = await db.pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    if (existing.length > 0) {
      console.log('Username exists:', username);
      return res.render('add-admin', { error: 'Username already exists', success: null, validationErrors: [], user });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const permissions = {
      entry: can_entry === 'on',
      exit: can_exit === 'on',
      manage: can_manage === 'on',
      profile: can_profile === 'on',
      add_admin: false
    };
    await db.pool.query(
      'INSERT INTO admins (username, password, plaintext_password, email, permissions) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPassword, password, email, JSON.stringify(permissions)]
    );
    console.log('Admin added:', { username, permissions });
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Add admin error:', err);
    fs.writeFileSync('server.log', `Add admin error: ${err}\n`, { flag: 'a' });
    res.render('add-admin', { error: 'Failed to add admin', success: null, validationErrors: [], user });
  }
});

// Manage Admins Routes
app.get('/manage-admins', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  console.log('GET /manage-admins');
  try {
    const user = req.session.admin;
    const [admins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE username != ?', [user.username]);
    // Parse permissions for each admin and set a default if null or invalid
    const parsedAdmins = admins.map(admin => {
      let parsedPermissions = { entry: false, exit: false, manage: false, profile: false, add_admin: false };
      if (admin.permissions) {
        try {
          parsedPermissions = { ...parsedPermissions, ...JSON.parse(admin.permissions) };
        } catch (err) {
          console.error(`Error parsing permissions for admin ${admin.username}:`, err);
        }
      }
      return { ...admin, permissions: parsedPermissions };
    });
    console.log('Admins list:', parsedAdmins);
    res.render('manage-admins', { admins: parsedAdmins, error: null, success: null, user });
  } catch (err) {
    console.error('Manage admins error:', err);
    fs.writeFileSync('server.log', `Manage admins error: ${err}\n`, { flag: 'a' });
    res.render('manage-admins', { admins: [], error: 'Server error: ' + err.message, success: null, user: req.session.admin });
  }
});

app.get('/manage-admins/confirm-delete/:id', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  console.log('GET /manage-admins/confirm-delete/:id');
  const user = req.session.admin;
  const { id } = req.params;
  try {
    const [admins] = await db.pool.query('SELECT id, username, email FROM admins WHERE id = ? AND username != ?', [id, user.username]);
    console.log('Fetched admin for deletion confirmation:', admins);
    if (admins.length === 0) {
      console.log('Admin not found for ID:', id);
      const [allAdmins] = await db.pool.query('SELECT id, username, email FROM admins WHERE username != ?', [user.username]);
      return res.render('manage-admins', { admins: allAdmins, error: 'Admin not found or cannot delete yourself', success: null, user });
    }
    const adminToDelete = admins[0];
    res.render('confirm-delete-admin', { admin: adminToDelete, error: null, success: null, user });
  } catch (err) {
    console.error('Confirm delete admin error:', err);
    fs.writeFileSync('server.log', `Confirm delete admin error: ${err}\n`, { flag: 'a' });
    const [admins] = await db.pool.query('SELECT id, username, email FROM admins WHERE username != ?', [user.username]);
    res.render('manage-admins', { admins, error: 'Server error: ' + err.message, success: null, user });
  }
});

app.post('/manage-admins/delete/:id', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  console.log('POST /manage-admins/delete/:id');
  const user = req.session.admin;
  const { id } = req.params;
  try {
    const [admins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE id = ? AND username != ?', [id, user.username]);
    if (admins.length === 0) {
      const [allAdmins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE username != ?', [user.username]);
      const parsedAllAdmins = allAdmins.map(admin => {
        let parsedPermissions = { entry: false, exit: false, manage: false, profile: false, add_admin: false };
        if (admin.permissions) {
          try {
            parsedPermissions = { ...parsedPermissions, ...JSON.parse(admin.permissions) };
          } catch (err) {
            console.error(`Error parsing permissions for admin ${admin.username}:`, err);
          }
        }
        return { ...admin, permissions: parsedPermissions };
      });
      return res.render('manage-admins', { admins: parsedAllAdmins, error: 'Admin not found or cannot delete yourself', success: null, user });
    }

    await db.pool.query('DELETE FROM admins WHERE id = ?', [id]);
    console.log('Admin deleted:', { id });

    const [updatedAdmins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE username != ?', [user.username]);
    const parsedUpdatedAdmins = updatedAdmins.map(admin => {
      let parsedPermissions = { entry: false, exit: false, manage: false, profile: false, add_admin: false };
      if (admin.permissions) {
        try {
          parsedPermissions = { ...parsedPermissions, ...JSON.parse(admin.permissions) };
        } catch (err) {
          console.error(`Error parsing permissions for admin ${admin.username}:`, err);
        }
      }
      return { ...admin, permissions: parsedPermissions };
    });
    res.render('manage-admins', { admins: parsedUpdatedAdmins, error: null, success: 'Admin deleted successfully', user });
  } catch (err) {
    console.error('Delete admin error:', err);
    fs.writeFileSync('server.log', `Delete admin error: ${err}\n`, { flag: 'a' });
    const [admins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE username != ?', [user.username]);
    const parsedAdmins = admins.map(admin => {
      let parsedPermissions = { entry: false, exit: false, manage: false, profile: false, add_admin: false };
      if (admin.permissions) {
        try {
          parsedPermissions = { ...parsedPermissions, ...JSON.parse(admin.permissions) };
        } catch (err) {
          console.error(`Error parsing permissions for admin ${admin.username}:`, err);
        }
      }
      return { ...admin, permissions: parsedPermissions };
    });
    res.render('manage-admins', { admins: parsedAdmins, error: 'Failed to delete admin: ' + err.message, success: null, user });
  }
});

app.get('/manage-admins/edit/:id', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  console.log('GET /manage-admins/edit/:id');
  const user = req.session.admin;
  const { id } = req.params;
  try {
    const [admins] = await db.pool.query('SELECT id, username, email, permissions, password, plaintext_password FROM admins WHERE id = ? AND username != ?', [id, user.username]);
    console.log('Fetched admin:', admins);
    if (admins.length === 0) {
      console.log('Admin not found for ID:', id);
      return res.render('manage-admins', { admins: [], error: 'Admin not found', success: null, user });
    }
    const adminToEdit = admins[0];
    let parsedPermissions = { entry: false, exit: false, manage: false, profile: false, add_admin: false };
    if (adminToEdit.permissions) {
      try {
        parsedPermissions = { ...parsedPermissions, ...JSON.parse(adminToEdit.permissions) };
      } catch (err) {
        console.error(`Error parsing permissions for admin ${adminToEdit.username}:`, err);
      }
    }
    adminToEdit.permissions = parsedPermissions;
    // Use the session's plaintext_password if available, otherwise indicate it's not set
    adminToEdit.plaintext_password = adminToEdit.plaintext_password || user.plaintext_password || '';
    console.log('Rendering edit-admin with details:', {
      id: adminToEdit.id,
      username: adminToEdit.username,
      email: adminToEdit.email,
      plaintext_password: adminToEdit.plaintext_password ? '[REDACTED]' : 'Not set',
      permissions: adminToEdit.permissions
    });
    res.render('edit-admin', { admin: adminToEdit, error: null, success: null, validationErrors: [], user });
  } catch (err) {
    console.error('Edit admin fetch error:', err);
    fs.writeFileSync('server.log', `Edit admin fetch error: ${err}\n`, { flag: 'a' });
    res.render('edit-admin', { admin: null, error: 'Server error: ' + err.message, success: null, validationErrors: [], user });
  }
});

app.post('/manage-admins/edit/:id', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  const user = req.session.admin;
  const { id } = req.params;
  const { username, email, password, can_entry, can_exit, can_manage, can_profile } = req.body;
  console.log('POST /manage-admins/edit/:id:', { id, username, email, password: password ? '[REDACTED]' : 'Not provided', can_entry, can_exit, can_manage, can_profile });

  try {
    const [admins] = await db.pool.query('SELECT id, username, email, permissions, password FROM admins WHERE id = ? AND username != ?', [id, user.username]);
    if (admins.length === 0) {
      return res.render('edit-admin', { admin: null, error: 'Admin not found', success: null, validationErrors: [], user });
    }

    const adminToEdit = admins[0];
    const validationErrors = [];
    const usernameError = validateUsername(username);
    const emailError = validateEmail(email);
    if (password) { // Only validate password if provided
      const passwordError = validatePassword(password);
      if (passwordError) validationErrors.push(passwordError);
    } else {
      validationErrors.push('Password is required');
    }

    if (usernameError) validationErrors.push(usernameError);
    if (emailError) validationErrors.push(emailError);

    const [duplicateUsername] = await db.pool.query('SELECT id FROM admins WHERE username = ? AND id != ?', [username, id]);
    if (duplicateUsername.length > 0) {
      validationErrors.push('Username already exists');
    }
    const [duplicateEmail] = await db.pool.query('SELECT id FROM admins WHERE email = ? AND id != ?', [email, id]);
    if (duplicateEmail.length > 0) {
      validationErrors.push('Email already exists');
    }

    if (validationErrors.length > 0) {
      const adminToEditForRender = { 
        id, 
        username, 
        email, 
        password,
        plaintext_password: password,
        permissions: { entry: can_entry === 'on', exit: can_exit === 'on', manage: can_manage === 'on', profile: can_profile === 'on', add_admin: false }
      };
      return res.render('edit-admin', { admin: adminToEditForRender, error: null, success: null, validationErrors, user });
    }

    const permissions = {
      entry: can_entry === 'on',
      exit: can_exit === 'on',
      manage: can_manage === 'on',
      profile: can_profile === 'on',
      add_admin: false
    };

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.pool.query(
      'UPDATE admins SET username = ?, email = ?, password = ?, plaintext_password = ?, permissions = ? WHERE id = ?',
      [username, email, hashedPassword, password, JSON.stringify(permissions), id]
    );
    console.log('Admin details updated:', { id, username, email, permissions });

    // If username or password has changed, invalidate all sessions for the admin
    const usernameChanged = username !== adminToEdit.username;
    const passwordChanged = !(await bcrypt.compare(password, adminToEdit.password));
    if (usernameChanged || passwordChanged) {
      invalidateUserSessions(id, req.sessionID);
      console.log(`Invalidated sessions for admin with ID ${id} due to ${usernameChanged ? 'username' : ''}${usernameChanged && passwordChanged ? ' and ' : ''}${passwordChanged ? 'password' : ''} change`);
    }

    res.redirect('/manage-admins');
  } catch (err) {
    console.error('Edit admin update error:', err);
    fs.writeFileSync('server.log', `Edit admin update error: ${err}\n`, { flag: 'a' });
    const adminToEditForRender = { 
      id, 
      username, 
      email, 
      password,
      plaintext_password: password,
      permissions: { entry: can_entry === 'on', exit: can_exit === 'on', manage: can_manage === 'on', profile: can_profile === 'on', add_admin: false }
    };
    res.render('edit-admin', { admin: adminToEditForRender, error: 'Failed to update admin: ' + err.message, success: null, validationErrors: [], user });
  }
});

// Notification Routes
app.get('/vapidPublicKey', (req, res) => {
  res.send(vapidKeys.publicKey);
});

app.post('/subscribe', (req, res) => {
  const subscription = req.body;
  req.session.subscription = subscription;
  res.status(201).json({});
});

// Logout Route
app.get('/logout', (req, res) => {
  console.log('GET /logout');
  req.session.destroy();
  res.redirect('/login');
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});