const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');
const fs = require('fs');
const webPush = require('web-push');
require('dotenv').config();

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
    cookie: { secure: process.env.NODE_ENV === 'production' }
  })
);

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.admin) {
    // Parse permissions if it's a string
    if (typeof req.session.admin.permissions === 'string') {
      try {
        req.session.admin.permissions = JSON.parse(req.session.admin.permissions);
      } catch (err) {
        console.error('Error parsing permissions:', err);
        req.session.admin.permissions = {};
      }
    }
    console.log('Authenticated user:', { username: req.session.admin.username, permissions: req.session.admin.permissions });
    next();
  } else {
    res.redirect('/login');
  }
};

// Permission middleware
const hasPermission = (permission) => (req, res, next) => {
  const user = req.session.admin;
  const permissions = user.permissions || {};
  console.log('Checking permission:', { user: user.username, permission, permissions });
  if (permissions[permission] === true) {
    next();
  } else {
    console.log('Permission denied, redirecting to /dashboard');
    res.redirect('/dashboard');
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

// Routes
app.get('/login', (req, res) => {
  console.log('GET /login');
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('POST /login:', { username });
  try {
    const [rows] = await db.pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    console.log('Database user:', rows);
    if (rows.length > 0) {
      const match = await bcrypt.compare(password, rows[0].password);
      if (match) {
        if (typeof rows[0].permissions === 'string') {
          rows[0].permissions = JSON.parse(rows[0].permissions);
        }
        console.log('Parsed permissions:', rows[0].permissions);
        req.session.admin = rows[0];
        console.log('Session admin set:', req.session.admin);
        res.redirect('/');
      } else {
        console.log('Invalid credentials for:', username);
        res.render('login', { error: 'Invalid credentials' });
      }
    } else {
      console.log('User not found:', username);
      res.render('login', { error: 'Invalid credentials' });
    }
  } catch (err) {
    console.error('Login error:', err);
    fs.writeFileSync('server.log', `Login error: ${err}\n`, { flag: 'a' });
    res.render('login', { error: 'Server error' });
  }
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
  console.log('GET /dashboard');
  try {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');

    const user = req.session.admin;
    const filter = req.query.filter || 'today';
    let days = 1;
    let dateCondition = '';
    if (filter === 'weekly') {
      days = 7;
      dateCondition = 'AND DATE(x.exit_time) >= CURDATE() - INTERVAL 7 DAY';
    } else if (filter === 'monthly') {
      days = 30;
      dateCondition = 'AND DATE(x.exit_time) >= CURDATE() - INTERVAL 30 DAY';
    } else {
      dateCondition = 'AND DATE(x.exit_time) = CURDATE()';
    }

    const [vehicleCounts] = await db.pool.query(
      `SELECT DATE(e.entry_time) as date, COUNT(*) as count 
       FROM entries e 
       WHERE DATE(e.entry_time) >= CURDATE() - INTERVAL ? DAY 
       GROUP BY DATE(e.entry_time) 
       ORDER BY DATE(e.entry_time)`,
      [days]
    );

    const [earningsPerDay] = await db.pool.query(
      `SELECT DATE(x.exit_time) as date, COALESCE(SUM(x.cost), 0) as total 
       FROM exits x 
       WHERE DATE(x.exit_time) >= CURDATE() - INTERVAL ? DAY 
       GROUP BY DATE(x.exit_time) 
       ORDER BY DATE(x.exit_time)`,
      [days]
    );

    const [vehicles] = await db.pool.query(
      `SELECT COUNT(*) as count FROM entries WHERE DATE(entry_time) = CURDATE()`
    );
    const [earnings] = await db.pool.query(
      `SELECT COALESCE(SUM(x.cost), 0) as total 
       FROM exits x 
       WHERE 1=1 ${dateCondition}`
    );
    const [parked] = await db.pool.query(
      `SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)`
    );
    const [totalSpaces] = await db.pool.query(
      `SELECT SUM(total_spaces) as total FROM vehicle_categories`
    );
    const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;

    console.log('Dashboard queries:', { vehicles: vehicles[0], earnings: earnings[0], parked: parked[0], totalSpaces: totalSpaces[0] });

    const platformFee = (earnings[0].total || 0) * 0.05;
    const tenantEarnings = (earnings[0].total || 0) - platformFee;

    const labels = [];
    const vehicleData = [];
    const earningsData = [];
    const today = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(today.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      labels.push(dateStr);

      const vehicleEntry = vehicleCounts.find(v => v.date.toISOString().split('T')[0] === dateStr);
      vehicleData.push(vehicleEntry ? vehicleEntry.count : 0);

      const earningEntry = earningsPerDay.find(e => e.date.toISOString().split('T')[0] === dateStr);
      earningsData.push(earningEntry ? earningEntry.total : 0);
    }

    const renderData = {
      vehicles: vehicles[0].count || 0,
      earnings: tenantEarnings,
      platformFee,
      available,
      parked: parked[0].count || 0,
      filter,
      error: null,
      chartLabels: labels,
      vehicleData,
      earningsData,
      user,
      hardRefresh: req.query.hardrefresh || null
    };
    console.log('Rendering dashboard with:', renderData);

    res.render('dashboard', renderData);
  } catch (err) {
    console.error('Dashboard error:', err);
    fs.writeFileSync('server.log', `Dashboard error: ${err}\n`, { flag: 'a' });
    res.render('dashboard', {
      vehicles: 0,
      earnings: 0,
      platformFee: 0,
      available: 0,
      parked: 0,
      filter: 'today',
      error: 'Server error',
      chartLabels: [],
      vehicleData: [],
      earningsData: [],
      user: req.session.admin,
      hardRefresh: null
    });
  }
});

app.get('/manage', isAuthenticated, hasPermission('manage'), async (req, res) => {
  console.log('GET /manage');
  try {
    const user = req.session.admin;
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    console.log('Manage categories:', formattedCategories);
    res.render('manage', { categories: formattedCategories, error: null, editCategory: null, validationErrors: [], user });
  } catch (err) {
    console.error('Manage error:', err);
    fs.writeFileSync('server.log', `Manage error: ${err}\n`, { flag: 'a' });
    res.render('manage', { categories: [], error: 'Server error', editCategory: null, validationErrors: [], user: req.session.admin });
  }
});

app.post('/manage/add-category', isAuthenticated, hasPermission('manage'), async (req, res) => {
  const user = req.session.admin;
  const { name, total_spaces, pricing_type, price } = req.body;
  console.log('POST /manage/add-category:', { name, total_spaces, pricing_type, price });
  
  const validationErrors = [];
  const nameError = validateCategoryName(name);
  const spacesError = validateTotalSpaces(total_spaces);
  const pricingError = validatePricingType(pricing_type);
  const priceError = validatePrice(price);

  if (nameError) validationErrors.push(nameError);
  if (spacesError) validationErrors.push(spacesError);
  if (pricingError) validationErrors.push(pricingError);
  if (priceError) validationErrors.push(priceError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    return res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      editCategory: null, 
      validationErrors,
      user
    });
  }

  try {
    await db.pool.query(
      'INSERT INTO vehicle_categories (name, total_spaces, pricing_type, price) VALUES (?, ?, ?, ?)',
      [name, total_spaces, pricing_type, price]
    );
    res.redirect('/manage');
  } catch (err) {
    console.error('Add category error:', err);
    fs.writeFileSync('server.log', `Add category error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to add category', 
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
        price: Number(cat.price) || 0
      }));
      return res.render('manage', { 
        categories: formattedCategories, 
        error: 'Category not found', 
        editCategory: null, 
        validationErrors: [], 
        user
      });
    }
    const formattedCategories = categories.map(cat => ({
      ...cat,
      price: Number(cat.price) || 0
    }));
    const formattedCategory = { ...category[0], price: Number(category[0].price) || 0 };
    res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
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
      editCategory: null, 
      validationErrors: [], 
      user
    });
  }
});

app.post('/manage/edit/:id', isAuthenticated, hasPermission('manage'), async (req, res) => {
  const user = req.session.admin;
  const { id } = req.params;
  const { name, total_spaces, pricing_type, price } = req.body;
  console.log('POST /manage/edit/:id:', { id, name, total_spaces, pricing_type, price });

  const validationErrors = [];
  const nameError = validateCategoryName(name);
  const spacesError = validateTotalSpaces(total_spaces);
  const pricingError = validatePricingType(pricing_type);
  const priceError = validatePrice(price);

  if (nameError) validationErrors.push(nameError);
  if (spacesError) validationErrors.push(spacesError);
  if (pricingError) validationErrors.push(pricingError);
  if (priceError) validationErrors.push(priceError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    return res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      editCategory: { id, name, total_spaces, pricing_type, price: Number(price) || 0 }, 
      validationErrors,
      user
    });
  }

  try {
    await db.pool.query(
      'UPDATE vehicle_categories SET name = ?, total_spaces = ?, pricing_type = ?, price = ? WHERE id = ?',
      [name, total_spaces, pricing_type, price, id]
    );
    res.redirect('/manage');
  } catch (err) {
    console.error('Edit category update error:', err);
    fs.writeFileSync('server.log', `Edit category update error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to update category', 
      editCategory: { id, name, total_spaces, pricing_type, price: Number(price) || 0 },
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
    const [entries] = await db.pool.query('SELECT * FROM entries WHERE category_id = ?', [id]);
    if (entries.length > 0) {
      const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
      const formattedCategories = categories.map(category => ({
        ...category,
        price: Number(category.price) || 0
      }));
      return res.render('manage', { 
        categories: formattedCategories, 
        error: 'Cannot delete category: it is in use by existing entries', 
        editCategory: null, 
        validationErrors: [], 
        user
      });
    }

    await db.pool.query('DELETE FROM vehicle_categories WHERE id = ?', [id]);
    res.redirect('/manage');
  } catch (err) {
    console.error('Delete category error:', err);
    fs.writeFileSync('server.log', `Delete category error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to delete category', 
      editCategory: null, 
      validationErrors: [], 
      user
    });
  }
});

app.get('/entry', isAuthenticated, hasPermission('entry'), async (req, res) => {
  console.log('GET /entry');
  try {
    const user = req.session.admin;
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    console.log('Entry categories:', categories);
    res.render('entry', { 
      categories, 
      error: null, 
      autofill: {}, 
      validationErrors: [], 
      user
    });
  } catch (err) {
    console.error('Entry error:', err);
    fs.writeFileSync('server.log', `Entry error: ${err}\n`, { flag: 'a' });
    res.render('entry', { 
      categories: [], 
      error: 'Server error', 
      autofill: {}, 
      validationErrors: [], 
      user: req.session.admin
    });
  }
});

app.post('/entry', isAuthenticated, hasPermission('entry'), async (req, res) => {
  const user = req.session.admin;
  const { number_plate, owner_name, phone, category_id } = req.body;
  console.log('POST /entry:', { number_plate, owner_name, phone, category_id });

  const validationErrors = [];
  const plateError = validateNumberPlate(number_plate);
  const ownerError = validateOwnerName(owner_name);
  const phoneError = validatePhone(phone);

  let categoryError = null;
  const [categoryCheck] = await db.pool.query('SELECT id FROM vehicle_categories WHERE id = ?', [category_id]);
  if (categoryCheck.length === 0) {
    categoryError = 'Selected category does not exist';
  }

  if (plateError) validationErrors.push(plateError);
  if (ownerError) validationErrors.push(ownerError);
  if (phoneError) validationErrors.push(phoneError);
  if (categoryError) validationErrors.push(categoryError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    return res.render('entry', { 
      categories, 
      error: null, 
      autofill: { number_plate, owner_name, phone, category_id }, 
      validationErrors,
      user
    });
  }

  try {
    const [existing] = await db.pool.query(
      'SELECT owner_name, phone FROM entries WHERE number_plate = ? ORDER BY entry_time DESC LIMIT 1',
      [number_plate]
    );
    const autofill = {
      number_plate,
      owner_name: owner_name || (existing.length > 0 ? existing[0].owner_name : ''),
      phone: phone || (existing.length > 0 ? existing[0].phone : ''),
      category_id
    };
    console.log('Autofill data:', autofill);

    await db.pool.query(
      'INSERT INTO entries (number_plate, owner_name, phone, category_id, entry_time) VALUES (?, ?, ?, ?, NOW())',
      [number_plate, owner_name || null, phone || null, category_id]
    );

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Add entry error:', err);
    fs.writeFileSync('server.log', `Add entry error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    res.render('entry', { 
      categories, 
      error: 'Failed to add entry', 
      autofill: { number_plate, owner_name, phone, category_id }, 
      validationErrors: [],
      user
    });
  }
});

app.get('/exit', isAuthenticated, hasPermission('exit'), async (req, res) => {
  console.log('GET /exit');
  try {
    const user = req.session.admin;
    const [entries] = await db.pool.query(
      'SELECT e.id, e.number_plate, e.entry_time, e.owner_name, e.phone, vc.name as category, vc.pricing_type, vc.price ' +
      'FROM entries e LEFT JOIN vehicle_categories vc ON e.category_id = vc.id ' +
      'WHERE e.id NOT IN (SELECT entry_id FROM exits)'
    );
    console.log('Exit entries:', entries);
    res.render('exit', { entries: entries || [], error: null, user });
  } catch (err) {
    console.error('Exit error:', err);
    fs.writeFileSync('server.log', `Exit error: ${err}\n`, { flag: 'a' });
    res.render('exit', { entries: [], error: 'Server error', user: req.session.admin });
  }
});

app.post('/exit', isAuthenticated, hasPermission('exit'), async (req, res) => {
  const user = req.session.admin;
  const { entry_id } = req.body;
  console.log('POST /exit:', { entry_id });

  try {
    const [parkedBefore] = await db.pool.query(
      `SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)`
    );
    const [earningsBefore] = await db.pool.query(
      `SELECT COALESCE(SUM(x.cost), 0) as total FROM exits x WHERE DATE(x.exit_time) = CURDATE()`
    );
    console.log('Dashboard stats before exit:', { parked: parkedBefore[0].count, earnings: earningsBefore[0].total });

    const [entry] = await db.pool.query(
      'SELECT e.entry_time, e.number_plate, vc.pricing_type, vc.price ' +
      'FROM entries e JOIN vehicle_categories vc ON e.category_id = vc.id ' +
      'WHERE e.id = ?',
      [entry_id]
    );
    console.log('Exit entry:', entry);
    if (entry.length === 0) {
      return res.status(404).send('Entry not found');
    }

    const entryTime = new Date(entry[0].entry_time);
    const exitTime = new Date();
    let cost = 0;
    if (entry[0].pricing_type === 'hourly') {
      const hours = Math.ceil((exitTime - entryTime) / (1000 * 60 * 60));
      cost = hours * (parseFloat(entry[0].price) || 0);
    } else {
      cost = parseFloat(entry[0].price) || 0;
    }
    console.log('Calculated cost:', cost);

    const [result] = await db.pool.query(
      'INSERT INTO exits (entry_id, exit_time, cost) VALUES (?, NOW(), ?)',
      [entry_id, cost]
    );
    console.log('Exit record inserted:', { entry_id, cost, insertId: result.insertId });

    const [newExit] = await db.pool.query('SELECT * FROM exits WHERE entry_id = ?', [entry_id]);
    console.log('New exit record:', newExit);

    const [parkedAfter] = await db.pool.query(
      `SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)`
    );
    const [earningsAfter] = await db.pool.query(
      `SELECT COALESCE(SUM(x.cost), 0) as total FROM exits x WHERE DATE(x.exit_time) = CURDATE()`
    );
    console.log('Dashboard stats after exit:', { parked: parkedAfter[0].count, earnings: earningsAfter[0].total });

    if (req.session.subscription) {
      const payload = JSON.stringify({
        title: 'Vehicle Exited',
        body: `Your vehicle ${entry[0].number_plate} has exited. Total cost: $${cost.toFixed(2)}.`
      });
      await webPush.sendNotification(req.session.subscription, payload);
    }

    // Force hard refresh with meta tag and JavaScript
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Exit Processed</title>
        <meta http-equiv="refresh" content="0;url=/dashboard?hardrefresh=${Date.now()}">
        <meta http-equiv="cache-control" content="no-store, no-cache, must-revalidate">
        <meta http-equiv="pragma" content="no-cache">
        <meta http-equiv="expires" content="0">
        <script>
          // Clear local storage and session storage
          localStorage.clear();
          sessionStorage.clear();
          // Force hard navigation
          window.location.href = '/dashboard?hardrefresh=${Date.now()}';
          window.location.reload(true);
        </script>
      </head>
      <body>
        <p>Exit processed. Redirecting to dashboard...</p>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('Process exit error:', err);
    fs.writeFileSync('server.log', `Process exit error: ${err}\n`, { flag: 'a' });
    res.render('exit', { entries: [], error: 'Failed to process exit: ' + err.message, user });
  }
});

app.get('/add-admin', isAuthenticated, hasPermission('add_admin'), (req, res) => {
  console.log('GET /add-admin');
  const user = req.session.admin;
  res.render('add-admin', { error: null, validationErrors: [], user });
});

app.post('/add-admin', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  const user = req.session.admin;
  const { username, password, email, can_entry, can_exit, can_manage } = req.body;
  console.log('POST /add-admin:', { username, email, can_entry, can_exit, can_manage });

  const validationErrors = [];
  const usernameError = validateUsername(username);
  const passwordError = validatePassword(password);
  const emailError = validateEmail(email);

  if (usernameError) validationErrors.push(usernameError);
  if (passwordError) validationErrors.push(passwordError);
  if (emailError) validationErrors.push(emailError);

  if (validationErrors.length > 0) {
    return res.render('add-admin', { error: null, validationErrors, user });
  }

  try {
    if (!username || !password || !email) {
      console.log('Missing fields');
      return res.render('add-admin', { error: 'All fields are required', validationErrors: [], user });
    }

    const [existing] = await db.pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    if (existing.length > 0) {
      console.log('Username exists:', username);
      return res.render('add-admin', { error: 'Username already exists', validationErrors: [], user });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const permissions = {
      entry: can_entry === 'on',
      exit: can_exit === 'on',
      manage: can_manage === 'on',
      add_admin: false
    };
    await db.pool.query(
      'INSERT INTO admins (username, password, email, permissions) VALUES (?, ?, ?, ?)',
      [username, hashedPassword, email, JSON.stringify(permissions)]
    );
    console.log('Admin added:', username);

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Add admin error:', err);
    fs.writeFileSync('server.log', `Add admin error: ${err}\n`, { flag: 'a' });
    res.render('add-admin', { error: 'Failed to add admin', validationErrors: [], user });
  }
});

// Manage Admins - List all admins (Super Admin only)
app.get('/manage-admins', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  console.log('GET /manage-admins');
  try {
    const user = req.session.admin;
    const [admins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE username != ?', [user.username]);
    console.log('Admins list:', admins);
    res.render('manage-admins', { admins, error: null, user });
  } catch (err) {
    console.error('Manage admins error:', err);
    fs.writeFileSync('server.log', `Manage admins error: ${err}\n`, { flag: 'a' });
    res.render('manage-admins', { admins: [], error: 'Server error: ' + err.message, user });
  }
});

// Manage Admins - Edit an admin's permissions (Super Admin only)
app.get('/manage-admins/edit/:id', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  console.log('GET /manage-admins/edit/:id');
  const user = req.session.admin;
  const { id } = req.params;
  try {
    const [admins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE id = ? AND username != ?', [id, user.username]);
    if (admins.length === 0) {
      return res.render('manage-admins', { admins: [], error: 'Admin not found', user });
    }
    const adminToEdit = admins[0];
    if (typeof adminToEdit.permissions === 'string') {
      adminToEdit.permissions = JSON.parse(adminToEdit.permissions);
    }
    console.log('Editing admin:', adminToEdit);
    res.render('edit-admin', { admin: adminToEdit, error: null, validationErrors: [], user });
  } catch (err) {
    console.error('Edit admin fetch error:', err);
    fs.writeFileSync('server.log', `Edit admin fetch error: ${err}\n`, { flag: 'a' });
    res.render('edit-admin', { admin: null, error: 'Server error: ' + err.message, validationErrors: [], user });
  }
});

app.post('/manage-admins/edit/:id', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  const user = req.session.admin;
  const { id } = req.params;
  const { can_entry, can_exit, can_manage } = req.body;
  console.log('POST /manage-admins/edit/:id:', { id, can_entry, can_exit, can_manage });

  try {
    const [admins] = await db.pool.query('SELECT id, username, email, permissions FROM admins WHERE id = ? AND username != ?', [id, user.username]);
    if (admins.length === 0) {
      return res.render('edit-admin', { admin: null, error: 'Admin not found', validationErrors: [], user });
    }

    const permissions = {
      entry: can_entry === 'on',
      exit: can_exit === 'on',
      manage: can_manage === 'on',
      add_admin: false
    };
    await db.pool.query(
      'UPDATE admins SET permissions = ? WHERE id = ?',
      [JSON.stringify(permissions), id]
    );
    console.log('Admin permissions updated:', { id, permissions });

    res.redirect('/manage-admins');
  } catch (err) {
    console.error('Edit admin update error:', err);
    fs.writeFileSync('server.log', `Edit admin update error: ${err}\n`, { flag: 'a' });
    const adminToEdit = { id, permissions: { entry: can_entry === 'on', exit: can_exit === 'on', manage: can_manage === 'on', add_admin: false } };
    res.render('edit-admin', { admin: adminToEdit, error: 'Failed to update admin: ' + err.message, validationErrors: [], user });
  }
});

// Reports - Generate system usage reports (Super Admin only)
app.get('/reports', isAuthenticated, hasPermission('add_admin'), async (req, res) => {
  console.log('GET /reports');
  try {
    const user = req.session.admin;
    const filter = req.query.filter || 'today';
    let days = 1;
    let dateCondition = '';
    if (filter === 'weekly') {
      days = 7;
      dateCondition = 'AND DATE(x.exit_time) >= CURDATE() - INTERVAL 7 DAY';
    } else if (filter === 'monthly') {
      days = 30;
      dateCondition = 'AND DATE(x.exit_time) >= CURDATE() - INTERVAL 30 DAY';
    } else {
      dateCondition = 'AND DATE(x.exit_time) = CURDATE()';
    }

    const [totalEarnings] = await db.pool.query(
      `SELECT COALESCE(SUM(x.cost), 0) as total 
       FROM exits x 
       WHERE 1=1 ${dateCondition}`
    );

    const [totalEntries] = await db.pool.query(
      `SELECT COUNT(*) as count 
       FROM entries e 
       WHERE DATE(e.entry_time) >= CURDATE() - INTERVAL ? DAY`,
      [days]
    );
    const [totalExits] = await db.pool.query(
      `SELECT COUNT(*) as count 
       FROM exits x 
       WHERE DATE(x.exit_time) >= CURDATE() - INTERVAL ? DAY`,
      [days]
    );

    const [adminActivity] = await db.pool.query(
      `SELECT a.username, 
              SUM(CASE WHEN e.entry_time >= CURDATE() - INTERVAL ? DAY THEN 1 ELSE 0 END) as entries_count,
              SUM(CASE WHEN x.exit_time >= CURDATE() - INTERVAL ? DAY THEN 1 ELSE 0 END) as exits_count
       FROM admins a
       LEFT JOIN entries e ON e.id IN (SELECT entry_id FROM exits WHERE DATE(exit_time) >= CURDATE() - INTERVAL ? DAY)
       LEFT JOIN exits x ON x.entry_id = e.id AND DATE(x.exit_time) >= CURDATE() - INTERVAL ? DAY
       GROUP BY a.id, a.username`,
      [days, days, days, days]
    );

    console.log('Reports data:', { totalEarnings, totalEntries, totalExits, adminActivity });

    res.render('reports', {
      totalEarnings: totalEarnings[0].total || 0,
      totalEntries: totalEntries[0].count || 0,
      totalExits: totalExits[0].count || 0,
      adminActivity,
      filter,
      error: null,
      user
    });
  } catch (err) {
    console.error('Reports error:', err);
    fs.writeFileSync('server.log', `Reports error: ${err}\n`, { flag: 'a' });
    res.render('reports', {
      totalEarnings: 0,
      totalEntries: 0,
      totalExits: 0,
      adminActivity: [],
      filter: 'today',
      error: 'Server error: ' + err.message,
      user: req.session.admin
    });
  }
});

// Public route to view parking availability
app.get('/public', async (req, res) => {
  console.log('GET /public');
  try {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const [parked] = await db.pool.query(
      'SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)'
    );
    const [totalSpaces] = await db.pool.query(
      'SELECT SUM(total_spaces) as total FROM vehicle_categories'
    );
    const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;
    const lotDetails = { categories, available, totalSpaces: totalSpaces[0].total || 0 };
    res.render('public-parking', { lots: [lotDetails], error: null, validationErrors: [], autofill: {} });
  } catch (err) {
    console.error('Public page error:', err);
    fs.writeFileSync('server.log', `Public page error: ${err}\n`, { flag: 'a' });
    res.render('public-parking', { lots: [], error: 'Server error', validationErrors: [], autofill: {} });
  }
});

// Public route to park a vehicle and get a ticket
app.post('/public/park', async (req, res) => {
  const { number_plate, owner_name, phone, category_id } = req.body;
  console.log('POST /public/park:', { number_plate, owner_name, phone, category_id });

  const validationErrors = [];
  const plateError = validateNumberPlate(number_plate);
  const ownerError = validateOwnerName(owner_name);
  const phoneError = validatePhone(phone);

  let categoryError = null;
  const [categoryCheck] = await db.pool.query('SELECT id FROM vehicle_categories WHERE id = ?', [category_id]);
  if (categoryCheck.length === 0) {
    categoryError = 'Selected category does not exist';
  }

  if (plateError) validationErrors.push(plateError);
  if (ownerError) validationErrors.push(ownerError);
  if (phoneError) validationErrors.push(phoneError);
  if (categoryError) validationErrors.push(categoryError);

  if (validationErrors.length > 0) {
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const [parked] = await db.pool.query(
      'SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)'
    );
    const [totalSpaces] = await db.pool.query(
      'SELECT SUM(total_spaces) as total FROM vehicle_categories'
    );
    const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;
    const lotDetails = { categories, available, totalSpaces: totalSpaces[0].total || 0 };
    return res.render('public-parking', { 
      lots: [lotDetails], 
      error: null, 
      validationErrors,
      autofill: { number_plate, owner_name, phone, category_id }
    });
  }

  try {
    const [entryResult] = await db.pool.query(
      'INSERT INTO entries (number_plate, owner_name, phone, category_id, entry_time) VALUES (?, ?, ?, ?, NOW())',
      [number_plate, owner_name || null, phone || null, category_id]
    );
    const entryId = entryResult.insertId;

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

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="entry_ticket_${number_plate}_${Date.now()}.pdf"`);
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
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
    console.error('Public park error:', err);
    fs.writeFileSync('server.log', `Public park error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.pool.query('SELECT * FROM vehicle_categories');
    const [parked] = await db.pool.query(
      'SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)'
    );
    const [totalSpaces] = await db.pool.query(
      'SELECT SUM(total_spaces) as total FROM vehicle_categories'
    );
    const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;
    const lotDetails = { categories, available, totalSpaces: totalSpaces[0].total || 0 };
    res.render('public-parking', { 
      lots: [lotDetails], 
      error: 'Failed to park vehicle', 
      validationErrors: [],
      autofill: { number_plate, owner_name, phone, category_id }
    });
  }
});

// Route to get VAPID public key for client-side subscription
app.get('/vapidPublicKey', (req, res) => {
  res.send(vapidKeys.publicKey);
});

// Route to subscribe to notifications
app.post('/subscribe', (req, res) => {
  const subscription = req.body;
  req.session.subscription = subscription;
  res.status(201).json({});
});

app.get('/logout', (req, res) => {
  console.log('GET /logout');
  req.session.destroy();
  res.redirect('/login');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});