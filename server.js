const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');
const fs = require('fs');
const webPush = require('web-push');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'your-stripe-secret-key');
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
    next();
  } else {
    res.redirect('/login');
  }
};

// Middleware to set lot_id for tenant-specific routes
const setLotId = async (req, res, next) => {
  if (!req.session.admin) {
    return res.redirect('/login');
  }

  const user = req.session.admin;
  if (user.role === 'super_admin') {
    // Super admins can select a lot
    if (!req.session.currentLotId && req.path !== '/lots' && req.path !== '/lots/create') {
      return res.redirect('/lots');
    }
  } else if (user.role === 'lot_owner' || user.role === 'admin') {
    // Lot owners and admins are tied to a specific lot
    req.session.currentLotId = user.lot_id;
  }

  req.lotId = req.session.currentLotId || null;
  next();
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

const validateLotName = (name) => {
  const nameRegex = /^[a-zA-Z0-9\s]{1,100}$/;
  if (!nameRegex.test(name)) {
    return 'Parking lot name must be 1-100 characters and contain only letters, numbers, and spaces';
  }
  return null;
};

// Redirect root URL to /dashboard
app.get('/', isAuthenticated, setLotId, (req, res) => {
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
    if (rows.length > 0) {
      const match = await bcrypt.compare(password, rows[0].password);
      if (match) {
        req.session.admin = rows[0];
        console.log('Login successful:', username);
        res.redirect('/lots');
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

app.get('/lots', isAuthenticated, async (req, res) => {
  console.log('GET /lots');
  try {
    const user = req.session.admin;
    let lots;
    if (user.role === 'super_admin') {
      [lots] = await db.pool.query('SELECT * FROM parking_lots');
    } else {
      [lots] = await db.pool.query('SELECT * FROM parking_lots WHERE owner_id = ? OR id = ?', [user.id, user.lot_id]);
    }
    res.render('lots', { lots, user, error: null });
  } catch (err) {
    console.error('Lots fetch error:', err);
    fs.writeFileSync('server.log', `Lots fetch error: ${err}\n`, { flag: 'a' });
    res.render('lots', { lots: [], user: req.session.admin, error: 'Server error' });
  }
});

app.get('/lots/create', isAuthenticated, (req, res) => {
  console.log('GET /lots/create');
  const user = req.session.admin;
  if (user.role !== 'super_admin') {
    return res.redirect('/lots');
  }
  res.render('create-lot', { user, error: null, validationErrors: [] });
});

app.post('/lots/create', isAuthenticated, async (req, res) => {
  const user = req.session.admin;
  if (user.role !== 'super_admin') {
    return res.redirect('/lots');
  }

  const { name, owner_username, owner_password, owner_email } = req.body;
  console.log('POST /lots/create:', { name, owner_username, owner_email });

  const validationErrors = [];
  const nameError = validateLotName(name);
  const usernameError = validateUsername(owner_username);
  const passwordError = validatePassword(owner_password);
  const emailError = validateEmail(owner_email);

  if (nameError) validationErrors.push(nameError);
  if (usernameError) validationErrors.push(usernameError);
  if (passwordError) validationErrors.push(passwordError);
  if (emailError) validationErrors.push(emailError);

  if (validationErrors.length > 0) {
    return res.render('create-lot', { user, error: null, validationErrors });
  }

  try {
    const [existingAdmin] = await db.pool.query('SELECT * FROM admins WHERE username = ?', [owner_username]);
    if (existingAdmin.length > 0) {
      return res.render('create-lot', { user, error: 'Username already exists', validationErrors: [] });
    }

    const hashedPassword = await bcrypt.hash(owner_password, 10);
    const [adminResult] = await db.pool.query(
      'INSERT INTO admins (username, password, email, role) VALUES (?, ?, ?, ?)',
      [owner_username, hashedPassword, owner_email, 'lot_owner']
    );

    const ownerId = adminResult.insertId;
    await db.pool.query(
      'INSERT INTO parking_lots (name, owner_id) VALUES (?, ?)',
      [name, ownerId]
    );

    const [lotResult] = await db.pool.query('SELECT id FROM parking_lots WHERE owner_id = ?', [ownerId]);
    const lotId = lotResult[0].id;

    await db.pool.query('UPDATE admins SET lot_id = ? WHERE id = ?', [lotId, ownerId]);

    res.redirect('/lots');
  } catch (err) {
    console.error('Create lot error:', err);
    fs.writeFileSync('server.log', `Create lot error: ${err}\n`, { flag: 'a' });
    res.render('create-lot', { user, error: 'Failed to create parking lot', validationErrors: [] });
  }
});

app.post('/lots/select/:id', isAuthenticated, async (req, res) => {
  const { id } = req.params;
  const user = req.session.admin;
  console.log('POST /lots/select/:id:', { id, user });

  try {
    const [lot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [id]);
    if (lot.length === 0) {
      return res.redirect('/lots');
    }

    if (user.role === 'super_admin' || user.lot_id === parseInt(id) || lot[0].owner_id === user.id) {
      req.session.currentLotId = parseInt(id);
    }

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Select lot error:', err);
    fs.writeFileSync('server.log', `Select lot error: ${err}\n`, { flag: 'a' });
    res.redirect('/lots');
  }
});

app.get('/dashboard', isAuthenticated, setLotId, async (req, res) => {
  console.log('GET /dashboard');
  try {
    const user = req.session.admin;
    const lotId = req.lotId;
    const filter = req.query.filter || 'today';
    let days = 1;
    let dateCondition = '';
    if (filter === 'weekly') {
      days = 7;
      dateCondition = 'AND DATE(e.entry_time) >= CURDATE() - INTERVAL 7 DAY';
    } else if (filter === 'monthly') {
      days = 30;
      dateCondition = 'AND DATE(e.entry_time) >= CURDATE() - INTERVAL 30 DAY';
    } else {
      dateCondition = 'AND DATE(e.entry_time) = CURDATE()';
    }

    const [vehicleCounts] = await db.query(
      `SELECT DATE(e.entry_time) as date, COUNT(*) as count 
       FROM entries e 
       WHERE e.lot_id = ? AND DATE(e.entry_time) >= CURDATE() - INTERVAL ? DAY 
       GROUP BY DATE(e.entry_time) 
       ORDER BY DATE(e.entry_time)`,
      [lotId, days]
    );

    const [earningsPerDay] = await db.query(
      `SELECT DATE(e.entry_time) as date, COALESCE(SUM(x.cost), 0) as total 
       FROM exits x 
       JOIN entries e ON x.entry_id = e.id 
       WHERE x.lot_id = ? AND DATE(e.entry_time) >= CURDATE() - INTERVAL ? DAY 
       GROUP BY DATE(e.entry_time) 
       ORDER BY DATE(e.entry_time)`,
      [lotId, days]
    );

    const [vehicles] = await db.query(
      `SELECT COUNT(*) as count FROM entries WHERE lot_id = ? AND DATE(entry_time) = CURDATE()`,
      [lotId]
    );
    const [earnings] = await db.query(
      `SELECT COALESCE(SUM(x.cost), 0) as total 
       FROM exits x 
       JOIN entries e ON x.entry_id = e.id 
       WHERE x.lot_id = ? ${dateCondition}`,
      [lotId]
    );
    const [parked] = await db.query(
      `SELECT COUNT(*) as count FROM entries WHERE lot_id = ? AND id NOT IN (SELECT entry_id FROM exits)`,
      [lotId]
    );
    const [totalSpaces] = await db.query(
      `SELECT SUM(total_spaces) as total FROM vehicle_categories WHERE lot_id = ?`,
      [lotId]
    );
    const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;

    // Calculate platform fee (5%)
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

    console.log('Dashboard data:', {
      vehicles: vehicles[0].count,
      earnings: earnings[0].total,
      available,
      parked: parked[0].count,
      filter,
      chartLabels: labels,
      vehicleData,
      earningsData,
      platformFee,
      tenantEarnings
    });

    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);

    res.render('dashboard', {
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
      currentLot: currentLot[0] || null
    });
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
      currentLot: null
    });
  }
});

app.get('/manage', isAuthenticated, setLotId, async (req, res) => {
  console.log('GET /manage');
  try {
    const user = req.session.admin;
    const lotId = req.lotId;
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    console.log('Manage categories:', formattedCategories);
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('manage', { categories: formattedCategories, error: null, editCategory: null, validationErrors: [], user, currentLot: currentLot[0] || null });
  } catch (err) {
    console.error('Manage error:', err);
    fs.writeFileSync('server.log', `Manage error: ${err}\n`, { flag: 'a' });
    res.render('manage', { categories: [], error: 'Server error', editCategory: null, validationErrors: [], user: req.session.admin, currentLot: null });
  }
});

app.post('/manage/add-category', isAuthenticated, setLotId, async (req, res) => {
  const user = req.session.admin;
  const lotId = req.lotId;
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
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    return res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      editCategory: null, 
      validationErrors,
      user,
      currentLot: currentLot[0] || null
    });
  }

  try {
    await db.query(
      'INSERT INTO vehicle_categories (name, total_spaces, pricing_type, price, lot_id) VALUES (?, ?, ?, ?, ?)',
      [name, total_spaces, pricing_type, price, lotId], lotId
    );
    res.redirect('/manage');
  } catch (err) {
    console.error('Add category error:', err);
    fs.writeFileSync('server.log', `Add category error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to add category', 
      editCategory: null, 
      validationErrors: [], 
      user,
      currentLot: currentLot[0] || null
    });
  }
});

app.get('/manage/edit/:id', isAuthenticated, setLotId, async (req, res) => {
  const user = req.session.admin;
  const lotId = req.lotId;
  const { id } = req.params;
  console.log('GET /manage/edit/:id:', { id });
  try {
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const [category] = await db.query('SELECT * FROM vehicle_categories WHERE id = ?', [id], lotId);
    if (category.length === 0) {
      const formattedCategories = categories.map(cat => ({
        ...cat,
        price: Number(cat.price) || 0
      }));
      const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
      return res.render('manage', { 
        categories: formattedCategories, 
        error: 'Category not found', 
        editCategory: null, 
        validationErrors: [], 
        user,
        currentLot: currentLot[0] || null
      });
    }
    const formattedCategories = categories.map(cat => ({
      ...cat,
      price: Number(cat.price) || 0
    }));
    const formattedCategory = { ...category[0], price: Number(category[0].price) || 0 };
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      editCategory: formattedCategory, 
      validationErrors: [], 
      user,
      currentLot: currentLot[0] || null
    });
  } catch (err) {
    console.error('Edit category fetch error:', err);
    fs.writeFileSync('server.log', `Edit category fetch error: ${err}\n`, { flag: 'a' });
    res.render('manage', { 
      categories: [], 
      error: 'Server error', 
      editCategory: null, 
      validationErrors: [], 
      user,
      currentLot: null
    });
  }
});

app.post('/manage/edit/:id', isAuthenticated, setLotId, async (req, res) => {
  const user = req.session.admin;
  const lotId = req.lotId;
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
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    return res.render('manage', { 
      categories: formattedCategories, 
      error: null, 
      editCategory: { id, name, total_spaces, pricing_type, price: Number(price) || 0 }, 
      validationErrors,
      user,
      currentLot: currentLot[0] || null
    });
  }

  try {
    await db.query(
      'UPDATE vehicle_categories SET name = ?, total_spaces = ?, pricing_type = ?, price = ? WHERE id = ?',
      [name, total_spaces, pricing_type, price, id], lotId
    );
    res.redirect('/manage');
  } catch (err) {
    console.error('Edit category update error:', err);
    fs.writeFileSync('server.log', `Edit category update error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to update category', 
      editCategory: { id, name, total_spaces, pricing_type, price: Number(price) || 0 },
      validationErrors: [],
      user,
      currentLot: currentLot[0] || null
    });
  }
});

app.post('/manage/delete/:id', isAuthenticated, setLotId, async (req, res) => {
  const user = req.session.admin;
  const lotId = req.lotId;
  const { id } = req.params;
  console.log('POST /manage/delete/:id:', { id });
  try {
    const [entries] = await db.query('SELECT * FROM entries WHERE category_id = ?', [id], lotId);
    if (entries.length > 0) {
      const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
      const formattedCategories = categories.map(category => ({
        ...category,
        price: Number(category.price) || 0
      }));
      const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
      return res.render('manage', { 
        categories: formattedCategories, 
        error: 'Cannot delete category: it is in use by existing entries', 
        editCategory: null, 
        validationErrors: [], 
        user,
        currentLot: currentLot[0] || null
      });
    }

    await db.query('DELETE FROM vehicle_categories WHERE id = ?', [id], lotId);
    res.redirect('/manage');
  } catch (err) {
    console.error('Delete category error:', err);
    fs.writeFileSync('server.log', `Delete category error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const formattedCategories = categories.map(category => ({
      ...category,
      price: Number(category.price) || 0
    }));
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('manage', { 
      categories: formattedCategories, 
      error: 'Failed to delete category', 
      editCategory: null, 
      validationErrors: [], 
      user,
      currentLot: currentLot[0] || null
    });
  }
});

app.get('/entry', isAuthenticated, setLotId, async (req, res) => {
  console.log('GET /entry');
  try {
    const user = req.session.admin;
    const lotId = req.lotId;
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    console.log('Entry categories:', categories);
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('entry', { 
      categories, 
      error: null, 
      autofill: {}, 
      validationErrors: [], 
      user,
      currentLot: currentLot[0] || null
    });
  } catch (err) {
    console.error('Entry error:', err);
    fs.writeFileSync('server.log', `Entry error: ${err}\n`, { flag: 'a' });
    res.render('entry', { 
      categories: [], 
      error: 'Server error', 
      autofill: {}, 
      validationErrors: [], 
      user: req.session.admin,
      currentLot: null
    });
  }
});

app.post('/entry', isAuthenticated, setLotId, async (req, res) => {
  const user = req.session.admin;
  const lotId = req.lotId;
  const { number_plate, owner_name, phone, category_id } = req.body;
  console.log('POST /entry:', { number_plate, owner_name, phone, category_id });

  const validationErrors = [];
  const plateError = validateNumberPlate(number_plate);
  const ownerError = validateOwnerName(owner_name);
  const phoneError = validatePhone(phone);

  let categoryError = null;
  const [categoryCheck] = await db.query('SELECT id FROM vehicle_categories WHERE id = ?', [category_id], lotId);
  if (categoryCheck.length === 0) {
    categoryError = 'Selected category does not exist';
  }

  if (plateError) validationErrors.push(plateError);
  if (ownerError) validationErrors.push(ownerError);
  if (phoneError) validationErrors.push(phoneError);
  if (categoryError) validationErrors.push(categoryError);

  if (validationErrors.length > 0) {
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    return res.render('entry', { 
      categories, 
      error: null, 
      autofill: { number_plate, owner_name, phone, category_id }, 
      validationErrors,
      user,
      currentLot: currentLot[0] || null
    });
  }

  try {
    const [existing] = await db.query(
      'SELECT owner_name, phone FROM entries WHERE number_plate = ? ORDER BY entry_time DESC LIMIT 1',
      [number_plate], lotId
    );
    const autofill = {
      number_plate,
      owner_name: owner_name || (existing.length > 0 ? existing[0].owner_name : ''),
      phone: phone || (existing.length > 0 ? existing[0].phone : ''),
      category_id
    };
    console.log('Autofill data:', autofill);

    await db.query(
      'INSERT INTO entries (number_plate, owner_name, phone, category_id, entry_time, lot_id) VALUES (?, ?, ?, ?, NOW(), ?)',
      [number_plate, owner_name || null, phone || null, category_id, lotId], lotId
    );

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Add entry error:', err);
    fs.writeFileSync('server.log', `Add entry error: ${err}\n`, { flag: 'a' });
    const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lotId);
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('entry', { 
      categories, 
      error: 'Failed to add entry', 
      autofill: { number_plate, owner_name, phone, category_id }, 
      validationErrors: [],
      user,
      currentLot: currentLot[0] || null
    });
  }
});

app.get('/exit', isAuthenticated, setLotId, async (req, res) => {
  console.log('GET /exit');
  try {
    const user = req.session.admin;
    const lotId = req.lotId;
    console.log('User and Lot ID:', { user, lotId });

    const [entries] = await db.query(
      'SELECT e.id, e.number_plate, e.entry_time, e.owner_name, e.phone, vc.name as category, vc.pricing_type, vc.price ' +
      'FROM entries e JOIN vehicle_categories vc ON e.category_id = vc.id ' +
      'WHERE e.lot_id = ? AND e.id NOT IN (SELECT entry_id FROM exits)',
      [lotId]
    );
    console.log('Exit entries:', entries);

    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    console.log('Current Lot:', currentLot);

    res.render('exit', { entries: entries || [], error: null, user, currentLot: currentLot[0] || null });
  } catch (err) {
    console.error('Exit error:', err);
    fs.writeFileSync('server.log', `Exit error: ${err}\n`, { flag: 'a' });
    res.status(500).render('exit', { entries: [], error: 'Server error: ' + err.message, user: req.session.admin, currentLot: null });
  }
});

app.post('/exit', isAuthenticated, setLotId, async (req, res) => {
  const user = req.session.admin;
  const lotId = req.lotId;
  const { entry_id } = req.body;
  console.log('POST /exit:', { entry_id });

  try {
    const [entry] = await db.query(
      'SELECT e.entry_time, e.number_plate, vc.pricing_type, vc.price ' +
      'FROM entries e JOIN vehicle_categories vc ON e.category_id = vc.id ' +
      'WHERE e.id = ? AND e.lot_id = ?',
      [entry_id, lotId]
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
      cost = hours * (entry[0].price || 0);
    } else {
      cost = entry[0].price || 0;
    }

    await db.query(
      'INSERT INTO exits (entry_id, exit_time, cost, lot_id) VALUES (?, NOW(), ?, ?)',
      [entry_id, cost, lotId], lotId
    );

    // Send notification
    if (req.session.subscription) {
      const payload = JSON.stringify({
        title: 'Vehicle Exited',
        body: `Your vehicle ${entry[0].number_plate} has exited Lot ${lotId}. Total cost: $${cost.toFixed(2)}.`
      });
      await webPush.sendNotification(req.session.subscription, payload);
    }

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Process exit error:', err);
    fs.writeFileSync('server.log', `Process exit error: ${err}\n`, { flag: 'a' });
    const [currentLot] = await db.pool.query('SELECT * FROM parking_lots WHERE id = ?', [lotId]);
    res.render('exit', { entries: [], error: 'Failed to process exit: ' + err.message, user, currentLot: currentLot[0] || null });
  }
});

app.get('/add-admin', isAuthenticated, setLotId, (req, res) => {
  console.log('GET /add-admin');
  const user = req.session.admin;
  const lotId = req.lotId;
  if (user.role !== 'lot_owner') {
    return res.redirect('/dashboard');
  }
  res.render('add-admin', { error: null, validationErrors: [], user, lotId });
});

app.post('/add-admin', isAuthenticated, setLotId, async (req, res) => {
  const user = req.session.admin;
  const lotId = req.lotId;
  if (user.role !== 'lot_owner') {
    return res.redirect('/dashboard');
  }

  const { username, password, email } = req.body;
  console.log('POST /add-admin:', { username, email });

  const validationErrors = [];
  const usernameError = validateUsername(username);
  const passwordError = validatePassword(password);
  const emailError = validateEmail(email);

  if (usernameError) validationErrors.push(usernameError);
  if (passwordError) validationErrors.push(passwordError);
  if (emailError) validationErrors.push(emailError);

  if (validationErrors.length > 0) {
    return res.render('add-admin', { error: null, validationErrors, user, lotId });
  }

  try {
    if (!username || !password || !email) {
      console.log('Missing fields');
      return res.render('add-admin', { error: 'All fields are required', validationErrors: [], user, lotId });
    }

    const [existing] = await db.pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    if (existing.length > 0) {
      console.log('Username exists:', username);
      return res.render('add-admin', { error: 'Username already exists', validationErrors: [], user, lotId });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.pool.query(
      'INSERT INTO admins (username, password, email, role, lot_id) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPassword, email, 'admin', lotId]
    );
    console.log('Admin added:', username);

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Add admin error:', err);
    fs.writeFileSync('server.log', `Add admin error: ${err}\n`, { flag: 'a' });
    res.render('add-admin', { error: 'Failed to add admin', validationErrors: [], user, lotId });
  }
});

// Public route to view parking lots and availability
app.get('/public', async (req, res) => {
  console.log('GET /public');
  try {
    const [lots] = await db.pool.query('SELECT * FROM parking_lots');
    const lotDetails = await Promise.all(lots.map(async (lot) => {
      const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lot.id);
      const [parked] = await db.query(
        'SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)',
        [], lot.id
      );
      const [totalSpaces] = await db.query(
        'SELECT SUM(total_spaces) as total FROM vehicle_categories',
        [], lot.id
      );
      const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;
      return { ...lot, categories, available, totalSpaces: totalSpaces[0].total || 0 };
    }));
    res.render('public-parking', { lots: lotDetails, error: null, validationErrors: [], autofill: {} });
  } catch (err) {
    console.error('Public page error:', err);
    fs.writeFileSync('server.log', `Public page error: ${err}\n`, { flag: 'a' });
    res.render('public-parking', { lots: [], error: 'Server error', validationErrors: [], autofill: {} });
  }
});

// Public route to park a vehicle and get a ticket
app.post('/public/park', async (req, res) => {
  const { lot_id, number_plate, owner_name, phone, category_id } = req.body;
  console.log('POST /public/park:', { lot_id, number_plate, owner_name, phone, category_id });

  const validationErrors = [];
  const plateError = validateNumberPlate(number_plate);
  const ownerError = validateOwnerName(owner_name);
  const phoneError = validatePhone(phone);

  let categoryError = null;
  const [categoryCheck] = await db.query('SELECT id FROM vehicle_categories WHERE id = ?', [category_id], lot_id);
  if (categoryCheck.length === 0) {
    categoryError = 'Selected category does not exist';
  }

  if (plateError) validationErrors.push(plateError);
  if (ownerError) validationErrors.push(ownerError);
  if (phoneError) validationErrors.push(phoneError);
  if (categoryError) validationErrors.push(categoryError);

  if (validationErrors.length > 0) {
    const [lots] = await db.pool.query('SELECT * FROM parking_lots');
    const lotDetails = await Promise.all(lots.map(async (lot) => {
      const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lot.id);
      const [parked] = await db.query(
        'SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)',
        [], lot.id
      );
      const [totalSpaces] = await db.query(
        'SELECT SUM(total_spaces) as total FROM vehicle_categories',
        [], lot.id
      );
      const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;
      return { ...lot, categories, available, totalSpaces: totalSpaces[0].total || 0 };
    }));
    return res.render('public-parking', { 
      lots: lotDetails, 
      error: null, 
      validationErrors,
      autofill: { number_plate, owner_name, phone, category_id, lot_id }
    });
  }

  try {
    const [entryResult] = await db.query(
      'INSERT INTO entries (number_plate, owner_name, phone, category_id, entry_time, lot_id) VALUES (?, ?, ?, ?, NOW(), ?)',
      [number_plate, owner_name || null, phone || null, category_id, lot_id], lot_id
    );
    const entryId = entryResult.insertId;

    // Send notification
    if (req.session.subscription) {
      const payload = JSON.stringify({
        title: 'Vehicle Parked',
        body: `Your vehicle ${number_plate} has been parked in Lot ${lot_id}.`
      });
      await webPush.sendNotification(req.session.subscription, payload);
    }

    const ticketContent = `
      <div style="text-align: center; font-family: Arial, sans-serif; padding: 20px;">
        <h2>Parking System</h2>
        <h4>Entry Ticket</h4>
        <p><strong>Parking Lot:</strong> ${lot_id}</p>
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
    const [lots] = await db.pool.query('SELECT * FROM parking_lots');
    const lotDetails = await Promise.all(lots.map(async (lot) => {
      const [categories] = await db.query('SELECT * FROM vehicle_categories', [], lot.id);
      const [parked] = await db.query(
        'SELECT COUNT(*) as count FROM entries WHERE id NOT IN (SELECT entry_id FROM exits)',
        [], lot.id
      );
      const [totalSpaces] = await db.query(
        'SELECT SUM(total_spaces) as total FROM vehicle_categories',
        [], lot.id
      );
      const available = totalSpaces[0].total ? totalSpaces[0].total - parked[0].count : 0;
      return { ...lot, categories, available, totalSpaces: totalSpaces[0].total || 0 };
    }));
    res.render('public-parking', { 
      lots: lotDetails, 
      error: 'Failed to park vehicle', 
      validationErrors: [],
      autofill: { number_plate, owner_name, phone, category_id, lot_id }
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
  req.session.subscription = subscription; // Store subscription in session
  res.status(201).json({});
});

// Route to create a Stripe payment intent
app.post('/create-payment-intent', async (req, res) => {
  const { amount } = req.body;
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100, // Amount in cents
      currency: 'usd',
      payment_method_types: ['card']
    });
    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error('Payment intent error:', err);
    res.status(500).json({ error: err.message });
  }
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