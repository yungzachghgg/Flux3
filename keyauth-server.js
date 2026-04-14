const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// In-memory database (persisted to JSON file)
const DB_FILE = './keys.json';
let db = { users: {}, keys: {} };

// Load database
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch (e) {
    console.log('Starting with fresh database');
  }
}

// Save database
function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Hash password
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Generate API key
function generateKey() {
  return 'ak_' + crypto.randomBytes(24).toString('base64').replace(/[+/=]/g, '').substring(0, 32);
}

// ========== AUTH ENDPOINTS ==========

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  if (db.users[username]) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  
  db.users[username] = {
    password: hashPassword(password),
    created: new Date().toISOString()
  };
  
  saveDB();
  res.json({ success: true, message: 'Account created' });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const user = db.users[username];
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  res.json({ 
    success: true, 
    username,
    token: hashPassword(username + Date.now()) // Simple session token
  });
});

// ========== KEY MANAGEMENT ==========

// Generate new API key (requires login)
app.post('/api/keys/generate', (req, res) => {
  const { username, password, keyName, expiryDays } = req.body;
  
  // Verify user
  const user = db.users[username];
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const key = generateKey();
  const expiry = expiryDays 
    ? new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString()
    : null;
  
  db.keys[key] = {
    owner: username,
    name: keyName || 'Unnamed Key',
    created: new Date().toISOString(),
    expiry,
    active: true,
    lastUsed: null,
    hwid: null // For hardware locking
  };
  
  saveDB();
  
  res.json({
    success: true,
    key,
    name: db.keys[key].name,
    expiry
  });
});

// Get all keys for user
app.post('/api/keys/list', (req, res) => {
  const { username, password } = req.body;
  
  const user = db.users[username];
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const userKeys = Object.entries(db.keys)
    .filter(([key, data]) => data.owner === username)
    .map(([key, data]) => ({
      key: key.substring(0, 10) + '...', // Masked
      fullKey: key,
      name: data.name,
      created: data.created,
      expiry: data.expiry,
      active: data.active,
      lastUsed: data.lastUsed
    }));
  
  res.json({ success: true, keys: userKeys });
});

// Revoke key
app.post('/api/keys/revoke', (req, res) => {
  const { username, password, key } = req.body;
  
  const user = db.users[username];
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  if (!db.keys[key] || db.keys[key].owner !== username) {
    return res.status(404).json({ error: 'Key not found' });
  }
  
  db.keys[key].active = false;
  saveDB();
  
  res.json({ success: true, message: 'Key revoked' });
});

// ========== KEY AUTHENTICATION (for C++ clients) ==========

// Validate key (C++ clients call this)
app.post('/api/auth/validate', (req, res) => {
  const { key, hwid } = req.body;
  
  if (!key) {
    return res.status(400).json({ 
      success: false, 
      message: 'No key provided',
      subscription: 'Expired'
    });
  }
  
  // First try to find by full key
  let keyData = db.keys[key];
  let actualKey = key;
  
  // If not found, try to find by name
  if (!keyData) {
    for (const [fullKey, data] of Object.entries(db.keys)) {
      if (data.name === key && data.active) {
        keyData = data;
        actualKey = fullKey;
        break;
      }
    }
  }
  
  // Key doesn't exist
  if (!keyData) {
    return res.json({ 
      success: false, 
      message: 'Invalid key',
      subscription: 'Expired'
    });
  }
  
  // Key revoked
  if (!keyData.active) {
    return res.json({ 
      success: false, 
      message: 'Key revoked',
      subscription: 'Expired'
    });
  }
  
  // Key expired
  if (keyData.expiry && new Date() > new Date(keyData.expiry)) {
    return res.json({ 
      success: false, 
      message: 'Key expired',
      subscription: 'Expired'
    });
  }
  
  // HWID lock (disk-based locking - prevents key sharing)
  if (hwid) {
    if (keyData.hwid && keyData.hwid !== hwid) {
      return res.json({ 
        success: false, 
        message: `HWID mismatch - key locked to different disk (${keyData.hwid})`,
        subscription: 'Expired',
        currentHwid: hwid
      });
    }
    if (!keyData.hwid) {
      keyData.hwid = hwid; // Lock to first disk
      console.log(`Key ${actualKey} locked to HWID: ${hwid}`);
    }
  }
  
  // Update last used
  keyData.lastUsed = new Date().toISOString();
  db.keys[actualKey] = keyData; // Ensure we update the correct key
  saveDB();
  
  res.json({
    success: true,
    message: 'Valid key',
    subscription: keyData.expiry ? 'Active' : 'Lifetime',
    expiry: keyData.expiry,
    owner: keyData.owner,
    name: keyData.name,
    diskLocked: keyData.hwid ? true : false
  });
});

// Get app info (like KeyAuth's app info endpoint)
app.get('/api/app/info', (req, res) => {
  res.json({
    name: 'My Auth API',
    version: '1.0.0',
    subscriptionSystem: true,
    hwidLock: true,
    registerSystem: true
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    users: Object.keys(db.users).length,
    keys: Object.keys(db.keys).length
  });
});

// Load database on start
loadDB();

// Start server
app.listen(PORT, () => {
  console.log(`KeyAuth-style server running on http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}/keyauth.html`);
  console.log(`API base: http://localhost:${PORT}/api/`);
});
