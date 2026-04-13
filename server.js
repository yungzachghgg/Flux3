const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

// YOUR DATABASE FILE - persists on Railway
const DB_FILE = path.join(__dirname, 'fluxauth-data.json');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Root route - serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Load database
async function loadDb() {
  try {
    const data = await fs.readFile(DB_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return { users: [], keys: [], created: new Date().toISOString() };
  }
}

// Save database
async function saveDb(data) {
  await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const db = await loadDb();

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password required' });
  }

  if (password.length < 4) {
    return res.status(400).json({ success: false, error: 'Password must be at least 4 characters' });
  }

  const sanitizedUsername = username.toLowerCase().trim();
  
  if (!/^[a-z0-9_]+$/.test(sanitizedUsername) || sanitizedUsername.length < 3) {
    return res.status(400).json({ success: false, error: 'Username must be 3+ alphanumeric characters' });
  }

  if (db.users.find(u => u.username === sanitizedUsername)) {
    return res.status(400).json({ success: false, error: 'Username already exists' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    db.users.push({
      id: userId,
      username: sanitizedUsername,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    });

    // Auto-create default API key
    const defaultKey = `FLUX-${sanitizedUsername.toUpperCase()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    
    db.keys.push({
      id: uuidv4(),
      userId: userId,
      username: sanitizedUsername,
      name: 'Default Key',
      fullKey: defaultKey,
      createdAt: new Date().toISOString(),
      active: true,
      lockedIp: null,
      useCount: 0
    });

    await saveDb(db);
    
    res.json({ 
      success: true, 
      message: 'User registered', 
      userId: userId,
      apiKey: defaultKey 
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await loadDb();

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password required' });
  }

  const sanitizedUsername = username.toLowerCase().trim();
  const user = db.users.find(u => u.username === sanitizedUsername);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({ success: true, token, username: user.username });
});

// Change Password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const db = await loadDb();

  const user = db.users.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }

  if (!(await bcrypt.compare(currentPassword, user.password))) {
    return res.status(400).json({ success: false, error: 'Current password is incorrect' });
  }

  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ success: false, error: 'New password must be at least 4 characters' });
  }

  user.password = await bcrypt.hash(newPassword, 10);
  await saveDb(db);

  res.json({ success: true, message: 'Password updated successfully' });
});

// Delete Account
app.post('/api/auth/delete-account', authenticateToken, async (req, res) => {
  const { password } = req.body;
  const db = await loadDb();

  const user = db.users.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }

  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ success: false, error: 'Invalid password' });
  }

  // Delete user's keys
  db.keys = db.keys.filter(k => k.userId !== user.id);
  // Delete user
  db.users = db.users.filter(u => u.id !== user.id);
  
  await saveDb(db);

  res.json({ success: true, message: 'Account deleted successfully' });
});

// ===== KEY ROUTES =====

// List Keys
app.post('/api/keys/list', authenticateToken, async (req, res) => {
  const db = await loadDb();
  
  const userKeys = db.keys
    .filter(k => k.userId === req.user.userId)
    .map(k => ({
      id: k.id,
      fullKey: k.fullKey,
      name: k.name,
      created: k.createdAt,
      lastUsed: k.lastUsed || null,
      active: k.active,
      lockedIp: k.lockedIp,
      useCount: k.useCount || 0,
      expiry: k.expiry
    }));

  res.json({ success: true, keys: userKeys });
});

// Create Key
app.post('/api/keys/create', authenticateToken, async (req, res) => {
  const { customKey, expiryDays } = req.body;
  const db = await loadDb();

  if (!customKey) {
    return res.status(400).json({ success: false, error: 'Custom key is required' });
  }

  if (db.keys.find(k => k.fullKey === customKey)) {
    return res.status(400).json({ success: false, error: 'Key already exists' });
  }

  const expiry = expiryDays 
    ? new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString() 
    : null;

  const newKey = {
    id: uuidv4(),
    userId: req.user.userId,
    username: req.user.username,
    name: customKey,
    fullKey: customKey,
    createdAt: new Date().toISOString(),
    expiry: expiry,
    active: true,
    lockedIp: null,
    useCount: 0
  };

  db.keys.push(newKey);
  await saveDb(db);

  res.json({ success: true, key: customKey, name: customKey, id: newKey.id });
});

// Revoke Key
app.post('/api/keys/revoke', authenticateToken, async (req, res) => {
  const { key } = req.body;
  const db = await loadDb();

  const keyIndex = db.keys.findIndex(k => k.fullKey === key && k.userId === req.user.userId);

  if (keyIndex === -1) {
    return res.status(404).json({ success: false, error: 'Key not found' });
  }

  db.keys[keyIndex].active = false;
  await saveDb(db);

  res.json({ success: true, message: 'Key revoked' });
});

// Reset Key (unlock IP)
app.post('/api/keys/reset', authenticateToken, async (req, res) => {
  const { key } = req.body;
  const db = await loadDb();

  const keyIndex = db.keys.findIndex(k => k.fullKey === key && k.userId === req.user.userId);

  if (keyIndex === -1) {
    return res.status(404).json({ success: false, error: 'Key not found' });
  }

  const oldIp = db.keys[keyIndex].lockedIp;
  db.keys[keyIndex].lockedIp = null;
  db.keys[keyIndex].useCount = 0;
  db.keys[keyIndex].lastReset = new Date().toISOString();
  
  await saveDb(db);

  res.json({ success: true, message: 'Key reset successfully', previousIp: oldIp });
});

// ===== API VALIDATION (for C++ clients) =====

app.get('/api/data', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const requestIp = req.headers['x-forwarded-for'] || req.ip || 'unknown';
  const db = await loadDb();

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  const keyData = db.keys.find(k => k.fullKey === apiKey && k.active);

  if (!keyData) {
    return res.status(403).json({ error: 'Invalid or revoked API key' });
  }

  // Check IP lock
  if (keyData.lockedIp && keyData.lockedIp !== requestIp) {
    return res.status(403).json({ 
      error: 'Key locked to different IP', 
      lockedIp: keyData.lockedIp, 
      yourIp: requestIp 
    });
  }

  // Lock to IP if not locked
  if (!keyData.lockedIp) {
    keyData.lockedIp = requestIp;
  }
  
  keyData.useCount = (keyData.useCount || 0) + 1;
  keyData.lastUsed = new Date().toISOString();
  
  await saveDb(db);

  res.json({
    success: true,
    message: 'Access granted',
    data: {
      key: keyData.fullKey,
      created: keyData.createdAt,
      useCount: keyData.useCount
    }
  });
});

// Admin: Get all users
app.get('/api/admin/users', async (req, res) => {
  const db = await loadDb();
  const { search, banned } = req.query;
  
  let users = db.users.map(u => {
    const userKeys = db.keys.filter(k => k.userId === u.id);
    return {
      id: u.id,
      username: u.username,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin || null,
      firstActivation: u.firstActivation || null,
      hwid: u.hwid || null,
      banned: u.banned || false,
      banReason: u.banReason || null,
      keys: userKeys.map(k => ({
        fullKey: k.fullKey,
        active: k.active,
        lockedIp: k.lockedIp,
        useCount: k.useCount || 0
      }))
    };
  });
  
  // Filter by search
  if (search) {
    users = users.filter(u => 
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      u.keys.some(k => k.fullKey.toLowerCase().includes(search.toLowerCase()))
    );
  }
  
  // Filter by banned status
  if (banned === 'true') {
    users = users.filter(u => u.banned);
  } else if (banned === 'false') {
    users = users.filter(u => !u.banned);
  }
  
  res.json({ success: true, users });
});

// Admin: Ban user
app.post('/api/admin/users/:id/ban', async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  const db = await loadDb();
  
  const userIndex = db.users.findIndex(u => u.id === id);
  if (userIndex === -1) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }
  
  db.users[userIndex].banned = true;
  db.users[userIndex].banReason = reason || 'Banned by admin';
  db.users[userIndex].bannedAt = new Date().toISOString();
  
  // Also revoke all their keys
  db.keys.forEach(k => {
    if (k.userId === id) {
      k.active = false;
      k.revokedReason = 'User banned';
    }
  });
  
  await saveDb(db);
  res.json({ success: true, message: 'User banned', username: db.users[userIndex].username });
});

// Admin: Unban user
app.post('/api/admin/users/:id/unban', async (req, res) => {
  const { id } = req.params;
  const db = await loadDb();
  
  const userIndex = db.users.findIndex(u => u.id === id);
  if (userIndex === -1) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }
  
  db.users[userIndex].banned = false;
  db.users[userIndex].banReason = null;
  db.users[userIndex].unbannedAt = new Date().toISOString();
  
  await saveDb(db);
  res.json({ success: true, message: 'User unbanned', username: db.users[userIndex].username });
});

// Admin: Ban specific key
app.post('/api/admin/keys/:key/ban', async (req, res) => {
  const { key } = req.params;
  const { reason } = req.body;
  const db = await loadDb();
  
  const keyIndex = db.keys.findIndex(k => k.fullKey === key);
  if (keyIndex === -1) {
    return res.status(404).json({ success: false, error: 'Key not found' });
  }
  
  db.keys[keyIndex].active = false;
  db.keys[keyIndex].banned = true;
  db.keys[keyIndex].banReason = reason || 'Banned by admin';
  db.keys[keyIndex].bannedAt = new Date().toISOString();
  
  await saveDb(db);
  res.json({ success: true, message: 'Key banned', key });
});

// Admin: Get stats
app.get('/api/admin/stats', async (req, res) => {
  const db = await loadDb();
  
  const totalUsers = db.users.length;
  const bannedUsers = db.users.filter(u => u.banned).length;
  const totalKeys = db.keys.length;
  const activeKeys = db.keys.filter(k => k.active && !k.banned).length;
  const bannedKeys = db.keys.filter(k => k.banned).length;
  const totalUses = db.keys.reduce((sum, k) => sum + (k.useCount || 0), 0);
  
  res.json({
    success: true,
    stats: {
      totalUsers,
      bannedUsers,
      totalKeys,
      activeKeys,
      bannedKeys,
      totalUses
    }
  });
});

// Update login to track HWID and last login
app.post('/api/auth/login', async (req, res) => {
  const { username, password, hwid } = req.body;
  const db = await loadDb();

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password required' });
  }

  const sanitizedUsername = username.toLowerCase().trim();
  const userIndex = db.users.findIndex(u => u.username === sanitizedUsername);
  
  if (userIndex === -1) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
  
  const user = db.users[userIndex];
  
  // Check if banned
  if (user.banned) {
    return res.status(403).json({ success: false, error: 'Account banned', reason: user.banReason });
  }

  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  // Update last login and HWID
  user.lastLogin = new Date().toISOString();
  if (hwid) {
    if (!user.firstActivation) {
      user.firstActivation = new Date().toISOString();
    }
    user.hwid = hwid;
  }
  
  await saveDb(db);

  const token = jwt.sign(
    { userId: user.id, username: user.username, isAdmin: user.username === 'owner' || user.username === 'admin' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({ success: true, token, username: user.username, isAdmin: user.username === 'owner' || user.username === 'admin' });
});

// Health check
app.get('/api/health', async (req, res) => {
  const db = await loadDb();
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    database: DB_FILE,
    users: db.users.length,
    keys: db.keys.length
  });
});

app.listen(PORT, () => {
  console.log(`Auth server running on port ${PORT}`);
  console.log(`Database: ${DB_FILE}`);
});
