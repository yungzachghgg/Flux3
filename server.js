const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

// PostgreSQL database - PERSISTS on Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        banned BOOLEAN DEFAULT FALSE,
        ban_reason TEXT,
        hwid TEXT,
        first_activation TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS keys (
        id TEXT PRIMARY KEY,
        key TEXT UNIQUE NOT NULL,
        user_id TEXT REFERENCES users(id),
        name TEXT DEFAULT 'Default Key',
        active BOOLEAN DEFAULT TRUE,
        expiry TIMESTAMP,
        locked_ip TEXT,
        use_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('PostgreSQL database ready - data will PERSIST!');
  } catch (e) {
    console.error('Database init error:', e);
  }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Root route
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

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

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const defaultKey = `FLUX-${sanitizedUsername.toUpperCase()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    
    await pool.query(
      'INSERT INTO users (id, username, password) VALUES ($1, $2, $3)',
      [userId, sanitizedUsername, hashedPassword]
    );
    
    await pool.query(
      'INSERT INTO keys (id, key, user_id, name) VALUES ($1, $2, $3, $4)',
      [uuidv4(), defaultKey, userId, 'Default Key']
    );

    res.json({ success: true, message: 'Account created' });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    console.error('Register error:', e);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase().trim()]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    if (user.banned) {
      return res.status(403).json({ success: false, error: 'Account banned', reason: user.ban_reason });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Update login info
    const now = new Date();
    await pool.query(
      'UPDATE users SET last_login = $1, hwid = COALESCE($2, hwid), first_activation = COALESCE(first_activation, $1) WHERE id = $3',
      [now, hwid, user.id]
    );

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      success: true, 
      token, 
      username: user.username,
      isAdmin: user.username === 'owner' || user.username === 'admin'
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

// Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword || newPassword.length < 4) {
    return res.status(400).json({ success: false, error: 'Valid current and new password required (4+ chars)' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    const user = result.rows[0];

    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.user.userId]);

    res.json({ success: true, message: 'Password updated' });
  } catch (e) {
    console.error('Change password error:', e);
    res.status(500).json({ success: false, error: 'Failed to change password' });
  }
});

// Delete account
app.post('/api/auth/delete-account', authenticateToken, async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, error: 'Password required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Password is incorrect' });
    }

    await pool.query('DELETE FROM keys WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.userId]);

    res.json({ success: true, message: 'Account deleted' });
  } catch (e) {
    console.error('Delete account error:', e);
    res.status(500).json({ success: false, error: 'Failed to delete account' });
  }
});

// ===== KEY ROUTES =====

// List user's keys
app.post('/api/keys/list', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM keys WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    
    const keys = result.rows.map(k => ({
      id: k.id,
      name: k.name,
      fullKey: k.key,
      created: k.created_at,
      expiry: k.expiry,
      active: k.active,
      lockedIp: k.locked_ip,
      useCount: k.use_count
    }));
    
    res.json({ success: true, keys });
  } catch (e) {
    console.error('List keys error:', e);
    res.status(500).json({ success: false, error: 'Failed to list keys' });
  }
});

// Create new key
app.post('/api/keys/create', authenticateToken, async (req, res) => {
  const { customKey, expiryDays } = req.body;

  if (!customKey) {
    return res.status(400).json({ success: false, error: 'Custom key required' });
  }

  try {
    const id = uuidv4();
    const expiry = expiryDays ? new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000) : null;
    
    await pool.query(
      'INSERT INTO keys (id, key, user_id, name, expiry) VALUES ($1, $2, $3, $4, $5)',
      [id, customKey, req.user.userId, 'Custom Key', expiry]
    );
    
    res.json({ success: true, message: 'Key created' });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(400).json({ success: false, error: 'Key already exists' });
    }
    console.error('Create key error:', e);
    res.status(500).json({ success: false, error: 'Failed to create key' });
  }
});

// Revoke key
app.post('/api/keys/revoke', authenticateToken, async (req, res) => {
  const { key } = req.body;

  try {
    await pool.query(
      'DELETE FROM keys WHERE key = $1 AND user_id = $2',
      [key, req.user.userId]
    );
    
    res.json({ success: true, message: 'Key revoked' });
  } catch (e) {
    console.error('Revoke key error:', e);
    res.status(500).json({ success: false, error: 'Failed to revoke key' });
  }
});

// Reset key IP
app.post('/api/keys/reset', authenticateToken, async (req, res) => {
  const { key } = req.body;

  try {
    await pool.query(
      'UPDATE keys SET locked_ip = NULL WHERE key = $1 AND user_id = $2',
      [key, req.user.userId]
    );
    
    res.json({ success: true, message: 'Key reset' });
  } catch (e) {
    console.error('Reset key error:', e);
    res.status(500).json({ success: false, error: 'Failed to reset key' });
  }
});

// ===== API DATA ENDPOINT =====

app.get('/api/data', async (req, res) => {
  const key = req.headers['x-api-key'];
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!key) {
    return res.status(401).json({ success: false, error: 'API key required' });
  }

  try {
    const result = await pool.query(
      'SELECT k.*, u.banned FROM keys k JOIN users u ON k.user_id = u.id WHERE k.key = $1',
      [key]
    );
    
    const keyData = result.rows[0];

    if (!keyData) {
      return res.status(401).json({ success: false, error: 'Invalid key' });
    }

    if (keyData.banned) {
      return res.status(403).json({ success: false, error: 'Key banned' });
    }

    if (!keyData.active) {
      return res.status(403).json({ success: false, error: 'Key revoked' });
    }

    if (keyData.expiry && new Date(keyData.expiry) < new Date()) {
      return res.status(403).json({ success: false, error: 'Key expired' });
    }

    // IP lock check
    if (keyData.locked_ip && keyData.locked_ip !== clientIp) {
      return res.status(403).json({ success: false, error: 'IP locked', lockedIp: keyData.locked_ip });
    }

    // Lock to IP on first use
    if (!keyData.locked_ip) {
      await pool.query('UPDATE keys SET locked_ip = $1 WHERE id = $2', [clientIp, keyData.id]);
    }

    // Increment use count
    await pool.query('UPDATE keys SET use_count = use_count + 1 WHERE id = $1', [keyData.id]);

    res.json({ 
      success: true, 
      message: 'Access granted',
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    console.error('API data error:', e);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ===== ADMIN ROUTES =====

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.username !== 'owner' && req.user.username !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  const { search = '', banned } = req.query;

  try {
    let query = `
      SELECT u.*, 
        COALESCE(json_agg(k.*) FILTER (WHERE k.id IS NOT NULL), '[]') as keys
      FROM users u
      LEFT JOIN keys k ON u.id = k.user_id
      WHERE u.username ILIKE $1
    `;
    const params = [`%${search}%`];

    if (banned === 'true') {
      query += ' AND u.banned = TRUE';
    } else if (banned === 'false') {
      query += ' AND u.banned = FALSE';
    }

    query += ' GROUP BY u.id ORDER BY u.created_at DESC';

    const result = await pool.query(query, params);
    
    const users = result.rows.map(u => ({
      id: u.id,
      username: u.username,
      banned: u.banned,
      banReason: u.ban_reason,
      hwid: u.hwid,
      createdAt: u.created_at,
      firstActivation: u.first_activation,
      lastLogin: u.last_login,
      keys: u.keys.filter(k => k.id) // Remove empty keys
    }));
    
    res.json({ success: true, users });
  } catch (e) {
    console.error('Admin users error:', e);
    res.status(500).json({ success: false, error: 'Failed to load users' });
  }
});

// Ban user
app.post('/api/admin/users/:id/ban', authenticateToken, async (req, res) => {
  if (req.user.username !== 'owner' && req.user.username !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  const { reason } = req.body;

  try {
    await pool.query(
      'UPDATE users SET banned = TRUE, ban_reason = $1 WHERE id = $2',
      [reason || null, req.params.id]
    );
    
    // Revoke all user keys
    await pool.query('UPDATE keys SET active = FALSE WHERE user_id = $1', [req.params.id]);
    
    res.json({ success: true, message: 'User banned' });
  } catch (e) {
    console.error('Ban user error:', e);
    res.status(500).json({ success: false, error: 'Failed to ban user' });
  }
});

// Unban user
app.post('/api/admin/users/:id/unban', authenticateToken, async (req, res) => {
  if (req.user.username !== 'owner' && req.user.username !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  try {
    await pool.query(
      'UPDATE users SET banned = FALSE, ban_reason = NULL WHERE id = $1',
      [req.params.id]
    );
    
    res.json({ success: true, message: 'User unbanned' });
  } catch (e) {
    console.error('Unban user error:', e);
    res.status(500).json({ success: false, error: 'Failed to unban user' });
  }
});

// Admin stats
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  if (req.user.username !== 'owner' && req.user.username !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  try {
    const usersResult = await pool.query('SELECT COUNT(*) as total, COUNT(CASE WHEN banned THEN 1 END) as banned FROM users');
    const keysResult = await pool.query('SELECT COUNT(*) as total, SUM(use_count) as uses FROM keys WHERE active = TRUE');
    
    res.json({
      success: true,
      stats: {
        totalUsers: parseInt(usersResult.rows[0].total),
        bannedUsers: parseInt(usersResult.rows[0].banned),
        activeKeys: parseInt(keysResult.rows[0].total) || 0,
        totalUses: parseInt(keysResult.rows[0].uses) || 0
      }
    });
  } catch (e) {
    console.error('Admin stats error:', e);
    res.status(500).json({ success: false, error: 'Failed to load stats' });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const usersResult = await pool.query('SELECT COUNT(*) as count FROM users');
    const keysResult = await pool.query('SELECT COUNT(*) as count FROM keys');
    
    res.json({ 
      status: 'ok', 
      database: 'PostgreSQL',
      timestamp: new Date().toISOString(),
      users: parseInt(usersResult.rows[0].count),
      keys: parseInt(keysResult.rows[0].count)
    });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});

// Start server
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
    console.log(`Database: PostgreSQL (PERSISTENT)`);
  });
});
