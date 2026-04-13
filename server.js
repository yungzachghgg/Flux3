const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

// Supabase PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database tables
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        banned BOOLEAN DEFAULT FALSE,
        ban_reason TEXT,
        hwid TEXT,
        first_activation TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        full_key TEXT UNIQUE NOT NULL,
        active BOOLEAN DEFAULT TRUE,
        locked_ip TEXT,
        use_count INTEGER DEFAULT 0,
        expiry TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('Database initialized - using Supabase!');
  } finally {
    client.release();
  }
}

initDb();

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

  const client = await pool.connect();
  try {
    // Check if username exists
    const existing = await client.query('SELECT id FROM users WHERE username = $1', [sanitizedUsername]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    // Insert user
    await client.query(
      'INSERT INTO users (id, username, password, created_at) VALUES ($1, $2, $3, NOW())',
      [userId, sanitizedUsername, hashedPassword]
    );

    // Auto-create default API key
    const defaultKey = `FLUX-${sanitizedUsername.toUpperCase()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    
    await client.query(
      'INSERT INTO api_keys (id, user_id, full_key, active, use_count, created_at) VALUES ($1, $2, $3, true, 0, NOW())',
      [uuidv4(), userId, defaultKey]
    );
    
    res.json({ 
      success: true, 
      message: 'User registered', 
      userId: userId,
      apiKey: defaultKey 
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password required' });
  }

  const sanitizedUsername = username.toLowerCase().trim();
  
  const client = await pool.connect();
  try {
    // Get user from database
    const result = await client.query('SELECT * FROM users WHERE username = $1', [sanitizedUsername]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Check if banned
    if (user.banned) {
      return res.status(403).json({ success: false, error: 'Account banned', reason: user.ban_reason });
    }

    // Update last login and HWID
    const updates = ['last_login = NOW()'];
    const values = [];
    if (hwid) {
      updates.push('hwid = $1');
      values.push(hwid);
      if (!user.first_activation) {
        updates.push('first_activation = NOW()');
      }
    }
    
    await client.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length + 1}`,
      [...values, user.id]
    );

    const token = jwt.sign(
      { userId: user.id, username: user.username, isAdmin: user.username === 'owner' || user.username === 'admin' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ success: true, token, username: user.username, isAdmin: user.username === 'owner' || user.username === 'admin' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Change Password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }

    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ success: false, error: 'New password must be at least 4 characters' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.user.userId]);

    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Delete Account
app.post('/api/auth/delete-account', authenticateToken, async (req, res) => {
  const { password } = req.body;

  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ success: false, error: 'Invalid password' });
    }

    // Delete user (keys auto-delete via CASCADE)
    await client.query('DELETE FROM users WHERE id = $1', [req.user.userId]);

    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// ===== KEY ROUTES =====

// List Keys
app.post('/api/keys/list', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT * FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    
    const userKeys = result.rows.map(k => ({
      id: k.id,
      fullKey: k.full_key,
      name: k.full_key,
      created: k.created_at,
      lastUsed: null,
      active: k.active,
      lockedIp: k.locked_ip,
      useCount: k.use_count || 0,
      expiry: k.expiry
    }));

    res.json({ success: true, keys: userKeys });
  } catch (error) {
    console.error('List keys error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Create Key
app.post('/api/keys/create', authenticateToken, async (req, res) => {
  const { customKey, expiryDays } = req.body;

  const client = await pool.connect();
  try {
    // Check if key exists
    const existing = await client.query('SELECT id FROM api_keys WHERE full_key = $1', [customKey]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Key already exists' });
    }

    const expiry = expiryDays 
      ? new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString() 
      : null;

    const keyId = uuidv4();
    await client.query(
      'INSERT INTO api_keys (id, user_id, full_key, expiry, active, use_count, created_at) VALUES ($1, $2, $3, $4, true, 0, NOW())',
      [keyId, req.user.userId, customKey, expiry]
    );

    res.json({ success: true, key: customKey, name: customKey, id: keyId });
  } catch (error) {
    console.error('Create key error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Revoke Key
app.post('/api/keys/revoke', authenticateToken, async (req, res) => {
  const { key } = req.body;

  const client = await pool.connect();
  try {
    const result = await client.query(
      'UPDATE api_keys SET active = false WHERE full_key = $1 AND user_id = $2 RETURNING id',
      [key, req.user.userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Key not found' });
    }

    res.json({ success: true, message: 'Key revoked' });
  } catch (error) {
    console.error('Revoke key error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Reset Key (unlock IP)
app.post('/api/keys/reset', authenticateToken, async (req, res) => {
  const { key } = req.body;

  const client = await pool.connect();
  try {
    const result = await client.query(
      'UPDATE api_keys SET locked_ip = NULL, use_count = 0 WHERE full_key = $1 AND user_id = $2 RETURNING locked_ip',
      [key, req.user.userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Key not found' });
    }

    res.json({ success: true, message: 'Key reset successfully', previousIp: result.rows[0].locked_ip });
  } catch (error) {
    console.error('Reset key error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// ===== API VALIDATION (for C++ clients) =====

app.get('/api/data', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const requestIp = req.headers['x-forwarded-for'] || req.ip || 'unknown';

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT * FROM api_keys WHERE full_key = $1 AND active = true',
      [apiKey]
    );
    const keyData = result.rows[0];

    if (!keyData) {
      return res.status(403).json({ error: 'Invalid or revoked API key' });
    }

    // Check IP lock
    if (keyData.locked_ip && keyData.locked_ip !== requestIp) {
      return res.status(403).json({ 
        error: 'Key locked to different IP', 
        lockedIp: keyData.locked_ip, 
        yourIp: requestIp 
      });
    }

    // Update key: lock IP and increment use count
    const newCount = (keyData.use_count || 0) + 1;
    await client.query(
      'UPDATE api_keys SET locked_ip = COALESCE(locked_ip, $1), use_count = $2 WHERE id = $3',
      [requestIp, newCount, keyData.id]
    );

    res.json({
      success: true,
      message: 'Access granted',
      data: {
        key: keyData.full_key,
        created: keyData.created_at,
        useCount: newCount
      }
    });
  } catch (error) {
    console.error('API data error:', error);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// Admin: Get all users
app.get('/api/admin/users', async (req, res) => {
  const { search, banned } = req.query;
  
  const client = await pool.connect();
  try {
    // Get all users with their keys
    const usersResult = await client.query(`
      SELECT u.*, 
        COALESCE(json_agg(
          json_build_object(
            'fullKey', k.full_key,
            'active', k.active,
            'lockedIp', k.locked_ip,
            'useCount', k.use_count
          ) ORDER BY k.created_at DESC
        ) FILTER (WHERE k.id IS NOT NULL), '[]') as keys
      FROM users u
      LEFT JOIN api_keys k ON k.user_id = u.id
      GROUP BY u.id, u.username, u.created_at, u.last_login, u.first_activation, u.hwid, u.banned, u.ban_reason
      ORDER BY u.created_at DESC
    `);
    
    let users = usersResult.rows.map(u => ({
      id: u.id,
      username: u.username,
      createdAt: u.created_at,
      lastLogin: u.last_login,
      firstActivation: u.first_activation,
      hwid: u.hwid,
      banned: u.banned || false,
      banReason: u.ban_reason,
      keys: u.keys
    }));
    
    // Filter by search
    if (search) {
      const searchLower = search.toLowerCase();
      users = users.filter(u => 
        u.username.toLowerCase().includes(searchLower) ||
        u.keys.some(k => k.fullKey.toLowerCase().includes(searchLower))
      );
    }
    
    // Filter by banned status
    if (banned === 'true') {
      users = users.filter(u => u.banned);
    } else if (banned === 'false') {
      users = users.filter(u => !u.banned);
    }
    
    res.json({ success: true, users });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Admin: Ban user
app.post('/api/admin/users/:id/ban', async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  
  const client = await pool.connect();
  try {
    // Check user exists
    const userResult = await client.query('SELECT username FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const username = userResult.rows[0].username;
    
    // Ban user
    await client.query(
      'UPDATE users SET banned = true, ban_reason = $1 WHERE id = $2',
      [reason || 'Banned by admin', id]
    );
    
    // Also revoke all their keys
    await client.query(
      'UPDATE api_keys SET active = false WHERE user_id = $1',
      [id]
    );
    
    res.json({ success: true, message: 'User banned', username });
  } catch (error) {
    console.error('Ban user error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Admin: Unban user
app.post('/api/admin/users/:id/unban', async (req, res) => {
  const { id } = req.params;
  
  const client = await pool.connect();
  try {
    // Check user exists
    const userResult = await client.query('SELECT username FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const username = userResult.rows[0].username;
    
    // Unban user
    await client.query(
      'UPDATE users SET banned = false, ban_reason = NULL WHERE id = $1',
      [id]
    );
    
    res.json({ success: true, message: 'User unbanned', username });
  } catch (error) {
    console.error('Unban user error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Admin: Ban specific key
app.post('/api/admin/keys/:key/ban', async (req, res) => {
  const { key } = req.params;
  const { reason } = req.body;
  
  const client = await pool.connect();
  try {
    const result = await client.query(
      'UPDATE api_keys SET active = false WHERE full_key = $1 RETURNING id',
      [key]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Key not found' });
    }
    
    res.json({ success: true, message: 'Key banned', key });
  } catch (error) {
    console.error('Ban key error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Admin: Get stats
app.get('/api/admin/stats', async (req, res) => {
  const client = await pool.connect();
  try {
    const usersResult = await client.query('SELECT COUNT(*) as total, COUNT(CASE WHEN banned THEN 1 END) as banned FROM users');
    const keysResult = await client.query(`
      SELECT 
        COUNT(*) as total, 
        COUNT(CASE WHEN active THEN 1 END) as active,
        COALESCE(SUM(use_count), 0) as total_uses
      FROM api_keys
    `);
    
    res.json({
      success: true,
      stats: {
        totalUsers: parseInt(usersResult.rows[0].total),
        bannedUsers: parseInt(usersResult.rows[0].banned),
        totalKeys: parseInt(keysResult.rows[0].total),
        activeKeys: parseInt(keysResult.rows[0].active),
        bannedKeys: parseInt(usersResult.rows[0].total) - parseInt(keysResult.rows[0].active),
        totalUses: parseInt(keysResult.rows[0].total_uses)
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Login with HWID tracking
app.post('/api/auth/login', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password required' });
  }

  const sanitizedUsername = username.toLowerCase().trim();
  
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [sanitizedUsername]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    // Check if banned
    if (user.banned) {
      return res.status(403).json({ success: false, error: 'Account banned', reason: user.ban_reason });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Update last login and HWID
    const updates = ['last_login = NOW()'];
    const values = [];
    if (hwid) {
      updates.push('hwid = $1');
      values.push(hwid);
      if (!user.first_activation) {
        updates.push('first_activation = NOW()');
      }
    }
    
    await client.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length + 1}`,
      [...values, user.id]
    );

    const token = jwt.sign(
      { userId: user.id, username: user.username, isAdmin: user.username === 'owner' || user.username === 'admin' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ success: true, token, username: user.username, isAdmin: user.username === 'owner' || user.username === 'admin' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  const client = await pool.connect();
  try {
    const usersResult = await client.query('SELECT COUNT(*) as count FROM users');
    const keysResult = await client.query('SELECT COUNT(*) as count FROM api_keys');
    
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      database: 'Supabase PostgreSQL',
      users: parseInt(usersResult.rows[0].count),
      keys: parseInt(keysResult.rows[0].count)
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({ status: 'error', error: error.message });
  } finally {
    client.release();
  }
});

app.listen(PORT, () => {
  console.log(`Auth server running on port ${PORT}`);
  console.log('Database: Supabase PostgreSQL');
});
