// server.js - AuthAPI v3.3 ULTIMATE - No Email Validation
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();

/* ================= ERROR HANDLING ================= */
process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ UNHANDLED REJECTION:', reason);
});

app.use((err, req, res, next) => {
  console.error('❌ Express Error:', err.stack);
  res.status(500).json({
    success: false, 
    message: 'Internal Server Error', 
    error_code: 'SERVER_ERROR'
  });
});

/* ================= MIDDLEWARE ================= */
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

/* ================= CONSTANTS ================= */
const PORT = process.env.PORT || 10000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'keys.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const DEVICES_FILE = path.join(DATA_DIR, 'devices.json');
const LOGS_FILE = path.join(DATA_DIR, 'activity_logs.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');

const JWT_SECRET = process.env.JWT_SECRET || 'please-change-jwt-secret-2025';
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-hmac-secret-2025';

const MAX_ACCOUNTS_PER_DEVICE = 3;

/* ================= BACKUP SYSTEM ================= */
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  console.log('✅ Created backup directory');
}

function createBackup() {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupSubDir = path.join(BACKUP_DIR, timestamp);
    
    if (!fs.existsSync(backupSubDir)) {
      fs.mkdirSync(backupSubDir, { recursive: true });
    }

    const filesToBackup = [DATA_FILE, USERS_FILE, CONFIG_FILE, DEVICES_FILE, LOGS_FILE];
    
    filesToBackup.forEach(file => {
      if (fs.existsSync(file)) {
        const filename = path.basename(file);
        const backupPath = path.join(backupSubDir, filename);
        fs.copyFileSync(file, backupPath);
      }
    });

    console.log(`✅ Backup created: ${timestamp}`);
    cleanOldBackups();
  } catch(err) {
    console.error('❌ Backup error:', err);
  }
}

function cleanOldBackups() {
  try {
    const backups = fs.readdirSync(BACKUP_DIR);
    const now = new Date();
    
    backups.forEach(backup => {
      const backupPath = path.join(BACKUP_DIR, backup);
      const stats = fs.statSync(backupPath);
      const daysDiff = (now - stats.mtime) / (1000 * 60 * 60 * 24);
      
      if (daysDiff > 7) {
        fs.rmSync(backupPath, { recursive: true, force: true });
        console.log(`🗑️ Deleted old backup: ${backup}`);
      }
    });
  } catch(err) {
    console.error('❌ Clean backup error:', err);
  }
}

// Auto backup every 6 hours
setInterval(createBackup, 6 * 60 * 60 * 1000);

/* ================= AUTO DELETE EXPIRED KEYS ================= */
function autoDeleteExpiredKeys() {
  try {
    const keys = loadKeys();
    const now = new Date();
    let deletedCount = 0;
    
    const filteredKeys = keys.filter(k => {
      // Check if key has auto_delete flag and has expired
      if (k.auto_delete && new Date(k.expires_at) <= now) {
        console.log(`🗑️ Auto-deleted expired key: ${k.key_code}`);
        deletedCount++;
        return false; // Remove this key
      }
      return true; // Keep this key
    });
    
    if (deletedCount > 0) {
      saveKeys(filteredKeys);
      console.log(`✅ Auto-deleted ${deletedCount} expired keys`);
    }
  } catch(err) {
    console.error('❌ Auto-delete error:', err);
  }
}

// Run auto-delete every hour
setInterval(autoDeleteExpiredKeys, 60 * 60 * 1000);
// Run on startup
autoDeleteExpiredKeys();

/* ================= SAFE FILE OPERATIONS ================= */
function safeLoadJSON(file, defaultValue = []) {
  try {
    if (fs.existsSync(file)) {
      const data = fs.readFileSync(file, 'utf8');
      return JSON.parse(data);
    }
    return defaultValue;
  } catch(err) {
    console.error(`❌ Error loading ${file}:`, err);
    return defaultValue;
  }
}

function safeSaveJSON(file, data) {
  try {
    const tempFile = file + '.tmp';
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tempFile, file);
    return true;
  } catch(err) {
    console.error(`❌ Error saving ${file}:`, err);
    return false;
  }
}

/* ================= INIT FILES ================= */
if (!fs.existsSync(DATA_FILE)) {
  safeSaveJSON(DATA_FILE, []);
  console.log('✅ Initialized keys.json');
}

if (!fs.existsSync(USERS_FILE)) {
  safeSaveJSON(USERS_FILE, []);
  console.log('✅ Initialized users.json');
}

if (!fs.existsSync(DEVICES_FILE)) {
  safeSaveJSON(DEVICES_FILE, []);
  console.log('✅ Initialized devices.json');
}

if (!fs.existsSync(LOGS_FILE)) {
  safeSaveJSON(LOGS_FILE, []);
  console.log('✅ Initialized activity_logs.json');
}

if (!fs.existsSync(CONFIG_FILE)) {
  const adminPassword = process.env.ADMIN_PASSWORD || '1';
  const hash = bcrypt.hashSync(adminPassword, 10);
  const cfg = {
    admin: {
      username: 'admin',
      passwordHash: hash
    },
    contact: {
      admin_profile: 'https://www.facebook.com/duc.pham.396384',
      telegram: '@phamcduc0',
      email: 'monhpham15@gmail.com'
    },
    settings: {
      maintenance_mode: false,
      registration_enabled: true,
      max_key_days: 365,
      enable_email_verification: false
    }
  };
  safeSaveJSON(CONFIG_FILE, cfg);
  console.log('✅ Initialized config.json');
}

/* ================= HELPERS ================= */
function loadKeys() {
  return safeLoadJSON(DATA_FILE, []);
}

function saveKeys(keys) {
  return safeSaveJSON(DATA_FILE, keys);
}

function loadUsers() {
  return safeLoadJSON(USERS_FILE, []);
}

function saveUsers(users) {
  return safeSaveJSON(USERS_FILE, users);
}

function loadDevices() {
  return safeLoadJSON(DEVICES_FILE, []);
}

function saveDevices(devices) {
  return safeSaveJSON(DEVICES_FILE, devices);
}

function loadConfig() {
  return safeLoadJSON(CONFIG_FILE, {
    admin: { username: 'admin', passwordHash: '' },
    contact: {},
    settings: {}
  });
}

function saveConfig(config) {
  return safeSaveJSON(CONFIG_FILE, config);
}

function loadLogs() {
  return safeLoadJSON(LOGS_FILE, []);
}

function saveLogs(logs) {
  return safeSaveJSON(LOGS_FILE, logs);
}

/* ================= ACTIVITY LOGGING ================= */
function logActivity(action, userId, username, details = {}) {
  try {
    const logs = loadLogs();
    const log = {
      id: uuidv4(),
      action,
      userId,
      username,
      details,
      timestamp: new Date().toISOString(),
      ip: details.ip || 'unknown'
    };
    
    logs.push(log);
    
    // Keep only last 1000 logs
    if (logs.length > 1000) {
      logs.splice(0, logs.length - 1000);
    }
    
    saveLogs(logs);
  } catch(err) {
    console.error('❌ Log error:', err);
  }
}

function signValue(val) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex');
}

// Format date with full details: year, month, day, hours, minutes, seconds
function getFullDateTime() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  // Return format: 2025-02-15T14:30:45 (includes year, hours, minutes, seconds)
  return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
}

function randomChunk(len) {
  return Math.random().toString(36).substring(2, 2 + len).toUpperCase();
}

function generateKey(type = "KEY") {
  const prefix = type;
  return `${prefix}-${randomChunk(6)}-${randomChunk(4)}`;
}

function generateAPICode() {
  return `API-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
}

function generateDeviceId(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection.remoteAddress || '';
  const combined = `${userAgent}-${ip}`;
  return crypto.createHash('sha256').update(combined).digest('hex');
}

/* ================= AUTH MIDDLEWARE ================= */
function requireAdmin(req, res, next) {
  try {
    const auth = req.headers['authorization'];
    if (!auth) return res.status(401).json({ error: 'Missing token' });

    const parts = auth.split(' ');
    if (parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid token' });

    const payload = jwt.verify(parts[1], JWT_SECRET);
    if (payload.role === 'admin') {
      req.user = payload;
      return next();
    }
    return res.status(403).json({ error: 'Admin access required' });
  } catch(err) {
    console.error('Auth error:', err);
    return res.status(401).json({ error: 'Token invalid' });
  }
}

function requireAuth(req, res, next) {
  try {
    const auth = req.headers['authorization'];
    if (!auth) return res.status(401).json({ error: 'Missing token' });

    const parts = auth.split(' ');
    if (parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid token' });

    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    return next();
  } catch(err) {
    console.error('Auth error:', err);
    return res.status(401).json({ error: 'Token invalid' });
  }
}

/* ================= MAINTENANCE MODE ================= */
function checkMaintenance(req, res, next) {
  const config = loadConfig();
  if (config.settings?.maintenance_mode && !req.path.includes('/admin')) {
    return res.status(503).json({
      success: false,
      message: '🔧 Hệ thống đang bảo trì. Vui lòng quay lại sau.',
      error_code: 'MAINTENANCE_MODE'
    });
  }
  next();
}

app.use(checkMaintenance);

/* ================= ADMIN LOGIN ================= */
app.post('/api/admin-login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const cfg = loadConfig();

    if (username !== cfg.admin.username) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, cfg.admin.passwordHash);
    if (!ok) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { username: cfg.admin.username, role: 'admin', iat: Date.now() },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    logActivity('admin_login', 'admin', 'admin', { ip: req.ip });

    res.json({ success: true, token, role: 'admin' });
  } catch(err) {
    console.error('Admin login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= USER REGISTRATION (NO EMAIL VALIDATION) ================= */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body || {};
    
    const config = loadConfig();
    if (!config.settings?.registration_enabled) {
      return res.status(403).json({ 
        success: false, 
        message: 'Đăng ký tạm thời bị tắt. Liên hệ admin.' 
      });
    }

    // Kiểm tra đầu vào cơ bản - email có thể là bất kỳ
    if (!username || !password || !email) {
      return res.status(400).json({ success: false, message: 'Vui lòng điền đầy đủ thông tin' });
    }

    if (username.length < 3 || password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username tối thiểu 3 ký tự, mật khẩu tối thiểu 6 ký tự' 
      });
    }

    // Không kiểm tra định dạng email - cho phép nhập bất kỳ
    // Email chỉ cần có giá trị, không cần hợp lệ

    const deviceId = generateDeviceId(req);
    const devices = loadDevices();
    const deviceRecord = devices.find(d => d.device_id === deviceId);
    
    if (deviceRecord && deviceRecord.accounts.length >= MAX_ACCOUNTS_PER_DEVICE) {
      return res.status(403).json({ 
        success: false, 
        message: `Thiết bị này đã đăng ký tối đa ${MAX_ACCOUNTS_PER_DEVICE} tài khoản.` 
      });
    }

    const users = loadUsers();
    
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ success: false, message: 'Tên đăng nhập đã tồn tại' });
    }
    
    // ĐÃ BỎ: Không kiểm tra email trùng - cho phép nhiều acc cùng 1 email

    const hashedPassword = await bcrypt.hash(password, 10);
    const apiCode = generateAPICode();
    
    const newUser = {
      id: uuidv4(),
      username,
      email,
      passwordHash: hashedPassword,
      role: 'user',
      isActive: true,
      isBanned: false,
      createdAt: getFullDateTime(),
      keyCount: 0,
      lastLogin: null,
      apiCode: apiCode,
      deviceId: deviceId,
      totalKeysCreated: 0,
      totalVerifications: 0,
      emailVerified: false
    };

    users.push(newUser);
    saveUsers(users);

    if (deviceRecord) {
      deviceRecord.accounts.push(newUser.id);
    } else {
      devices.push({
        device_id: deviceId,
        accounts: [newUser.id],
        created_at: getFullDateTime()
      });
    }
    saveDevices(devices);

    logActivity('register', newUser.id, username, { email, ip: req.ip });

    res.json({ 
      success: true, 
      message: 'Đăng ký thành công!',
      apiCode: apiCode
    });
  } catch(err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= USER LOGIN ================= */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
    }

    const users = loadUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(401).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không đúng' });
    }

    if (user.isBanned) {
      return res.status(403).json({ 
        success: false, 
        message: 'Tài khoản đã bị khóa.' 
      });
    }

    if (!user.isActive) {
      return res.status(403).json({ 
        success: false, 
        message: 'Tài khoản đã bị tạm khóa.' 
      });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không đúng' });
    }

    user.lastLogin = getFullDateTime();
    saveUsers(users);

    const token = jwt.sign(
      { 
        userId: user.id,
        username: user.username, 
        role: user.role,
        iat: Date.now() 
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    logActivity('login', user.id, username, { ip: req.ip });

    res.json({ 
      success: true, 
      token,
      user: {
        username: user.username,
        email: user.email,
        keyCount: user.keyCount,
        apiCode: user.apiCode
      }
    });
  } catch(err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= CREATE KEY (ENHANCED với Custom Key) ================= */
app.post('/api/create-key', requireAuth, (req, res) => {
  try {
    const { days, devices, type, customKey, autoDelete, name } = req.body || {};
    
    if (!days || !devices) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
    }

    const config = loadConfig();
    const maxDays = config.settings?.max_key_days || 365;
    
    if (days > maxDays && req.user.role !== 'admin') {
      return res.status(400).json({ 
        success: false, 
        message: `Thời hạn tối đa ${maxDays} ngày` 
      });
    }

    const users = loadUsers();
    const user = users.find(u => u.id === req.user.userId);

    if (req.user.role !== 'admin') {
      if (!user) {
        return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
      }

      if (user.isBanned || !user.isActive) {
        return res.status(403).json({ success: false, message: 'Tài khoản đã bị khóa' });
      }
    }

    let keyCode;
    
    // Custom key logic
    if (customKey && customKey.trim()) {
      keyCode = customKey.trim();
      const keys = loadKeys();
      if (keys.find(k => k.key_code === keyCode)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Key code đã tồn tại. Vui lòng chọn mã khác.' 
        });
      }
    } else {
      keyCode = generateKey(type || "KEY");
    }

    const createdAt = getFullDateTime();
    const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    const signature = signValue(keyCode);

    const keys = loadKeys();
    const record = {
      id: uuidv4(),
      key_code: keyCode,
      type: type || "KEY",
      signature,
      created_at: createdAt,
      expires_at: expiresAt,
      allowed_devices: Number(devices),
      devices: [],
      owner_id: req.user.role === 'admin' ? 'admin' : user.id,
      owner_username: req.user.role === 'admin' ? 'admin' : user.username,
      require_api_key: false,
      total_verifications: 0,
      last_verified: null,
      is_custom: !!customKey,
      auto_delete: autoDelete || false,
      alias_name: name ? String(name).trim() : null
    };

    keys.push(record);
    saveKeys(keys);

    if (req.user.role !== 'admin' && user) {
      user.keyCount++;
      user.totalKeysCreated = (user.totalKeysCreated || 0) + 1;
      saveUsers(users);
    }

    logActivity('create_key', req.user.userId, req.user.username, { 
      keyCode, 
      type, 
      days, 
      devices,
      custom: !!customKey,
      autoDelete: autoDelete || false,
      name: name || null
    });

    res.json({ 
      success: true, 
      message: 'Tạo key thành công',
      key: record,
      usage_info: {
        key_code: record.key_code,
        alias: record.alias_name || 'Chưa có alias',
        verify_endpoint: '/api/verify-key',
        info_endpoint: '/api/key-info'
      }
    });
  } catch(err) {
    console.error('Create key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= BULK CREATE KEYS ================= */
app.post('/api/bulk-create-keys', requireAuth, (req, res) => {
  try {
    const { count, days, devices, type, autoDelete, name } = req.body || {};
    
    if (!count || !days || !devices || count < 1 || count > 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Số lượng phải từ 1-100' 
      });
    }

    const users = loadUsers();
    const user = users.find(u => u.id === req.user.userId);

    if (req.user.role !== 'admin') {
      if (!user) {
        return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
      }
    }

    const keys = loadKeys();
    const createdKeys = [];

    for (let i = 0; i < count; i++) {
      const keyCode = generateKey(type || "KEY");
      const createdAt = getFullDateTime();
      const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
      const signature = signValue(keyCode);

      const record = {
        id: uuidv4(),
        key_code: keyCode,
        type: type || "KEY",
        signature,
        created_at: createdAt,
        expires_at: expiresAt,
        allowed_devices: Number(devices),
        devices: [],
        owner_id: req.user.role === 'admin' ? 'admin' : user.id,
        owner_username: req.user.role === 'admin' ? 'admin' : user.username,
        require_api_key: false,
        total_verifications: 0,
        last_verified: null,
        auto_delete: autoDelete || false,
        alias_name: name ? String(name).trim() : null
      };

      keys.push(record);
      createdKeys.push(record);
    }

    saveKeys(keys);

    if (req.user.role !== 'admin' && user) {
      user.keyCount += count;
      user.totalKeysCreated = (user.totalKeysCreated || 0) + count;
      saveUsers(users);
    }

    logActivity('bulk_create_keys', req.user.userId, req.user.username, { 
      count, 
      type, 
      days, 
      devices,
      autoDelete: autoDelete || false,
      name: name || null
    });

    res.json({ 
      success: true, 
      message: `Tạo thành công ${count} keys`, 
      keys: createdKeys 
    });
  } catch(err) {
    console.error('Bulk create error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= LIST USER KEYS ================= */
app.get('/api/my-keys', requireAuth, (req, res) => {
  try {
    const keys = loadKeys();
    const userKeys = keys.filter(k => k.owner_id === req.user.userId)
      .map(k => ({
        key_code: k.key_code,
        type: k.type,
        alias: k.alias_name || 'N/A',
        created_at: k.created_at,
        expires_at: k.expires_at,
        is_expired: new Date(k.expires_at) < new Date(),
        devices_used: k.devices.length,
        devices_allowed: k.allowed_devices,
        total_verifications: k.total_verifications || 0,
        is_custom: k.is_custom || false
      }));
    res.json({ 
      success: true, 
      count: userKeys.length, 
      keys: userKeys 
    });
  } catch(err) {
    console.error('List keys error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= LIST ALL KEYS (ADMIN) ================= */
app.get('/api/list-keys', requireAdmin, (req, res) => {
  try {
    res.json(loadKeys());
  } catch(err) {
    console.error('List all keys error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= SEARCH KEYS BY ALIAS ================= */
app.post('/api/search-keys', requireAuth, (req, res) => {
  try {
    const { query } = req.body || {};
    
    if (!query || query.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'Nhập từ khóa tìm kiếm' });
    }

    const keys = loadKeys();
    const searchTerm = query.toLowerCase().trim();
    
    const results = keys.filter(k => 
      k.owner_id === req.user.userId && (
        (k.alias_name && k.alias_name.toLowerCase().includes(searchTerm)) ||
        k.key_code.toLowerCase().includes(searchTerm) ||
        k.type.toLowerCase().includes(searchTerm)
      )
    ).map(k => ({
      key_code: k.key_code,
      type: k.type,
      alias: k.alias_name || 'Không có alias',
      created_at: k.created_at,
      expires_at: k.expires_at,
      is_expired: new Date(k.expires_at) < new Date(),
      devices_used: k.devices.length,
      devices_allowed: k.allowed_devices,
      total_verifications: k.total_verifications || 0
    }));

    res.json({ 
      success: true, 
      query,
      found: results.length,
      results 
    });
  } catch(err) {
    console.error('Search keys error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= USER STATS ================= */
app.get('/api/my-stats', requireAuth, (req, res) => {
  try {
    const users = loadUsers();
    const user = users.find(u => u.id === req.user.userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const keys = loadKeys();
    const userKeys = keys.filter(k => k.owner_id === user.id);
    const now = new Date();

    const stats = {
      totalKeys: userKeys.length,
      activeKeys: userKeys.filter(k => new Date(k.expires_at) > now).length,
      expiredKeys: userKeys.filter(k => new Date(k.expires_at) <= now).length,
      keyLimit: 'Không giới hạn',
      apiCode: user.apiCode,
      totalKeysCreated: user.totalKeysCreated || 0,
      totalVerifications: user.totalVerifications || 0
    };

    res.json(stats);
  } catch(err) {
    console.error('Stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= GET API CODE ================= */
app.get('/api/my-api-code', requireAuth, (req, res) => {
  try {
    const users = loadUsers();
    const user = users.find(u => u.id === req.user.userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ 
      success: true, 
      apiCode: user.apiCode,
      username: user.username,
      note: 'Tất cả users có thể verify key mà không cần API Key'
    });
  } catch(err) {
    console.error('Get API code error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= RESET API CODE ================= */
app.post('/api/reset-api-code', requireAuth, (req, res) => {
  try {
    const users = loadUsers();
    const user = users.find(u => u.id === req.user.userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const oldApiCode = user.apiCode;
    user.apiCode = generateAPICode();
    saveUsers(users);

    logActivity('reset_api_code', user.id, user.username, { 
      oldCode: oldApiCode.substring(0, 15) + '...' 
    });

    res.json({ 
      success: true, 
      message: 'API Code đã được reset', 
      newApiCode: user.apiCode 
    });
  } catch(err) {
    console.error('Reset API code error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= EXTEND KEY ================= */
app.post('/api/extend-key', requireAuth, (req, res) => {
  try {
    const { key, days } = req.body || {};
    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
    }

    found.expires_at = new Date(
      new Date(found.expires_at).getTime() + days * 86400000
    ).toISOString();

    saveKeys(keys);

    logActivity('extend_key', req.user.userId, req.user.username, { keyCode: key, days });

    res.json({ success: true, message: 'Gia hạn key thành công' });
  } catch(err) {
    console.error('Extend key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= UPDATE KEY ALIAS ================= */
app.post('/api/update-key-alias', requireAuth, (req, res) => {
  try {
    const { key, alias } = req.body || {};
    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    }

    if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
    }

    found.alias_name = alias ? String(alias).trim() : null;
    saveKeys(keys);

    logActivity('update_key_alias', req.user.userId, req.user.username, { 
      keyCode: key, 
      newAlias: alias || null
    });

    res.json({ 
      success: true, 
      message: 'Cập nhật alias thành công',
      key_code: key,
      new_alias: found.alias_name || 'Không có'
    });
  } catch(err) {
    console.error('Update key alias error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= RESET KEY ================= */
app.post('/api/reset-key', requireAuth, (req, res) => {
  try {
    const { key } = req.body || {};
    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
    }

    const oldDevices = found.devices.length;
    found.devices = [];
    saveKeys(keys);

    logActivity('reset_key', req.user.userId, req.user.username, { 
      keyCode: key, 
      devicesCleared: oldDevices 
    });

    res.json({ success: true, message: 'Reset thiết bị thành công' });
  } catch(err) {
    console.error('Reset key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= DELETE KEY ================= */
app.post('/api/delete-key', requireAuth, (req, res) => {
  try {
    const { key } = req.body || {};
    let keys = loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
    }

    keys = keys.filter(k => k.key_code !== key);
    saveKeys(keys);

    if (found.owner_id && found.owner_id !== 'admin') {
      const users = loadUsers();
      const user = users.find(u => u.id === found.owner_id);
      if (user && user.keyCount > 0) {
        user.keyCount--;
        saveUsers(users);
      }
    }

    logActivity('delete_key', req.user.userId, req.user.username, { keyCode: key });

    res.json({ success: true, message: 'Xóa key thành công' });
  } catch(err) {
    console.error('Delete key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= VERIFY KEY (PUBLIC - ENHANCED) ================= */
app.post('/api/verify-key', (req, res) => {
  try {
    const { key, device_id, api_code } = req.body || {};
    
    if (!key || !device_id) {
      return res.status(400).json({ 
        success: false, 
        message: 'Thiếu key hoặc device_id',
        error_code: 'MISSING_PARAMS'
      });
    }

    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ 
        success: false, 
        message: 'Key không tồn tại',
        error_code: 'KEY_NOT_FOUND'
      });
    }

    // API Code check for free users
    if (found.require_api_key) {
      if (!api_code) {
        return res.status(401).json({ 
          success: false, 
          message: '🔒 Key này yêu cầu API Code!',
          error_code: 'API_CODE_REQUIRED',
          hint: 'Lấy API Code tại: Dashboard → Cài Đặt'
        });
      }

      const users = loadUsers();
      const keyOwner = users.find(u => u.id === found.owner_id);
      
      if (!keyOwner) {
        return res.status(500).json({ 
          success: false, 
          message: 'Lỗi hệ thống',
          error_code: 'OWNER_NOT_FOUND'
        });
      }

      if (keyOwner.apiCode !== api_code) {
        return res.status(401).json({ 
          success: false, 
          message: '❌ API Code không đúng!',
          error_code: 'INVALID_API_CODE'
        });
      }

      if (keyOwner.isBanned || !keyOwner.isActive) {
        return res.status(403).json({ 
          success: false, 
          message: 'Tài khoản chủ key đã bị khóa',
          error_code: 'OWNER_BANNED'
        });
      }

      // Update user verification count
      keyOwner.totalVerifications = (keyOwner.totalVerifications || 0) + 1;
      saveUsers(users);
    }

    // Verify signature
    const expectedSig = signValue(found.key_code);
    if (expectedSig !== found.signature) {
      return res.status(500).json({ 
        success: false, 
        message: 'Chữ ký không khớp',
        error_code: 'SIGNATURE_MISMATCH'
      });
    }

    // Check expiry
    if (new Date(found.expires_at) < new Date()) {
      return res.json({ 
        success: false, 
        message: 'Key đã hết hạn',
        error_code: 'KEY_EXPIRED',
        expired_at: found.expires_at
      });
    }

    // Check device limit
    if (!found.devices.includes(device_id)) {
      if (found.devices.length >= found.allowed_devices) {
        return res.json({ 
          success: false, 
          message: 'Đã đạt giới hạn thiết bị',
          error_code: 'DEVICE_LIMIT_REACHED',
          devices_used: found.devices.length,
          devices_allowed: found.allowed_devices
        });
      }

      found.devices.push(device_id);
    }

    // Update verification stats
    found.total_verifications = (found.total_verifications || 0) + 1;
    found.last_verified = getFullDateTime();
    saveKeys(keys);

    res.json({ 
      success: true, 
      message: 'Xác thực thành công', 
      type: found.type,
      expires_at: found.expires_at,
      devices_remaining: found.allowed_devices - found.devices.length,
      alias: found.alias_name || 'N/A'
    });
  } catch(err) {
    console.error('Verify error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error_code: 'SERVER_ERROR'
    });
  }
});

/* ================= KEY INFO ================= */
app.post('/api/key-info', (req, res) => {
  try {
    const { key } = req.body || {};
    
    if (!key) {
      return res.status(400).json({ success: false, message: 'Thiếu key' });
    }

    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    }

    const now = new Date();
    const expiresAt = new Date(found.expires_at);
    const isExpired = expiresAt < now;
    const daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));

    res.json({
      success: true,
      info: {
        type: found.type,
        created_at: found.created_at,
        expires_at: found.expires_at,
        is_expired: isExpired,
        days_remaining: isExpired ? 0 : daysRemaining,
        devices_used: found.devices.length,
        devices_allowed: found.allowed_devices,
        require_api_key: found.require_api_key,
        total_verifications: found.total_verifications || 0,
        last_verified: found.last_verified || 'Never',
        is_custom: found.is_custom || false,
        alias_name: found.alias_name || null
      }
    });
  } catch(err) {
    console.error('Key info error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: USER MANAGEMENT ================= */
app.get('/api/admin/users', requireAdmin, (req, res) => {
  try {
    const users = loadUsers().map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      isActive: u.isActive,
      isBanned: u.isBanned,
      keyCount: u.keyCount,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin,
      apiCode: u.apiCode,
      deviceId: u.deviceId,
      totalKeysCreated: u.totalKeysCreated || 0,
      totalVerifications: u.totalVerifications || 0
    }));
    res.json(users);
  } catch(err) {
    console.error('List users error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



app.post('/api/admin/ban-user', requireAdmin, (req, res) => {
  try {
    const { userId } = req.body || {};
    
    const users = loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    user.isBanned = true;
    saveUsers(users);

    logActivity('ban_user', 'admin', 'admin', { targetUser: user.username });
    
    res.json({ success: true, message: 'Đã ban user' });
  } catch(err) {
    console.error('Ban user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/unban-user', requireAdmin, (req, res) => {
  try {
    const { userId } = req.body || {};
    
    const users = loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    user.isBanned = false;
    saveUsers(users);

    logActivity('unban_user', 'admin', 'admin', { targetUser: user.username });
    
    res.json({ success: true, message: 'Đã unban user' });
  } catch(err) {
    console.error('Unban user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/toggle-active', requireAdmin, (req, res) => {
  try {
    const { userId } = req.body || {};
    
    const users = loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    user.isActive = !user.isActive;
    saveUsers(users);

    logActivity('toggle_active', 'admin', 'admin', { 
      targetUser: user.username, 
      newStatus: user.isActive 
    });
    
    res.json({ success: true, message: user.isActive ? 'Đã kích hoạt user' : 'Đã khóa user' });
  } catch(err) {
    console.error('Toggle active error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  try {
    const { userId } = req.body || {};
    
    let users = loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    let keys = loadKeys();
    keys = keys.filter(k => k.owner_id !== userId);
    saveKeys(keys);

    users = users.filter(u => u.id !== userId);
    saveUsers(users);

    logActivity('delete_user', 'admin', 'admin', { targetUser: user.username });
    
    res.json({ success: true, message: 'Đã xóa user và tất cả key của họ' });
  } catch(err) {
    console.error('Delete user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: SETTINGS ================= */
app.get('/api/admin/settings', requireAdmin, (req, res) => {
  try {
    const config = loadConfig();
    res.json(config.settings || {});
  } catch(err) {
    console.error('Get settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  try {
    const config = loadConfig();
    config.settings = { ...config.settings, ...req.body };
    saveConfig(config);

    logActivity('update_settings', 'admin', 'admin', req.body);

    res.json({ success: true, message: 'Cập nhật settings thành công' });
  } catch(err) {
    console.error('Update settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: LOGS ================= */
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  try {
    const logs = loadLogs();
    const limit = parseInt(req.query.limit) || 100;
    res.json(logs.slice(-limit).reverse());
  } catch(err) {
    console.error('Get logs error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: BACKUP ================= */
app.post('/api/admin/backup', requireAdmin, (req, res) => {
  try {
    createBackup();
    res.json({ success: true, message: 'Backup thành công' });
  } catch(err) {
    console.error('Backup error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/backups', requireAdmin, (req, res) => {
  try {
    const backups = fs.readdirSync(BACKUP_DIR).map(name => {
      const backupPath = path.join(BACKUP_DIR, name);
      const stats = fs.statSync(backupPath);
      return {
        name,
        created: stats.mtime,
        size: stats.size
      };
    });
    res.json(backups);
  } catch(err) {
    console.error('List backups error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: STATS ================= */
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const users = loadUsers();
    const keys = loadKeys();
    const devices = loadDevices();
    const now = new Date();

    const stats = {
      totalUsers: users.length,
      activeUsers: users.filter(u => u.isActive && !u.isBanned).length,
      bannedUsers: users.filter(u => u.isBanned).length,
      totalKeys: keys.length,
      activeKeys: keys.filter(k => new Date(k.expires_at) > now).length,
      expiredKeys: keys.filter(k => new Date(k.expires_at) <= now).length,
      totalDevices: devices.length,
      totalVerifications: keys.reduce((sum, k) => sum + (k.total_verifications || 0), 0)
    };

    res.json(stats);
  } catch(err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= CONTACT INFO ================= */
app.get('/api/contact', (req, res) => {
  try {
    const cfg = loadConfig();
    res.json(cfg.contact || {});
  } catch(err) {
    console.error('Get contact error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ALIAS GUIDE ================= */
app.get('/api/docs/alias-guide', (req, res) => {
  res.json({
    title: 'Key Alias/Naming Guide',
    description: 'Hướng dẫn sử dụng tính năng đặt tên (alias) cho keys',
    features: [
      'Đặt tên cho key khi tạo',
      'Cập nhật tên cho key hiện tại',
      'Tìm kiếm key theo tên/alias',
      'Xem tên alias khi lấy thông tin key'
    ],
    endpoints: {
      create_with_alias: {
        method: 'POST',
        url: '/api/create-key',
        description: 'Tạo key với alias/tên',
        body: {
          days: 30,
          devices: 5,
          type: 'KEY',
          customKey: 'MY-CUSTOM-KEY',
          name: 'Công ty A - Server 1',
          autoDelete: false
        },
        response: {
          success: true,
          key: {
            key_code: 'MY-CUSTOM-KEY',
            alias_name: 'Công ty A - Server 1'
          }
        }
      },
      update_alias: {
        method: 'POST',
        url: '/api/update-key-alias',
        description: 'Cập nhật alias cho key đã tồn tại',
        body: {
          key: 'KEY-ABC123',
          alias: 'Công ty B - Server 2'
        },
        response: {
          success: true,
          new_alias: 'Công ty B - Server 2'
        }
      },
      search_by_alias: {
        method: 'POST',
        url: '/api/search-keys',
        description: 'Tìm kiếm key theo alias hoặc key code',
        body: {
          query: 'Công ty A'
        },
        response: {
          success: true,
          found: 2,
          results: [
            {
              key_code: 'MY-KEY-001',
              alias: 'Công ty A - Server 1'
            }
          ]
        }
      },
      list_keys: {
        method: 'GET',
        url: '/api/my-keys',
        description: 'Danh sách tất cả keys với alias của người dùng',
        response: {
          keys: [
            {
              key_code: 'MY-KEY-001',
              alias: 'Công ty A - Server 1'
            }
          ]
        }
      },
      get_key_info: {
        method: 'POST',
        url: '/api/key-info',
        description: 'Xem chi tiết key bao gồm alias',
        body: {
          key: 'MY-KEY-001'
        },
        response: {
          info: {
            alias_name: 'Công ty A - Server 1'
          }
        }
      }
    },
    examples: {
      scenario_1: {
        title: 'Tạo key cho project',
        steps: [
          {
            action: 'POST /api/create-key',
            body: 'days: 365, devices: 10, name: "Project A - Production"'
          },
          {
            action: 'Nhận response',
            key_code: 'KEY-XYZ789',
            alias: 'Project A - Production'
          }
        ]
      },
      scenario_2: {
        title: 'Đổi tên key',
        steps: [
          {
            action: 'POST /api/update-key-alias',
            body: 'key: KEY-XYZ789, alias: "Project A - Staging"'
          }
        ]
      },
      scenario_3: {
        title: 'Tìm key theo tên',
        steps: [
          {
            action: 'POST /api/search-keys',
            body: 'query: "Project A"'
          }
        ]
      }
    }
  });
});

/* ================= ROOT & API INFO ================= */
app.get('/', (req, res) => {
app.use(express.static("public"));
});

app.get('/api', (req, res) => {
  const config = loadConfig();
  res.json({
    name: "AuthAPI v3.3 ULTIMATE - Free Unlimited Keys for Everyone",
    version: "3.3.0",
    status: "online",
    maintenance_mode: config.settings?.maintenance_mode || false,
    features: [
      "✅ Multi-user authentication",
      "✅ Same email for multiple accounts",
      "✅ UNLIMITED key creation - No limits!",
      "✅ 3 accounts per device limit (strict)",
      "✅ Custom key creation for all users",
      "✅ Bulk key creation (1-100 keys per request)",
      "✅ Key alias/naming support",
      "💾 Auto backup every 6 hours",
      "📊 Activity logging system",
      "🔄 API Code reset",
      "🔐 HMAC signature verification",
      "📱 Device tracking (by UserAgent + IP)",
      "🛡️ Anti-crash error handling",
      "⚙️ System settings management",
      "🔧 Maintenance mode support"
    ],
    security: {
      email_verification: "DISABLED - Accept any email, allow duplicates",
      device_limit: "3 accounts per device (UserAgent + IP hash)",
      api_code: "Optional for all users",
      custom_keys: "Unlimited for all users!",
      bulk_creation: "Unlimited (max 100 keys per request)",
      key_limit: "COMPLETELY UNLIMITED FOR ALL USERS"
    },
    note: "All users have the same rights - No VIP/Premium tiers"
  });
});

/* ================= HEALTH CHECK ================= */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

/* ================= 404 HANDLER ================= */
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    error_code: 'NOT_FOUND'
  });
});

/* ================= SERVER START ================= */
const server = app.listen(PORT, () => {
  console.log('╔═══════════════════════════════════════════════════╗');
  console.log('║   AuthAPI v3.3 ULTIMATE - Free Unlimited System   ║');
  console.log('╚═══════════════════════════════════════════════════╝');
  console.log(`✅ Server: http://localhost:${PORT}`);
  console.log('📧 Same email: Multiple accounts allowed');
  console.log('🔒 Device limit: Max 3 accounts per device');
  console.log('🔑 Keys: UNLIMITED for all users!!');
  console.log('💎 Custom keys: UNLIMITED for all users!!');
  console.log('📦 Bulk create: Available for all (1-100 keys per request)');
  console.log('🏷️  Key alias: Full support for naming keys');
  console.log('💾 Auto backup: Every 6 hours');
  console.log('📊 Activity logs: Last 1000 actions');
  console.log('✅ API Code: Optional for all users');
  console.log('🎉 No VIP/Premium - All users have same rights!');
  console.log('═══════════════════════════════════════════════════');
  
  // Create initial backup
  createBackup();
});

/* ================= GRACEFUL SHUTDOWN ================= */
process.on('SIGTERM', () => {
  console.log('SIGTERM received...');
  createBackup();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received...');
  createBackup();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });

});
