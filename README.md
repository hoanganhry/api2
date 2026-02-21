# AuthAPI v3.3 ULTIMATE - api.hoangxuantu.com

Free unlimited key management API system.

## Features

- ✅ Multi-user authentication
- ✅ UNLIMITED key creation
- ✅ Custom key support
- ✅ Bulk key creation (1-100)
- ✅ Key alias/naming
- ✅ Auto backup every 6 hours
- ✅ Activity logging
- ✅ Device tracking

## Quick Deploy to Render

### 1. Create GitHub Repository
```bash
cd api-hoangxuantu
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/api-hoangxuantu.git
git push -u origin main
```

### 2. Create Render App
1. Go to https://render.com
2. Click "New +"
3. Select "Web Service"
4. Connect GitHub repo
5. Fill in:
   - **Name**: `api-hoangxuantu`
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `node server_new_api.js`
   - **Region**: Singapore (recommended for Vietnam)

### 3. Set Environment Variables in Render Dashboard
```
JWT_SECRET=your-secret-key-2025
HMAC_SECRET=your-hmac-secret-2025
ADMIN_PASSWORD=your-admin-password
PORT=10000
```

### 4. Add Custom Domain
1. Go to Settings → Custom Domain
2. Add: `api.hoangxuantu.com`
3. Update DNS with CNAME record

## Local Development

```bash
npm install
npm start
# Server runs at http://localhost:10000
```

## API Documentation

Base URL: `https://api.hoangxuantu.com/api`

### Register
```bash
POST /api/register
{
  "username": "user123",
  "password": "pass123",
  "email": "user@example.com"
}
```

### Login
```bash
POST /api/login
{
  "username": "user123",
  "password": "pass123"
}
```

### Create Key
```bash
POST /api/create-key
Headers: Authorization: Bearer {token}
{
  "days": 30,
  "devices": 5,
  "type": "KEY"
}
```

### Verify Key
```bash
POST /api/verify-key
{
  "key": "KEY-ABC123",
  "device_id": "device_hash_here"
}
```

## Support
- Facebook: https://www.facebook.com/duc.pham.396384
- Telegram: @phamcduc0
- Email: monhpham15@gmail.com
