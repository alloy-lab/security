# Basic Security Example

This example demonstrates how to use the `@alloylab/security` package in a basic Express.js application.

## Setup

1. Install the package:

```bash
npm install @alloylab/security express
```

2. Set up environment variables:

```bash
# .env
NODE_ENV=development
PORT=3000
DATABASE_URI=mongodb://localhost:27017/myapp
PAYLOAD_SECRET=your-32-character-secret-key-here
PAYLOAD_PUBLIC_SERVER_URL=http://localhost:3000
PAYLOAD_PUBLIC_CMS_URL=http://localhost:3001
API_KEY=your-api-key-here
ADMIN_TOKEN=your-admin-token-here
ALLOWED_ORIGIN_1=http://localhost:3000
```

3. Create your Express application:

```typescript
import express from 'express';
import {
  validateEnv,
  createApiSecurity,
  createValidateApiKey,
  createRequireAdmin,
  createFormatApiResponse,
  createValidateFileUpload,
  validationRules,
  createValidateRequest,
} from '@alloylab/security';
import multer from 'multer';

// Validate environment variables
const env = validateEnv();

const app = express();
const upload = multer();

// Apply security middleware to all routes
app.use(
  createApiSecurity(
    [env.ALLOWED_ORIGIN_1, env.ALLOWED_ORIGIN_2].filter(Boolean)
  )
);

// Format API responses
app.use(createFormatApiResponse());

// Public routes
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the secure API' });
});

// API routes with key validation
app.use('/api', createValidateApiKey());

app.get('/api/data', (req, res) => {
  res.json({
    data: 'This is secure data',
    timestamp: new Date().toISOString(),
  });
});

// Admin routes with admin authentication
app.use('/api/admin', createRequireAdmin());

app.get('/api/admin/users', (req, res) => {
  res.json({
    users: [
      { id: 1, name: 'John Doe', email: 'john@example.com' },
      { id: 2, name: 'Jane Smith', email: 'jane@example.com' },
    ],
  });
});

// File upload with security validation
app.post(
  '/api/upload',
  upload.single('file'),
  createValidateFileUpload(
    5 * 1024 * 1024, // 5MB max size
    ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
  ),
  (req, res) => {
    res.json({
      message: 'File uploaded successfully',
      filename: req.file?.originalname,
    });
  }
);

// User registration with validation
app.post(
  '/api/users',
  validationRules.email,
  validationRules.password,
  validationRules.name,
  createValidateRequest(),
  (req, res) => {
    // Handle user registration
    res.json({
      message: 'User created successfully',
      user: {
        email: req.body.email,
        name: req.body.name,
      },
    });
  }
);

// Error handling middleware
app.use(
  (
    err: any,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    console.error(err.stack);
    res.status(500).json({
      error: 'Something went wrong!',
      ...(env.NODE_ENV === 'development' && { stack: err.stack }),
    });
  }
);

// Start server
app.listen(env.PORT, () => {
  console.log(`🚀 Server running on port ${env.PORT}`);
  console.log(`📊 Environment: ${env.NODE_ENV}`);
  console.log(`🔒 Security features enabled`);
});
```

## Testing the API

### 1. Test Public Endpoint

```bash
curl http://localhost:3000/
```

Expected response:

```json
{
  "success": true,
  "status": 200,
  "data": {
    "message": "Welcome to the secure API"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### 2. Test API Endpoint (without key)

```bash
curl http://localhost:3000/api/data
```

Expected response:

```json
{
  "success": false,
  "status": 401,
  "data": {
    "error": "Invalid or missing API key"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### 3. Test API Endpoint (with key)

```bash
curl -H "X-API-Key: your-api-key-here" http://localhost:3000/api/data
```

Expected response:

```json
{
  "success": true,
  "status": 200,
  "data": {
    "data": "This is secure data",
    "timestamp": "2024-01-01T00:00:00.000Z"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### 4. Test Admin Endpoint (without admin token)

```bash
curl -H "X-API-Key: your-api-key-here" http://localhost:3000/api/admin/users
```

Expected response:

```json
{
  "success": false,
  "status": 403,
  "data": {
    "error": "Admin access required"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### 5. Test Admin Endpoint (with admin token)

```bash
curl -H "X-API-Key: your-api-key-here" -H "X-Admin-Token: your-admin-token-here" http://localhost:3000/api/admin/users
```

Expected response:

```json
{
  "success": true,
  "status": 200,
  "data": {
    "users": [
      {
        "id": 1,
        "name": "John Doe",
        "email": "john@example.com"
      },
      {
        "id": 2,
        "name": "Jane Smith",
        "email": "jane@example.com"
      }
    ]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### 6. Test File Upload

```bash
curl -X POST \
  -H "X-API-Key: your-api-key-here" \
  -F "file=@/path/to/your/image.jpg" \
  http://localhost:3000/api/upload
```

### 7. Test User Registration (with validation)

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123",
    "name": "Test User"
  }' \
  http://localhost:3000/api/users
```

## Security Features Demonstrated

1. **Environment Validation**: All environment variables are validated on startup
2. **CORS Protection**: Only allowed origins can access the API
3. **Rate Limiting**: Built-in rate limiting for different endpoint types
4. **Security Headers**: Helmet provides security headers
5. **Request Sanitization**: XSS protection for all inputs
6. **API Key Validation**: API endpoints require valid API keys
7. **Admin Authentication**: Admin endpoints require admin tokens
8. **File Upload Security**: File type, size, and extension validation
9. **Input Validation**: Express-validator integration for data validation
10. **Response Formatting**: Consistent API response format with security headers

## Customization

You can customize the security configuration by providing your own logger and allowed origins:

```typescript
import { createApiSecurity } from '@alloylab/security';

const customLogger = {
  info: (message: string, meta?: any) => console.log(`[INFO] ${message}`, meta),
  warn: (message: string, meta?: any) =>
    console.warn(`[WARN] ${message}`, meta),
  error: (message: string, meta?: any) =>
    console.error(`[ERROR] ${message}`, meta),
  debug: (message: string, meta?: any) =>
    console.debug(`[DEBUG] ${message}`, meta),
};

app.use(createApiSecurity(['https://yourdomain.com'], customLogger));
```
