# @alloylab/security

[![npm version](https://badge.fury.io/js/%40alloylab%2Fsecurity.svg)](https://badge.fury.io/js/%40alloy-lab%2Fsecurity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security utilities and middleware for modern web applications. This package provides comprehensive security tools including CORS configuration, rate limiting, request sanitization, validation, and API security middleware.

## Features

- 🛡️ **CORS Configuration**: Flexible CORS setup with origin validation
- ⏱️ **Rate Limiting**: Configurable rate limiting for different endpoints
- 🔒 **Security Headers**: Helmet configuration for security headers
- 🧹 **Request Sanitization**: XSS protection and input sanitization
- ✅ **Validation**: Express-validator integration with common validation rules
- 🔑 **API Security**: API key validation and admin authentication
- 📁 **File Upload Security**: Secure file upload validation
- 🌍 **Environment Validation**: Zod-based environment variable validation
- 🔧 **TypeScript Support**: Full TypeScript definitions and type safety
- 📦 **Framework Agnostic**: Works with any Express-based application

## Installation

```bash
npm install @alloylab/security
# or
yarn add @alloylab/security
# or
pnpm add @alloylab/security
```

## Quick Start

### 1. Basic Security Middleware

```typescript
import express from 'express';
import { createApiSecurity } from '@alloylab/security';

const app = express();

// Apply security middleware to all routes
app.use(createApiSecurity(['https://yourdomain.com']));

app.get('/api/data', (req, res) => {
  res.json({ message: 'Secure data' });
});
```

### 2. Environment Validation

```typescript
import { validateEnv } from '@alloylab/security';

// Validate environment variables on startup
const env = validateEnv();

console.log('Server running on port:', env.PORT);
```

### 3. API Security

```typescript
import express from 'express';
import {
  createValidateApiKey,
  createRequireAdmin,
  createFormatApiResponse,
} from '@alloylab/security';

const app = express();

// API key validation for public API
app.use('/api/public', createValidateApiKey());

// Admin authentication for admin routes
app.use('/api/admin', createRequireAdmin());

// Format API responses
app.use(createFormatApiResponse());

app.get('/api/public/data', (req, res) => {
  res.json({ data: 'public data' });
});

app.get('/api/admin/users', (req, res) => {
  res.json({ users: [] });
});
```

### 4. File Upload Security

```typescript
import express from 'express';
import multer from 'multer';
import { createValidateFileUpload } from '@alloylab/security';

const app = express();
const upload = multer();

// Secure file upload
app.post(
  '/api/upload',
  upload.single('file'),
  createValidateFileUpload(
    5 * 1024 * 1024, // 5MB max size
    ['image/jpeg', 'image/png', 'image/gif'] // Allowed types
  ),
  (req, res) => {
    res.json({ message: 'File uploaded successfully' });
  }
);
```

## API Reference

### Environment Validation

#### `validateEnv(logger?)`

Validates environment variables using a predefined schema.

```typescript
import { validateEnv } from '@alloylab/security';

const env = validateEnv();
```

#### `createEnvSchema(schema)`

Creates a custom environment validation schema.

```typescript
import { createEnvSchema, validateCustomEnv } from '@alloylab/security';
import { z } from 'zod';

const customSchema = createEnvSchema({
  CUSTOM_VAR: z.string().min(1),
  OPTIONAL_VAR: z.string().optional(),
});

const env = validateCustomEnv(customSchema);
```

### Security Middleware

#### `createApiSecurity(allowedOrigins?, logger?)`

Creates comprehensive security middleware for API routes.

```typescript
import { createApiSecurity } from '@alloylab/security';

app.use(createApiSecurity(['https://yourdomain.com']));
```

#### `createAuthSecurity(allowedOrigins?, logger?)`

Creates security middleware for authentication routes with stricter rate limiting.

```typescript
import { createAuthSecurity } from '@alloylab/security';

app.use('/auth', createAuthSecurity());
```

#### `createPasswordResetSecurity(allowedOrigins?, logger?)`

Creates security middleware for password reset with very strict rate limiting.

```typescript
import { createPasswordResetSecurity } from '@alloylab/security';

app.use('/auth/reset', createPasswordResetSecurity());
```

### API Security

#### `createValidateApiKey(logger?)`

Validates API keys from headers or query parameters.

```typescript
import { createValidateApiKey } from '@alloylab/security';

app.use('/api', createValidateApiKey());
```

#### `createRequireAdmin(logger?)`

Requires admin authentication via X-Admin-Token header.

```typescript
import { createRequireAdmin } from '@alloylab/security';

app.use('/admin', createRequireAdmin());
```

#### `createValidateFileUpload(maxSize?, allowedTypes?, logger?)`

Validates file uploads for size, type, and malicious extensions.

```typescript
import { createValidateFileUpload } from '@alloylab/security';

app.post(
  '/upload',
  upload.single('file'),
  createValidateFileUpload(10 * 1024 * 1024, ['image/jpeg', 'image/png'])
);
```

### Validation Rules

The package includes pre-configured validation rules:

```typescript
import { validationRules } from '@alloylab/security';

// Use in your routes
app.post(
  '/users',
  validationRules.email,
  validationRules.password,
  validationRules.name,
  createValidateRequest(),
  (req, res) => {
    // Handle validated request
  }
);
```

Available validation rules:

- `email` - Email validation with normalization
- `password` - Strong password requirements
- `name` - Name validation with character restrictions
- `slug` - URL-friendly slug validation
- `content` - Content length validation
- `title` - Title length validation
- `page` - Pagination page validation
- `limit` - Pagination limit validation

### Request Sanitization

#### `createSanitizeRequest(logger?)`

Sanitizes request body and query parameters to prevent XSS attacks.

```typescript
import { createSanitizeRequest } from '@alloylab/security';

app.use(createSanitizeRequest());
```

### Response Formatting

#### `createFormatApiResponse(includeRequestId?, logger?)`

Formats API responses with consistent structure and security headers.

```typescript
import { createFormatApiResponse } from '@alloylab/security';

app.use(createFormatApiResponse(true));
```

## Configuration

### Environment Variables

The package validates these environment variables:

```bash
# Required
NODE_ENV=development|production|test
DATABASE_URI=your_database_uri
PAYLOAD_SECRET=your_32_character_secret
PAYLOAD_PUBLIC_SERVER_URL=https://your-api.com
PAYLOAD_PUBLIC_CMS_URL=https://your-cms.com

# Optional Security
API_KEY=your_api_key
ADMIN_TOKEN=your_admin_token
ALLOWED_ORIGIN_1=https://yourdomain.com
ALLOWED_ORIGIN_2=https://anotherdomain.com
ADMIN_IP_WHITELIST=192.168.1.0/24

# Features
ENABLE_RATE_LIMITING=true
ENABLE_CORS=true
LOG_LEVEL=info
MAX_FILE_SIZE=10MB
ALLOWED_FILE_TYPES=image/jpeg,image/png,image/gif
```

### Custom Logger

You can provide a custom logger that implements the `Logger` interface:

```typescript
import type { Logger } from '@alloylab/security';

const customLogger: Logger = {
  info: (message, meta) => console.log(`[INFO] ${message}`, meta),
  warn: (message, meta) => console.warn(`[WARN] ${message}`, meta),
  error: (message, meta) => console.error(`[ERROR] ${message}`, meta),
  debug: (message, meta) => console.debug(`[DEBUG] ${message}`, meta),
};

const env = validateEnv(customLogger);
```

## Integration Examples

### Express.js Application

```typescript
import express from 'express';
import {
  validateEnv,
  createApiSecurity,
  createValidateApiKey,
  createFormatApiResponse,
} from '@alloylab/security';

// Validate environment
const env = validateEnv();

const app = express();

// Apply security middleware
app.use(createApiSecurity([env.ALLOWED_ORIGIN_1, env.ALLOWED_ORIGIN_2]));

// API routes with key validation
app.use('/api', createValidateApiKey());

// Format responses
app.use(createFormatApiResponse());

app.get('/api/data', (req, res) => {
  res.json({ data: 'secure data' });
});

app.listen(env.PORT, () => {
  console.log(`Server running on port ${env.PORT}`);
});
```

### Next.js API Routes

```typescript
// pages/api/secure.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { createValidateApiKey } from '@alloylab/security';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  // Apply API key validation
  const validateApiKey = createValidateApiKey();

  validateApiKey(req as any, res as any, () => {
    res.json({ message: 'Secure API response' });
  });
}
```

## Best Practices

1. **Environment Validation**: Always validate environment variables on startup
2. **Rate Limiting**: Use appropriate rate limits for different endpoint types
3. **CORS Configuration**: Only allow necessary origins
4. **Input Sanitization**: Sanitize all user inputs
5. **File Upload Security**: Validate file types and sizes
6. **API Key Management**: Use strong, unique API keys
7. **Logging**: Implement comprehensive security logging
8. **Headers**: Always include security headers

## Contributing

Contributions are welcome! Please read our [Contributing Guide](../../CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## Support

- 📖 [Documentation](https://github.com/alloy-lab/overland/tree/main/packages/security#readme)
- 🐛 [Issue Tracker](https://github.com/alloy-lab/overland/issues)
- 💬 [Discussions](https://github.com/alloy-lab/overland/discussions)
