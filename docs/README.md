# @alloylab/security Documentation

Welcome to the security package documentation. This package provides comprehensive security utilities and middleware for modern web applications.

## Quick Start

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

## Features

- 🛡️ **CORS Configuration**: Flexible CORS setup with origin validation
- ⏱️ **Rate Limiting**: Configurable rate limiting for different endpoints
- 🔒 **Security Headers**: Helmet configuration for security headers
- 🧹 **Request Sanitization**: XSS protection and input sanitization
- ✅ **Validation**: Express-validator integration with common validation rules
- 🔑 **API Security**: API key validation and admin authentication
- 📁 **File Upload Security**: Secure file upload validation
- 🌍 **Environment Validation**: Zod-based environment variable validation

## Documentation

- [API Reference](./api-reference.md)
- [Security Best Practices](./best-practices.md)
- [Configuration Guide](./configuration.md)
- [Examples](./examples.md)

## Support

- 📖 [GitHub Repository](https://github.com/alloy-lab/overland/tree/main/packages/security)
- 🐛 [Issue Tracker](https://github.com/alloy-lab/overland/issues)
- 💬 [Discussions](https://github.com/alloy-lab/overland/discussions)
