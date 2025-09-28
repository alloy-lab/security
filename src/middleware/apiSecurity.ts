/**
 * @fileoverview API Security Middleware
 * @description API-specific security middleware and validation
 */

import type { NextFunction, Request, Response } from 'express';
import { body, param, query, validationResult } from 'express-validator';
import type { ApiResponse, Logger, RequestWithFiles } from '../types/index.js';

// Default logger implementation
const defaultLogger: Logger = {
  info: (message: string, meta?: Record<string, unknown>) =>
    console.log(`[INFO] ${message}`, meta || ''),
  warn: (message: string, meta?: Record<string, unknown>) =>
    console.warn(`[WARN] ${message}`, meta || ''),
  error: (message: string, meta?: Record<string, unknown>) =>
    console.error(`[ERROR] ${message}`, meta || ''),
  debug: (message: string, meta?: Record<string, unknown>) =>
    console.debug(`[DEBUG] ${message}`, meta || ''),
};

/**
 * API key validation middleware
 */
export function createValidateApiKey(logger: Logger = defaultLogger) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const apiKey = req.get('X-API-Key') || req.query.apiKey;
    const validApiKey = process.env.API_KEY;

    if (!validApiKey) {
      logger.warn('API_KEY not configured in environment');
      res.status(500).json({
        error: 'API key validation not configured',
      });
      return;
    }

    if (!apiKey || apiKey !== validApiKey) {
      logger.warn(`Invalid API key attempt from IP: ${req.ip}`);
      res.status(401).json({
        error: 'Invalid or missing API key',
      });
      return;
    }

    next();
  };
}

/**
 * Admin authentication middleware
 */
export function createRequireAdmin(logger: Logger = defaultLogger) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // This would integrate with your authentication system
    // For now, we'll use a simple header check
    const adminToken = req.get('X-Admin-Token');
    const validAdminToken = process.env.ADMIN_TOKEN;

    if (!validAdminToken) {
      logger.warn('ADMIN_TOKEN not configured in environment');
      res.status(500).json({
        error: 'Admin authentication not configured',
      });
      return;
    }

    if (!adminToken || adminToken !== validAdminToken) {
      logger.warn(`Unauthorized admin access attempt from IP: ${req.ip}`);
      res.status(403).json({
        error: 'Admin access required',
      });
      return;
    }

    next();
  };
}

/**
 * Request logging middleware for API routes
 */
export function createApiRequestLogger(logger: Logger = defaultLogger) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const startTime = Date.now();

    // Log the request
    logger.info('API Request', {
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    });

    // Log response when it finishes
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      logger.info('API Response', {
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        ip: req.ip,
      });
    });

    next();
  };
}

/**
 * API validation rules
 */
export const apiValidationRules = {
  // Page creation/update
  createPage: [
    body('title')
      .trim()
      .isLength({ min: 1, max: 200 })
      .withMessage('Title must be between 1 and 200 characters'),
    body('content')
      .trim()
      .isLength({ min: 1 })
      .withMessage('Content is required'),
    body('slug')
      .optional()
      .matches(/^[a-z0-9-]+$/)
      .withMessage(
        'Slug can only contain lowercase letters, numbers, and hyphens'
      ),
    body('status')
      .optional()
      .isIn(['draft', 'published'])
      .withMessage('Status must be either draft or published'),
  ],

  // Page update
  updatePage: [
    param('id').isMongoId().withMessage('Invalid page ID'),
    body('title')
      .optional()
      .trim()
      .isLength({ min: 1, max: 200 })
      .withMessage('Title must be between 1 and 200 characters'),
    body('content')
      .optional()
      .trim()
      .isLength({ min: 1 })
      .withMessage('Content cannot be empty'),
    body('status')
      .optional()
      .isIn(['draft', 'published'])
      .withMessage('Status must be either draft or published'),
  ],

  // Page deletion
  deletePage: [param('id').isMongoId().withMessage('Invalid page ID')],

  // Media upload
  uploadMedia: [
    body('alt')
      .optional()
      .trim()
      .isLength({ max: 200 })
      .withMessage('Alt text must be less than 200 characters'),
    body('caption')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('Caption must be less than 500 characters'),
  ],

  // Site settings update
  updateSiteSettings: [
    body('title')
      .optional()
      .trim()
      .isLength({ min: 1, max: 100 })
      .withMessage('Site title must be between 1 and 100 characters'),
    body('description')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('Site description must be less than 500 characters'),
    body('contact.email')
      .optional()
      .isEmail()
      .withMessage('Contact email must be valid'),
  ],

  // Pagination
  pagination: [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    query('sort')
      .optional()
      .isIn([
        'title',
        'createdAt',
        'updatedAt',
        '-title',
        '-createdAt',
        '-updatedAt',
      ])
      .withMessage('Invalid sort field'),
  ],

  // Search
  search: [
    query('q')
      .trim()
      .isLength({ min: 1, max: 100 })
      .withMessage('Search query must be between 1 and 100 characters'),
    query('type')
      .optional()
      .isIn(['pages', 'media', 'all'])
      .withMessage('Search type must be pages, media, or all'),
  ],
};

/**
 * Validation middleware for API requests
 */
export function createValidateApiRequest(logger: Logger = defaultLogger) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('API validation failed', {
        errors: errors.array(),
        ip: req.ip,
        url: req.url,
        method: req.method,
      });

      res.status(400).json({
        error: 'Validation failed',
        details: errors.array().map((err) => ({
          field: err.type === 'field' ? err.path : 'unknown',
          message: err.msg,
          value: (err as { value?: unknown }).value,
        })),
      });
      return;
    }
    next();
  };
}

/**
 * File upload security middleware
 */
export function createValidateFileUpload(
  maxSize: number = 10 * 1024 * 1024, // 10MB
  allowedTypes: string[] = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf',
    'text/plain',
  ],
  logger: Logger = defaultLogger
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const reqWithFiles = req as RequestWithFiles;

    if (!reqWithFiles.file && !reqWithFiles.files) {
      res.status(400).json({
        error: 'No file uploaded',
      });
      return;
    }

    const file =
      reqWithFiles.file ||
      (Array.isArray(reqWithFiles.files) ? reqWithFiles.files[0] : undefined);
    if (!file) {
      res.status(400).json({
        error: 'No file uploaded',
      });
      return;
    }

    // Check file size
    if (file.size > maxSize) {
      logger.warn(`File too large: ${file.size} bytes from IP: ${req.ip}`);
      res.status(413).json({
        error: `File too large. Maximum size is ${Math.round(maxSize / 1024 / 1024)}MB.`,
      });
      return;
    }

    // Check file type
    if (!allowedTypes.includes(file.mimetype)) {
      logger.warn(`Invalid file type: ${file.mimetype} from IP: ${req.ip}`);
      res.status(400).json({
        error: `Invalid file type. Allowed types: ${allowedTypes.join(', ')}`,
      });
      return;
    }

    // Check for malicious file extensions
    const maliciousExtensions = [
      '.exe',
      '.bat',
      '.cmd',
      '.scr',
      '.pif',
      '.vbs',
      '.js',
    ];
    const fileExtension = file.originalname
      .toLowerCase()
      .substring(file.originalname.lastIndexOf('.'));

    if (maliciousExtensions.includes(fileExtension)) {
      logger.warn(
        `Malicious file extension blocked: ${fileExtension} from IP: ${req.ip}`
      );
      res.status(400).json({
        error: 'File type not allowed',
      });
      return;
    }

    next();
  };
}

/**
 * Rate limiting for specific API endpoints
 */
export function createApiRateLimit(
  _windowMs: number,
  _max: number,
  _message: string
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // This would integrate with your rate limiting system
    // For now, we'll use a simple in-memory store
    // const key = `rate_limit_${req.ip}_${req.path}`;
    // const now = Date.now();
    // const windowStart = now - windowMs;

    // In a real implementation, you'd use Redis or a proper rate limiting library
    // This is just a placeholder
    next();
  };
}

/**
 * API response formatting middleware
 */
export function createFormatApiResponse(
  includeRequestId: boolean = false,
  _logger: Logger = defaultLogger
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const originalJson = res.json;

    res.json = function (body: unknown) {
      // Add security headers to API responses
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');

      // Format the response
      const formattedResponse: ApiResponse = {
        success: res.statusCode >= 200 && res.statusCode < 300,
        status: res.statusCode,
        data: body,
        timestamp: new Date().toISOString(),
        ...(includeRequestId && {
          requestId: req.get('X-Request-ID') || undefined,
        }),
      };

      return originalJson.call(this, formattedResponse);
    };

    next();
  };
}
