/**
 * @fileoverview Security Middleware
 * @description Core security middleware for Express applications
 */

import cors from 'cors';
import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { body, param, query, validationResult } from 'express-validator';
import helmet from 'helmet';
import type { CorsConfig, Logger } from '../types/index.js';

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
 * Create CORS configuration
 */
export function createCorsConfig(
  allowedOrigins: string[] = [],
  logger: Logger = defaultLogger
): CorsConfig {
  return {
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true);

      const defaultOrigins = [
        'http://localhost:3000',
        'http://localhost:3001',
        'https://localhost:3000',
        'https://localhost:3001',
        ...allowedOrigins,
      ].filter(Boolean);

      if (defaultOrigins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn(`CORS blocked request from origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'X-API-Key',
      'X-Admin-Token',
    ],
  };
}

/**
 * Create rate limiting configurations
 */
export function createRateLimitConfig() {
  return {
    // General API rate limit
    general: rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // Limit each IP to 100 requests per windowMs
      message: {
        error: 'Too many requests from this IP, please try again later.',
      },
      standardHeaders: true,
      legacyHeaders: false,
    }),

    // Stricter rate limit for authentication
    auth: rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // Limit each IP to 5 auth requests per windowMs
      message: {
        error: 'Too many authentication attempts, please try again later.',
      },
      standardHeaders: true,
      legacyHeaders: false,
    }),

    // Very strict rate limit for password reset
    passwordReset: rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 3, // Limit each IP to 3 password reset requests per hour
      message: {
        error: 'Too many password reset attempts, please try again later.',
      },
      standardHeaders: true,
      legacyHeaders: false,
    }),
  };
}

/**
 * Create Helmet configuration for security headers
 */
export function createHelmetConfig() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: false, // Disable for development
  });
}

/**
 * Request size limit middleware
 */
export function createRequestSizeLimit(limit: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = req.get('content-length');
    if (contentLength) {
      const size = parseInt(contentLength, 10);
      const limitBytes = parseInt(limit.replace(/[^\d]/g, ''), 10);
      const limitUnit = limit.replace(/[\d]/g, '').toUpperCase();

      let limitInBytes = limitBytes;
      if (limitUnit === 'KB') limitInBytes *= 1024;
      if (limitUnit === 'MB') limitInBytes *= 1024 * 1024;
      if (limitUnit === 'GB') limitInBytes *= 1024 * 1024 * 1024;

      if (size > limitInBytes) {
        res.status(413).json({
          error: `Request entity too large. Maximum size allowed: ${limit}`,
        });
        return;
      }
    }
    next();
  };
}

/**
 * Request sanitization middleware
 */
export function createSanitizeRequest(_logger: Logger = defaultLogger) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Remove potentially dangerous characters from string inputs
    const sanitizeString = (str: string): string => {
      return str
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
        .replace(/on\w+\s*=\s*[^>\s]+/gi, '')
        .trim();
    };

    // Sanitize body parameters
    if (req.body && typeof req.body === 'object') {
      for (const key in req.body) {
        if (typeof req.body[key] === 'string') {
          req.body[key] = sanitizeString(req.body[key]);
        }
      }
    }

    // Sanitize query parameters
    if (req.query && typeof req.query === 'object') {
      for (const key in req.query) {
        if (typeof req.query[key] === 'string') {
          req.query[key] = sanitizeString(req.query[key] as string);
        }
      }
    }

    next();
  };
}

/**
 * Request validation middleware
 */
export function createValidateRequest(logger: Logger = defaultLogger) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Request validation failed', {
        errors: errors.array(),
        ip: req.ip,
        url: req.url,
        method: req.method,
      });

      res.status(400).json({
        error: 'Validation failed',
        details: errors.array(),
      });
      return;
    }
    next();
  };
}

/**
 * Validation rules
 */
export const validationRules = {
  // Email validation
  email: body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),

  // Password validation
  password: body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage(
      'Password must contain at least one lowercase letter, one uppercase letter, and one number'
    ),

  // Name validation
  name: body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Name must be between 1 and 100 characters')
    .matches(/^[a-zA-Z\s\-'.]+$/)
    .withMessage(
      'Name can only contain letters, spaces, hyphens, apostrophes, and periods'
    ),

  // Slug validation
  slug: param('slug')
    .matches(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    .withMessage(
      'Slug must contain only lowercase letters, numbers, and hyphens'
    ),

  // Content validation
  content: body('content')
    .trim()
    .isLength({ min: 1 })
    .withMessage('Content is required')
    .isLength({ max: 10000 })
    .withMessage('Content must be less than 10,000 characters'),

  // Title validation
  title: body('title')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Title must be between 1 and 200 characters'),

  // Pagination validation
  page: query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),

  limit: query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
};

/**
 * Create security middleware for API routes
 */
export function createApiSecurity(
  allowedOrigins: string[] = [],
  logger: Logger = defaultLogger
) {
  const corsConfig = createCorsConfig(allowedOrigins, logger);
  const helmetConfig = createHelmetConfig();
  const rateLimitConfig = createRateLimitConfig();
  const sanitizeRequest = createSanitizeRequest(logger);

  return [
    helmetConfig,
    cors(corsConfig),
    rateLimitConfig.general,
    sanitizeRequest,
  ];
}

/**
 * Create security middleware for auth routes
 */
export function createAuthSecurity(
  allowedOrigins: string[] = [],
  logger: Logger = defaultLogger
) {
  const corsConfig = createCorsConfig(allowedOrigins, logger);
  const helmetConfig = createHelmetConfig();
  const rateLimitConfig = createRateLimitConfig();
  const sanitizeRequest = createSanitizeRequest(logger);

  return [
    helmetConfig,
    cors(corsConfig),
    rateLimitConfig.auth,
    sanitizeRequest,
  ];
}

/**
 * Create security middleware for password reset
 */
export function createPasswordResetSecurity(
  allowedOrigins: string[] = [],
  logger: Logger = defaultLogger
) {
  const corsConfig = createCorsConfig(allowedOrigins, logger);
  const helmetConfig = createHelmetConfig();
  const rateLimitConfig = createRateLimitConfig();
  const sanitizeRequest = createSanitizeRequest(logger);

  return [
    helmetConfig,
    cors(corsConfig),
    rateLimitConfig.passwordReset,
    sanitizeRequest,
  ];
}

/**
 * Create security middleware for forms
 */
export function createFormSecurity(
  allowedOrigins: string[] = [],
  logger: Logger = defaultLogger
) {
  const corsConfig = createCorsConfig(allowedOrigins, logger);
  const helmetConfig = createHelmetConfig();
  const rateLimitConfig = createRateLimitConfig();
  const sanitizeRequest = createSanitizeRequest(logger);

  return [
    helmetConfig,
    cors(corsConfig),
    rateLimitConfig.general,
    sanitizeRequest,
  ];
}

/**
 * Create static file security middleware
 */
export function createStaticSecurity() {
  const helmetConfig = createHelmetConfig();

  return [
    helmetConfig,
    (req: Request, res: Response, next: NextFunction) => {
      // Set cache headers for static assets
      if (
        req.url.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/)
      ) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      }
      next();
    },
  ];
}
