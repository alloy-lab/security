/**
 * @fileoverview Security Package Types
 * @description Core type definitions for security utilities and middleware
 */

import type { NextFunction, Request, Response } from 'express';
import type { z } from 'zod';

// Multer file type
interface MulterFile {
  fieldname: string;
  originalname: string;
  encoding: string;
  mimetype: string;
  size: number;
  destination: string;
  filename: string;
  path: string;
  buffer: Buffer;
}

// Environment validation types
export interface EnvConfig {
  NODE_ENV: 'development' | 'production' | 'test';
  PORT: number;
  DATABASE_URI: string;
  PAYLOAD_SECRET: string;
  PAYLOAD_PUBLIC_SERVER_URL: string;
  PAYLOAD_PUBLIC_CMS_URL: string;
  API_KEY?: string | undefined;
  ADMIN_TOKEN?: string | undefined;
  ALLOWED_ORIGIN_1?: string | undefined;
  ALLOWED_ORIGIN_2?: string | undefined;
  ADMIN_IP_WHITELIST?: string | undefined;
  ENABLE_RATE_LIMITING: boolean;
  ENABLE_CORS: boolean;
  LOG_LEVEL: 'error' | 'warn' | 'info' | 'http' | 'debug';
  SENTRY_DSN?: string | undefined;
  MAX_FILE_SIZE: string;
  ALLOWED_FILE_TYPES: string;
}

// CORS configuration types
export interface CorsConfig {
  origin:
    | string[]
    | ((
        origin: string | undefined,
        callback: (err: Error | null, allow?: boolean) => void
      ) => void);
  credentials: boolean;
  methods: string[];
  allowedHeaders: string[];
}

// Rate limiting configuration types
export interface RateLimitConfig {
  windowMs: number;
  max: number;
  message: {
    error: string;
  };
  standardHeaders: boolean;
  legacyHeaders: boolean;
}

// Helmet configuration types
export interface HelmetConfig {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: string[];
      styleSrc: string[];
      fontSrc: string[];
      imgSrc: string[];
      scriptSrc: string[];
      connectSrc: string[];
      frameSrc: string[];
      objectSrc: string[];
      upgradeInsecureRequests: string[];
    };
  };
  crossOriginEmbedderPolicy: boolean;
}

// Validation rule types
export interface ValidationRule {
  field: string;
  rules: unknown[];
}

// File upload types
export interface FileUploadConfig {
  maxSize: number;
  allowedTypes: string[];
  maliciousExtensions: string[];
}

// Security middleware types
export type SecurityMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => void;

// API response types
export interface ApiResponse<T = unknown> {
  success: boolean;
  status: number;
  data: T;
  timestamp: string;
  requestId?: string | undefined;
}

// Validation error types
export interface ValidationError {
  field: string;
  message: string;
  value?: unknown;
}

// Logger interface
export interface Logger {
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

// Request with files type
export interface RequestWithFiles extends Request {
  file?: MulterFile;
  files?: MulterFile[] | { [fieldname: string]: MulterFile[] };
}

// Security configuration types
export interface SecurityConfig {
  cors: CorsConfig;
  rateLimit: {
    general: RateLimitConfig;
    auth: RateLimitConfig;
    passwordReset: RateLimitConfig;
  };
  helmet: HelmetConfig;
  fileUpload: FileUploadConfig;
  validation: {
    email: ValidationRule;
    password: ValidationRule;
    name: ValidationRule;
    slug: ValidationRule;
    content: ValidationRule;
    title: ValidationRule;
    page: ValidationRule;
    limit: ValidationRule;
  };
}

// Environment schema type
export type EnvSchema = z.ZodSchema<EnvConfig>;
