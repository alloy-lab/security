/**
 * @fileoverview Security Package - Main entry point
 * @description This module exports all security utilities and middleware
 * @version 1.0.0
 * @author Stephen Way <stephen@stephenway.net>
 * @license MIT
 */

// Environment validation
export {
  createEnvSchema,
  envSchema,
  validateCustomEnv,
  validateEnv,
} from './utils/envValidation.js';

// Security middleware
export {
  createApiSecurity,
  createAuthSecurity,
  createCorsConfig,
  createFormSecurity,
  createHelmetConfig,
  createPasswordResetSecurity,
  createRateLimitConfig,
  createRequestSizeLimit,
  createSanitizeRequest,
  createStaticSecurity,
  createValidateRequest,
  validationRules,
} from './middleware/security.js';

// API security middleware
export {
  apiValidationRules,
  createApiRateLimit,
  createApiRequestLogger,
  createFormatApiResponse,
  createRequireAdmin,
  createValidateApiKey,
  createValidateApiRequest,
  createValidateFileUpload,
} from './middleware/apiSecurity.js';

// Types
export type {
  ApiResponse,
  CorsConfig,
  EnvConfig,
  EnvSchema,
  FileUploadConfig,
  HelmetConfig,
  Logger,
  RateLimitConfig,
  RequestWithFiles,
  SecurityConfig,
  SecurityMiddleware,
  ValidationError,
  ValidationRule,
} from './types/index.js';
