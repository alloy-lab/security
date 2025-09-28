/**
 * @fileoverview Environment Validation Utilities
 * @description Environment variable validation using Zod
 */

import { z } from 'zod';
import type { EnvConfig, Logger } from '../types/index.js';

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

// Environment variable schema
const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  PORT: z.string().transform(Number).default('3000'),

  // Database
  DATABASE_URI: z.string().min(1, 'DATABASE_URI is required'),

  // Payload CMS
  PAYLOAD_SECRET: z
    .string()
    .min(32, 'PAYLOAD_SECRET must be at least 32 characters'),
  PAYLOAD_PUBLIC_SERVER_URL: z
    .string()
    .url('PAYLOAD_PUBLIC_SERVER_URL must be a valid URL'),
  PAYLOAD_PUBLIC_CMS_URL: z
    .string()
    .url('PAYLOAD_PUBLIC_CMS_URL must be a valid URL'),

  // Security (optional)
  API_KEY: z.string().optional(),
  ADMIN_TOKEN: z.string().optional(),
  ALLOWED_ORIGIN_1: z.string().url().optional(),
  ALLOWED_ORIGIN_2: z.string().url().optional(),
  ADMIN_IP_WHITELIST: z.string().optional(),

  // Optional features
  ENABLE_RATE_LIMITING: z
    .string()
    .transform((val) => val === 'true')
    .default('true'),
  ENABLE_CORS: z
    .string()
    .transform((val) => val === 'true')
    .default('true'),

  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'http', 'debug']).default('info'),

  // Sentry (optional)
  SENTRY_DSN: z.string().url().optional(),

  // File uploads
  MAX_FILE_SIZE: z.string().default('10MB'),
  ALLOWED_FILE_TYPES: z
    .string()
    .default('image/jpeg,image/png,image/gif,image/webp'),
});

/**
 * Parse and validate environment variables
 */
export function validateEnv(logger: Logger = defaultLogger): EnvConfig {
  try {
    const env = envSchema.parse(process.env);
    logger.info('Environment variables validated successfully');
    return env;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors
        .map((err) => `${err.path.join('.')}: ${err.message}`)
        .join('\n');

      logger.error('Environment validation failed:', {
        errors: error.errors,
        errorMessages,
      } as Record<string, unknown>);

      console.error('❌ Environment validation failed:');
      console.error(errorMessages);
      process.exit(1);
    }

    logger.error('Unexpected error during environment validation:', {
      error: String(error),
    });
    process.exit(1);
  }
}

/**
 * Create a custom environment schema
 */
export function createEnvSchema<T extends z.ZodRawShape>(schema: T) {
  return z.object(schema);
}

/**
 * Validate environment variables with custom schema
 */
export function validateCustomEnv<T>(
  schema: z.ZodSchema<T>,
  logger: Logger = defaultLogger
): T {
  try {
    const env = schema.parse(process.env);
    logger.info('Custom environment variables validated successfully');
    return env;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors
        .map((err) => `${err.path.join('.')}: ${err.message}`)
        .join('\n');

      logger.error('Custom environment validation failed:', {
        errors: error.errors,
        errorMessages,
      } as Record<string, unknown>);

      console.error('❌ Custom environment validation failed:');
      console.error(errorMessages);
      process.exit(1);
    }

    logger.error('Unexpected error during custom environment validation:', {
      error: String(error),
    });
    process.exit(1);
  }
}

// Export the default schema for convenience
export { envSchema };
