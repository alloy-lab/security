/**
 * @fileoverview Security Middleware Tests
 * @description Tests for security middleware utilities
 */

import type { NextFunction, Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createCorsConfig,
  createHelmetConfig,
  createRateLimitConfig,
  createSanitizeRequest,
  createValidateRequest,
  validationRules,
} from '../middleware/security.js';

// Mock logger
const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

describe('Security Middleware', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      ip: '127.0.0.1',
      get: vi.fn(),
      body: {},
      query: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      setHeader: vi.fn(),
    };
    mockNext = vi.fn();
  });

  describe('CORS Configuration', () => {
    it('should create CORS config with default origins', () => {
      const corsConfig = createCorsConfig([], mockLogger);

      expect(corsConfig.credentials).toBe(true);
      expect(corsConfig.methods).toContain('GET');
      expect(corsConfig.methods).toContain('POST');
      expect(corsConfig.allowedHeaders).toContain('Authorization');
    });

    it('should allow requests from localhost', () => {
      const corsConfig = createCorsConfig([], mockLogger);
      const callback = vi.fn();

      if (typeof corsConfig.origin === 'function') {
        corsConfig.origin('http://localhost:3000', callback);
        expect(callback).toHaveBeenCalledWith(null, true);
      }
    });

    it('should block requests from unauthorized origins', () => {
      const corsConfig = createCorsConfig([], mockLogger);
      const callback = vi.fn();

      if (typeof corsConfig.origin === 'function') {
        corsConfig.origin('http://malicious-site.com', callback);
        expect(callback).toHaveBeenCalledWith(expect.any(Error));
      }
    });
  });

  describe('Rate Limiting', () => {
    it('should have general rate limit configured', () => {
      const rateLimitConfig = createRateLimitConfig();

      expect(rateLimitConfig.general).toBeDefined();
      expect(typeof rateLimitConfig.general).toBe('function');
    });

    it('should have auth rate limit configured', () => {
      const rateLimitConfig = createRateLimitConfig();

      expect(rateLimitConfig.auth).toBeDefined();
      expect(typeof rateLimitConfig.auth).toBe('function');
    });

    it('should have password reset rate limit configured', () => {
      const rateLimitConfig = createRateLimitConfig();

      expect(rateLimitConfig.passwordReset).toBeDefined();
      expect(typeof rateLimitConfig.passwordReset).toBe('function');
    });
  });

  describe('Helmet Configuration', () => {
    it('should create helmet config with security headers', () => {
      const helmetConfig = createHelmetConfig();

      expect(helmetConfig).toBeDefined();
      expect(typeof helmetConfig).toBe('function');
    });
  });

  describe('Validation Rules', () => {
    it('should have email validation rule', () => {
      expect(validationRules.email).toBeDefined();
    });

    it('should have password validation rule', () => {
      expect(validationRules.password).toBeDefined();
    });

    it('should have name validation rule', () => {
      expect(validationRules.name).toBeDefined();
    });

    it('should have slug validation rule', () => {
      expect(validationRules.slug).toBeDefined();
    });

    it('should have content validation rule', () => {
      expect(validationRules.content).toBeDefined();
    });

    it('should have title validation rule', () => {
      expect(validationRules.title).toBeDefined();
    });

    it('should have pagination validation rules', () => {
      expect(validationRules.page).toBeDefined();
      expect(validationRules.limit).toBeDefined();
    });
  });

  describe('Request Sanitization', () => {
    it('should sanitize script tags from body', () => {
      const sanitizeRequest = createSanitizeRequest(mockLogger);
      mockReq.body = {
        content: '<script>alert("xss")</script>Hello World',
      };

      sanitizeRequest(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.body.content).toBe('Hello World');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should sanitize javascript: URLs from body', () => {
      const sanitizeRequest = createSanitizeRequest(mockLogger);
      mockReq.body = {
        url: 'javascript:alert("xss")',
      };

      sanitizeRequest(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.body.url).toBe('alert("xss")');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should sanitize event handlers from body', () => {
      const sanitizeRequest = createSanitizeRequest(mockLogger);
      mockReq.body = {
        content: '<div onclick="alert(\'xss\')">Click me</div>',
      };

      sanitizeRequest(mockReq as Request, mockRes as Response, mockNext);

      // The regex should remove the onclick attribute but keep the rest
      expect(mockReq.body.content).toContain('<div');
      expect(mockReq.body.content).toContain('>Click me</div>');
      expect(mockReq.body.content).not.toContain('onclick');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should sanitize query parameters', () => {
      const sanitizeRequest = createSanitizeRequest(mockLogger);
      mockReq.query = {
        search: '<script>alert("xss")</script>test',
      };

      sanitizeRequest(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.query.search).toBe('test');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle non-string values', () => {
      const sanitizeRequest = createSanitizeRequest(mockLogger);
      mockReq.body = {
        number: 123,
        boolean: true,
        object: { key: 'value' },
      };

      sanitizeRequest(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.body.number).toBe(123);
      expect(mockReq.body.boolean).toBe(true);
      expect(mockReq.body.object).toEqual({ key: 'value' });
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Request Validation', () => {
    it('should have validateRequest function defined', () => {
      const validateRequest = createValidateRequest(mockLogger);

      expect(validateRequest).toBeDefined();
      expect(typeof validateRequest).toBe('function');
    });
  });
});
