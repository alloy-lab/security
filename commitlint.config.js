export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat', // New feature
        'fix', // Bug fix
        'docs', // Documentation changes
        'style', // Code style changes (formatting, etc.)
        'refactor', // Code refactoring
        'perf', // Performance improvements
        'test', // Adding or updating tests
        'chore', // Maintenance tasks
        'ci', // CI/CD changes
        'build', // Build system changes
        'revert', // Reverting previous commits
      ],
    ],
    'scope-enum': [
      2,
      'always',
      [
        'core', // Core security functionality
        'middleware', // Security middleware
        'validation', // Input validation
        'auth', // Authentication
        'cors', // CORS configuration
        'helmet', // Helmet security headers
        'rate-limit', // Rate limiting
        'types', // Type definitions
        'utils', // Utility functions
        'docs', // Documentation
        'deps', // Dependencies
        'config', // Configuration
        'ci', // CI/CD
        'release', // Release process
        'tests', // Test-related changes
        'test', // Test-related changes (alternative)
      ],
    ],
    'subject-case': [
      2,
      'never',
      ['sentence-case', 'start-case', 'pascal-case', 'upper-case'],
    ],
    'subject-empty': [2, 'never'],
    'subject-full-stop': [2, 'never', '.'],
    'header-max-length': [2, 'always', 100],
  },
};
