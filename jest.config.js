export default {
  transform: {
    '^.+\\.js$': 'babel-jest'
  },
  testEnvironment: 'jsdom',
  testMatch: ['<rootDir>/tests/js/**/*.test.js'],
  testPathIgnorePatterns: ['<rootDir>/tests/e2e/']
}; 