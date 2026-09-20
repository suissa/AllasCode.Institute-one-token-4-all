import { describe, it, expect } from 'vitest';
import { sanitizeHTU } from '../../src/proof/sanitizeHTU.js';

describe('sanitizeHTU', () => {
  it('strips query parameters', () => {
    expect(sanitizeHTU('https://example.com/token?audience=x&foo=bar')).toBe('https://example.com/token');
  });

  it('strips hash fragments', () => {
    expect(sanitizeHTU('https://example.com/path#fragment')).toBe('https://example.com/path');
  });

  it('preserves origin and pathname', () => {
    expect(sanitizeHTU('https://example.com:8443/api/v1/token?x=1')).toBe('https://example.com:8443/api/v1/token');
  });

  it('handles trailing slash path', () => {
    expect(sanitizeHTU('https://example.com/')).toBe('https://example.com/');
  });
});
