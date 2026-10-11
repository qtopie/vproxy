import { describe, it, expect } from 'vitest';
import { generateCurlCommand } from '../utils/curl';
import { TraceEntry } from '../types';

describe('generateCurlCommand (SPEC-FRONTEND-003)', () => {
  it('generates standard GET curl command with headers', () => {
    const trace: TraceEntry = {
      id: 'trace-1',
      timestamp: '2026-10-11T12:00:00Z',
      method: 'GET',
      url: 'https://api.example.com/items?page=1',
      path: '/items',
      host: 'api.example.com',
      request_proto: 'HTTP/1.1',
      req_headers: {
        'Accept': ['application/json'],
        'Authorization': ['Bearer token123'],
      },
      status_code: 200,
      resp_headers: {},
      latency_ms: 120,
    };

    const cmd = generateCurlCommand(trace);
    expect(cmd).toContain('curl');
    expect(cmd).toContain('"https://api.example.com/items?page=1"');
    expect(cmd).toContain('-H "Accept: application/json"');
    expect(cmd).toContain('-H "Authorization: Bearer token123"');
    expect(cmd).not.toContain('-X GET'); // GET is default
  });

  it('generates POST curl command with body payload', () => {
    const trace: TraceEntry = {
      id: 'trace-2',
      timestamp: '2026-10-11T12:00:00Z',
      method: 'POST',
      url: 'https://api.example.com/login',
      path: '/login',
      host: 'api.example.com',
      request_proto: 'HTTP/1.1',
      req_headers: {
        'Content-Type': ['application/json'],
      },
      req_body: '{"username":"test","password":"123"}',
      status_code: 200,
      resp_headers: {},
      latency_ms: 250,
    };

    const cmd = generateCurlCommand(trace);
    expect(cmd).toContain('-X POST');
    expect(cmd).toContain('"https://api.example.com/login"');
    expect(cmd).toContain('--data-raw \'{"username":"test","password":"123"}\'');
  });
});
