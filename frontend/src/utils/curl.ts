import { TraceEntry } from '../types';

export function generateCurlCommand(trace: TraceEntry): string {
  const parts: string[] = ['curl'];

  // Method
  if (trace.method && trace.method.toUpperCase() !== 'GET') {
    parts.push(`-X ${trace.method.toUpperCase()}`);
  }

  // URL
  parts.push(`"${trace.url}"`);

  // Headers
  if (trace.req_headers) {
    for (const [key, values] of Object.entries(trace.req_headers)) {
      // Skip pseudo headers or hop-by-hop headers if any
      if (key.startsWith(':')) continue;
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'content-length' || lowerKey === 'connection') continue;

      for (const val of values) {
        // Escape quotes
        const escaped = val.replace(/"/g, '\\"');
        parts.push(`-H "${key}: ${escaped}"`);
      }
    }
  }

  // Body
  if (trace.req_body && trace.req_body.trim() !== '') {
    const escapedBody = trace.req_body.replace(/'/g, "'\\''");
    parts.push(`--data-raw '${escapedBody}'`);
  }

  return parts.join(' \\\n  ');
}
