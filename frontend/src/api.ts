import { TraceEntry, VProxyConfig } from './types';

export async function fetchTraces(): Promise<TraceEntry[]> {
  const res = await fetch('/api/traces');
  if (!res.ok) {
    throw new Error(`Failed to fetch traces: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchConfig(): Promise<VProxyConfig> {
  const res = await fetch('/api/config');
  if (!res.ok) {
    throw new Error(`Failed to fetch config: ${res.statusText}`);
  }
  return res.json();
}

export async function saveConfig(config: VProxyConfig): Promise<string> {
  const res = await fetch('/api/config', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(config, null, 2),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to save config: ${text || res.statusText}`);
  }
  return res.text();
}
