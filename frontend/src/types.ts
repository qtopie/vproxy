export interface TraceEntry {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  path: string;
  host: string;
  request_proto: string;
  req_headers: Record<string, string[]>;
  req_body?: string;
  status_code: number;
  resp_headers: Record<string, string[]>;
  resp_body?: string;
  latency_ms: number;
}

export interface OtelConfig {
  enabled: boolean;
  endpoint?: string;
  protocol?: string;
  insecure?: boolean;
  service_name?: string;
  sample_rate?: number;
}

export interface VProxyConfig {
  upstreams: string[];
  rules: string[];
  test_interval?: number;
  web_port?: number;
  socks_port?: number;
  http_port?: number;
  enable_ebpf?: boolean;
  direct_dns?: boolean;
  dial_timeout_ms?: number;
  dial_retry_count?: number;
  bypass_nodes?: string[];
  rewrites?: string[];
  otel?: OtelConfig;
}
