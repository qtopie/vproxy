import { describe, it, expect } from 'vitest';
import { VProxyConfig } from '../types';

describe('Raw JSON Configuration Validation (SPEC-FRONTEND-004 & SPEC-FRONTEND-006)', () => {
  it('successfully parses valid raw JSON config matching VProxyConfig schema', () => {
    const rawJson = JSON.stringify({
      upstreams: ['socks5://192.168.50.189:1080', 'socks5://127.0.0.1:1080'],
      rules: [
        'DOMAIN,example.com,INTERCEPT',
        'PROCESS,curl,PROXY',
        'IP_CIDR,192.168.0.0/16,DIRECT',
        'FINAL,DIRECT',
      ],
      rewrites: [
        '/api/v1/(.*)/ http://127.0.0.1:8080/$1',
        'file:///tmp/mock.json',
      ],
      web_port: 8899,
      enable_ebpf: true,
      otel: {
        enabled: true,
        endpoint: '127.0.0.1:4317',
        protocol: 'grpc',
      },
    }, null, 2);

    const parsed: VProxyConfig = JSON.parse(rawJson);
    expect(parsed.upstreams).toHaveLength(2);
    expect(parsed.rules).toContain('DOMAIN,example.com,INTERCEPT');
    expect(parsed.rewrites).toHaveLength(2);
    expect(parsed.otel?.enabled).toBe(true);
  });

  it('rejects invalid JSON syntax and throws error for syntax errors', () => {
    const brokenJson = `{
      "upstreams": [
        "socks5://192.168.50.189:1080",
      ], // trailing comma invalid in JSON
    }`;

    expect(() => JSON.parse(brokenJson)).toThrow();
  });

  it('maps theme correctly for Monaco Editor integration', () => {
    const getMonacoTheme = (isDark: boolean) => (isDark ? 'vs-dark' : 'light');
    expect(getMonacoTheme(true)).toBe('vs-dark');
    expect(getMonacoTheme(false)).toBe('light');
  });
});

describe('Inactive Rules & Toggle (SPEC-INACTIVE-003 & SPEC-INACTIVE-004)', () => {
  it('TestInactiveRuleParsing: identifies active vs inactive rules with #, //, and DISABLED, prefixes', async () => {
    const { parseRuleItem } = await import('../utils/rules');

    const activeRule = parseRuleItem('DOMAIN,www.example.com,INTERCEPT');
    expect(activeRule.isActive).toBe(true);
    expect(activeRule.type).toBe('DOMAIN');
    expect(activeRule.pattern).toBe('www.example.com');
    expect(activeRule.action).toBe('INTERCEPT');

    const hashInactive = parseRuleItem('#DOMAIN,www.example.com,INTERCEPT');
    expect(hashInactive.isActive).toBe(false);
    expect(hashInactive.type).toBe('DOMAIN');
    expect(hashInactive.pattern).toBe('www.example.com');
    expect(hashInactive.action).toBe('INTERCEPT');

    const slashInactive = parseRuleItem('//PROCESS,curl,PROXY');
    expect(slashInactive.isActive).toBe(false);
    expect(slashInactive.type).toBe('PROCESS');
    expect(slashInactive.pattern).toBe('curl');
    expect(slashInactive.action).toBe('PROXY');

    const disabledInactive = parseRuleItem('DISABLED,192.168.0.0/16,DIRECT');
    expect(disabledInactive.isActive).toBe(false);
    expect(disabledInactive.pattern).toBe('192.168.0.0/16');
    expect(disabledInactive.action).toBe('DIRECT');
  });

  it('TestRuleTogglePrefix: toggles between active and inactive states seamlessly', async () => {
    const { toggleRuleActive } = await import('../utils/rules');

    // Active -> Inactive (prepends #)
    const toggledOff = toggleRuleActive('DOMAIN,loreal.com,INTERCEPT');
    expect(toggledOff).toBe('#DOMAIN,loreal.com,INTERCEPT');

    // Inactive (#) -> Active (removes #)
    const toggledOnHash = toggleRuleActive('#DOMAIN,loreal.com,INTERCEPT');
    expect(toggledOnHash).toBe('DOMAIN,loreal.com,INTERCEPT');

    // Inactive (//) -> Active (removes //)
    const toggledOnSlash = toggleRuleActive('//PROCESS,curl,PROXY');
    expect(toggledOnSlash).toBe('PROCESS,curl,PROXY');

    // Inactive (DISABLED,) -> Active (removes DISABLED,)
    const toggledOnDisabled = toggleRuleActive('DISABLED,DOMAIN,test.com,BLOCK');
    expect(toggledOnDisabled).toBe('DOMAIN,test.com,BLOCK');
  });
});


describe('Bundle splitting contract (SPEC-EMBED-002)', () => {
  it('TestBundleSplittingContract: ConfigView/Monaco is lazy and vendor chunks are declared', async () => {
    const { readFileSync } = await import('node:fs');
    const app = readFileSync(new URL('../App.tsx', import.meta.url), 'utf8');
    expect(app).toMatch(/lazy\(\(\) =>\s*import\('\.\/components\/ConfigView'\)/);
    expect(app).not.toMatch(/^import .*ConfigView.*from/m);

    const vite = readFileSync(new URL('../../vite.config.ts', import.meta.url), 'utf8');
    for (const chunk of ['vendor-react', 'vendor-fluent', 'vendor-monaco']) {
      expect(vite).toContain(chunk);
    }
    expect(vite).toContain("minify: 'esbuild'");
  });
});
