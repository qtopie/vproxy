export interface ParsedRule {
  raw: string;
  isActive: boolean;
  type: string;
  pattern: string;
  action: string;
}

/**
 * Parses a routing rule entry into structured metadata, detecting active vs inactive/commented status.
 * Supports '#', '//', and 'DISABLED,' prefixes. (SPEC-INACTIVE-003)
 */
export function parseRuleItem(ruleStr: string): ParsedRule {
  const trimmed = ruleStr.trim();
  let isActive = true;
  let clean = trimmed;

  if (clean.startsWith('#')) {
    isActive = false;
    clean = clean.replace(/^#\s*/, '');
  } else if (clean.startsWith('//')) {
    isActive = false;
    clean = clean.replace(/^\/\/\s*/, '');
  } else if (/^disabled,/i.test(clean)) {
    isActive = false;
    clean = clean.replace(/^disabled,\s*/i, '');
  }

  const parts = clean.split(',').map((p) => p.trim());
  let type = '';
  let pattern = '';
  let action = '';

  if (parts.length >= 3) {
    type = parts[0];
    pattern = parts[1];
    action = parts[2];
  } else if (parts.length === 2) {
    if (['DEFAULT', 'FINAL'].includes(parts[0].toUpperCase())) {
      type = '';
      pattern = parts[0];
      action = parts[1];
    } else {
      type = 'DOMAIN';
      pattern = parts[0];
      action = parts[1];
    }
  } else {
    pattern = clean;
  }

  return {
    raw: ruleStr,
    isActive,
    type,
    pattern,
    action,
  };
}

/**
 * Toggles a rule between active and inactive states. (SPEC-INACTIVE-004)
 * Active rules receive a '#' prefix; inactive rules have '#', '//', or 'DISABLED,' stripped.
 */
export function toggleRuleActive(ruleStr: string): string {
  const parsed = parseRuleItem(ruleStr);
  if (parsed.isActive) {
    return `#${ruleStr.trim()}`;
  }

  const trimmed = ruleStr.trim();
  if (trimmed.startsWith('#')) {
    return trimmed.replace(/^#\s*/, '');
  }
  if (trimmed.startsWith('//')) {
    return trimmed.replace(/^\/\/\s*/, '');
  }
  if (/^disabled,/i.test(trimmed)) {
    return trimmed.replace(/^disabled,\s*/i, '');
  }
  return trimmed;
}
