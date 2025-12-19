export function isString(value) {
  return typeof value === 'string';
}

export function isNonEmptyString(value) {
  return isString(value) && value.trim().length > 0;
}

// Future expansion: add schema-based validation, pattern checks, and typed coercion helpers.
export function requiredString(value, fieldName = 'value') {
  if (!isNonEmptyString(value)) {
    return { ok: false, message: `${fieldName} is required and must be a non-empty string` };
  }
  return { ok: true, value: value.trim() };
}

export function guardSize(bytes, limit = 32 * 1024) {
  if (typeof bytes !== 'number' || Number.isNaN(bytes)) {
    return { ok: false, message: 'Payload size unknown' };
  }
  if (bytes > limit) {
    return { ok: false, message: `Payload too large (max ${limit} bytes)` };
  }
  return { ok: true };
}

function normalizeAllowlistEntry(entry) {
  if (!isString(entry)) return '';
  let value = entry.trim().toLowerCase();
  if (!value) return '';
  value = value.replace(/^https?:\/\//, '');
  const cut = value.search(/[/?#]/);
  if (cut !== -1) value = value.slice(0, cut);
  if (value.startsWith('[') && value.includes(']')) {
    value = value.slice(1, value.indexOf(']'));
  }
  value = value.replace(/^\*\./, '').replace(/^\./, '');
  value = value.replace(/\.+$/, '');
  const colonMatches = value.match(/:/g);
  if (colonMatches && colonMatches.length === 1) {
    value = value.split(':')[0];
  }
  return value;
}

export function parseAllowlist(envValue) {
  if (!envValue || !isString(envValue)) return [];
  return envValue
    .split(',')
    .map(normalizeAllowlistEntry)
    .filter(Boolean);
}

export function guardUrlLength(urlString, limit = 2048) {
  if (!isString(urlString)) return { ok: false, message: 'url must be a string' };
  if (urlString.length > limit) return { ok: false, message: `url exceeds ${limit} characters` };
  return { ok: true };
}

export function isHostname(value) {
  if (!isString(value)) return false;
  if (value.length === 0 || value.length > 253) return false;
  if (value.includes('://') || value.includes('/')) return false;
  if (value.includes(':')) return false;
  const labels = value.split('.');
  if (labels.some((l) => l.length === 0 || l.length > 63 || !/^[a-zA-Z0-9-]+$/.test(l) || l.startsWith('-') || l.endsWith('-'))) {
    return false;
  }
  return labels.length >= 2;
}

export function isIpLiteral(value) {
  return (
    /^(\d{1,3}\.){3}\d{1,3}$/.test(value) ||
    /^[0-9a-fA-F:]+$/.test(value)
  );
}

export function matchesAllowlist(host, allowlist = []) {
  const target = host.toLowerCase();
  return allowlist.some((entry) => target === entry || target.endsWith(`.${entry}`));
}

export function isPrivateIp(ip) {
  if (!isString(ip)) return false;
  if (/^127\./.test(ip)) return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (/^0\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;
  if (ip.includes(':')) {
    // Basic IPv6 private ranges
    if (ip === '::1' || ip === '::' || /^0:0:0:0:0:0:0:1$/i.test(ip)) return true;
    if (/^fc00:/i.test(ip) || /^fd00:/i.test(ip)) return true; // ULA
    if (/^fe80:/i.test(ip)) return true; // link-local
    if (/^::ffff:/i.test(ip)) {
      const v4 = ip.split(':').pop();
      if (v4 && isPrivateIp(v4)) return true;
    }
  }
  return false;
}
