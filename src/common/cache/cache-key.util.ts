import { createHash } from 'crypto';

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);

  if (typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`,
  );
  return `{${parts.join(',')}}`;
}

export function cacheKeyFromParts(
  ...parts: Array<string | number | boolean | object | undefined | null>
): string {
  return parts
    .filter((p) => p !== undefined && p !== null)
    .map((p) => (typeof p === 'object' ? stableStringify(p) : String(p)))
    .join(':');
}

export function cacheKeyHash(input: string): string {
  return createHash('sha1').update(input).digest('hex');
}
