import { BadRequestException } from '@nestjs/common';

export function normalizeCurrencyCode(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toUpperCase();
  if (!normalized) return null;
  if (!/^[A-Z]{3}$/.test(normalized)) return null;
  return normalized;
}

export function normalizeCurrencyCodeOrThrow(value: unknown): string {
  const normalized = normalizeCurrencyCode(value);
  if (!normalized) {
    throw new BadRequestException('currency code must be a 3-letter ISO code');
  }
  return normalized;
}
