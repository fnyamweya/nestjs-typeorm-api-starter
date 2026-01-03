export type ID = string;

export type LocalizedString = Record<string, string>;
export type LocalizedText = Record<string, string>;

export type ProductType = string;
export type ProductStatus = 'draft' | 'active' | 'archived' | string;

export type AttributeValue =
  | string
  | number
  | boolean
  | string[]
  | number[]
  | {
      value: unknown;
      unit?: string;
      precision?: number;
    };

export interface RuleExpression {
  type: 'EXPRESSION' | 'SCRIPT';
  language?: 'CEL' | 'JSONLOGIC';
  expression: string;
}

export interface PricingModelDTO {
  currency: string;
  pricingType: 'FIXED' | 'TIERED' | 'USAGE' | 'DYNAMIC';

  basePrice?: number;

  tiers?: Array<{
    min: number;
    max?: number;
    price: number;
  }>;

  formula?: string;

  priceRules?: RuleExpression[];
}

export interface AvailabilityDTO {
  channels: string[];
  countries?: string[];
  locations?: string[];
  stock?: {
    type: 'FINITE' | 'INFINITE' | string;
    quantity?: number;
  };
  schedule?: {
    timezone: string;
    windows: Array<{ from: string; to: string }>;
  };
  meta?: Record<string, unknown>;
}

export interface JsonPatchOperation {
  op: 'add' | 'replace' | 'remove' | 'copy' | 'move' | 'test';
  path: string;
  from?: string;
  value?: unknown;
}

export interface ContextMatch {
  channel?: string;
  customerTier?: string;
  location?: string;
  role?: string;
}

export interface ContextualOverrideDTO {
  id: ID;

  priority: number;
  isActive: boolean;

  validFrom?: string;
  validUntil?: string;

  match?: ContextMatch;
  rule?: RuleExpression;

  patch: JsonPatchOperation[];

  description?: string;
}

export interface AppliedOverrideInfo {
  id: ID;
  priority: number;
}
