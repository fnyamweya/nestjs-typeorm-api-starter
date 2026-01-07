import * as jsonLogic from 'json-logic-js';

export type CustomerTierFacts = Record<string, unknown>;

export interface CustomerTierRuleView {
  id: string;
  tierCode: string;
  priority: number;
  isActive: boolean;
  validFrom?: Date;
  validUntil?: Date;
  ruleJson: Record<string, unknown>;
}

export interface ResolveCustomerTierResult {
  tierCode: string;
  matchedRuleId?: string;
  source: 'manual' | 'rule' | 'default';
}

function isWithinValidityWindow(
  now: Date,
  validFrom?: Date,
  validUntil?: Date,
): boolean {
  if (validFrom && now < validFrom) return false;
  if (validUntil && now > validUntil) return false;
  return true;
}

function safeJsonLogicEval(
  rule: Record<string, unknown>,
  facts: CustomerTierFacts,
): boolean {
  try {
    // json-logic-js returns any; coerce to boolean.
    return Boolean(jsonLogic.apply(rule as any, facts as any));
  } catch {
    return false;
  }
}

export function resolveCustomerTier(opts: {
  now?: Date;
  defaultTierCode?: string;
  overrideTierCode?: string | null;
  rules: CustomerTierRuleView[];
  facts: CustomerTierFacts;
}): ResolveCustomerTierResult {
  const now = opts.now ?? new Date();
  const defaultTierCode = (opts.defaultTierCode ?? 'BASE').toUpperCase();

  const override = (opts.overrideTierCode ?? '').trim();
  if (override) {
    return { tierCode: override.toUpperCase(), source: 'manual' };
  }

  const candidates = (opts.rules ?? [])
    .filter((r) => r.isActive)
    .filter((r) => isWithinValidityWindow(now, r.validFrom, r.validUntil))
    .slice()
    .sort((a, b) => {
      const byPriority = (b.priority ?? 0) - (a.priority ?? 0);
      if (byPriority) return byPriority;
      return a.id.localeCompare(b.id);
    });

  for (const r of candidates) {
    if (!r.ruleJson || typeof r.ruleJson !== 'object') continue;
    if (safeJsonLogicEval(r.ruleJson, opts.facts)) {
      return {
        tierCode: r.tierCode.toUpperCase(),
        matchedRuleId: r.id,
        source: 'rule',
      };
    }
  }

  return { tierCode: defaultTierCode, source: 'default' };
}
