import { resolveCustomerTier } from '../customer-tier.util';

describe('resolveCustomerTier', () => {
  it('prefers manual override', () => {
    const result = resolveCustomerTier({
      overrideTierCode: 'vip',
      rules: [
        {
          id: 'r1',
          tierCode: 'GOLD',
          priority: 10,
          isActive: true,
          ruleJson: { '==': [{ var: 'ordersCount' }, 999] },
        },
      ],
      facts: { ordersCount: 0 },
    });

    expect(result.tierCode).toBe('VIP');
    expect(result.source).toBe('manual');
  });

  it('selects highest priority matching rule', () => {
    const result = resolveCustomerTier({
      rules: [
        {
          id: 'low',
          tierCode: 'SILVER',
          priority: 1,
          isActive: true,
          ruleJson: { '>=': [{ var: 'lifetimeSpend' }, 100] },
        },
        {
          id: 'high',
          tierCode: 'GOLD',
          priority: 10,
          isActive: true,
          ruleJson: { '>=': [{ var: 'lifetimeSpend' }, 500] },
        },
      ],
      facts: { lifetimeSpend: 600 },
      defaultTierCode: 'BASE',
    });

    expect(result.tierCode).toBe('GOLD');
    expect(result.source).toBe('rule');
    expect(result.matchedRuleId).toBe('high');
  });

  it('falls back to default', () => {
    const result = resolveCustomerTier({
      rules: [],
      facts: {},
      defaultTierCode: 'BASE',
    });

    expect(result.tierCode).toBe('BASE');
    expect(result.source).toBe('default');
  });
});
