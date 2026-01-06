import {
  createOrderItemChargeReversal,
  createOrderLevelChargeReversal,
} from '../charge-ledger.util';

describe('charge-ledger.util', () => {
  it('creates an order-level reversal row', () => {
    const r = createOrderLevelChargeReversal({
      original: {
        id: 'c1',
        orderId: 'o1',
        chargeKind: 'discount',
        displayName: 'Promotion Discount',
        calculationType: 'fixed',
        amount: '-20.0000',
        isIncludedInPrice: false,
        appliesToShipping: false,
        sourceType: 'promotion',
        sourceReference: 'p1',
        metaJson: { applied: ['PROMO10'] },
      },
      reason: 'manual_adjustment',
    });

    expect(r.orderId).toBe('o1');
    expect(r.sourceType).toBe('reversal');
    expect(r.sourceReference).toBe('c1');
    expect(r.amount).toBe('20.0000');
    expect(r.metaJson).toBeDefined();
    expect(r.metaJson!.reversalOfChargeId).toBe('c1');
    expect(r.metaJson!.reason).toBe('manual_adjustment');
  });

  it('creates an order-item reversal row', () => {
    const r = createOrderItemChargeReversal({
      original: {
        id: 'ic1',
        orderItemId: 'oi1',
        chargeKind: 'tax',
        displayName: 'Tax',
        calculationType: 'percentage',
        rate: '0.160000',
        baseAmount: '180.0000',
        quantityBasis: 2,
        amount: '28.8000',
        isIncludedInPrice: false,
        sourceType: 'tax',
        metaJson: { configuredRate: 16 },
      },
    });

    expect(r.orderItemId).toBe('oi1');
    expect(r.sourceType).toBe('reversal');
    expect(r.sourceReference).toBe('ic1');
    expect(r.amount).toBe('-28.8000');
    expect(r.metaJson).toBeDefined();
    expect(r.metaJson!.reversalOfChargeId).toBe('ic1');
  });
});
