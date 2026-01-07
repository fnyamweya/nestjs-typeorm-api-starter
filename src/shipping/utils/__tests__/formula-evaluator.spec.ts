import { evaluateFormula } from '../formula-evaluator';

describe('evaluateFormula', () => {
  it('evaluates simple arithmetic with variables', () => {
    const res = evaluateFormula('subtotal * 0.1 + totalWeight * 2', {
      subtotal: 200,
      totalWeight: 3,
    });
    expect(res).toBeCloseTo(200 * 0.1 + 3 * 2);
  });

  it('supports allowed functions like max and min', () => {
    const res = evaluateFormula(
      'max(0, totalWeight - 5) * 2 + min(10, subtotal)',
      { subtotal: 8, totalWeight: 7 },
    );
    expect(res).toBeCloseTo(Math.max(0, 7 - 5) * 2 + Math.min(10, 8));
  });

  it('throws on disallowed identifiers', () => {
    expect(() => evaluateFormula('process.exit()', { subtotal: 1 })).toThrow(
      /Disallowed identifier/,
    );
  });

  it('throws when formula does not return finite number', () => {
    expect(() => evaluateFormula('subtotal / 0', { subtotal: 1 })).toThrow(
      /did not evaluate to a finite number/,
    );
  });
});
