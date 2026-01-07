const ALLOWED_FUNCTIONS = new Set([
  'min',
  'max',
  'abs',
  'ceil',
  'floor',
  'round',
  'pow',
  'sqrt',
]);

export function evaluateFormula(
  expression: string,
  context: Record<string, number>,
): number {
  if (!expression || typeof expression !== 'string')
    throw new Error('Invalid formula');

  // 1) normalize whitespace
  let expr = expression.trim();

  // 2) replace allowed function names with themselves (we check them later)
  //    but prefixing isn't necessary. We will validate identifiers below.

  // 3) replace variables with numeric literal values from context
  // Sort keys by length desc so that longer names (eg. totalWeight) are replaced first
  const keys = Object.keys(context).sort((a, b) => b.length - a.length);
  for (const k of keys) {
    // only allow safe identifier names
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) continue;
    const v = Number(context[k]);
    const safe = Number.isFinite(v) ? v : 0;
    const re = new RegExp('\\b' + k + '\\b', 'g');
    expr = expr.replace(re, `(${safe})`);
  }

  // 4) Validate identifiers (anything left that looks like a name must be an allowed function name)
  const idRegex = /[A-Za-z_][A-Za-z0-9_]*/g;
  const found = expr.match(idRegex) || [];
  for (const id of found) {
    if (id === 'Math') continue; // "Math" may appear if the user wrote it
    if (!ALLOWED_FUNCTIONS.has(id)) {
      throw new Error(`Disallowed identifier in formula: ${id}`);
    }
  }

  // 5) map allowed function names to Math.<fn>
  for (const fn of ALLOWED_FUNCTIONS) {
    const re = new RegExp('\\b' + fn + '\\b', 'g');
    expr = expr.replace(re, `Math.${fn}`);
  }

  // 6) final check: only allow digits, operators, parentheses, commas, dots, whitespace and letters from Math and allowed functions
  if (/[^0-9+\-*/().,\sMatha-zA-Z]/.test(expr)) {
    throw new Error('Invalid characters in formula');
  }

  // 7) evaluate in a safe, minimal environment using Function
  let res: unknown;
  try {
    const fn = new Function(`return (${expr});`);
    res = fn();
  } catch (err) {
    throw new Error('Error evaluating formula');
  }

  if (typeof res !== 'number' || !Number.isFinite(res))
    throw new Error('Formula did not evaluate to a finite number');

  return res;
}

export function validateFormula(
  expression: string,
  sampleContext: Record<string, number> = {
    subtotal: 100,
    totalWeight: 1,
    itemCount: 1,
  },
) {
  try {
    evaluateFormula(expression, sampleContext);
    return true;
  } catch (err: any) {
    // normalize message
    throw new Error(err?.message || 'Invalid formula');
  }
}
