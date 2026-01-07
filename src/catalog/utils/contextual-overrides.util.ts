import { applyPatch } from 'fast-json-patch';
import jsonLogic from 'json-logic-js';
import {
  AppliedOverrideInfo,
  ContextMatch,
  ContextualOverrideDTO,
  JsonPatchOperation,
  RuleExpression,
} from '../dto/product-v2/product.types';
import { ProductDTO } from '../dto/product-v2/product.dto';

export interface ProductViewContext {
  channel?: string;
  customerTier?: string;
  location?: string;
  role?: string;
  now?: Date;
}

function matchesContext(
  match: ContextMatch | undefined,
  ctx: ProductViewContext,
): boolean {
  if (!match) return true;
  if (match.channel && match.channel !== ctx.channel) return false;
  if (match.customerTier && match.customerTier !== ctx.customerTier)
    return false;
  if (match.location && match.location !== ctx.location) return false;
  if (match.role && match.role !== ctx.role) return false;
  return true;
}

function isWithinValidity(o: ContextualOverrideDTO, now: Date): boolean {
  if (o.validFrom) {
    const from = new Date(o.validFrom);
    if (Number.isFinite(from.getTime()) && now < from) return false;
  }
  if (o.validUntil) {
    const until = new Date(o.validUntil);
    if (Number.isFinite(until.getTime()) && now > until) return false;
  }
  return true;
}

function evalRule(
  rule: RuleExpression | undefined,
  base: ProductDTO,
  ctx: ProductViewContext,
): boolean {
  if (!rule) return true;
  if (rule.type === 'SCRIPT') {
    // Intentionally not supported: arbitrary scripts are unsafe in a backend.
    return false;
  }

  const language = rule.language ?? 'JSONLOGIC';
  if (language !== 'JSONLOGIC') return false;

  try {
    const expr = JSON.parse(rule.expression);
    const result = jsonLogic.apply(expr, { context: ctx, product: base });
    return Boolean(result);
  } catch {
    return false;
  }
}

function specificity(match?: ContextMatch): number {
  if (!match) return 0;
  return Object.values(match).filter(Boolean).length;
}

function isForbiddenPath(path: string): boolean {
  // Protect stable identity. You can still override pricing/availability/labels/etc.
  return (
    path === '/id' ||
    path.startsWith('/id/') ||
    path === '/code' ||
    path.startsWith('/code/')
  );
}

function sanitizePatch(patch: JsonPatchOperation[]): JsonPatchOperation[] {
  return patch.filter((op) => op.path && !isForbiddenPath(op.path));
}

export function applyContextualOverrides(
  baseProduct: ProductDTO,
  overrides: ContextualOverrideDTO[] | undefined,
  context: ProductViewContext,
): { product: ProductDTO; appliedOverrides: AppliedOverrideInfo[] } {
  const now = context.now ?? new Date();
  const candidates = (overrides ?? [])
    .filter((o) => o.isActive)
    .filter((o) => isWithinValidity(o, now))
    .filter((o) => matchesContext(o.match, context))
    .filter((o) => evalRule(o.rule, baseProduct, context));

  candidates.sort((a, b) => {
    if (a.priority !== b.priority) return b.priority - a.priority;
    const sa = specificity(a.match);
    const sb = specificity(b.match);
    if (sa !== sb) return sb - sa;
    return a.id.localeCompare(b.id);
  });

  const appliedOverrides: AppliedOverrideInfo[] = [];
  let current: ProductDTO = structuredClone(baseProduct);

  for (const o of candidates) {
    const patch = sanitizePatch(o.patch);
    try {
      const res = applyPatch(current as any, patch as any, false, false);
      current = res.newDocument as ProductDTO;
      appliedOverrides.push({ id: o.id, priority: o.priority });
    } catch {
      // Ignore invalid patch to keep view resolution robust.
      continue;
    }
  }

  return { product: current, appliedOverrides };
}
