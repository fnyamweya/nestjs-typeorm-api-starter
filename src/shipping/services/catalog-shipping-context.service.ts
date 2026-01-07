import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { Product } from '../../catalog/entities/product.entity';
import { ProductCategory } from '../../catalog/entities/product-category.entity';
import { CategoryClosure } from '../../catalog/entities/category-closure.entity';
import { Taxonomy } from '../../catalog/entities/taxonomy.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  cacheKeyFromParts,
  cacheKeyHash,
} from 'src/common/cache/cache-key.util';
import { ShippingCatalogContextCacheIndexService } from 'src/common/cache/shipping-catalog-context-cache-index.service';

@Injectable()
export class CatalogShippingContextService {
  constructor(
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(ProductCategory)
    private readonly productCategoryRepository: Repository<ProductCategory>,
    @InjectRepository(CategoryClosure)
    private readonly categoryClosureRepository: Repository<CategoryClosure>,
    @InjectRepository(Taxonomy)
    private readonly taxonomyRepository: Repository<Taxonomy>,
    private readonly cache: AppCacheService,
    private readonly cacheIndex: ShippingCatalogContextCacheIndexService,
  ) {}

  async resolveCatalogShippingContext(productIds: string[]): Promise<{
    productIds: string[];
    categoryIds: string[];
    taxonomyIds: string[];
    allowedMethodCodes?: string[];
    excludedMethodCodes?: string[];
    ratePriorityBoost?: number;
  }> {
    if (!productIds.length) {
      return { productIds: [], categoryIds: [], taxonomyIds: [] };
    }

    const normalizedProductIds = Array.from(
      new Set(productIds.map(String)),
    ).sort();
    const rawKey = cacheKeyFromParts('shipping', 'catalog-context', {
      productIds: normalizedProductIds,
    });
    const key = `shipping:catalog-context:${cacheKeyHash(rawKey)}`;

    const cached = await this.cache.get<{
      productIds: string[];
      categoryIds: string[];
      taxonomyIds: string[];
      allowedMethodCodes?: string[];
      excludedMethodCodes?: string[];
      ratePriorityBoost?: number;
    }>(key);
    if (cached !== null) return cached;

    const ttlSeconds = 300;
    const value =
      await this.computeCatalogShippingContext(normalizedProductIds);
    await this.cache.set(key, value, ttlSeconds);
    await this.cacheIndex.indexCacheKey(key, value, ttlSeconds);
    return value;
  }

  private async computeCatalogShippingContext(productIds: string[]): Promise<{
    productIds: string[];
    categoryIds: string[];
    taxonomyIds: string[];
    allowedMethodCodes?: string[];
    excludedMethodCodes?: string[];
    ratePriorityBoost?: number;
  }> {
    const products = await this.productRepository.find({
      where: { id: In(productIds) },
    });

    const productCategories = await this.productCategoryRepository.find({
      where: { productId: In(productIds) },
      relations: ['category'],
    });

    const allCategoryIds = Array.from(
      new Set(productCategories.map((pc) => pc.categoryId)),
    );

    // Compute a "specificity" depth for each category (bigger = deeper in tree)
    const depthByCategoryId = new Map<string, number>();
    if (allCategoryIds.length) {
      const rows: Array<{ descendant_id: string; max_depth: string }> =
        await this.categoryClosureRepository.query(
          `SELECT descendant_id, MAX(depth) as max_depth FROM "category_closure" WHERE descendant_id = ANY($1) GROUP BY descendant_id;`,
          [allCategoryIds],
        );
      for (const r of rows) {
        depthByCategoryId.set(r.descendant_id, Number(r.max_depth));
      }
    }

    const taxonomyIds = Array.from(
      new Set(
        productCategories
          .map((pc) => pc.category?.taxonomyId)
          .filter((id): id is string => Boolean(id)),
      ),
    );

    const taxonomies = taxonomyIds.length
      ? await this.taxonomyRepository.find({ where: { id: In(taxonomyIds) } })
      : [];
    const taxonomyById = new Map(taxonomies.map((t) => [t.id, t] as const));

    const allowedSets: Array<Set<string>> = [];
    const excludedSet = new Set<string>();
    let ratePriorityBoost = 0;

    // Resolve per-product effective shipping rules (product overrides category overrides taxonomy)
    for (const product of products) {
      const pcs = productCategories.filter((pc) => pc.productId === product.id);

      // pick best category: primary wins; otherwise deepest wins
      let chosen = pcs.find((pc) => pc.isPrimary);
      if (!chosen && pcs.length) {
        chosen = pcs
          .slice()
          .sort(
            (a, b) =>
              (depthByCategoryId.get(b.categoryId) ?? 0) -
              (depthByCategoryId.get(a.categoryId) ?? 0),
          )[0];
      }

      const category = chosen?.category;
      const taxonomy = category?.taxonomyId
        ? taxonomyById.get(category.taxonomyId)
        : undefined;

      const prodMeta: any = (product as any).metaJson || {};
      const catMeta: any = category?.metaJson || {};
      const taxMeta: any = taxonomy?.metaJson || {};

      const productRules = prodMeta.shipping ?? {};
      const categoryRules = catMeta.shipping ?? {};
      const taxonomyRules = taxMeta.shipping ?? {};

      const productProfile = prodMeta.shippingProfile;
      const categoryProfile = catMeta.shippingProfile;
      const taxonomyProfile = taxMeta.shippingProfile;

      const allowedMethodCodes: string[] | undefined =
        (Array.isArray(productRules.allowedMethodCodes)
          ? productRules.allowedMethodCodes
          : undefined) ??
        (typeof productProfile === 'string' && productProfile
          ? [productProfile]
          : undefined) ??
        (Array.isArray(categoryRules.allowedMethodCodes)
          ? categoryRules.allowedMethodCodes
          : undefined) ??
        (typeof categoryProfile === 'string' && categoryProfile
          ? [categoryProfile]
          : undefined) ??
        (Array.isArray(taxonomyRules.allowedMethodCodes)
          ? taxonomyRules.allowedMethodCodes
          : undefined) ??
        (typeof taxonomyProfile === 'string' && taxonomyProfile
          ? [taxonomyProfile]
          : undefined);

      const excludedMethodCodes: string[] | undefined =
        (Array.isArray(productRules.excludedMethodCodes)
          ? productRules.excludedMethodCodes
          : undefined) ??
        (Array.isArray(categoryRules.excludedMethodCodes)
          ? categoryRules.excludedMethodCodes
          : undefined) ??
        (Array.isArray(taxonomyRules.excludedMethodCodes)
          ? taxonomyRules.excludedMethodCodes
          : undefined);

      const boost: number | undefined =
        (typeof productRules.ratePriorityBoost === 'number'
          ? productRules.ratePriorityBoost
          : undefined) ??
        (typeof categoryRules.ratePriorityBoost === 'number'
          ? categoryRules.ratePriorityBoost
          : undefined) ??
        (typeof taxonomyRules.ratePriorityBoost === 'number'
          ? taxonomyRules.ratePriorityBoost
          : undefined);

      if (allowedMethodCodes?.length) {
        allowedSets.push(new Set(allowedMethodCodes.map((s) => String(s))));
      }

      if (excludedMethodCodes?.length) {
        for (const c of excludedMethodCodes) excludedSet.add(String(c));
      }

      if (boost !== undefined) {
        ratePriorityBoost = Math.max(ratePriorityBoost, boost);
      }
    }

    // Intersection across items for allowed methods (strict)
    let allowed: string[] | undefined;
    if (allowedSets.length) {
      const [first, ...rest] = allowedSets;
      const intersection = new Set(Array.from(first));
      for (const s of rest) {
        for (const v of Array.from(intersection)) {
          if (!s.has(v)) intersection.delete(v);
        }
      }
      allowed = Array.from(intersection);
    }

    const excluded = excludedSet.size ? Array.from(excludedSet) : undefined;

    return {
      productIds,
      categoryIds: allCategoryIds,
      taxonomyIds,
      allowedMethodCodes: allowed,
      excludedMethodCodes: excluded,
      ratePriorityBoost: ratePriorityBoost || undefined,
    };
  }
}
