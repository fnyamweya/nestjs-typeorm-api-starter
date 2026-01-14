import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, In } from 'typeorm';
import { Product } from '../entities/product.entity';
import { ProductStatus } from '../dto/create-product.dto';
import { CustomerProductViewService } from './customer-product-view.service';

@Injectable()
export class RecommendationsService {
  constructor(
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly customerProductViewService: CustomerProductViewService,
  ) {}

  async recommendForCustomer(customerId: string, limit = 12): Promise<Product[]> {
    const safeLimit = Math.max(1, Math.min(50, limit));

    const purchasedProductIds = await this.getPurchasedProductIds(customerId, 200);
    const viewedProductIds = await this.customerProductViewService.listRecentlyViewedProductIds(
      customerId,
      50,
    );

    const seedProductIds = Array.from(
      new Set([...(purchasedProductIds ?? []), ...(viewedProductIds ?? [])]),
    ).slice(0, 200);

    // If we have no signal, fall back to newest products.
    if (!seedProductIds.length) {
      return this.dataSource.getRepository(Product).find({
        where: { status: ProductStatus.ACTIVE },
        order: { createdAt: 'DESC' },
        take: safeLimit,
      });
    }

    const { categoryIds, taxonomyIds, brandIds } = await this.getAffinitySignals(
      seedProductIds,
    );

    const excludeIds = Array.from(new Set([...seedProductIds]));

    // If signals are empty (e.g. products have no categories), still fallback to newest excluding already-seen.
    if (!categoryIds.length && !taxonomyIds.length && !brandIds.length) {
      const qb = this.dataSource
        .getRepository(Product)
        .createQueryBuilder('product')
        .where('product.status = :status', { status: ProductStatus.ACTIVE })
        .orderBy('product.created_at', 'DESC')
        .take(safeLimit);

      if (excludeIds.length) {
        qb.andWhere('product.id NOT IN (:...excludeIds)', { excludeIds });
      }

      return qb.getMany();
    }

    const qb = this.dataSource
      .getRepository(Product)
      .createQueryBuilder('product')
      .leftJoin('product.productCategories', 'pc')
      .leftJoin('pc.category', 'category')
      .where('product.status = :status', { status: ProductStatus.ACTIVE });

    if (excludeIds.length) {
      qb.andWhere('product.id NOT IN (:...excludeIds)', { excludeIds });
    }

    // Score: category match (3), taxonomy match (2), brand match (1)
    const categoryExpr = categoryIds.length
      ? `SUM(CASE WHEN pc.category_id IN (:...categoryIds) THEN 3 ELSE 0 END)`
      : '0';

    const taxonomyExpr = taxonomyIds.length
      ? `SUM(CASE WHEN category.taxonomy_id IN (:...taxonomyIds) THEN 2 ELSE 0 END)`
      : '0';

    const brandExpr = brandIds.length
      ? `MAX(CASE WHEN product.brand_id IN (:...brandIds) THEN 1 ELSE 0 END)`
      : '0';

    qb.select('product')
      .addSelect(`(${categoryExpr} + ${taxonomyExpr} + ${brandExpr})`, 'score')
      .groupBy('product.id')
      .orderBy('score', 'DESC')
      .addOrderBy('product.created_at', 'DESC')
      .take(safeLimit);

    if (categoryIds.length) qb.setParameter('categoryIds', categoryIds);
    if (taxonomyIds.length) qb.setParameter('taxonomyIds', taxonomyIds);
    if (brandIds.length) qb.setParameter('brandIds', brandIds);

    const rows = await qb.getRawAndEntities();
    return rows.entities;
  }

  private async getPurchasedProductIds(customerId: string, limit: number) {
    const rows = await this.dataSource
      .createQueryBuilder()
      .select('oi.product_id', 'productId')
      .from('order_item', 'oi')
      .innerJoin('order', 'o', 'o.id = oi.order_id')
      .where('o.customer_id = :customerId', { customerId })
      .andWhere('oi.product_id IS NOT NULL')
      .orderBy('o.created_at', 'DESC')
      .limit(limit)
      .getRawMany<{ productId: string }>();

    return Array.from(new Set(rows.map((r) => r.productId).filter(Boolean)));
  }

  private async getAffinitySignals(productIds: string[]): Promise<{
    categoryIds: string[];
    taxonomyIds: string[];
    brandIds: string[];
  }> {
    if (!productIds.length) return { categoryIds: [], taxonomyIds: [], brandIds: [] };

    const brandRows = await this.dataSource
      .getRepository(Product)
      .createQueryBuilder('product')
      .select('product.brand_id', 'brandId')
      .where('product.id IN (:...productIds)', { productIds })
      .andWhere('product.brand_id IS NOT NULL')
      .getRawMany<{ brandId: string }>();

    const brandIds = Array.from(new Set(brandRows.map((r) => r.brandId).filter(Boolean))).slice(0, 20);

    const categoryRows = await this.dataSource
      .createQueryBuilder()
      .select('pc.category_id', 'categoryId')
      .addSelect('c.taxonomy_id', 'taxonomyId')
      .from('product_category', 'pc')
      .innerJoin('category', 'c', 'c.id = pc.category_id')
      .where('pc.product_id IN (:...productIds)', { productIds })
      .getRawMany<{ categoryId: string; taxonomyId: string }>();

    const categoryIds = Array.from(new Set(categoryRows.map((r) => r.categoryId).filter(Boolean))).slice(0, 50);
    const taxonomyIds = Array.from(new Set(categoryRows.map((r) => r.taxonomyId).filter(Boolean))).slice(0, 20);

    return { categoryIds, taxonomyIds, brandIds };
  }
}
