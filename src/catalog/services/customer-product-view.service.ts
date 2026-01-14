import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CustomerProductView } from '../entities/customer-product-view.entity';

@Injectable()
export class CustomerProductViewService {
  private readonly maxEntries = 50;

  constructor(
    @InjectRepository(CustomerProductView)
    private readonly customerProductViewRepository: Repository<CustomerProductView>,
  ) {}

  async recordView(customerId: string, productId: string) {
    const now = new Date();

    await this.customerProductViewRepository
      .createQueryBuilder()
      .insert()
      .into(CustomerProductView)
      .values({ customerId, productId, viewedAt: now } as any)
      .orUpdate(['viewed_at', 'updated_at'], ['customer_id', 'product_id'])
      .execute();

    await this.trim(customerId);
  }

  async listRecentlyViewed(customerId: string, limit = 20) {
    const safeLimit = Math.max(1, Math.min(50, limit));

    return this.customerProductViewRepository
      .createQueryBuilder('v')
      .innerJoinAndSelect('v.product', 'product')
      .where('v.customerId = :customerId', { customerId })
      .orderBy('v.viewedAt', 'DESC')
      .take(safeLimit)
      .getMany();
  }

  async listRecentlyViewedProductIds(customerId: string, limit = 50) {
    const safeLimit = Math.max(1, Math.min(this.maxEntries, limit));

    const rows = await this.customerProductViewRepository
      .createQueryBuilder('v')
      .select(['v.productId'])
      .where('v.customerId = :customerId', { customerId })
      .orderBy('v.viewedAt', 'DESC')
      .take(safeLimit)
      .getMany();

    return rows.map((r) => r.productId);
  }

  private async trim(customerId: string) {
    const idsToKeep = await this.customerProductViewRepository
      .createQueryBuilder('v')
      .select('v.id', 'id')
      .where('v.customerId = :customerId', { customerId })
      .orderBy('v.viewedAt', 'DESC')
      .take(this.maxEntries)
      .getRawMany<{ id: string }>();

    const keep = idsToKeep.map((r) => r.id);
    if (!keep.length) return;

    await this.customerProductViewRepository
      .createQueryBuilder()
      .delete()
      .from(CustomerProductView)
      .where('customer_id = :customerId', { customerId })
      .andWhere('id NOT IN (:...keep)', { keep })
      .execute();
  }
}
