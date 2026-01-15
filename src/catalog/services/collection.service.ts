import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, EntityManager, In, Not, Repository } from 'typeorm';
import {
  Collection,
  CollectionRulePayload,
  CollectionRuleType,
} from '../entities/collection.entity';
import { CollectionItem } from '../entities/collection-item.entity';
import { Product } from '../entities/product.entity';
import {
  CreateCollectionDto,
  FilterCollectionDto,
  UpdateCollectionDto,
  UpdateCollectionItemsDto,
} from '../dto/collection.dto';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { ProductStatus } from '../dto/create-product.dto';

const DEFAULT_COLLECTION_LIMIT = 12;
const DEFAULT_COLLECTIONS_TAKE = 20;

export type ResolvedCollectionItem = {
  product: Product;
  position?: number;
};

@Injectable()
export class CollectionService {
  constructor(
    @InjectRepository(Collection)
    private readonly collectionRepository: Repository<Collection>,
    @InjectRepository(CollectionItem)
    private readonly collectionItemRepository: Repository<CollectionItem>,
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly cache: AppCacheService,
  ) {}

  async create(payload: CreateCollectionDto): Promise<Collection> {
    const collectionId = await this.dataSource.transaction(async (manager) => {
      const collectionRepo = manager.getRepository(Collection);
      const slugBase = payload.slug?.trim() || this.slugify(payload.title);
      if (!slugBase) throw new BadRequestException('title/slug is required');

      const slug = await this.ensureUniqueSlug(slugBase, undefined, manager);
      const collection = collectionRepo.create({
        title: payload.title,
        description: payload.description,
        icon: payload.icon,
        avatarUrl: payload.avatarUrl,
        slug,
        type: payload.type?.trim() || 'default',
        ruleType: payload.ruleType ?? CollectionRuleType.STATIC,
        rulePayload: payload.rulePayload ?? {},
        isActive: payload.isActive ?? true,
        priority: payload.priority ?? 0,
        validFrom: payload.validFrom,
        validTo: payload.validTo,
      });

      const saved = await collectionRepo.save(collection);

      if (
        collection.ruleType === CollectionRuleType.STATIC &&
        payload.items?.length
      ) {
        await this.replaceItemsInternal(saved.id, payload.items, manager);
      }

      return saved.id;
    });

    await this.clearCacheForCollection(collectionId);
    return this.findOne(collectionId);
  }

  async findAll(filters: FilterCollectionDto) {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;

    const qb = this.collectionRepository
      .createQueryBuilder('collection')
      .orderBy('collection.priority', 'DESC')
      .addOrderBy('collection.createdAt', 'DESC')
      .skip((page - 1) * limit)
      .take(limit);

    if (filters.type) qb.andWhere('collection.type = :type', { type: filters.type });
    if (filters.isActive !== undefined)
      qb.andWhere('collection.isActive = :isActive', {
        isActive: filters.isActive,
      });

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(id: string): Promise<Collection> {
    const collection = await this.collectionRepository.findOne({
      where: { id },
      relations: ['items', 'items.product'],
      order: { items: { position: 'ASC' } },
    });

    if (!collection) throw new NotFoundException('Collection not found');
    collection.items = (collection.items ?? []).sort(
      (a, b) => (a.position ?? 0) - (b.position ?? 0),
    );
    return collection;
  }

  async update(id: string, payload: UpdateCollectionDto): Promise<Collection> {
    const existing = await this.findOne(id);

    const slug =
      payload.slug !== undefined
        ? await this.ensureUniqueSlug(
            payload.slug || this.slugify(payload.title ?? existing.title),
            existing.id,
          )
        : existing.slug;

    Object.assign(existing, {
      title: payload.title ?? existing.title,
      description: payload.description ?? existing.description,
      icon: payload.icon ?? existing.icon,
      avatarUrl: payload.avatarUrl ?? existing.avatarUrl,
      slug,
      type: payload.type?.trim() ?? existing.type,
      ruleType: payload.ruleType ?? existing.ruleType,
      rulePayload: payload.rulePayload ?? existing.rulePayload,
      isActive: payload.isActive ?? existing.isActive,
      priority: payload.priority ?? existing.priority,
      validFrom: payload.validFrom ?? existing.validFrom,
      validTo: payload.validTo ?? existing.validTo,
    });

    if (
      existing.ruleType !== CollectionRuleType.STATIC &&
      payload.items?.length
    ) {
      throw new BadRequestException(
        'Items can only be provided for STATIC collections',
      );
    }

    await this.dataSource.transaction(async (manager) => {
      await manager.getRepository(Collection).save(existing);
      if (payload.items && existing.ruleType === CollectionRuleType.STATIC) {
        await this.replaceItemsInternal(existing.id, payload.items, manager);
      }
    });

    await this.clearCacheForCollection(id);
    return this.findOne(id);
  }

  async replaceItems(
    id: string,
    payload: UpdateCollectionItemsDto,
  ): Promise<Collection> {
    const collection = await this.findOne(id);
    if (collection.ruleType !== CollectionRuleType.STATIC) {
      throw new BadRequestException('Only STATIC collections support items');
    }

    await this.dataSource.transaction(async (manager) => {
      await this.replaceItemsInternal(id, payload.items, manager);
    });

    await this.clearCacheForCollection(id);
    return this.findOne(id);
  }

  async remove(id: string): Promise<void> {
    const exists = await this.collectionRepository.exist({ where: { id } });
    if (!exists) throw new NotFoundException('Collection not found');
    await this.collectionRepository.delete(id);
    await this.clearCacheForCollection(id);
  }

  async getPublicCollection(slug: string, limit?: number) {
    const safeLimit = limit ?? DEFAULT_COLLECTION_LIMIT;
    const cacheKey = `catalog:collections:public:${slug}:limit:${safeLimit}`;
    await this.cleanupExpiredItems();

    return this.cache.remember(
      cacheKey,
      async () => {
        const collection = await this.collectionRepository.findOne({
          where: { slug, isActive: true },
        });

        if (!collection) throw new NotFoundException('Collection not found');
        this.assertValidity(collection);

        const items = await this.resolveItems(collection, safeLimit);
        return {
          id: collection.id,
          slug: collection.slug,
          title: collection.title,
          description: collection.description,
          icon: collection.icon,
          avatarUrl: collection.avatarUrl,
          type: collection.type,
          priority: collection.priority,
          validFrom: collection.validFrom,
          validTo: collection.validTo,
          items,
        };
      },
      { ttlSeconds: 90 },
    );
  }

  async getPublicCollections(slugs: string[], limit?: number) {
    const unique = Array.from(new Set(slugs.filter((s) => s?.trim())));
    const results: any[] = [];
    await this.cleanupExpiredItems();

    for (const slug of unique) {
      results.push(await this.getPublicCollection(slug, limit));
    }

    return results;
  }

  async listPublicCollections(input?: {
    type?: string;
    isActive?: boolean;
    take?: number;
    itemsLimit?: number;
  }) {
    await this.cleanupExpiredItems();

    const take = input?.take ?? DEFAULT_COLLECTIONS_TAKE;
    const itemsLimit = input?.itemsLimit ?? DEFAULT_COLLECTION_LIMIT;
    const now = new Date();

    const qb = this.collectionRepository
      .createQueryBuilder('collection')
      .orderBy('collection.priority', 'DESC')
      .addOrderBy('collection.createdAt', 'DESC')
      .take(take);

    if (input?.type) {
      qb.andWhere('collection.type = :type', { type: input.type });
    }

    // Default to only active collections for public listing.
    qb.andWhere('collection.isActive = :isActive', {
      isActive: input?.isActive ?? true,
    });

    // Only collections within validity window (or no window).
    qb.andWhere('(collection.validFrom IS NULL OR collection.validFrom <= :now)', {
      now,
    });
    qb.andWhere('(collection.validTo IS NULL OR collection.validTo >= :now)', { now });

    const rows = await qb.getMany();
    const results: any[] = [];

    for (const collection of rows) {
      const items = await this.resolveItems(collection, itemsLimit);
      results.push({
        id: collection.id,
        slug: collection.slug,
        title: collection.title,
        description: collection.description,
        icon: collection.icon,
        avatarUrl: collection.avatarUrl,
        type: collection.type,
        priority: collection.priority,
        validFrom: collection.validFrom,
        validTo: collection.validTo,
        items,
      });
    }

    return results;
  }

  private async resolveItems(
    collection: Collection,
    limit: number,
  ): Promise<ResolvedCollectionItem[]> {
    if (collection.ruleType === CollectionRuleType.STATIC) {
      const items = await this.collectionItemRepository
        .createQueryBuilder('item')
        .innerJoinAndSelect('item.product', 'product')
        .where('item.collectionId = :collectionId', { collectionId: collection.id })
        .andWhere('product.status = :status', { status: ProductStatus.ACTIVE })
        .orderBy('item.position', 'ASC')
        .addOrderBy('item.createdAt', 'ASC')
        .take(limit)
        .getMany();

      return items.map((item) => ({ product: item.product, position: item.position }));
    }

    return this.resolveQueryRule(collection.rulePayload, limit);
  }

  private async resolveQueryRule(
    rule: CollectionRulePayload,
    limit: number,
  ): Promise<ResolvedCollectionItem[]> {
    const qb = this.productRepository
      .createQueryBuilder('product')
      .where('product.status = :status', { status: ProductStatus.ACTIVE });

    if (rule?.productIds?.length) {
      qb.andWhere('product.id IN (:...productIds)', { productIds: rule.productIds });
    }

    if (rule?.brandIds?.length) {
      qb.andWhere('product.brandId IN (:...brandIds)', { brandIds: rule.brandIds });
    }

    if (rule?.categoryIds?.length) {
      qb.innerJoin('product.productCategories', 'pc');
      qb.andWhere('pc.categoryId IN (:...categoryIds)', {
        categoryIds: rule.categoryIds,
      });
    }

    const sortKey = rule?.sort === '-newest' ? 'ASC' : 'DESC';
    qb.orderBy('product.createdAt', sortKey);

    const take = rule?.limit ?? limit ?? DEFAULT_COLLECTION_LIMIT;
    qb.take(take);

    const products = await qb.getMany();
    return products.map((product, index) => ({ product, position: index }));
  }

  private async replaceItemsInternal(
    collectionId: string,
    items: { productId: string; position?: number }[],
    manager: EntityManager,
  ) {
    const normalized = (items ?? []).map((item, index) => ({
      productId: item.productId,
      position: item.position ?? index,
    }));

    if (!normalized.length) {
      await manager.getRepository(CollectionItem).delete({ collectionId });
      return;
    }

    const productIds = normalized.map((item) => item.productId);
    const products = await manager.getRepository(Product).find({
      where: { id: In(productIds) },
      select: ['id'],
    });

    if (products.length !== normalized.length) {
      throw new BadRequestException('One or more products do not exist');
    }

    await manager.getRepository(CollectionItem).delete({ collectionId });

    const entities = normalized.map((item) =>
      manager.getRepository(CollectionItem).create({
        collectionId,
        productId: item.productId,
        position: item.position ?? 0,
      }),
    );

    await manager.getRepository(CollectionItem).save(entities);
  }

  private async ensureUniqueSlug(
    baseSlug: string,
    excludeId?: string,
    manager?: EntityManager,
  ): Promise<string> {
    const repo = manager
      ? manager.getRepository(Collection)
      : this.collectionRepository;

    const slugCandidate = this.slugify(baseSlug);
    let slug = slugCandidate;
    let suffix = 1;

    while (
      await repo.exist({
        where: excludeId ? { slug, id: Not(excludeId) } : { slug },
      })
    ) {
      suffix += 1;
      slug = `${slugCandidate}-${suffix}`;
    }

    return slug;
  }

  private slugify(input?: string): string {
    if (!input) return '';
    return input
      .toString()
      .trim()
      .toLowerCase()
      .replace(/['"]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+/, '')
      .replace(/-+$/, '');
  }

  private assertValidity(collection: Collection) {
    const now = new Date();
    if (collection.validFrom && collection.validFrom > now) {
      throw new NotFoundException('Collection is not active');
    }
    if (collection.validTo && collection.validTo < now) {
      throw new NotFoundException('Collection has expired');
    }
  }

  private async clearCacheForCollection(collectionIdOrSlug?: string) {
    if (collectionIdOrSlug) {
      await this.cache.delByPrefix(`catalog:collections:${collectionIdOrSlug}`);
    }
    await this.cache.delByPrefix('catalog:collections:public:');
  }

  private async cleanupExpiredItems() {
    const now = new Date();
    await this.collectionItemRepository
      .createQueryBuilder()
      .delete()
      .where(
        `collection_id IN (SELECT id FROM collection WHERE valid_to IS NOT NULL AND valid_to < :now)`,
        { now },
      )
      .execute();
  }
}
