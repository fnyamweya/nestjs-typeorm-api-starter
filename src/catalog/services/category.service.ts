import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindOptionsWhere, Repository } from 'typeorm';
import { Category } from '../entities/category.entity';
import { CategoryTranslation } from '../entities/category-translation.entity';
import { CategoryClosure } from '../entities/category-closure.entity';
import { CreateCategoryDto } from '../dto/create-category.dto';
import { UpdateCategoryDto } from '../dto/update-category.dto';
import { FilterCategoryDto } from '../dto/filter-category.dto';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  cacheKeyFromParts,
  cacheKeyHash,
} from 'src/common/cache/cache-key.util';
import { ShippingCatalogContextCacheIndexService } from 'src/common/cache/shipping-catalog-context-cache-index.service';
import { PublicCategoryDto } from '../dto/public/public-category.dto';
import { PublicListCategoriesDto } from '../dto/public/public-list-categories.dto';

@Injectable()
export class CategoryService {
  constructor(
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
    @InjectRepository(CategoryTranslation)
    private readonly translationRepository: Repository<CategoryTranslation>,
    @InjectRepository(CategoryClosure)
    private readonly closureRepository: Repository<CategoryClosure>,
    private readonly cache: AppCacheService,
    private readonly shippingCatalogContextCacheIndex: ShippingCatalogContextCacheIndexService,
  ) {}

  async create(payload: CreateCategoryDto): Promise<Category> {
    const parentId = this.normalizeParentId(payload);

    const baseName =
      payload.name ??
      payload.translations?.[0]?.name ??
      payload.key ??
      payload.slug;

    const baseSlug = payload.slug ?? this.slugify(baseName);
    if (!baseSlug) {
      throw new BadRequestException('slug is required (or provide name/key)');
    }

    const slug = await this.ensureUniqueSlug(payload.taxonomyId, baseSlug);
    const key = payload.key ?? slug;

    const metaFromUi = this.buildMetaFromUi(payload);
    const metaJson = { ...metaFromUi, ...(payload.metaJson ?? {}) };

    const category = this.categoryRepository.create({
      taxonomyId: payload.taxonomyId,
      parentId,
      key,
      slug,
      isActive:
        payload.isActive ?? this.isActiveFromStatus(payload.status) ?? true,
      isLeaf: payload.isLeaf ?? false,
      sortOrder: payload.order ?? payload.sortOrder ?? 0,
      icon: payload.icon,
      avatarUrl: payload.avatarUrl,
      imageUrl: payload.imageUrl,
      metaJson,
    });

    const saved = await this.categoryRepository.save(category);

    await this.createClosureRows(saved.id, parentId);

    const translations = payload.translations?.length
      ? payload.translations
      : payload.name
        ? [
            {
              locale: 'en',
              name: payload.name,
              description: payload.description,
              seoTitle: payload.seoTitle,
              seoDescription: payload.seoDescription,
            },
          ]
        : undefined;

    if (translations?.length) {
      const entities = translations.map((t) =>
        this.translationRepository.create({ ...t, categoryId: saved.id }),
      );
      await this.translationRepository.save(entities);
    }

    await this.cache.delByPrefix('catalog:categories:list:');
    await this.cache.del(`catalog:categories:${saved.id}`);
    return this.findOne(saved.id);
  }

  async findAll(filters: FilterCategoryDto): Promise<Category[]> {
    const rawKey = cacheKeyFromParts('catalog', 'categories', 'list', {
      taxonomyId: filters.taxonomyId,
      isActive: filters.isActive,
    });
    const key = `catalog:categories:list:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      () => {
        const where: FindOptionsWhere<Category> = {};

        if (filters.taxonomyId) {
          where.taxonomyId = filters.taxonomyId;
        }

        if (filters.isActive !== undefined) {
          where.isActive = filters.isActive;
        }

        return this.categoryRepository.find({
          where: Object.keys(where).length ? where : undefined,
          relations: ['translations'],
          order: { sortOrder: 'ASC', key: 'ASC' },
        });
      },
      { ttlSeconds: 120 },
    );
  }

  async findOne(id: string): Promise<Category> {
    const key = `catalog:categories:${id}`;
    const category = await this.cache.remember(
      key,
      () =>
        this.categoryRepository.findOne({
          where: { id },
          relations: ['translations', 'children'],
        }),
      { ttlSeconds: 300 },
    );

    if (!category) throw new NotFoundException('Category not found');
    return category;
  }

  private pickCategoryTranslation(category: Category, locale?: string) {
    const preferredLocale = (locale || 'en').toLowerCase();
    const translations = category.translations ?? [];
    return (
      translations.find((t) => t.locale?.toLowerCase() === preferredLocale) ??
      translations.find((t) =>
        t.locale?.toLowerCase().startsWith(preferredLocale),
      ) ??
      translations.find((t) => t.locale?.toLowerCase() === 'en') ??
      translations[0]
    );
  }

  async findAllPublic(
    filters: PublicListCategoriesDto,
  ): Promise<PublicCategoryDto[]> {
    const locale = filters.locale;
    const rawKey = cacheKeyFromParts(
      'public',
      'catalog',
      'categories',
      'list',
      {
        taxonomyId: filters.taxonomyId,
        locale: locale || 'en',
      },
    );
    const key = `public:catalog:categories:list:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const qb = this.categoryRepository
          .createQueryBuilder('category')
          .leftJoinAndSelect('category.translations', 'translations')
          .innerJoin('category.taxonomy', 'taxonomy')
          .where('category.is_active = true')
          .andWhere('taxonomy.is_active = true')
          .orderBy('category.sort_order', 'ASC')
          .addOrderBy('category.key', 'ASC');

        if (filters.taxonomyId) {
          qb.andWhere('category.taxonomy_id = :taxonomyId', {
            taxonomyId: filters.taxonomyId,
          });
        }

        const rows = await qb.getMany();
        return rows.map((c) => {
          const t = this.pickCategoryTranslation(c, locale);
          return {
            id: c.id,
            taxonomyId: c.taxonomyId,
            parentId: c.parentId,
            key: c.key,
            slug: c.slug,
            name: t?.name ?? c.key,
            description: t?.description,
            icon: c.icon,
            avatarUrl: c.avatarUrl,
            imageUrl: c.imageUrl,
            sortOrder: c.sortOrder,
            isLeaf: c.isLeaf,
          };
        });
      },
      { ttlSeconds: 120 },
    );
  }

  async findOnePublic(
    id: string,
    opts?: { locale?: string },
  ): Promise<PublicCategoryDto> {
    const locale = opts?.locale;
    const rawKey = cacheKeyFromParts('public', 'catalog', 'categories', 'one', {
      id,
      locale: locale || 'en',
    });
    const key = `public:catalog:categories:${cacheKeyHash(rawKey)}`;

    const row = await this.cache.remember(
      key,
      async () => {
        const qb = this.categoryRepository
          .createQueryBuilder('category')
          .leftJoinAndSelect('category.translations', 'translations')
          .innerJoin('category.taxonomy', 'taxonomy')
          .where('category.id = :id', { id })
          .andWhere('category.is_active = true')
          .andWhere('taxonomy.is_active = true');
        return qb.getOne();
      },
      { ttlSeconds: 300 },
    );

    if (!row) throw new NotFoundException('Category not found');
    const t = this.pickCategoryTranslation(row, locale);
    return {
      id: row.id,
      taxonomyId: row.taxonomyId,
      parentId: row.parentId,
      key: row.key,
      slug: row.slug,
      name: t?.name ?? row.key,
      description: t?.description,
      icon: row.icon,
      avatarUrl: row.avatarUrl,
      imageUrl: row.imageUrl,
      sortOrder: row.sortOrder,
      isLeaf: row.isLeaf,
    };
  }

  async update(id: string, payload: UpdateCategoryDto): Promise<Category> {
    const category = await this.findOneEntityOrThrow(id);
    const previousParentId = category.parentId;

    const parentId = payload.parentId ?? this.normalizeParentId(payload);

    if (
      parentId &&
      parentId !== category.parentId &&
      category.children?.length
    ) {
      throw new BadRequestException(
        'Cannot re-parent a category with children',
      );
    }

    const metaFromUi = this.buildMetaFromUi(payload);
    const metaJson = {
      ...(category.metaJson ?? {}),
      ...metaFromUi,
      ...(payload.metaJson ?? {}),
    };

    Object.assign(category, {
      key: payload.key ?? category.key,
      slug: payload.slug ?? category.slug,
      isActive:
        payload.isActive ??
        this.isActiveFromStatus(payload.status) ??
        category.isActive,
      isLeaf: payload.isLeaf ?? category.isLeaf,
      sortOrder: payload.order ?? payload.sortOrder ?? category.sortOrder,
      icon: payload.icon ?? category.icon,
      avatarUrl: payload.avatarUrl ?? category.avatarUrl,
      imageUrl: payload.imageUrl ?? category.imageUrl,
      metaJson,
      parentId: parentId ?? category.parentId,
    });

    const saved = await this.categoryRepository.save(category);

    if (parentId !== undefined && parentId !== previousParentId) {
      await this.resetClosureRows(saved.id, parentId);
    }

    if (payload.translations) {
      await this.translationRepository.delete({ categoryId: saved.id });
      const translations = payload.translations.map((t) =>
        this.translationRepository.create({ ...t, categoryId: saved.id }),
      );
      if (translations.length) {
        await this.translationRepository.save(translations);
      }
    }

    await this.cache.delByPrefix('catalog:categories:list:');
    await this.cache.del(`catalog:categories:${saved.id}`);
    await this.shippingCatalogContextCacheIndex.invalidateByCategoryIds([
      saved.id,
    ]);
    return this.findOne(saved.id);
  }

  async remove(id: string): Promise<void> {
    const category = await this.findOneEntityOrThrow(id);
    await this.categoryRepository.remove(category);

    await this.cache.delByPrefix('catalog:categories:list:');
    await this.cache.del(`catalog:categories:${id}`);
    await this.shippingCatalogContextCacheIndex.invalidateByCategoryIds([id]);
  }

  private async findOneEntityOrThrow(id: string): Promise<Category> {
    const category = await this.categoryRepository.findOne({
      where: { id },
      relations: ['translations', 'children'],
    });

    if (!category) throw new NotFoundException('Category not found');
    return category;
  }

  private async createClosureRows(categoryId: string, parentId?: string) {
    const rows: CategoryClosure[] = [
      this.closureRepository.create({
        ancestorId: categoryId,
        descendantId: categoryId,
        depth: 0,
      }),
    ];

    if (parentId) {
      const ancestorClosures = await this.closureRepository.find({
        where: { descendantId: parentId },
      });

      for (const ancestor of ancestorClosures) {
        rows.push(
          this.closureRepository.create({
            ancestorId: ancestor.ancestorId,
            descendantId: categoryId,
            depth: ancestor.depth + 1,
          }),
        );
      }
    }

    await this.closureRepository.save(rows);
  }

  private async resetClosureRows(categoryId: string, parentId?: string) {
    await this.closureRepository.delete({ descendantId: categoryId });
    await this.createClosureRows(categoryId, parentId);
  }

  private normalizeParentId(payload: {
    parentId?: string;
    parent?: string;
  }): string | undefined {
    if (payload.parentId) return payload.parentId;
    if (!payload.parent) return undefined;
    if (payload.parent === 'ROOT') return undefined;
    return payload.parent;
  }

  private isActiveFromStatus(status?: string): boolean | undefined {
    if (!status) return undefined;
    if (status === 'active') return true;
    if (status === 'inactive') return false;
    return undefined;
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

  private async ensureUniqueSlug(
    taxonomyId: string,
    baseSlug: string,
    excludeId?: string,
  ): Promise<string> {
    const qb = this.categoryRepository
      .createQueryBuilder('c')
      .select(['c.slug'])
      .where('c.taxonomyId = :taxonomyId', { taxonomyId })
      .andWhere('c.slug LIKE :prefix', { prefix: `${baseSlug}%` });

    if (excludeId) {
      qb.andWhere('c.id != :excludeId', { excludeId });
    }

    const rows = await qb.getMany();
    const slugs = new Set(rows.map((r) => r.slug));
    if (!slugs.has(baseSlug)) return baseSlug;

    let maxSuffix = 1;
    const suffixRegex = new RegExp(`^${baseSlug}-(\\d+)$`);
    for (const slug of slugs) {
      const match = slug.match(suffixRegex);
      if (!match) continue;
      const n = Number(match[1]);
      if (Number.isFinite(n) && n > maxSuffix) maxSuffix = n;
    }

    return `${baseSlug}-${maxSuffix + 1}`;
  }

  private buildMetaFromUi(
    payload: Partial<CreateCategoryDto & UpdateCategoryDto>,
  ): Record<string, unknown> {
    const meta: Record<string, unknown> = {};
    const set = (key: string, value: unknown) => {
      if (value !== undefined) meta[key] = value;
    };

    set('description', payload.description);
    set('seoTitle', payload.seoTitle);
    set('seoDescription', payload.seoDescription);
    set('status', payload.status);
    set('order', payload.order);
    set('synonyms', payload.synonyms);
    set('keywords', payload.keywords);
    set('level', payload.level);
    set('audience', payload.audience);
    set('returnPolicy', payload.returnPolicy);
    set('taxCode', payload.taxCode);
    set('highlight', payload.highlight);
    set('navPlacement', payload.navPlacement);
    set('featured', payload.featured);
    set('banner', payload.banner);
    set('marginTarget', payload.marginTarget);
    set('availability', payload.availability);
    set('compliance', payload.compliance);
    set('shippingProfile', payload.shippingProfile);
    set('marketingHeadline', payload.marketingHeadline);
    set('marketingSub', payload.marketingSub);
    set('heroCta', payload.heroCta);
    set('heroCtaLink', payload.heroCtaLink);
    set('contentPillar', payload.contentPillar);
    set('story', payload.story);
    set('themeColor', payload.themeColor);
    set('shippingMatrix', payload.shippingMatrix);

    return meta;
  }
}
