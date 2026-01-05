// @ts-nocheck
import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { Brackets, DataSource, EntityManager, In, IsNull, Not, Repository } from 'typeorm';
import { randomBytes } from 'crypto';
import { Product } from '../entities/product.entity';
import { Brand } from '../entities/brand.entity';
import { ProductTranslation } from '../entities/product-translation.entity';
import { ProductSku } from '../entities/product-sku.entity';
import { ProductCategory } from '../entities/product-category.entity';
import { ProductChannel } from '../entities/product-channel.entity';
import { ProductContextOverride } from '../entities/product-context-override.entity';
import { PriceList } from '../entities/price-list.entity';
import { Currency } from '../entities/currency.entity';
import { PriceRow } from '../entities/price-row.entity';
import { Category } from '../entities/category.entity';
import { Channel } from 'src/channels/entities/channel.entity';
import { CreateProductDto, ProductStatus } from '../dto/create-product.dto';
import { UpdateProductDto } from '../dto/update-product.dto';
import { FilterProductDto } from '../dto/filter-product.dto';
import { PublicListProductsDto } from '../dto/public/public-list-products.dto';
import { PublicListProductsViewDto } from '../dto/public/public-list-products-view.dto';
import { PublicCategoryDto } from '../dto/public/public-category.dto';
import {
  PublicProductCategoryRefDto,
  PublicProductDto,
  PublicProductPriceDto,
  PublicProductTranslationDto,
  PublicProductSkuDto,
} from '../dto/public/public-product.dto';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { cacheKeyFromParts, cacheKeyHash } from 'src/common/cache/cache-key.util';
import { ShippingCatalogContextCacheIndexService } from 'src/common/cache/shipping-catalog-context-cache-index.service';
import { ProductAvailabilityDto } from '../dto/product-availability.dto';
import { CreateProductSkuDto } from '../dto/create-product-sku.dto';
import { CreateProductPriceDto } from '../dto/create-product-price.dto';
import { CreateProductContextOverrideDto } from '../dto/product-v2/create-product-context-override.dto';
import { UpdateProductContextOverrideDto } from '../dto/product-v2/update-product-context-override.dto';
import { ProductDTO, ProductViewDTO } from '../dto/product-v2/product.dto';
import { AvailabilityDTO, ContextualOverrideDTO, LocalizedString } from '../dto/product-v2/product.types';
import { applyContextualOverrides, ProductViewContext } from '../utils/contextual-overrides.util';
import { PriceService } from './price.service';

interface PaginatedProducts {
  data: Product[];
  total: number;
  page: number;
  limit: number;
}

interface AvailabilityNormalized {
  // Make this structurally assignable to jsonb records.
  [key: string]: any;
  channels: string[];
  countries: string[];
  locations: string[];
  stock: {
    type: string;
    quantity?: number;
  };
  schedule: {
    startAt?: string;
    endAt?: string;
    timezone?: string;
  };
  meta?: Record<string, unknown>;
}

@Injectable()
export class ProductService {
  constructor(
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(Brand)
    private readonly brandRepository: Repository<Brand>,
    @InjectRepository(ProductTranslation)
    private readonly translationRepository: Repository<ProductTranslation>,
    @InjectRepository(ProductSku)
    private readonly skuRepository: Repository<ProductSku>,
    @InjectRepository(ProductCategory)
    private readonly productCategoryRepository: Repository<ProductCategory>,
    @InjectRepository(ProductChannel)
    private readonly productChannelRepository: Repository<ProductChannel>,
    @InjectRepository(ProductContextOverride)
    private readonly productContextOverrideRepository: Repository<ProductContextOverride>,
    @InjectRepository(PriceRow)
    private readonly priceRowRepository: Repository<PriceRow>,
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(Currency)
    private readonly currencyRepository: Repository<Currency>,
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
    @InjectRepository(Channel)
    private readonly channelRepository: Repository<Channel>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly cache: AppCacheService,
    private readonly shippingCatalogContextCacheIndex: ShippingCatalogContextCacheIndexService,
    private readonly priceService: PriceService,
  ) {}

  private getRepos(manager?: EntityManager) {
    if (!manager) {
      return {
        productRepository: this.productRepository,
        brandRepository: this.brandRepository,
        translationRepository: this.translationRepository,
        skuRepository: this.skuRepository,
        productCategoryRepository: this.productCategoryRepository,
        productChannelRepository: this.productChannelRepository,
        productContextOverrideRepository: this.productContextOverrideRepository,
        priceRowRepository: this.priceRowRepository,
        priceListRepository: this.priceListRepository,
        currencyRepository: this.currencyRepository,
        categoryRepository: this.categoryRepository,
        channelRepository: this.channelRepository,
      };
    }

    return {
      productRepository: manager.getRepository(Product),
      brandRepository: manager.getRepository(Brand),
      translationRepository: manager.getRepository(ProductTranslation),
      skuRepository: manager.getRepository(ProductSku),
      productCategoryRepository: manager.getRepository(ProductCategory),
      productChannelRepository: manager.getRepository(ProductChannel),
      productContextOverrideRepository: manager.getRepository(ProductContextOverride),
      priceRowRepository: manager.getRepository(PriceRow),
      priceListRepository: manager.getRepository(PriceList),
      currencyRepository: manager.getRepository(Currency),
      categoryRepository: manager.getRepository(Category),
      channelRepository: manager.getRepository(Channel),
    };
  }

  private toMinorUnits(value: number, precision: number) {
    const p = Math.max(0, precision ?? 2);
    const fixed = Number(value).toFixed(p);
    const negative = fixed.startsWith('-');
    const normalized = negative ? fixed.slice(1) : fixed;
    const parts = normalized.split('.');
    const intPart = parts[0] ?? '0';
    const fracPart = (parts[1] ?? '').padEnd(p, '0');
    const digits = `${intPart}${p ? fracPart : ''}`.replace(/^0+(?=\d)/, '0');
    return `${negative ? '-' : ''}${digits}`;
  }

  private fromMinorUnits(amount: string, precision: number) {
    const p = Math.max(0, precision ?? 2);
    const negative = String(amount).startsWith('-');
    const digits = negative ? String(amount).slice(1) : String(amount);
    const padded = digits.padStart(p + 1, '0');
    const intPart = padded.slice(0, padded.length - p);
    const fracPart = padded.slice(padded.length - p);
    const normalizedInt = intPart.replace(/^0+(?=\d)/, '0');
    const value = p === 0 ? normalizedInt : `${normalizedInt}.${fracPart}`;
    return negative ? `-${value}` : value;
  }

  async create(payload: CreateProductDto): Promise<Product> {
    const productId = await this.dataSource.transaction(async (manager) => {
      const { brandRepository, productRepository } = this.getRepos(manager);

      if (payload.brandId) {
        const exists = await brandRepository.exist({ where: { id: payload.brandId } });
        if (!exists) throw new NotFoundException('Brand not found');
      }

      const slugBase = payload.slug?.trim() || this.slugify(payload.title);
      if (!slugBase) throw new BadRequestException('slug/title is required');

      const slug = await this.ensureUniqueSlug(slugBase, undefined, manager);
      const availability = this.normalizeAvailability(payload.availability);

      const product = productRepository.create({
        title: payload.title,
        description: payload.description,
        status: payload.status ?? ProductStatus.DRAFT,
        slug,
        externalRef: payload.externalRef,
        brandId: payload.brandId,
        availabilityJson: availability as any,
        imagesJson: this.normalizeImages(payload.images),
        optionDefinitionsJson: (payload.optionDefinitions ?? []) as any,
        metaJson: payload.metaJson ?? {},
      });

      const saved = await productRepository.save(product);

      await this.persistTranslations(saved.id, payload, saved.title, saved.description, manager);
      const { skus, inputs } = await this.persistSkus(saved.id, saved.slug, payload.skus, payload.optionDefinitions ?? [], manager);
      await this.persistPrices(saved.id, payload.prices, skus, inputs, manager);

      if (payload.categoryIds?.length) {
        await this.attachCategories(saved.id, payload.categoryIds, manager);
      }

      await this.syncChannels(saved.id, availability.channels, manager);
      return saved.id;
    });

    await this.clearProductCaches(productId);
    return this.findOne(productId);
  }

  async findAll(filters: FilterProductDto): Promise<PaginatedProducts> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;

    const rawKey = cacheKeyFromParts('catalog', 'products', 'list', {
      page,
      limit,
      status: filters.status,
      brandId: filters.brandId,
      categoryId: filters.categoryId,
      search: filters.search,
    });
    const key = `catalog:products:list:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const qb = this.productRepository
          .createQueryBuilder('product')
          .leftJoinAndSelect('product.brand', 'brand')
          .leftJoinAndSelect('product.translations', 'translations')
          .leftJoinAndSelect('product.skus', 'skus')
          .leftJoinAndSelect('product.productCategories', 'productCategories')
          .leftJoinAndSelect('productCategories.category', 'category')
          .orderBy('product.createdAt', 'DESC')
          .skip((page - 1) * limit)
          .take(limit);

        if (filters.status) {
          qb.andWhere('product.status = :status', { status: filters.status });
        }

        if (filters.brandId) {
          qb.andWhere('product.brand_id = :brandId', { brandId: filters.brandId });
        }

        if (filters.categoryId) {
          qb.andWhere('productCategories.categoryId = :categoryId', { categoryId: filters.categoryId });
        }

        if (filters.search) {
          qb.andWhere(
            new Brackets((qbInner) => {
              qbInner
                .where('product.title ILIKE :search', { search: `%${filters.search}%` })
                .orWhere('product.slug ILIKE :search', { search: `%${filters.search}%` });
            }),
          );
        }

        const [data, total] = await qb.getManyAndCount();
        return { data, total, page, limit };
      },
      { ttlSeconds: 45 },
    );
  }

  async findOne(id: string): Promise<Product> {
    const key = `catalog:products:${id}`;
    const product = await this.cache.remember(
      key,
      () =>
        this.productRepository.findOne({
          where: { id },
          relations: [
            'brand',
            'translations',
            'skus',
            'productCategories',
            'productCategories.category',
            'productChannels',
            'productChannels.channel',
          ],
        }),
      { ttlSeconds: 180 },
    );

    if (!product) throw new NotFoundException('Product not found');
    return product;
  }

  async update(id: string, payload: UpdateProductDto): Promise<Product> {
    const product = await this.findOneEntityOrThrow(id);

    if (payload.brandId) {
      const exists = await this.brandRepository.exist({ where: { id: payload.brandId } });
      if (!exists) throw new NotFoundException('Brand not found');
    }

    let slug = product.slug;
    if (payload.slug !== undefined) {
      const baseSlug = payload.slug?.trim() ? this.slugify(payload.slug) : '';
      if (!baseSlug) throw new BadRequestException('slug cannot be empty');
      slug = await this.ensureUniqueSlug(baseSlug, product.id);
    }

    const availability = payload.availability
      ? this.normalizeAvailability(payload.availability)
      : (product.availabilityJson as unknown as AvailabilityNormalized);

    Object.assign(product, {
      title: payload.title ?? product.title,
      description: payload.description ?? product.description,
      status: payload.status ?? product.status,
      slug,
      externalRef: payload.externalRef ?? product.externalRef,
      brandId: payload.brandId ?? product.brandId,
      availabilityJson: availability,
      imagesJson: payload.images ? this.normalizeImages(payload.images) : product.imagesJson,
      optionDefinitionsJson:
        payload.optionDefinitions !== undefined ? ((payload.optionDefinitions ?? []) as any) : product.optionDefinitionsJson,
      metaJson: payload.metaJson ?? product.metaJson,
    });

    const saved = await this.productRepository.save(product);

    if (payload.translations) {
      await this.translationRepository.delete({ productId: saved.id });
      await this.persistTranslations(saved.id, payload, saved.title, saved.description);
    }

    if ((payload as any).skus) {
      await this.skuRepository.delete({ productId: saved.id });
      const optionDefs = (payload.optionDefinitions ?? (saved.optionDefinitionsJson as any) ?? []) as any[];
      const { skus, inputs } = await this.persistSkus(saved.id, saved.slug, (payload as any).skus, optionDefs);
      await this.persistPrices(saved.id, payload.prices, skus, inputs);
    }

    if (payload.prices && !(payload as any).skus) {
      await this.persistPrices(saved.id, payload.prices, [], []);
    }

    if (payload.categoryIds) {
      await this.productCategoryRepository.delete({ productId: saved.id });
      if (payload.categoryIds.length) {
        await this.attachCategories(saved.id, payload.categoryIds);
      }
    }

    if (payload.availability?.channels) {
      await this.syncChannels(saved.id, availability.channels);
    }

    await this.clearProductCaches(saved.id);
    return this.findOne(saved.id);
  }

  async remove(id: string): Promise<void> {
    const product = await this.findOneEntityOrThrow(id);
    await this.productRepository.remove(product);

    await this.clearProductCaches(id);
  }

  async findAllPublic(filters: PublicListProductsDto): Promise<{ data: PublicProductDto[]; total: number; page: number; limit: number }> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;

    const rawKey = cacheKeyFromParts('public', 'catalog', 'products', 'list', {
      page,
      limit,
      search: filters.search,
      brandId: filters.brandId,
      categoryId: filters.categoryId,
      taxonomyId: filters.taxonomyId,
      channel: filters.channel,
      country: filters.country,
      location: filters.location,
      locale: filters.locale,
      priceListId: filters.priceListId,
      currencyCode: filters.currencyCode,
    });
    const key = `public:catalog:products:list:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const qb = this.productRepository
          .createQueryBuilder('product')
          .leftJoinAndSelect('product.brand', 'brand')
          .leftJoinAndSelect('product.translations', 'translations')
          .leftJoinAndSelect('product.skus', 'skus')
          .leftJoinAndSelect('product.productCategories', 'productCategories')
          .leftJoinAndSelect('productCategories.category', 'category')
          .where('product.status = :status', { status: ProductStatus.ACTIVE });

        if (filters.brandId) {
          qb.andWhere('product.brand_id = :brandId', { brandId: filters.brandId });
        }

        if (filters.categoryId) {
          qb.andWhere('productCategories.categoryId = :categoryId', { categoryId: filters.categoryId });
        }

        if (filters.taxonomyId) {
          qb.andWhere('category.taxonomyId = :taxonomyId', { taxonomyId: filters.taxonomyId });
        }

        if (filters.search) {
          qb.andWhere(
            new Brackets((qbInner) => {
              qbInner
                .where('product.title ILIKE :search', { search: `%${filters.search}%` })
                .orWhere('product.slug ILIKE :search', { search: `%${filters.search}%` });
            }),
          );
        }

        if (filters.channel) {
          qb.leftJoin('product.productChannels', 'productChannels')
            .leftJoin('productChannels.channel', 'channel')
            .andWhere('channel.code = :channel', { channel: filters.channel.toUpperCase() });
        }

        if (filters.country) {
          const country = filters.country.toUpperCase();
          qb.andWhere("product.availability_json -> 'countries' ? :country", { country });
        }

        if (filters.location) {
          qb.andWhere("product.availability_json -> 'locations' ? :location", { location: filters.location });
        }

        qb.orderBy('product.createdAt', 'DESC').skip((page - 1) * limit).take(limit);

        const [rows, total] = await qb.getManyAndCount();
        const data = await Promise.all(
          rows.map((row) =>
            this.toPublicProduct(row, {
              locale: filters.locale,
              includeSkus: false,
              priceListId: filters.priceListId,
              currencyCode: filters.currencyCode,
            }),
          ),
        );

        return { data, total, page, limit };
      },
      { ttlSeconds: 45 },
    );
  }

  async findOnePublic(id: string, opts?: { locale?: string; priceListId?: string; currencyCode?: string }): Promise<PublicProductDto> {
    const rawKey = cacheKeyFromParts('public', 'catalog', 'products', 'one', { id, locale: opts?.locale, priceListId: opts?.priceListId, currencyCode: opts?.currencyCode });
    const key = `public:catalog:products:${cacheKeyHash(rawKey)}`;

    const product = await this.cache.remember(
      key,
      () =>
        this.productRepository.findOne({
          where: { id, status: ProductStatus.ACTIVE },
          relations: [
            'brand',
            'translations',
            'skus',
            'productCategories',
            'productCategories.category',
            'productChannels',
            'productChannels.channel',
          ],
        }),
      { ttlSeconds: 180 },
    );

    if (!product) throw new NotFoundException('Product not found');
    return this.toPublicProduct(product, {
      locale: opts?.locale,
      includeSkus: true,
      priceListId: opts?.priceListId,
      currencyCode: opts?.currencyCode,
    });
  }

  async findAllPublicView(
    filters: PublicListProductsViewDto,
  ): Promise<{ data: ProductViewDTO[]; total: number; page: number; limit: number }> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;
    const context = this.buildViewContext(filters);

    const rawKey = cacheKeyFromParts('public', 'catalog', 'products', 'view', 'list', {
      page,
      limit,
      search: filters.search,
      brandId: filters.brandId,
      categoryId: filters.categoryId,
      taxonomyId: filters.taxonomyId,
      channel: filters.channel,
      country: filters.country,
      location: filters.location,
      locale: filters.locale,
      priceListId: filters.priceListId,
      currencyCode: filters.currencyCode,
      customerTier: filters.customerTier,
      role: filters.role,
      context,
    });
    const key = `public:catalog:products:view:list:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const qb = this.productRepository
          .createQueryBuilder('product')
          .leftJoinAndSelect('product.brand', 'brand')
          .leftJoinAndSelect('product.translations', 'translations')
          .leftJoinAndSelect('product.skus', 'skus')
          .leftJoinAndSelect('product.productCategories', 'productCategories')
          .leftJoinAndSelect('productCategories.category', 'category')
          .where('product.status = :status', { status: ProductStatus.ACTIVE });

        if (filters.brandId) {
          qb.andWhere('product.brand_id = :brandId', { brandId: filters.brandId });
        }

        if (filters.categoryId) {
          qb.andWhere('productCategories.categoryId = :categoryId', { categoryId: filters.categoryId });
        }

        if (filters.taxonomyId) {
          qb.andWhere('category.taxonomyId = :taxonomyId', { taxonomyId: filters.taxonomyId });
        }

        if (filters.search) {
          qb.andWhere(
            new Brackets((qbInner) => {
              qbInner
                .where('product.title ILIKE :search', { search: `%${filters.search}%` })
                .orWhere('product.slug ILIKE :search', { search: `%${filters.search}%` });
            }),
          );
        }

        if (filters.channel) {
          qb.leftJoin('product.productChannels', 'productChannels')
            .leftJoin('productChannels.channel', 'channel')
            .andWhere('channel.code = :channel', { channel: filters.channel.toUpperCase() });
        }

        if (filters.country) {
          const country = filters.country.toUpperCase();
          qb.andWhere("product.availability_json -> 'countries' ? :country", { country });
        }

        if (filters.location) {
          qb.andWhere("product.availability_json -> 'locations' ? :location", { location: filters.location });
        }

        qb.orderBy('product.createdAt', 'DESC').skip((page - 1) * limit).take(limit);

        const [rows, total] = await qb.getManyAndCount();
        const overridesByProduct = await this.loadContextOverridesByProductIds(rows.map((row) => row.id));

        const data = await Promise.all(
          rows.map((row) =>
            this.toProductView(row, overridesByProduct.get(row.id), {
              locale: filters.locale,
              priceListId: filters.priceListId,
              currencyCode: filters.currencyCode,
              context,
            }),
          ),
        );

        return { data, total, page, limit };
      },
      { ttlSeconds: 45 },
    );
  }

  async findOnePublicView(
    id: string,
    opts?: { locale?: string; priceListId?: string; currencyCode?: string; context?: ProductViewContext },
  ): Promise<ProductViewDTO> {
    const rawKey = cacheKeyFromParts('public', 'catalog', 'products', 'view', 'one', {
      id,
      locale: opts?.locale,
      priceListId: opts?.priceListId,
      currencyCode: opts?.currencyCode,
      context: opts?.context ?? null,
    });
    const key = `public:catalog:products:view:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const product = await this.productRepository.findOne({
          where: { id, status: ProductStatus.ACTIVE },
          relations: [
            'brand',
            'translations',
            'skus',
            'productCategories',
            'productCategories.category',
            'productChannels',
            'productChannels.channel',
          ],
        });

        if (!product) throw new NotFoundException('Product not found');

        const overrides = await this.productContextOverrideRepository.find({ where: { productId: product.id } });
        const overrideDtos = overrides.map((override) => this.toContextualOverrideDto(override));
        return this.toProductView(product, overrideDtos, {
          locale: opts?.locale,
          priceListId: opts?.priceListId,
          currencyCode: opts?.currencyCode,
          context: opts?.context,
        });
      },
      { ttlSeconds: 180 },
    );
  }

  async listContextOverrides(productId: string): Promise<ProductContextOverride[]> {
    await this.findOneEntityOrThrow(productId);
    return this.productContextOverrideRepository.find({
      where: { productId },
      order: { priority: 'DESC', createdAt: 'DESC' },
    });
  }

  async createContextOverride(productId: string, payload: CreateProductContextOverrideDto): Promise<ProductContextOverride> {
    await this.findOneEntityOrThrow(productId);
    const override = this.productContextOverrideRepository.create({
      productId,
      isActive: payload.isActive ?? true,
      priority: payload.priority ?? 0,
      validFrom: payload.validFrom ? new Date(payload.validFrom) : undefined,
      validUntil: payload.validUntil ? new Date(payload.validUntil) : undefined,
      matchContext: (payload.match ?? {}) as any,
      rule: (payload.rule ?? undefined) as any,
      patch: (payload.patch ?? []) as any,
      description: payload.description,
      audit: {},
    });

    const saved = await this.productContextOverrideRepository.save(override);
    await this.clearProductCaches(productId);
    return saved;
  }

  async updateContextOverride(
    productId: string,
    overrideId: string,
    payload: UpdateProductContextOverrideDto,
  ): Promise<ProductContextOverride> {
    const override = await this.productContextOverrideRepository.findOne({
      where: { id: overrideId, productId },
    });
    if (!override) throw new NotFoundException('Product context override not found');

    if (payload.isActive !== undefined) override.isActive = payload.isActive;
    if (payload.priority !== undefined) override.priority = payload.priority;
    if (payload.validFrom !== undefined) override.validFrom = payload.validFrom ? new Date(payload.validFrom) : undefined;
    if (payload.validUntil !== undefined) override.validUntil = payload.validUntil ? new Date(payload.validUntil) : undefined;
    if (payload.match !== undefined) override.matchContext = (payload.match ?? {}) as any;
    if (payload.rule !== undefined) override.rule = (payload.rule ?? undefined) as any;
    if (payload.patch !== undefined) override.patch = (payload.patch ?? []) as any;
    if (payload.description !== undefined) override.description = payload.description;

    const saved = await this.productContextOverrideRepository.save(override);
    await this.clearProductCaches(productId);
    return saved;
  }

  async removeContextOverride(productId: string, overrideId: string): Promise<void> {
    const override = await this.productContextOverrideRepository.findOne({
      where: { id: overrideId, productId },
    });
    if (!override) throw new NotFoundException('Product context override not found');

    await this.productContextOverrideRepository.remove(override);
    await this.clearProductCaches(productId);
  }

  async addProductPrice(productId: string, payload: CreateProductPriceDto) {
    const product = await this.findOneEntityOrThrow(productId);
    const list = await this.priceListRepository.findOne({ where: { id: payload.priceListId } });
    if (!list) throw new NotFoundException('Price list not found');

    const currency = await this.currencyRepository.findOne({ where: { code: list.currency } });
    const precision = currency?.precision ?? 2;

    const conditions = (payload.metaJson as any)?.conditions ?? {};

    const row = this.priceRowRepository.create({
      priceListId: list.id,
      targetType: 'PRODUCT',
      targetId: product.id,
      selectorJson: conditions,
      currencyCode: undefined,
      unitAmount: this.toMinorUnits(payload.unitPrice, precision),
      compareAtAmount: payload.compareAtPrice !== undefined ? this.toMinorUnits(payload.compareAtPrice, precision) : undefined,
      minQuantity: payload.minQuantity ?? 1,
      maxQuantity: payload.maxQuantity,
      validFrom: payload.validFrom ? new Date(payload.validFrom) : undefined,
      validTo: payload.validTo ? new Date(payload.validTo) : undefined,
      tiersJson: [],
      metaJson: payload.metaJson ?? {},
    });

    const saved = await this.priceRowRepository.save(row);
    await this.cache.delByPrefix('price:resolve:');
    await this.clearProductCaches(product.id);
    return {
      ...saved,
      unitPrice: this.fromMinorUnits(saved.unitAmount, precision),
      compareAtPrice: saved.compareAtAmount ? this.fromMinorUnits(saved.compareAtAmount, precision) : undefined,
    };
  }

  async addSkuPrice(productId: string, skuId: string, payload: CreateProductPriceDto) {
    const sku = await this.skuRepository.findOne({ where: { id: skuId } });
    if (!sku) throw new NotFoundException('Product SKU not found');
    if (sku.productId !== productId) {
      throw new BadRequestException('SKU does not belong to product');
    }

    const list = await this.priceListRepository.findOne({ where: { id: payload.priceListId } });
    if (!list) throw new NotFoundException('Price list not found');

    const currency = await this.currencyRepository.findOne({ where: { code: list.currency } });
    const precision = currency?.precision ?? 2;

    const conditions = (payload.metaJson as any)?.conditions ?? {};

    const row = this.priceRowRepository.create({
      priceListId: list.id,
      targetType: 'SKU',
      targetId: sku.id,
      selectorJson: conditions,
      currencyCode: undefined,
      unitAmount: this.toMinorUnits(payload.unitPrice, precision),
      compareAtAmount: payload.compareAtPrice !== undefined ? this.toMinorUnits(payload.compareAtPrice, precision) : undefined,
      minQuantity: payload.minQuantity ?? 1,
      maxQuantity: payload.maxQuantity,
      validFrom: payload.validFrom ? new Date(payload.validFrom) : undefined,
      validTo: payload.validTo ? new Date(payload.validTo) : undefined,
      tiersJson: [],
      metaJson: payload.metaJson ?? {},
    });

    const saved = await this.priceRowRepository.save(row);
    await this.cache.delByPrefix('price:resolve:');
    await this.clearProductCaches(sku.productId);
    return {
      ...saved,
      unitPrice: this.fromMinorUnits(saved.unitAmount, precision),
      compareAtPrice: saved.compareAtAmount ? this.fromMinorUnits(saved.compareAtAmount, precision) : undefined,
    };
  }

  async listProductPrices(productId: string) {
    const product = await this.findOneEntityOrThrow(productId);
    const rows = await this.priceRowRepository.find({
      where: { targetType: 'PRODUCT' as any, targetId: product.id },
      order: { createdAt: 'DESC' },
    });

    const priceListIds = Array.from(new Set(rows.map((r) => r.priceListId)));
    const lists = priceListIds.length ? await this.priceListRepository.find({ where: { id: In(priceListIds) } }) : [];
    const listById = new Map(lists.map((l) => [l.id, l] as const));
    const currencyCodes = Array.from(new Set(lists.map((l) => l.currency)));
    const currencies = currencyCodes.length ? await this.currencyRepository.find({ where: { code: In(currencyCodes) } }) : [];
    const precisionByCode = new Map(currencies.map((c) => [c.code, c.precision] as const));

    return rows.map((r) => {
      const list = listById.get(r.priceListId);
      const precision = precisionByCode.get(list?.currency ?? '') ?? 2;
      return {
        ...r,
        unitPrice: this.fromMinorUnits(r.unitAmount, precision),
        compareAtPrice: r.compareAtAmount ? this.fromMinorUnits(r.compareAtAmount, precision) : undefined,
      };
    });
  }

  async listSkuPrices(productId: string, skuId: string) {
    const sku = await this.skuRepository.findOne({ where: { id: skuId } });
    if (!sku) throw new NotFoundException('Product SKU not found');
    if (sku.productId !== productId) {
      throw new BadRequestException('SKU does not belong to product');
    }
    const rows = await this.priceRowRepository.find({
      where: { targetType: 'SKU' as any, targetId: sku.id },
      order: { createdAt: 'DESC' },
    });

    const priceListIds = Array.from(new Set(rows.map((r) => r.priceListId)));
    const lists = priceListIds.length ? await this.priceListRepository.find({ where: { id: In(priceListIds) } }) : [];
    const listById = new Map(lists.map((l) => [l.id, l] as const));
    const currencyCodes = Array.from(new Set(lists.map((l) => l.currency)));
    const currencies = currencyCodes.length ? await this.currencyRepository.find({ where: { code: In(currencyCodes) } }) : [];
    const precisionByCode = new Map(currencies.map((c) => [c.code, c.precision] as const));

    return rows.map((r) => {
      const list = listById.get(r.priceListId);
      const precision = precisionByCode.get(list?.currency ?? '') ?? 2;
      return {
        ...r,
        unitPrice: this.fromMinorUnits(r.unitAmount, precision),
        compareAtPrice: r.compareAtAmount ? this.fromMinorUnits(r.compareAtAmount, precision) : undefined,
      };
    });
  }

  private async findOneEntityOrThrow(id: string): Promise<Product> {
    const product = await this.productRepository.findOne({ where: { id } });
    if (!product) throw new NotFoundException('Product not found');
    return product;
  }

  private async persistTranslations(
    productId: string,
    payload: CreateProductDto | UpdateProductDto,
    fallbackTitle: string,
    fallbackDescription?: string,
    manager?: EntityManager,
  ) {
    const { translationRepository } = this.getRepos(manager);
    const translations = payload.translations?.length
      ? payload.translations
      : [
          {
            locale: 'en',
            title: fallbackTitle,
            description: fallbackDescription,
            metaJson: {},
          },
        ];

    await translationRepository.save(
      translations.map((t) =>
        translationRepository.create({
          productId,
          locale: t.locale,
          title: t.title,
          description: t.description,
          metaJson: t.metaJson ?? {},
        }),
      ),
    );
  }

  private async persistSkus(
    productId: string,
    slug: string,
    skus?: CreateProductSkuDto[],
    optionDefinitions?: Array<{ key: string; allowedValues?: string[]; required?: boolean }>,
    manager?: EntityManager,
  ): Promise<{ skus: ProductSku[]; inputs: CreateProductSkuDto[] }> {
    const { skuRepository } = this.getRepos(manager);
    const normalized: CreateProductSkuDto[] = skus?.length
      ? skus
      : [
          {
            title: 'Default',
            isDefault: true,
          },
        ];

    const defs = (optionDefinitions ?? []).filter((d) => d && typeof d.key === 'string' && d.key.trim().length > 0);
    const allowedKeys = new Set(defs.map((d) => d.key));
    const requiredKeys = new Set(defs.filter((d) => d.required).map((d) => d.key));
    const allowedValuesByKey = new Map(defs.map((d) => [d.key, (d.allowedValues ?? []).map((v) => String(v))] as const));

    const validateOptions = (options: Record<string, unknown>) => {
      if (!defs.length) return;

      for (const key of Object.keys(options ?? {})) {
        if (!allowedKeys.has(key)) {
          throw new BadRequestException(`Invalid option key: ${key}`);
        }
      }

      for (const requiredKey of requiredKeys) {
        if (options?.[requiredKey] === undefined || options?.[requiredKey] === null || options?.[requiredKey] === '') {
          throw new BadRequestException(`Missing required option: ${requiredKey}`);
        }
      }

      for (const [key, allowed] of allowedValuesByKey.entries()) {
        if (!allowed.length) continue;
        if (options?.[key] === undefined || options?.[key] === null) continue;
        const v = String(options[key]);
        if (!allowed.includes(v)) {
          throw new BadRequestException(`Invalid value for option '${key}': ${v}`);
        }
      }
    };

    const skuEntities: ProductSku[] = [];
    for (const [index, v] of normalized.entries()) {
      const sku = v.sku?.trim() || (await this.generateSku(slug, index, manager));

      const options = (v.options ?? v.attributes ?? {}) as Record<string, unknown>;
      validateOptions(options);

      skuEntities.push(
        skuRepository.create({
          productId,
          title: v.title,
          sku,
          externalRef: v.externalRef,
          status: v.status ?? 'active',
          isDefault: v.isDefault ?? index === 0,
          position: v.position ?? index,
          attributesJson: options,
          imagesJson: this.normalizeImages(v.images),
          inventoryJson: (v.inventory ?? {}) as any,
          requiresShipping: v.requiresShipping ?? true,
          weight: v.weight !== undefined ? v.weight.toString() : undefined,
          length: v.length !== undefined ? v.length.toString() : undefined,
          width: v.width !== undefined ? v.width.toString() : undefined,
          height: v.height !== undefined ? v.height.toString() : undefined,
          dimensionUnit: v.dimensionUnit ?? 'cm',
          weightUnit: v.weightUnit ?? 'kg',
          metaJson: v.metaJson ?? {},
        }),
      );
    }

    const saved = await skuRepository.save(skuEntities);
    return { skus: saved, inputs: normalized };
  }

  private async persistPrices(
    productId: string,
    prices: CreateProductPriceDto[] | undefined,
    skus: ProductSku[],
    skuInputs: CreateProductSkuDto[] | undefined,
    manager?: EntityManager,
  ) {
    const { priceListRepository, currencyRepository, priceRowRepository } = this.getRepos(manager);
    const rows: PriceRow[] = [];

    const allPriceListIds = new Set<string>();
    for (const p of prices ?? []) allPriceListIds.add(p.priceListId);
    for (const skuInput of skuInputs ?? []) for (const p of skuInput?.prices ?? []) allPriceListIds.add(p.priceListId);

    const lists = allPriceListIds.size
      ? await priceListRepository.find({ where: { id: In(Array.from(allPriceListIds)) } })
      : [];
    const listById = new Map(lists.map((l) => [l.id, l] as const));

    const currencyCodes = Array.from(new Set(lists.map((l) => l.currency)));
    const currencies = currencyCodes.length
      ? await currencyRepository.find({ where: { code: In(currencyCodes) } })
      : [];
    const precisionByCode = new Map(currencies.map((c) => [c.code, c.precision] as const));

    const getPrecisionForList = (priceListId: string) => {
      const list = listById.get(priceListId);
      if (!list) throw new NotFoundException('Price list not found');
      return precisionByCode.get(list.currency) ?? 2;
    };

    if (prices?.length) {
      for (const p of prices) {
        const precision = getPrecisionForList(p.priceListId);
        const conditions = (p.metaJson as any)?.conditions ?? {};
        rows.push(
          priceRowRepository.create({
            priceListId: p.priceListId,
            targetType: 'PRODUCT',
            targetId: productId,
            selectorJson: conditions,
            currencyCode: undefined,
            unitAmount: this.toMinorUnits(p.unitPrice, precision),
            compareAtAmount: p.compareAtPrice !== undefined ? this.toMinorUnits(p.compareAtPrice, precision) : undefined,
            minQuantity: p.minQuantity ?? 1,
            maxQuantity: p.maxQuantity,
            validFrom: p.validFrom ? new Date(p.validFrom) : undefined,
            validTo: p.validTo ? new Date(p.validTo) : undefined,
            tiersJson: [],
            metaJson: p.metaJson ?? {},
          }),
        );
      }
    }

    for (const [index, sku] of (skus ?? []).entries()) {
      const skuInput = skuInputs?.[index];
      const inputPrices = skuInput?.prices ?? [];
      for (const p of inputPrices) {
        const precision = getPrecisionForList(p.priceListId);
        const conditions = (p.metaJson as any)?.conditions ?? {};
        rows.push(
          priceRowRepository.create({
            priceListId: p.priceListId,
            targetType: 'SKU',
            targetId: sku.id,
            selectorJson: conditions,
            currencyCode: undefined,
            unitAmount: this.toMinorUnits(p.unitPrice, precision),
            compareAtAmount: p.compareAtPrice !== undefined ? this.toMinorUnits(p.compareAtPrice, precision) : undefined,
            minQuantity: p.minQuantity ?? 1,
            maxQuantity: p.maxQuantity,
            validFrom: p.validFrom ? new Date(p.validFrom) : undefined,
            validTo: p.validTo ? new Date(p.validTo) : undefined,
            tiersJson: [],
            metaJson: p.metaJson ?? {},
          }),
        );
      }
    }

    if (rows.length) {
      await priceRowRepository.save(rows);
      await this.cache.delByPrefix('price:resolve:');
    }
  }

  private normalizeAvailability(input?: ProductAvailabilityDto): AvailabilityNormalized {
    const normalizeList = (values?: string[], upper?: boolean) =>
      Array.from(
        new Set(
          (values ?? [])
            .map((v) => String(v ?? '').trim())
            .filter(Boolean)
            .map((v) => (upper ? v.toUpperCase() : v.toLowerCase())),
        ),
      );

    return {
      channels: normalizeList(input?.channels, true),
      countries: normalizeList(input?.countries, true),
      locations: normalizeList(input?.locations, false),
      stock: {
        type: input?.stock?.type ?? 'FINITE',
        quantity: input?.stock?.quantity,
      },
      schedule: {
        startAt: input?.schedule?.startAt,
        endAt: input?.schedule?.endAt,
        timezone: input?.schedule?.timezone ?? 'UTC',
      },
      meta: input?.meta ?? {},
    };
  }

  private normalizeImages(images?: string[]): string[] {
    return (images ?? []).map((i) => String(i ?? '').trim()).filter(Boolean);
  }

  private async ensureUniqueSlug(baseSlug: string, excludeId?: string, manager?: EntityManager): Promise<string> {
    const { productRepository } = this.getRepos(manager);
    const slugCandidate = this.slugify(baseSlug);
    let slug = slugCandidate;
    let suffix = 1;

    while (
      await productRepository.exist({
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

  private async generateSku(slug: string, index: number, manager?: EntityManager): Promise<string> {
    const { skuRepository } = this.getRepos(manager);
    const base = slug.toUpperCase().replace(/[^A-Z0-9]+/g, '-');
    const suffix = randomBytes(2).toString('hex').toUpperCase();
    const candidate = `${base}-${String(index + 1).padStart(2, '0')}-${suffix}`;

    const exists = await skuRepository.exist({ where: { sku: candidate } });
    if (!exists) return candidate;
    return `${candidate}-${randomBytes(1).toString('hex').toUpperCase()}`;
  }

  private async attachCategories(productId: string, categoryIds: string[], manager?: EntityManager) {
    const { productCategoryRepository } = this.getRepos(manager);
    const categories = categoryIds.map((categoryId, index) =>
      productCategoryRepository.create({
        productId,
        categoryId,
        isPrimary: index === 0,
        sortOrder: index,
      }),
    );
    await productCategoryRepository.save(categories);
  }

  private async syncChannels(productId: string, channelCodes: string[], manager?: EntityManager): Promise<void> {
    const { productChannelRepository, channelRepository } = this.getRepos(manager);
    const normalized = Array.from(new Set((channelCodes ?? []).map((c) => c.toUpperCase())));
    await productChannelRepository.delete({ productId } as any);

    if (!normalized.length) return;

    const channels = await channelRepository.find({ where: { code: In(normalized), isActive: true } as any });
    const foundCodes = new Set(channels.map((c) => c.code.toUpperCase()));

    const missing = normalized.filter((code) => !foundCodes.has(code));
    if (missing.length) {
      throw new BadRequestException(`Unknown or inactive channel(s): ${missing.join(', ')}`);
    }

    await productChannelRepository.insert(
      channels.map((c) => ({ productId, channelId: c.id, isActive: true })) as any,
    );
  }

  private async clearProductCaches(productId: string) {
    await this.cache.delByPrefix('catalog:products:list:');
    await this.cache.del(`catalog:products:${productId}`);
    await this.cache.delByPrefix('public:catalog:products:list:');
    await this.cache.delByPrefix('public:catalog:products:');
    await this.cache.delByPrefix('public:catalog:products:view:');
    await this.cache.delByPrefix('price:resolve:');
    await this.shippingCatalogContextCacheIndex.invalidateByProductIds([productId]);
  }

  private pickTranslation(
    translations: ProductTranslation[] | undefined,
    locale?: string,
  ): ProductTranslation | undefined {
    const preferred = (locale || 'en').toLowerCase();
    const rows = translations ?? [];
    return (
      rows.find((t) => t.locale?.toLowerCase() === preferred) ??
      rows.find((t) => t.locale?.toLowerCase().startsWith(preferred)) ??
      rows.find((t) => t.locale?.toLowerCase() === 'en') ??
      rows[0]
    );
  }

  private categoryToPublicDto(category: Category, locale?: string): PublicProductCategoryRefDto {
    const translations = category.translations ?? [];
    const preferred = (locale || 'en').toLowerCase();
    const t =
      translations.find((x) => x.locale?.toLowerCase() === preferred) ??
      translations.find((x) => x.locale?.toLowerCase().startsWith(preferred)) ??
      translations.find((x) => x.locale?.toLowerCase() === 'en') ??
      translations[0];

    return {
      id: category.id,
      taxonomyId: category.taxonomyId,
      parentId: category.parentId,
      key: category.key,
      slug: category.slug,
      name: t?.name ?? category.key,
    };
  }

  private async resolvePriceForSku(
    productId: string,
    sku?: ProductSku,
    opts?: { priceListId?: string; currencyCode?: string },
  ): Promise<PublicProductPriceDto | undefined> {
    if (!sku && !productId) return undefined;

    try {
      const resolved = await this.priceService.resolveSkuPrice({
        productSkuId: sku?.id,
        productId,
        priceListId: opts?.priceListId,
        currencyCode: opts?.currencyCode,
        quantity: 1,
      });

      return {
        priceListId: resolved.priceListId,
        currencyCode: resolved.currencyCode,
        unitPrice: resolved.unitPrice,
        compareAtPrice: resolved.compareAtPrice,
      };
    } catch {
      return undefined;
    }
  }

  private buildViewContext(input: {
    channel?: string;
    customerTier?: string;
    location?: string;
    role?: string;
  }): ProductViewContext {
    const context: ProductViewContext = {};
    if (input.channel) context.channel = input.channel.toUpperCase();
    if (input.customerTier) context.customerTier = input.customerTier;
    if (input.location) context.location = input.location;
    if (input.role) context.role = input.role;
    return context;
  }

  private normalizeStringArray(input: unknown): string[] | undefined {
    if (!Array.isArray(input)) return undefined;
    const values = input.map((v) => String(v ?? '').trim()).filter(Boolean);
    if (!values.length) return undefined;
    return Array.from(new Set(values));
  }

  private buildLocalizedString(
    translations: ProductTranslation[] | undefined,
    field: 'title' | 'description',
    fallback?: string,
  ): LocalizedString {
    const localized: LocalizedString = {};
    for (const t of translations ?? []) {
      const value = field === 'title' ? t.title : t.description;
      if (value) localized[t.locale] = value;
    }
    if (!Object.keys(localized).length && fallback) {
      localized.en = fallback;
    }
    return localized;
  }

  private toContextualOverrideDto(override: ProductContextOverride): ContextualOverrideDTO {
    return {
      id: override.id,
      priority: override.priority,
      isActive: override.isActive,
      validFrom: override.validFrom?.toISOString(),
      validUntil: override.validUntil?.toISOString(),
      match: override.matchContext as any,
      rule: override.rule as any,
      patch: (override.patch ?? []) as any,
      description: override.description,
    };
  }

  private async loadContextOverridesByProductIds(
    productIds: string[],
  ): Promise<Map<string, ContextualOverrideDTO[]>> {
    const ids = Array.from(new Set(productIds.filter(Boolean)));
    const byProduct = new Map<string, ContextualOverrideDTO[]>();
    if (!ids.length) return byProduct;

    const overrides = await this.productContextOverrideRepository.find({
      where: { productId: In(ids) },
    });

    for (const override of overrides) {
      const dto = this.toContextualOverrideDto(override);
      const existing = byProduct.get(override.productId);
      if (existing) {
        existing.push(dto);
      } else {
        byProduct.set(override.productId, [dto]);
      }
    }

    return byProduct;
  }

  private categoryToPublicCategoryDto(category: Category, locale?: string): PublicCategoryDto {
    const translations = category.translations ?? [];
    const preferred = (locale || 'en').toLowerCase();
    const t =
      translations.find((x) => x.locale?.toLowerCase() === preferred) ??
      translations.find((x) => x.locale?.toLowerCase().startsWith(preferred)) ??
      translations.find((x) => x.locale?.toLowerCase() === 'en') ??
      translations[0];

    return {
      id: category.id,
      taxonomyId: category.taxonomyId,
      parentId: category.parentId,
      key: category.key,
      slug: category.slug,
      name: t?.name ?? category.key,
      description: t?.description,
      icon: category.icon,
      imageUrl: category.imageUrl,
      sortOrder: category.sortOrder,
      isLeaf: category.isLeaf,
    };
  }

  private buildAvailabilityDto(availability: Record<string, unknown> | undefined): AvailabilityDTO {
    const raw = (availability ?? {}) as Record<string, unknown>;
    const channels = (this.normalizeStringArray(raw.channels) ?? ['WEB']).map((c) => c.toUpperCase());
    const countries = this.normalizeStringArray(raw.countries)?.map((c) => c.toUpperCase());
    const locations = this.normalizeStringArray(raw.locations);

    const stock = raw.stock && typeof raw.stock === 'object'
      ? {
          type: String((raw.stock as any).type ?? 'FINITE'),
          quantity: (raw.stock as any).quantity,
        }
      : undefined;

    const scheduleInput = raw.schedule && typeof raw.schedule === 'object' ? (raw.schedule as any) : undefined;
    let schedule: { timezone: string; windows: Array<{ from: string; to: string }> } | undefined;
    if (scheduleInput) {
      const windows: Array<{ from: string; to: string }> = [];
      if (Array.isArray(scheduleInput.windows)) {
        for (const window of scheduleInput.windows) {
          if (!window) continue;
          const from = String(window.from ?? '').trim();
          const to = String(window.to ?? '').trim();
          if (from && to) windows.push({ from, to });
        }
      } else if (scheduleInput.startAt || scheduleInput.endAt) {
        const from = scheduleInput.startAt ?? scheduleInput.endAt;
        const to = scheduleInput.endAt ?? scheduleInput.startAt;
        if (from && to) windows.push({ from, to });
      }

      if (windows.length) {
        schedule = {
          timezone: String(scheduleInput.timezone ?? 'UTC'),
          windows,
        };
      }
    }

    return {
      channels,
      countries,
      locations,
      stock,
      schedule,
      meta: raw.meta && typeof raw.meta === 'object' ? (raw.meta as Record<string, unknown>) : undefined,
    };
  }

  private async toProductDTO(
    product: Product,
    opts?: { locale?: string; priceListId?: string; currencyCode?: string },
  ): Promise<ProductDTO> {
    const translations = product.translations ?? [];
    const name = this.buildLocalizedString(translations, 'title', product.title);
    const descriptionMap = this.buildLocalizedString(translations, 'description', product.description);
    const description = Object.keys(descriptionMap).length ? descriptionMap : undefined;

    const categories = (product.productCategories ?? [])
      .map((pc) => pc.category)
      .filter((c): c is Category => Boolean(c))
      .map((c) => this.categoryToPublicCategoryDto(c, opts?.locale));

    const meta = (product.metaJson ?? {}) as Record<string, unknown>;
    const tags = this.normalizeStringArray(meta.tags);
    const collections = this.normalizeStringArray(meta.collections);
    const attributes =
      meta.attributes && typeof meta.attributes === 'object' ? (meta.attributes as Record<string, unknown>) : {};

    const schemaRefRaw = meta.attributeSchemaRef as Record<string, unknown> | undefined;
    const attributeSchemaRef = {
      schemaId: typeof schemaRefRaw?.schemaId === 'string' ? (schemaRefRaw.schemaId as string) : 'standard',
      schemaVersion: typeof schemaRefRaw?.schemaVersion === 'number' ? (schemaRefRaw.schemaVersion as number) : 1,
    };

    const type = typeof meta.type === 'string' ? (meta.type as string) : 'standard';

    const defaultSku = (product.skus ?? []).find((s) => s.isDefault) ?? (product.skus ?? [])[0];
    const resolvedPrice = await this.resolvePriceForSku(product.id, defaultSku, opts);
    const basePrice = resolvedPrice?.unitPrice ? Number(resolvedPrice.unitPrice) : undefined;
    const pricing = resolvedPrice
      ? ({ currency: resolvedPrice.currencyCode, pricingType: 'FIXED' as const, basePrice } as any)
      : ({ currency: opts?.currencyCode ?? 'USD', pricingType: 'DYNAMIC' as const } as any);

    const availability = this.buildAvailabilityDto(product.availabilityJson as Record<string, unknown>);

    const schedule = (product.availabilityJson as any)?.schedule ?? {};
    const validFrom = schedule?.startAt;
    const validUntil = schedule?.endAt;

    const skus = (product.skus ?? []).map((s) => ({
      id: s.id,
      code: s.sku ?? s.id,
      name: { en: s.title },
      attributes: (s.attributesJson ?? {}) as any,
    }));

    const media = (product.imagesJson ?? []).map((url) => ({
      type: 'IMAGE',
      url,
    }));

    return {
      id: product.id,
      code: product.externalRef ?? product.slug ?? product.id,
      slug: product.slug,
      type,
      categories,
      tags,
      collections,
      brand: product.brand
        ? {
            id: product.brand.id,
            name: product.brand.name,
            slug: product.brand.slug,
            description: product.brand.description,
            logoUrl: product.brand.logoUrl,
            websiteUrl: product.brand.websiteUrl,
          }
        : undefined,
      name,
      description,
      media,
      attributes: attributes as any,
      attributeSchemaRef,
      pricing,
      status: product.status,
      availability,
      validFrom,
      validUntil,
      skus,
    };
  }

  private async toProductView(
    product: Product,
    overrides: ContextualOverrideDTO[] | undefined,
    opts?: { locale?: string; priceListId?: string; currencyCode?: string; context?: ProductViewContext },
  ): Promise<ProductViewDTO> {
    const base = await this.toProductDTO(product, {
      locale: opts?.locale,
      priceListId: opts?.priceListId,
      currencyCode: opts?.currencyCode,
    });
    const { product: resolved, appliedOverrides } = applyContextualOverrides(
      base,
      overrides,
      opts?.context ?? {},
    );

    return {
      ...resolved,
      appliedOverrides,
    };
  }

  private async toPublicProduct(
    product: Product,
    opts?: { locale?: string; includeSkus?: boolean; priceListId?: string; currencyCode?: string },
  ): Promise<PublicProductDto> {
    const translation = this.pickTranslation(product.translations, opts?.locale);
    const title = translation?.title ?? product.title;
    const description = translation?.description ?? product.description;

    const categories = (product.productCategories ?? [])
      .map((pc) => pc.category)
      .filter((c): c is Category => Boolean(c))
      .map((c) => this.categoryToPublicDto(c, opts?.locale));

    const skus = opts?.includeSkus
      ? await Promise.all(
          (product.skus ?? []).map(async (s) => {
            const price = await this.resolvePriceForSku(product.id, s, opts);
            return {
              id: s.id,
              title: s.title,
              sku: s.sku,
              attributes: s.attributesJson,
              images: s.imagesJson,
              price,
            } as PublicProductSkuDto;
          }),
        )
      : [];

    const defaultSku = (product.skus ?? []).find((s) => s.isDefault) ?? (product.skus ?? [])[0];
    const price = await this.resolvePriceForSku(product.id, defaultSku, opts);

    return {
      id: product.id,
      slug: product.slug,
      title,
      description,
      status: product.status,
      externalRef: product.externalRef,
      brand: product.brand
        ? {
            id: product.brand.id,
            name: product.brand.name,
            slug: product.brand.slug,
            description: product.brand.description,
            logoUrl: product.brand.logoUrl,
            websiteUrl: product.brand.websiteUrl,
          }
        : undefined,
      availability: (product.availabilityJson ?? {}) as Record<string, unknown>,
      images: product.imagesJson ?? [],
      price,
      skus,
      categories,
      translations: (product.translations ?? []).map((t) => ({
        locale: t.locale,
        title: t.title,
        description: t.description,
      })) as PublicProductTranslationDto[],
    };
  }
}
