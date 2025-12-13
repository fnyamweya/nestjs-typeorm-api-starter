import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Product } from '../entities/product.entity';
import { ProductTranslation } from '../entities/product-translation.entity';
import { ProductVariant } from '../entities/product-variant.entity';
import { ProductCategory } from '../entities/product-category.entity';
import {
  CreateProductDto,
  FulfillmentClass,
  InventoryStrategy,
  ProductStatus,
  ProductType,
} from '../dto/create-product.dto';
import { UpdateProductDto } from '../dto/update-product.dto';
import { FilterProductDto } from '../dto/filter-product.dto';

interface PaginatedProducts {
  data: Product[];
  total: number;
  page: number;
  limit: number;
}

@Injectable()
export class ProductService {
  constructor(
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(ProductTranslation)
    private readonly translationRepository: Repository<ProductTranslation>,
    @InjectRepository(ProductVariant)
    private readonly variantRepository: Repository<ProductVariant>,
    @InjectRepository(ProductCategory)
    private readonly productCategoryRepository: Repository<ProductCategory>,
  ) {}

  async create(payload: CreateProductDto): Promise<Product> {
    const product = this.productRepository.create({
      handle: payload.handle,
      type: payload.type ?? ProductType.STANDARD,
      status: payload.status ?? ProductStatus.DRAFT,
      brandId: payload.brandId,
      isFeatured: payload.isFeatured ?? false,
      taxClassCode: payload.taxClassCode,
      fulfillmentClass: payload.fulfillmentClass ?? FulfillmentClass.PHYSICAL,
      countryOfOrigin: payload.countryOfOrigin,
      hsCode: payload.hsCode,
      inventoryStrategy: payload.inventoryStrategy ?? InventoryStrategy.VARIANT,
      requiresShipping: payload.requiresShipping ?? true,
      publishedAt: payload.publishedAt ? new Date(payload.publishedAt) : undefined,
      metaJson: payload.metaJson ?? {},
    });

    const saved = await this.productRepository.save(product as Product);

    if (payload.translations?.length) {
      await this.translationRepository.save(
        payload.translations.map((t) =>
          this.translationRepository.create({ ...t, productId: saved.id }),
        ),
      );
    }

    if (payload.variants?.length) {
      const variants = payload.variants.map((v, index) =>
        this.variantRepository.create({
          productId: saved.id,
          sku: v.sku,
          barcode: v.barcode,
          externalId: v.externalId,
          title: v.title,
          isDefault: v.isDefault ?? index === 0,
          position: v.position ?? index,
          requiresShipping: v.requiresShipping ?? true,
          weight: v.weight !== undefined ? v.weight.toString() : undefined,
          length: v.length !== undefined ? v.length.toString() : undefined,
          width: v.width !== undefined ? v.width.toString() : undefined,
          height: v.height !== undefined ? v.height.toString() : undefined,
          dimensionUnit: v.dimensionUnit ?? 'cm',
          weightUnit: v.weightUnit ?? 'kg',
          allowBackorder: v.allowBackorder ?? false,
          preorderAvailable: v.preorderAvailable ?? false,
          preorderFrom: v.preorderFrom ? new Date(v.preorderFrom) : undefined,
          preorderTo: v.preorderTo ? new Date(v.preorderTo) : undefined,
          taxClassOverride: v.taxClassOverride,
          fulfillmentClassOverride: v.fulfillmentClassOverride,
          metaJson: v.metaJson ?? {},
        }),
      );
      const savedVariants = await this.variantRepository.save(variants);
      const defaultVariant =
        savedVariants.find((v) => v.isDefault) ?? savedVariants[0];
      if (defaultVariant) {
        saved.defaultVariantId = defaultVariant.id;
        await this.productRepository.save(saved as Product);
      }
    }

    if (payload.categoryIds?.length) {
      await this.attachCategories(saved.id, payload.categoryIds);
    }

    return this.findOne(saved.id);
  }

  async findAll(filters: FilterProductDto): Promise<PaginatedProducts> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;
    const qb = this.productRepository
      .createQueryBuilder('product')
      .leftJoinAndSelect('product.translations', 'translations')
      .skip((page - 1) * limit)
      .take(limit)
      .orderBy('product.created_at', 'DESC');

    if (filters.status) {
      qb.andWhere('product.status = :status', { status: filters.status });
    }

    if (filters.type) {
      qb.andWhere('product.type = :type', { type: filters.type });
    }

    if (filters.isFeatured !== undefined) {
      qb.andWhere('product.is_featured = :featured', {
        featured: filters.isFeatured,
      });
    }

    if (filters.search) {
      qb.andWhere('product.handle ILIKE :search', {
        search: `%${filters.search}%`,
      });
    }

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(id: string): Promise<Product> {
    const product = await this.productRepository.findOne({
      where: { id },
      relations: ['translations', 'variants', 'productCategories'],
    });

    if (!product) {
      throw new NotFoundException('Product not found');
    }

    return product;
  }

  async update(id: string, payload: UpdateProductDto): Promise<Product> {
    const product = await this.findOne(id);

    Object.assign(product, {
      handle: payload.handle ?? product.handle,
      type: payload.type ?? product.type,
      status: payload.status ?? product.status,
      brandId: payload.brandId ?? product.brandId,
      isFeatured: payload.isFeatured ?? product.isFeatured,
      taxClassCode: payload.taxClassCode ?? product.taxClassCode,
      fulfillmentClass: payload.fulfillmentClass ?? product.fulfillmentClass,
      countryOfOrigin: payload.countryOfOrigin ?? product.countryOfOrigin,
      hsCode: payload.hsCode ?? product.hsCode,
      inventoryStrategy: payload.inventoryStrategy ?? product.inventoryStrategy,
      requiresShipping: payload.requiresShipping ?? product.requiresShipping,
      publishedAt: payload.publishedAt
        ? new Date(payload.publishedAt)
        : product.publishedAt,
      metaJson: payload.metaJson ?? product.metaJson,
    });

    const saved = await this.productRepository.save(product as Product);

    if (payload.translations) {
      await this.translationRepository.delete({ productId: saved.id });
      await this.translationRepository.save(
        payload.translations.map((t) =>
          this.translationRepository.create({ ...t, productId: saved.id }),
        ),
      );
    }

    if (payload.variants) {
      await this.variantRepository.delete({ productId: saved.id });
      if (payload.variants.length) {
        const variants = payload.variants.map((v, index) =>
          this.variantRepository.create({
            productId: saved.id,
            sku: v.sku,
            barcode: v.barcode,
            externalId: v.externalId,
            title: v.title,
            isDefault: v.isDefault ?? index === 0,
            position: v.position ?? index,
            requiresShipping: v.requiresShipping ?? true,
            weight: v.weight !== undefined ? v.weight.toString() : undefined,
            length: v.length !== undefined ? v.length.toString() : undefined,
            width: v.width !== undefined ? v.width.toString() : undefined,
            height: v.height !== undefined ? v.height.toString() : undefined,
            dimensionUnit: v.dimensionUnit ?? 'cm',
            weightUnit: v.weightUnit ?? 'kg',
            allowBackorder: v.allowBackorder ?? false,
            preorderAvailable: v.preorderAvailable ?? false,
            preorderFrom: v.preorderFrom ? new Date(v.preorderFrom) : undefined,
            preorderTo: v.preorderTo ? new Date(v.preorderTo) : undefined,
            taxClassOverride: v.taxClassOverride,
            fulfillmentClassOverride: v.fulfillmentClassOverride,
            metaJson: v.metaJson ?? {},
          }),
        );
        const savedVariants = await this.variantRepository.save(variants);
        const defaultVariant =
          savedVariants.find((v) => v.isDefault) ?? savedVariants[0];
        saved.defaultVariantId = defaultVariant?.id;
        await this.productRepository.save(saved as Product);
      } else {
        saved.defaultVariantId = undefined;
        await this.productRepository.save(saved as Product);
      }
    }

    if (payload.categoryIds) {
      await this.productCategoryRepository.delete({ productId: saved.id });
      if (payload.categoryIds.length) {
        await this.attachCategories(saved.id, payload.categoryIds);
      }
    }

    return this.findOne(saved.id);
  }

  async remove(id: string): Promise<void> {
    const product = await this.findOne(id);
    await this.productRepository.remove(product);
  }

  private async attachCategories(productId: string, categoryIds: string[]) {
    const categories = categoryIds.map((categoryId, index) =>
      this.productCategoryRepository.create({
        productId,
        categoryId,
        isPrimary: index === 0,
        sortOrder: index,
      }),
    );
    await this.productCategoryRepository.save(categories);
  }
}
