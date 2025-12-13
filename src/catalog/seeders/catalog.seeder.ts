import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Taxonomy } from '../entities/taxonomy.entity';
import { Category } from '../entities/category.entity';
import { Product } from '../entities/product.entity';
import { ProductVariant } from '../entities/product-variant.entity';
import { Currency } from '../entities/currency.entity';
import { PriceList } from '../entities/price-list.entity';
import { ProductVariantPrice } from '../entities/product-variant-price.entity';
import { ProductStatus } from '../dto/create-product.dto';
import { CategoryService } from '../services/category.service';
import { ProductService } from '../services/product.service';

@Injectable()
export class CatalogSeeder {
  private readonly logger = new Logger(CatalogSeeder.name);

  constructor(
    @InjectRepository(Taxonomy)
    private readonly taxonomyRepository: Repository<Taxonomy>,
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(ProductVariant)
    private readonly variantRepository: Repository<ProductVariant>,
    @InjectRepository(Currency)
    private readonly currencyRepository: Repository<Currency>,
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(ProductVariantPrice)
    private readonly variantPriceRepository: Repository<ProductVariantPrice>,
    private readonly categoryService: CategoryService,
    private readonly productService: ProductService,
  ) {}

  async seed() {
    const taxonomy = await this.ensureDefaultTaxonomy();
    const electronics = await this.ensureCategory(taxonomy.id, {
      key: 'electronics',
      slug: 'electronics',
      name: 'Electronics',
    });

    await this.ensureCategory(taxonomy.id, {
      key: 'phones',
      slug: 'phones',
      name: 'Phones',
      parentId: electronics.id,
    });

    await this.ensureSampleProduct(electronics.id);
    await this.ensureCurrencyAndPriceList();
  }

  private async ensureDefaultTaxonomy(): Promise<Taxonomy> {
    let taxonomy = await this.taxonomyRepository.findOne({ where: { code: 'default' } });

    if (!taxonomy) {
      taxonomy = this.taxonomyRepository.create({
        code: 'default',
        name: 'Default Catalog',
        description: 'Primary storefront taxonomy',
        isDefault: true,
      });
      taxonomy = await this.taxonomyRepository.save(taxonomy);
      this.logger.log('Created default taxonomy');
    }

    return taxonomy;
  }

  private async ensureCategory(
    taxonomyId: string,
    payload: { key: string; slug: string; name: string; parentId?: string },
  ): Promise<Category> {
    const existing = await this.categoryRepository.findOne({
      where: { taxonomyId, key: payload.key },
    });

    if (existing) {
      return existing;
    }

    const category = await this.categoryService.create({
      taxonomyId,
      parentId: payload.parentId,
      key: payload.key,
      slug: payload.slug,
      translations: [
        {
          locale: 'en',
          name: payload.name,
        },
      ],
    });
    this.logger.log(`Created category ${payload.key}`);
    return category;
  }

  private async ensureSampleProduct(categoryId: string): Promise<void> {
    const existing = await this.productRepository.findOne({
      where: { handle: 'sample-phone' },
    });

    if (existing) {
      return;
    }

    await this.productService.create({
      handle: 'sample-phone',
      status: ProductStatus.ACTIVE,
      isFeatured: true,
      translations: [
        {
          locale: 'en',
          name: 'Sample Phone',
          shortDescription: 'Reference device listing',
        },
      ],
      variants: [
        {
          sku: 'PHONE-001',
          title: 'Sample Phone Default',
          isDefault: true,
          requiresShipping: true,
        },
      ],
      categoryIds: [categoryId],
    });
    this.logger.log('Created sample product sample-phone');
  }

  private async ensureCurrencyAndPriceList(): Promise<void> {
    // Ensure KES exists
    let kes = await this.currencyRepository.findOne({ where: { code: 'KES' } });
    if (!kes) {
      kes = this.currencyRepository.create({ code: 'KES', precision: 2, symbol: 'KES' });
      kes = await this.currencyRepository.save(kes);
      this.logger.log('Created currency KES');
    }

    // Ensure price list exists
    let priceList = await this.priceListRepository.findOne({ where: { code: 'retail-kes' } });
    if (!priceList) {
      priceList = this.priceListRepository.create({ code: 'retail-kes', name: 'Retail (KES)', currencyCode: 'KES' });
      priceList = await this.priceListRepository.save(priceList);
      this.logger.log('Created price list retail-kes');
    }

    // Ensure variant price for sample variant exists
    const variant = await this.variantRepository.findOne({ where: { sku: 'PHONE-001' } });
    if (variant) {
      const existing = await this.variantPriceRepository.findOne({ where: { priceListId: priceList.id, productVariantId: variant.id } });
      if (!existing) {
        const vp = this.variantPriceRepository.create({
          priceListId: priceList.id,
          productVariantId: variant.id,
          unitPrice: '200.00',
          compareAtPrice: '0',
          minQuantity: 1,
          metaJson: {},
        });
        await this.variantPriceRepository.save(vp);
        this.logger.log('Created sample variant price for PHONE-001');
      }
    }
  }
}
