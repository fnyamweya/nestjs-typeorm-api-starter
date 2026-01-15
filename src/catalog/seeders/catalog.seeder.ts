import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Taxonomy } from '../entities/taxonomy.entity';
import { Category } from '../entities/category.entity';
import { Product } from '../entities/product.entity';
import { ProductSku } from '../entities/product-sku.entity';
import { Currency } from '../entities/currency.entity';
import { PriceList } from '../entities/price-list.entity';
import { PriceRow } from '../entities/price-row.entity';
import { ProductStatus } from '../dto/create-product.dto';
import { CategoryService } from '../services/category.service';
import { ProductService } from '../services/product.service';
import { Brand } from '../entities/brand.entity';

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
    @InjectRepository(ProductSku)
    private readonly skuRepository: Repository<ProductSku>,
    @InjectRepository(Currency)
    private readonly currencyRepository: Repository<Currency>,
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(PriceRow)
    private readonly priceRowRepository: Repository<PriceRow>,
    @InjectRepository(Brand)
    private readonly brandRepository: Repository<Brand>,
    private readonly categoryService: CategoryService,
    private readonly productService: ProductService,
  ) {}

  async seed() {
    await this.resetCatalogData();

    const priceList = await this.ensureCurrencyAndPriceList();
    const [nova, acme] = await this.seedBrands();

    const taxonomy = await this.ensureDefaultTaxonomy();
    const categories = await this.seedCategories(taxonomy.id);

    await this.seedProducts({
      priceList,
      brands: { nova, acme },
      categories,
    });
  }

  private async resetCatalogData(): Promise<void> {
    await this.priceRowRepository
      .createQueryBuilder()
      .delete()
      .from(PriceRow)
      .execute();
    await this.skuRepository
      .createQueryBuilder()
      .delete()
      .from(ProductSku)
      .execute();
    await this.productRepository
      .createQueryBuilder()
      .delete()
      .from(Product)
      .execute();
    await this.categoryRepository
      .createQueryBuilder()
      .delete()
      .from(Category)
      .execute();
    await this.taxonomyRepository
      .createQueryBuilder()
      .delete()
      .from(Taxonomy)
      .execute();
    await this.brandRepository
      .createQueryBuilder()
      .delete()
      .from(Brand)
      .execute();
  }

  private async ensureDefaultTaxonomy(): Promise<Taxonomy> {
    const taxonomy = this.taxonomyRepository.create({
      code: 'default',
      name: 'Default Catalog',
      description: 'Primary storefront taxonomy',
      isDefault: true,
    });
    const saved = await this.taxonomyRepository.save(taxonomy);
    this.logger.log('Created default taxonomy');
    return saved;
  }

  private async seedBrands(): Promise<[Brand, Brand]> {
    const nova = await this.brandRepository.save(
      this.brandRepository.create({
        name: 'Nova',
        slug: 'nova',
        description: 'Premium electronics and devices',
        logoUrl: 'https://cdn.example.com/brands/nova.png',
        websiteUrl: 'https://example.com/nova',
        isActive: true,
        metaJson: { tier: 'premium' },
      }),
    );

    const acme = await this.brandRepository.save(
      this.brandRepository.create({
        name: 'Acme',
        slug: 'acme',
        description: 'Everyday accessories and essentials',
        logoUrl: 'https://cdn.example.com/brands/acme.png',
        websiteUrl: 'https://example.com/acme',
        isActive: true,
        metaJson: { tier: 'value' },
      }),
    );

    this.logger.log('Seeded brands Nova and Acme');
    return [nova, acme];
  }

  private async seedCategories(taxonomyId: string): Promise<{
    electronics: Category;
    phones: Category;
    accessories: Category;
    home: Category;
    lighting: Category;
  }> {
    const electronics = await this.categoryService.create({
      taxonomyId,
      key: 'electronics',
      slug: 'electronics',
      translations: [{ locale: 'en', name: 'Electronics' }],
    });

    const phones = await this.categoryService.create({
      taxonomyId,
      parentId: electronics.id,
      key: 'phones',
      slug: 'phones',
      translations: [{ locale: 'en', name: 'Phones' }],
    });

    const accessories = await this.categoryService.create({
      taxonomyId,
      parentId: electronics.id,
      key: 'accessories',
      slug: 'accessories',
      translations: [{ locale: 'en', name: 'Accessories' }],
    });

    const home = await this.categoryService.create({
      taxonomyId,
      key: 'home',
      slug: 'home',
      translations: [{ locale: 'en', name: 'Home' }],
    });

    const lighting = await this.categoryService.create({
      taxonomyId,
      parentId: home.id,
      key: 'lighting',
      slug: 'lighting',
      translations: [{ locale: 'en', name: 'Lighting' }],
    });

    this.logger.log('Seeded categories');
    return { electronics, phones, accessories, home, lighting };
  }

  private async ensureCurrencyAndPriceList(): Promise<PriceList> {
    // Ensure KES exists
    let kes = await this.currencyRepository.findOne({ where: { code: 'KES' } });
    if (!kes) {
      kes = this.currencyRepository.create({
        code: 'KES',
        precision: 2,
        symbol: 'KES',
      });
      kes = await this.currencyRepository.save(kes);
      this.logger.log('Created currency KES');
    }

    // Ensure price list exists
    let priceList = await this.priceListRepository.findOne({
      where: { code: 'retail-kes' },
    });
    if (!priceList) {
      priceList = this.priceListRepository.create({
        code: 'retail-kes',
        name: 'Retail (KES)',
        currency: 'KES',
        status: 'active',
        priority: 1,
        scope: {},
        stackingPolicy: 'EXCLUSIVE',
        matchPolicy: 'HIGHEST_PRIORITY',
        stopAfterMatch: true,
      });
      priceList = await this.priceListRepository.save(priceList);
      this.logger.log('Created price list retail-kes');
    }

    return priceList;
  }

  private async seedProducts(payload: {
    priceList: PriceList;
    brands: { nova: Brand; acme: Brand };
    categories: { phones: Category; accessories: Category; lighting: Category };
  }): Promise<void> {
    const channels = ['WEB', 'MOBILE', 'WHATSAPP'];
    const availability = {
      channels,
      countries: ['KE', 'TZ'],
      locations: ['Nairobi', 'Dar es Salaam'],
      stock: { type: 'FINITE', quantity: 120 },
      schedule: {
        startAt: '2025-01-01T00:00:00Z',
        endAt: '2026-01-01T00:00:00Z',
        timezone: 'UTC',
      },
      meta: { source: 'seed' },
    };

    const phone = await this.productService.create({
      title: 'Nova X Phone',
      description:
        'Flagship smartphone with pro-grade camera and long battery life.',
      status: ProductStatus.ACTIVE,
      externalRef: 'NOVA-X-001',
      brandId: payload.brands.nova.id,
      categoryIds: [payload.categories.phones.id],
      skus: [
        {
          title: 'Black / 128 GB',
          sku: 'PHONE-001',
          isDefault: true,
          attributes: { color: 'black', storage: '128GB' },
            availability,
          images: ['https://cdn.example.com/products/nova-x/black.png'],
          prices: [
            {
              priceListId: payload.priceList.id,
              unitPrice: 129999,
              compareAtPrice: 139999,
              minQuantity: 1,
            },
          ],
        },
        {
          title: 'Silver / 256 GB',
          sku: 'PHONE-002',
          attributes: { color: 'silver', storage: '256GB' },
            availability,
          images: ['https://cdn.example.com/products/nova-x/silver.png'],
          prices: [
            {
              priceListId: payload.priceList.id,
              unitPrice: 149999,
              compareAtPrice: 159999,
              minQuantity: 1,
            },
          ],
        },
      ],
      metaJson: { tags: ['smartphone', 'nova', 'flagship'] },
    });

    await this.productService.create({
      title: 'Acme Fast Charger',
      description: 'Compact USB-C charger with fast charging support.',
      status: ProductStatus.ACTIVE,
      externalRef: 'ACME-CHG-FAST',
      brandId: payload.brands.acme.id,
      categoryIds: [payload.categories.accessories.id],
      skus: [
        {
          title: 'Standard',
          sku: 'ACME-CHG-STD',
          isDefault: true,
          attributes: { color: 'white', power: '30W' },
            availability: {
              ...availability,
              stock: { type: 'FINITE', quantity: 300 },
            },
            images: ['https://cdn.example.com/products/acme-charger/main.png'],
            prices: [
              {
                priceListId: payload.priceList.id,
                unitPrice: 3999,
                compareAtPrice: 4999,
                minQuantity: 1,
              },
            ],
        },
      ],
      metaJson: { tags: ['charger', 'accessory'] },
    });

    await this.productService.create({
      title: 'Solar Lantern',
      description: 'Portable solar lantern with adjustable brightness.',
      status: ProductStatus.ACTIVE,
      externalRef: 'SOL-LANTERN-01',
      brandId: payload.brands.acme.id,
      categoryIds: [payload.categories.lighting.id],
      skus: [
        {
          title: 'Rechargeable',
          sku: 'SOL-LANT-REC',
          isDefault: true,
          attributes: { power: 'solar', battery: '4000mAh' },
            availability: {
              ...availability,
              stock: { type: 'FINITE', quantity: 80 },
              schedule: {
                startAt: '2025-03-01T00:00:00Z',
                endAt: '2026-03-01T00:00:00Z',
                timezone: 'UTC',
              },
            },
            images: ['https://cdn.example.com/products/lantern/main.png'],
          prices: [
            {
              priceListId: payload.priceList.id,
              unitPrice: 24999,
              minQuantity: 1,
            },
            {
              priceListId: payload.priceList.id,
              unitPrice: 22999,
              minQuantity: 1,
              metaJson: { conditions: { countryCodes: ['TZ'] } },
            },
          ],
        },
      ],
      metaJson: { tags: ['solar', 'lighting', 'outdoor'] },
    });

    this.logger.log('Seeded sample products');
  }
}
