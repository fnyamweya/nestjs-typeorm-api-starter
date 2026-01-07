import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Taxonomy } from './entities/taxonomy.entity';
import { Category } from './entities/category.entity';
import { CategoryTranslation } from './entities/category-translation.entity';
import { CategoryClosure } from './entities/category-closure.entity';
import { SalesChannel } from './entities/sales-channel.entity';
import { CategoryChannelSettings } from './entities/category-channel-settings.entity';
import { AttributeDefinition } from './entities/attribute-definition.entity';
import { CategoryAttribute } from './entities/category-attribute.entity';
import { Product } from './entities/product.entity';
import { ProductTranslation } from './entities/product-translation.entity';
import { ProductSku } from './entities/product-sku.entity';
import { ProductCategory } from './entities/product-category.entity';
import { Currency } from './entities/currency.entity';
import { PriceList } from './entities/price-list.entity';
import { PriceRow } from './entities/price-row.entity';
import { Brand } from './entities/brand.entity';
import { ProductChannel } from './entities/product-channel.entity';
import { ProductContextOverride } from './entities/product-context-override.entity';
import { Channel } from '../channels/entities/channel.entity';
import { TaxonomyController } from './controllers/taxonomy.controller';
import { CategoryController } from './controllers/category.controller';
import { ProductController } from './controllers/product.controller';
import { BrandController } from './controllers/brand.controller';
import { PublicProductsController } from './controllers/public/public-products.controller';
import { PublicBrandsController } from './controllers/public/public-brands.controller';
import { PublicCategoriesController } from './controllers/public/public-categories.controller';
import { PublicTaxonomiesController } from './controllers/public/public-taxonomies.controller';
import { TaxonomyService } from './services/taxonomy.service';
import { CategoryService } from './services/category.service';
import { ProductService } from './services/product.service';
import { BrandService } from './services/brand.service';
import { CatalogSeeder } from './seeders/catalog.seeder';
import { PriceService } from './services/price.service';
import { CustomerTierModule } from '../customer-tier/customer-tier.module';
import { CurrencyModule } from '../currency/currency.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Taxonomy,
      Category,
      CategoryTranslation,
      CategoryClosure,
      SalesChannel,
      CategoryChannelSettings,
      AttributeDefinition,
      CategoryAttribute,
      Product,
      ProductTranslation,
      ProductSku,
      ProductCategory,
      ProductChannel,
      ProductContextOverride,
      Currency,
      PriceList,
      PriceRow,
      Brand,
      Channel,
    ]),
    CustomerTierModule,
    CurrencyModule,
  ],
  controllers: [
    TaxonomyController,
    CategoryController,
    ProductController,
    BrandController,
    PublicProductsController,
    PublicBrandsController,
    PublicCategoriesController,
    PublicTaxonomiesController,
  ],
  providers: [
    TaxonomyService,
    CategoryService,
    ProductService,
    BrandService,
    CatalogSeeder,
    PriceService,
  ],
  exports: [
    TypeOrmModule,
    TaxonomyService,
    CategoryService,
    ProductService,
    BrandService,
    CatalogSeeder,
    PriceService,
  ],
})
export class CatalogModule {}
