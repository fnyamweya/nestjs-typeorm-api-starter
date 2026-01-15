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
import { ProductSku } from './entities/product-sku.entity';
import { ProductCategory } from './entities/product-category.entity';
import { Currency } from './entities/currency.entity';
import { PriceList } from './entities/price-list.entity';
import { PriceRow } from './entities/price-row.entity';
import { Brand } from './entities/brand.entity';
import { ProductChannel } from './entities/product-channel.entity';
import { ProductContextOverride } from './entities/product-context-override.entity';
import { Collection } from './entities/collection.entity';
import { CollectionItem } from './entities/collection-item.entity';
import { CustomerProductView } from './entities/customer-product-view.entity';
import { ProductReview } from './entities/product-review.entity';
import { ProductRatingSummary } from './entities/product-rating-summary.entity';
import { Channel } from '../channels/entities/channel.entity';
import { TaxonomyController } from './controllers/taxonomy.controller';
import { CategoryController } from './controllers/category.controller';
import { ProductController } from './controllers/product.controller';
import { BrandController } from './controllers/brand.controller';
import { CollectionController } from './controllers/collection.controller';
import { ProductReviewsController } from './controllers/product-reviews.controller';
import { PublicProductsController } from './controllers/public/public-products.controller';
import { PublicBrandsController } from './controllers/public/public-brands.controller';
import { PublicCategoriesController } from './controllers/public/public-categories.controller';
import { PublicTaxonomiesController } from './controllers/public/public-taxonomies.controller';
import { PublicCollectionsController } from './controllers/public/public-collections.controller';
import { PublicPersonalizationController } from './controllers/public/public-personalization.controller';
import { PublicProductReviewsController } from './controllers/public/public-product-reviews.controller';
import { TaxonomyService } from './services/taxonomy.service';
import { CategoryService } from './services/category.service';
import { ProductService } from './services/product.service';
import { BrandService } from './services/brand.service';
import { CollectionService } from './services/collection.service';
import { CustomerProductViewService } from './services/customer-product-view.service';
import { RecommendationsService } from './services/recommendations.service';
import { ProductReviewService } from './services/product-review.service';
import { CatalogSeeder } from './seeders/catalog.seeder';
import { CollectionSeeder } from './seeders/collection.seeder';
import { PriceService } from './services/price.service';
import { CustomerTierModule } from '../customer-tier/customer-tier.module';
import { CurrencyModule } from '../currency/currency.module';
import { CustomerProductReviewsController } from './controllers/customer/customer-product-reviews.controller';

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
      ProductSku,
      ProductCategory,
      ProductChannel,
      ProductContextOverride,
      Collection,
      CollectionItem,
      CustomerProductView,
      ProductReview,
      ProductRatingSummary,
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
    CollectionController,
    ProductReviewsController,
    PublicProductsController,
    PublicBrandsController,
    PublicCategoriesController,
    PublicTaxonomiesController,
    PublicCollectionsController,
    PublicPersonalizationController,
    PublicProductReviewsController,
    CustomerProductReviewsController,
  ],
  providers: [
    TaxonomyService,
    CategoryService,
    ProductService,
    BrandService,
    CollectionService,
    CustomerProductViewService,
    RecommendationsService,
    ProductReviewService,
    CatalogSeeder,
    CollectionSeeder,
    PriceService,
  ],
  exports: [
    TypeOrmModule,
    TaxonomyService,
    CategoryService,
    ProductService,
    BrandService,
    CollectionService,
    CustomerProductViewService,
    RecommendationsService,
    ProductReviewService,
    CatalogSeeder,
    CollectionSeeder,
    PriceService,
  ],
})
export class CatalogModule {}
