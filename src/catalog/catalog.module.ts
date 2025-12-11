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
import { ProductVariant } from './entities/product-variant.entity';
import { ProductOption } from './entities/product-option.entity';
import { ProductOptionValue } from './entities/product-option-value.entity';
import { VariantOptionValue } from './entities/variant-option-value.entity';
import { ProductCategory } from './entities/product-category.entity';
import { ProductAttributeValue } from './entities/product-attribute-value.entity';
import { TaxonomyController } from './controllers/taxonomy.controller';
import { CategoryController } from './controllers/category.controller';
import { ProductController } from './controllers/product.controller';
import { TaxonomyService } from './services/taxonomy.service';
import { CategoryService } from './services/category.service';
import { ProductService } from './services/product.service';
import { CatalogSeeder } from './seeders/catalog.seeder';

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
      ProductVariant,
      ProductOption,
      ProductOptionValue,
      VariantOptionValue,
      ProductCategory,
      ProductAttributeValue,
    ]),
  ],
  controllers: [TaxonomyController, CategoryController, ProductController],
  providers: [TaxonomyService, CategoryService, ProductService, CatalogSeeder],
  exports: [TypeOrmModule, TaxonomyService, CategoryService, ProductService, CatalogSeeder],
})
export class CatalogModule {}
