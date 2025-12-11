import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCatalogSchema20251211010000 implements MigrationInterface {
  name = 'AddCatalogSchema20251211010000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "taxonomy" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "code" TEXT NOT NULL UNIQUE,
        "name" TEXT NOT NULL,
        "description" TEXT,
        "is_default" BOOLEAN NOT NULL DEFAULT FALSE,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "category" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "taxonomy_id" uuid NOT NULL REFERENCES "taxonomy"("id"),
        "parent_id" uuid REFERENCES "category"("id") ON DELETE SET NULL,
        "key" TEXT NOT NULL,
        "slug" TEXT NOT NULL,
        "is_active" BOOLEAN NOT NULL DEFAULT TRUE,
        "is_leaf" BOOLEAN NOT NULL DEFAULT FALSE,
        "sort_order" INT NOT NULL DEFAULT 0,
        "icon" TEXT,
        "image_url" TEXT,
        "meta_json" JSONB NOT NULL DEFAULT '{}'::JSONB,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT "uq_category_key_per_taxonomy" UNIQUE ("taxonomy_id", "key"),
        CONSTRAINT "uq_category_slug_per_taxonomy" UNIQUE ("taxonomy_id", "slug")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_category_taxonomy" ON "category" ("taxonomy_id", "sort_order")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_category_active" ON "category" ("taxonomy_id", "is_active")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "category_closure" (
        "ancestor_id" uuid NOT NULL REFERENCES "category"("id") ON DELETE CASCADE,
        "descendant_id" uuid NOT NULL REFERENCES "category"("id") ON DELETE CASCADE,
        "depth" INT NOT NULL,
        PRIMARY KEY ("ancestor_id", "descendant_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_cat_closure_ancestor" ON "category_closure" ("ancestor_id", "depth")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_cat_closure_descendant" ON "category_closure" ("descendant_id", "depth")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "category_translation" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "category_id" uuid NOT NULL REFERENCES "category"("id") ON DELETE CASCADE,
        "locale" TEXT NOT NULL,
        "name" TEXT NOT NULL,
        "description" TEXT,
        "seo_title" TEXT,
        "seo_description" TEXT,
        "seo_keywords" TEXT[],
        "url_path" TEXT,
        CONSTRAINT "uq_category_locale" UNIQUE ("category_id", "locale")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_cat_translation_locale" ON "category_translation" ("locale")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "sales_channel" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "code" TEXT NOT NULL UNIQUE,
        "name" TEXT NOT NULL,
        "meta_json" JSONB NOT NULL DEFAULT '{}'::JSONB
      );
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "category_channel_settings" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "category_id" uuid NOT NULL REFERENCES "category"("id") ON DELETE CASCADE,
        "channel_id" uuid NOT NULL REFERENCES "sales_channel"("id") ON DELETE CASCADE,
        "is_visible" BOOLEAN NOT NULL DEFAULT TRUE,
        "custom_sort_mode" TEXT,
        "merchandising_json" JSONB NOT NULL DEFAULT '{}'::JSONB,
        CONSTRAINT "uq_category_channel" UNIQUE ("category_id", "channel_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_cat_channel_visible" ON "category_channel_settings" ("channel_id", "is_visible")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "attribute_definition" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "code" TEXT NOT NULL UNIQUE,
        "label" TEXT NOT NULL,
        "value_type" TEXT NOT NULL,
        "is_facet" BOOLEAN NOT NULL DEFAULT FALSE,
        "is_searchable" BOOLEAN NOT NULL DEFAULT FALSE,
        "is_variant_axis" BOOLEAN NOT NULL DEFAULT FALSE,
        "meta_json" JSONB NOT NULL DEFAULT '{}'::JSONB
      );
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "category_attribute" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "category_id" uuid NOT NULL REFERENCES "category"("id") ON DELETE CASCADE,
        "attribute_id" uuid NOT NULL REFERENCES "attribute_definition"("id") ON DELETE CASCADE,
        "is_required" BOOLEAN NOT NULL DEFAULT FALSE,
        "is_filterable" BOOLEAN NOT NULL DEFAULT FALSE,
        "filter_type" TEXT,
        "sort_order" INT NOT NULL DEFAULT 0,
        "meta_json" JSONB NOT NULL DEFAULT '{}'::JSONB,
        CONSTRAINT "uq_category_attribute" UNIQUE ("category_id", "attribute_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_category_attribute_cat" ON "category_attribute" ("category_id", "is_filterable")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "handle" TEXT NOT NULL UNIQUE,
        "type" TEXT NOT NULL DEFAULT 'standard',
        "status" TEXT NOT NULL DEFAULT 'draft',
        "brand_id" uuid,
        "default_variant_id" uuid,
        "is_featured" BOOLEAN NOT NULL DEFAULT FALSE,
        "published_at" TIMESTAMPTZ,
        "meta_json" JSONB NOT NULL DEFAULT '{}'::JSONB,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_status" ON "product" ("status", "published_at")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_translation" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "locale" TEXT NOT NULL,
        "name" TEXT NOT NULL,
        "short_description" TEXT,
        "long_description" TEXT,
        "seo_title" TEXT,
        "seo_description" TEXT,
        "seo_keywords" TEXT[],
        "slug" TEXT,
        CONSTRAINT "uq_product_locale" UNIQUE ("product_id", "locale")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_translation_locale" ON "product_translation" ("locale")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_variant" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "sku" TEXT NOT NULL UNIQUE,
        "barcode" TEXT,
        "external_id" TEXT,
        "title" TEXT NOT NULL,
        "is_default" BOOLEAN NOT NULL DEFAULT FALSE,
        "position" INT NOT NULL DEFAULT 0,
        "weight_grams" INT,
        "height_mm" INT,
        "width_mm" INT,
        "depth_mm" INT,
        "requires_shipping" BOOLEAN NOT NULL DEFAULT TRUE,
        "allow_backorder" BOOLEAN NOT NULL DEFAULT FALSE,
        "meta_json" JSONB NOT NULL DEFAULT '{}'::JSONB,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_variant_product" ON "product_variant" ("product_id", "is_default")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_option" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "name" TEXT NOT NULL,
        "position" INT NOT NULL DEFAULT 0,
        CONSTRAINT "uq_product_option_name" UNIQUE ("product_id", "name")
      );
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_option_value" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "option_id" uuid NOT NULL REFERENCES "product_option"("id") ON DELETE CASCADE,
        "value" TEXT NOT NULL,
        "position" INT NOT NULL DEFAULT 0,
        CONSTRAINT "uq_option_value" UNIQUE ("option_id", "value")
      );
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "variant_option_value" (
        "variant_id" uuid NOT NULL REFERENCES "product_variant"("id") ON DELETE CASCADE,
        "option_id" uuid NOT NULL REFERENCES "product_option"("id") ON DELETE CASCADE,
        "option_value_id" uuid NOT NULL REFERENCES "product_option_value"("id") ON DELETE CASCADE,
        PRIMARY KEY ("variant_id", "option_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_variant_option_value" ON "variant_option_value" ("variant_id")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_category" (
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "category_id" uuid NOT NULL REFERENCES "category"("id") ON DELETE CASCADE,
        "is_primary" BOOLEAN NOT NULL DEFAULT FALSE,
        "sort_order" INT NOT NULL DEFAULT 0,
        PRIMARY KEY ("product_id", "category_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_category_cat" ON "product_category" ("category_id", "is_primary", "sort_order")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_attribute_value" (
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "attribute_id" uuid NOT NULL REFERENCES "attribute_definition"("id") ON DELETE CASCADE,
        "value_string" TEXT,
        "value_number" NUMERIC,
        "value_boolean" BOOLEAN,
        "value_json" JSONB,
        PRIMARY KEY ("product_id", "attribute_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_attr_string" ON "product_attribute_value" ("attribute_id", "value_string")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_attr_number" ON "product_attribute_value" ("attribute_id", "value_number")',
    );

    await queryRunner.query(`
      ALTER TABLE "product"
      ADD CONSTRAINT "FK_product_default_variant"
      FOREIGN KEY ("default_variant_id")
      REFERENCES "product_variant"("id")
      ON DELETE SET NULL;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "product" DROP CONSTRAINT IF EXISTS "FK_product_default_variant"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_attr_number"');
    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_attr_string"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_attribute_value"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_category_cat"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_category"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_variant_option_value"');
    await queryRunner.query('DROP TABLE IF EXISTS "variant_option_value"');

    await queryRunner.query('DROP TABLE IF EXISTS "product_option_value"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_option"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_variant_product"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_variant"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_translation_locale"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_translation"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_status"');
    await queryRunner.query('DROP TABLE IF EXISTS "product"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_category_attribute_cat"');
    await queryRunner.query('DROP TABLE IF EXISTS "category_attribute"');

    await queryRunner.query('DROP TABLE IF EXISTS "attribute_definition"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_cat_channel_visible"');
    await queryRunner.query('DROP TABLE IF EXISTS "category_channel_settings"');

    await queryRunner.query('DROP TABLE IF EXISTS "sales_channel"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_cat_translation_locale"');
    await queryRunner.query('DROP TABLE IF EXISTS "category_translation"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_cat_closure_descendant"');
    await queryRunner.query('DROP INDEX IF EXISTS "idx_cat_closure_ancestor"');
    await queryRunner.query('DROP TABLE IF EXISTS "category_closure"');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_category_active"');
    await queryRunner.query('DROP INDEX IF EXISTS "idx_category_taxonomy"');
    await queryRunner.query('DROP TABLE IF EXISTS "category"');

    await queryRunner.query('DROP TABLE IF EXISTS "taxonomy"');
  }
}
