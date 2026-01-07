import { MigrationInterface, QueryRunner } from 'typeorm';

export class RefactorProductsSchema20260109_1768000000000
  implements MigrationInterface
{
  name = 'RefactorProductsSchema20260109_1768000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(
      'DROP TABLE IF EXISTS "product_context_override" CASCADE',
    );
    await queryRunner.query(
      'DROP TABLE IF EXISTS "product_variant_price" CASCADE',
    );
    await queryRunner.query(
      'DROP TABLE IF EXISTS "variant_option_value" CASCADE',
    );
    await queryRunner.query(
      'DROP TABLE IF EXISTS "product_option_value" CASCADE',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "product_option" CASCADE');
    await queryRunner.query(
      'DROP TABLE IF EXISTS "product_attribute_value" CASCADE',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "product_price" CASCADE');
    await queryRunner.query('DROP TABLE IF EXISTS "product_channel" CASCADE');
    await queryRunner.query('DROP TABLE IF EXISTS "product_category" CASCADE');
    await queryRunner.query('DROP TABLE IF EXISTS "product_variant" CASCADE');
    await queryRunner.query(
      'DROP TABLE IF EXISTS "product_translation" CASCADE',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "product" CASCADE');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "title" text NOT NULL,
        "description" text,
        "status" text NOT NULL DEFAULT 'draft',
        "slug" text NOT NULL,
        "external_ref" text,
        "brand_id" uuid,
        "availability_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "images_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "fk_product_brand" FOREIGN KEY ("brand_id") REFERENCES "brand"("id") ON DELETE SET NULL
      );
    `);
    await queryRunner.query(
      'CREATE UNIQUE INDEX IF NOT EXISTS "uq_product_slug" ON "product" ("slug")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_status" ON "product" ("status", "created_at")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_translation" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "locale" text NOT NULL,
        "title" text NOT NULL,
        "description" text,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
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
        "title" text NOT NULL,
        "sku" text,
        "external_ref" text,
        "status" text NOT NULL DEFAULT 'active',
        "is_default" boolean NOT NULL DEFAULT false,
        "position" int NOT NULL DEFAULT 0,
        "attributes_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "images_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "requires_shipping" boolean NOT NULL DEFAULT true,
        "weight" numeric(18,6),
        "length" numeric(18,6),
        "width" numeric(18,6),
        "height" numeric(18,6),
        "dimension_unit" text NOT NULL DEFAULT 'cm',
        "weight_unit" text NOT NULL DEFAULT 'kg',
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now()
      );
    `);
    await queryRunner.query(
      'CREATE UNIQUE INDEX IF NOT EXISTS "uq_variant_sku" ON "product_variant" ("sku")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_variant_product" ON "product_variant" ("product_id", "is_default")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_category" (
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "category_id" uuid NOT NULL REFERENCES "category"("id") ON DELETE CASCADE,
        "is_primary" boolean NOT NULL DEFAULT false,
        "sort_order" int NOT NULL DEFAULT 0,
        PRIMARY KEY ("product_id", "category_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_category_cat" ON "product_category" ("category_id", "is_primary", "sort_order")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_channel" (
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "channel_id" uuid NOT NULL REFERENCES "channel"("id") ON DELETE CASCADE,
        "is_active" boolean NOT NULL DEFAULT true,
        PRIMARY KEY ("product_id", "channel_id")
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_channel_active" ON "product_channel" ("product_id", "is_active")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_channel_channel" ON "product_channel" ("channel_id")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_price" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "price_list_id" uuid NOT NULL REFERENCES "price_list"("id") ON DELETE CASCADE,
        "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
        "product_variant_id" uuid REFERENCES "product_variant"("id") ON DELETE CASCADE,
        "unit_price" numeric(18,4) NOT NULL,
        "compare_at_price" numeric(18,4),
        "min_quantity" int NOT NULL DEFAULT 1,
        "max_quantity" int,
        "valid_from" timestamptz,
        "valid_to" timestamptz,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now()
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_price_lookup" ON "product_price" ("price_list_id", "product_id", "product_variant_id")',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_price_lookup"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_price" CASCADE');

    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_product_channel_channel"',
    );
    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_product_channel_active"',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "product_channel" CASCADE');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_category_cat"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_category" CASCADE');

    await queryRunner.query('DROP INDEX IF EXISTS "idx_variant_product"');
    await queryRunner.query('DROP INDEX IF EXISTS "uq_variant_sku"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_variant" CASCADE');

    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_product_translation_locale"',
    );
    await queryRunner.query(
      'DROP TABLE IF EXISTS "product_translation" CASCADE',
    );

    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_status"');
    await queryRunner.query('DROP INDEX IF EXISTS "uq_product_slug"');
    await queryRunner.query('DROP TABLE IF EXISTS "product" CASCADE');
  }
}
