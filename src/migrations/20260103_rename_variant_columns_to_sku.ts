import { MigrationInterface, QueryRunner } from 'typeorm';

export class RenameVariantColumnsToSku20260103_1767500000000
  implements MigrationInterface
{
  name = 'RenameVariantColumnsToSku20260103_1767500000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DO $$
    BEGIN
      -- order_item: product_variant_id -> product_sku_id
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='product_variant_id'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='product_sku_id'
      ) THEN
        ALTER TABLE "order_item" RENAME COLUMN "product_variant_id" TO "product_sku_id";
      END IF;

      -- order_item: variant_title -> sku_title
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='variant_title'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='sku_title'
      ) THEN
        ALTER TABLE "order_item" RENAME COLUMN "variant_title" TO "sku_title";
      END IF;

      -- order_item: variant_options_json -> sku_options_json
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='variant_options_json'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='sku_options_json'
      ) THEN
        ALTER TABLE "order_item" RENAME COLUMN "variant_options_json" TO "sku_options_json";
      END IF;

      -- attribute_definition: is_variant_axis -> is_sku_axis
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='attribute_definition' AND column_name='is_variant_axis'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='attribute_definition' AND column_name='is_sku_axis'
      ) THEN
        ALTER TABLE "attribute_definition" RENAME COLUMN "is_variant_axis" TO "is_sku_axis";
      END IF;
    END $$;`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='product_sku_id'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='product_variant_id'
      ) THEN
        ALTER TABLE "order_item" RENAME COLUMN "product_sku_id" TO "product_variant_id";
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='sku_title'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='variant_title'
      ) THEN
        ALTER TABLE "order_item" RENAME COLUMN "sku_title" TO "variant_title";
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='sku_options_json'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='order_item' AND column_name='variant_options_json'
      ) THEN
        ALTER TABLE "order_item" RENAME COLUMN "sku_options_json" TO "variant_options_json";
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='attribute_definition' AND column_name='is_sku_axis'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='attribute_definition' AND column_name='is_variant_axis'
      ) THEN
        ALTER TABLE "attribute_definition" RENAME COLUMN "is_sku_axis" TO "is_variant_axis";
      END IF;
    END $$;`);
  }
}
