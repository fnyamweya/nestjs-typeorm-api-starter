import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddProductOptionsAndPriceRow20260111_1768700000000
  implements MigrationInterface
{
  name = 'AddProductOptionsAndPriceRow20260111_1768700000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(
      'ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "option_definitions_json" jsonb NOT NULL DEFAULT \'[]\'::jsonb',
    );

    await queryRunner.query(
      'ALTER TABLE "product_variant" ADD COLUMN IF NOT EXISTS "inventory_json" jsonb NOT NULL DEFAULT \'{}\'::jsonb',
    );

    await queryRunner.query(
      'ALTER TABLE "price_list" ADD COLUMN IF NOT EXISTS "priority" int NOT NULL DEFAULT 0',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" ADD COLUMN IF NOT EXISTS "scope" text NOT NULL DEFAULT \'global\'',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" ADD COLUMN IF NOT EXISTS "status" text NOT NULL DEFAULT \'active\'',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" ADD COLUMN IF NOT EXISTS "stacking_policy" text NOT NULL DEFAULT \'replace\'',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" ADD COLUMN IF NOT EXISTS "match_policy" text NOT NULL DEFAULT \'best\'',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" ADD COLUMN IF NOT EXISTS "stop_after_match" boolean NOT NULL DEFAULT false',
    );

    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='meta_json'
        ) THEN
          UPDATE "price_list"
          SET "priority" = COALESCE(NULLIF(("meta_json"->>'priority')::text, '')::int, "priority")
          WHERE "meta_json" ? 'priority';
        END IF;
      END $$;
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "price_row" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "price_list_id" uuid NOT NULL REFERENCES "price_list"("id") ON DELETE CASCADE,
        "target_type" text NOT NULL,
        "target_id" uuid NOT NULL,
        "selector_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "currency_code" char(3),
        "unit_amount" bigint NOT NULL,
        "compare_at_amount" bigint,
        "min_quantity" int NOT NULL DEFAULT 1,
        "max_quantity" int,
        "valid_from" timestamptz,
        "valid_to" timestamptz,
        "tiers_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now()
      );
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_price_row_lookup" ON "price_row" ("price_list_id", "target_type", "target_id", "min_quantity")',
    );

    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.tables
          WHERE table_schema='public' AND table_name='product_price'
        ) THEN
          INSERT INTO "price_row" (
            "price_list_id",
            "target_type",
            "target_id",
            "selector_json",
            "currency_code",
            "unit_amount",
            "compare_at_amount",
            "min_quantity",
            "max_quantity",
            "valid_from",
            "valid_to",
            "tiers_json",
            "meta_json",
            "created_at",
            "updated_at"
          )
          SELECT
            pp."price_list_id",
            CASE WHEN pp."product_variant_id" IS NOT NULL THEN 'SKU' ELSE 'PRODUCT' END,
            COALESCE(pp."product_variant_id", pp."product_id"),
            COALESCE(pp."meta_json"->'conditions', '{}'::jsonb),
            NULL,
            (round(pp."unit_price" * power(10, COALESCE(c."precision", 2))))::bigint,
            CASE
              WHEN pp."compare_at_price" IS NULL THEN NULL
              ELSE (round(pp."compare_at_price" * power(10, COALESCE(c."precision", 2))))::bigint
            END,
            pp."min_quantity",
            pp."max_quantity",
            pp."valid_from",
            pp."valid_to",
            '[]'::jsonb,
            COALESCE(pp."meta_json", '{}'::jsonb),
            pp."created_at",
            pp."updated_at"
          FROM "product_price" pp
          JOIN "price_list" pl ON pl."id" = pp."price_list_id"
          LEFT JOIN "currency" c ON c."code" = pl."currency_code";
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS "idx_price_row_lookup"');
    await queryRunner.query('DROP TABLE IF EXISTS "price_row" CASCADE');

    await queryRunner.query(
      'ALTER TABLE "price_list" DROP COLUMN IF EXISTS "stop_after_match"',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" DROP COLUMN IF EXISTS "match_policy"',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" DROP COLUMN IF EXISTS "stacking_policy"',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" DROP COLUMN IF EXISTS "status"',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" DROP COLUMN IF EXISTS "scope"',
    );
    await queryRunner.query(
      'ALTER TABLE "price_list" DROP COLUMN IF EXISTS "priority"',
    );

    await queryRunner.query(
      'ALTER TABLE "product_variant" DROP COLUMN IF EXISTS "inventory_json"',
    );
    await queryRunner.query(
      'ALTER TABLE "product" DROP COLUMN IF EXISTS "option_definitions_json"',
    );
  }
}
