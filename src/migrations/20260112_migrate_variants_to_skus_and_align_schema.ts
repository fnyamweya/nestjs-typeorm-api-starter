import { MigrationInterface, QueryRunner } from 'typeorm';

export class MigrateVariantsToSkusAndAlignSchema20260112_1769000000000
  implements MigrationInterface
{
  name = 'MigrateVariantsToSkusAndAlignSchema20260112_1769000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    // --- Ensure schema alignment for Product metadata ---
    await queryRunner.query(`DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='product'
      ) THEN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='product' AND column_name='metadata_json'
        ) THEN
          ALTER TABLE "product" ADD COLUMN "metadata_json" jsonb NOT NULL DEFAULT '{}'::jsonb;
        END IF;

        -- Best-effort backfill from legacy meta_json
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='product' AND column_name='meta_json'
        ) THEN
          UPDATE "product" SET "metadata_json" = COALESCE("metadata_json", '{}'::jsonb) || COALESCE("meta_json", '{}'::jsonb);
        END IF;
      END IF;
    END $$;`);

    // --- Ensure schema alignment for PriceList (entity expects scope_json + policy columns) ---
    await queryRunner.query(`DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='price_list'
      ) THEN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='priority'
        ) THEN
          ALTER TABLE "price_list" ADD COLUMN "priority" int NOT NULL DEFAULT 0;
        END IF;

        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='scope_json'
        ) THEN
          ALTER TABLE "price_list" ADD COLUMN "scope_json" jsonb NOT NULL DEFAULT '{}'::jsonb;
        END IF;

        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='status'
        ) THEN
          ALTER TABLE "price_list" ADD COLUMN "status" text NOT NULL DEFAULT 'active';
        END IF;

        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='stacking_policy'
        ) THEN
          ALTER TABLE "price_list" ADD COLUMN "stacking_policy" text NOT NULL DEFAULT 'EXCLUSIVE';
        END IF;

        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='match_policy'
        ) THEN
          ALTER TABLE "price_list" ADD COLUMN "match_policy" text NOT NULL DEFAULT 'HIGHEST_PRIORITY';
        END IF;

        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='stop_after_match'
        ) THEN
          ALTER TABLE "price_list" ADD COLUMN "stop_after_match" boolean NOT NULL DEFAULT true;
        END IF;

        -- Backfill priority from meta_json->>'priority' if present
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='meta_json'
        ) THEN
          UPDATE "price_list"
          SET "priority" = COALESCE(NULLIF(("meta_json"->>'priority')::text, '')::int, "priority")
          WHERE "meta_json" ? 'priority';
        END IF;

        -- Map legacy is_active -> status
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='price_list' AND column_name='is_active'
        ) THEN
          UPDATE "price_list"
          SET "status" = CASE WHEN "is_active" THEN 'active' ELSE 'inactive' END
          WHERE "status" IS NULL OR "status" IN ('active','inactive');
        END IF;
      END IF;
    END $$;`);

    // --- Ensure product_option_definition exists (canonical option schema) ---
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "product_option_definition" (
      "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
      "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
      "code" text NOT NULL,
      "label" text NOT NULL,
      "allowed_values" text[],
      "is_required" boolean NOT NULL DEFAULT false,
      "position" int NOT NULL DEFAULT 0,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "uq_product_option_definition" UNIQUE ("product_id", "code")
    );`);

    // --- Create product_sku and migrate data from legacy product_variant if present ---
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "product_sku" (
      "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
      "product_id" uuid NOT NULL REFERENCES "product"("id") ON DELETE CASCADE,
      "title" text NOT NULL,
      "sku" text,
      "external_ref" text,
      "status" text NOT NULL DEFAULT 'active',
      "is_default" boolean NOT NULL DEFAULT false,
      "position" int NOT NULL DEFAULT 0,
      "options_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "attributes_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "inventory_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
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
    );`);

    await queryRunner.query(
      'CREATE UNIQUE INDEX IF NOT EXISTS "uq_product_sku_sku" ON "product_sku" ("sku")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_sku_product" ON "product_sku" ("product_id", "is_default")',
    );

    await queryRunner.query(`DO $$
    DECLARE
      variant_exists boolean;
      sku_count bigint;
      has_inventory boolean;
    BEGIN
      SELECT EXISTS(
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='product_variant'
      ) INTO variant_exists;

      IF variant_exists THEN
        SELECT COUNT(*) FROM "product_sku" INTO sku_count;

        SELECT EXISTS(
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='product_variant' AND column_name='inventory_json'
        ) INTO has_inventory;

        IF sku_count = 0 THEN
          IF has_inventory THEN
            INSERT INTO "product_sku" (
              "id","product_id","title","sku","external_ref","status","is_default","position",
              "options_json","attributes_json","inventory_json","images_json","requires_shipping",
              "weight","length","width","height","dimension_unit","weight_unit","meta_json",
              "created_at","updated_at"
            )
            SELECT
              v."id",v."product_id",v."title",v."sku",v."external_ref",v."status",v."is_default",v."position",
              COALESCE(v."attributes_json", '{}'::jsonb),
              COALESCE(v."attributes_json", '{}'::jsonb),
              COALESCE(v."inventory_json", '{}'::jsonb),
              COALESCE(v."images_json", '[]'::jsonb),
              COALESCE(v."requires_shipping", true),
              v."weight",v."length",v."width",v."height",v."dimension_unit",v."weight_unit",COALESCE(v."meta_json", '{}'::jsonb),
              COALESCE(v."created_at", now()), COALESCE(v."updated_at", now())
            FROM "product_variant" v;
          ELSE
            INSERT INTO "product_sku" (
              "id","product_id","title","sku","external_ref","status","is_default","position",
              "options_json","attributes_json","inventory_json","images_json","requires_shipping",
              "weight","length","width","height","dimension_unit","weight_unit","meta_json",
              "created_at","updated_at"
            )
            SELECT
              v."id",v."product_id",v."title",v."sku",v."external_ref",v."status",v."is_default",v."position",
              COALESCE(v."attributes_json", '{}'::jsonb),
              COALESCE(v."attributes_json", '{}'::jsonb),
              '{}'::jsonb,
              COALESCE(v."images_json", '[]'::jsonb),
              COALESCE(v."requires_shipping", true),
              v."weight",v."length",v."width",v."height",v."dimension_unit",v."weight_unit",COALESCE(v."meta_json", '{}'::jsonb),
              COALESCE(v."created_at", now()), COALESCE(v."updated_at", now())
            FROM "product_variant" v;
          END IF;
        END IF;
      END IF;
    END $$;`);

    // --- Repoint FK(s) that previously referenced product_variant -> product_sku ---
    await queryRunner.query(`DO $$
    DECLARE
      constraint_name text;
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='product_price'
      ) THEN
        SELECT c.conname INTO constraint_name
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (c.conkey)
        WHERE t.relname = 'product_price'
          AND c.contype = 'f'
          AND a.attname = 'product_variant_id'
        LIMIT 1;

        IF constraint_name IS NOT NULL THEN
          EXECUTE format('ALTER TABLE "product_price" DROP CONSTRAINT %I', constraint_name);
        END IF;

        -- Recreate FK to product_sku (id)
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='product_price' AND column_name='product_variant_id'
        ) THEN
          ALTER TABLE "product_price"
          ADD CONSTRAINT "fk_product_price_product_sku"
          FOREIGN KEY ("product_variant_id") REFERENCES "product_sku"("id") ON DELETE CASCADE;
        END IF;
      END IF;
    END $$;`);

    // Drop legacy product_variant table to fully migrate off it.
    await queryRunner.query(`DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='product_variant'
      ) THEN
        DROP TABLE "product_variant" CASCADE;
      END IF;
    END $$;`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Intentionally conservative: we do not recreate product_variant.
    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_sku_product"');
    await queryRunner.query('DROP INDEX IF EXISTS "uq_product_sku_sku"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_sku" CASCADE');

    await queryRunner.query(
      'DROP TABLE IF EXISTS "product_option_definition" CASCADE',
    );

    await queryRunner.query(`DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='price_list'
      ) THEN
        ALTER TABLE "price_list" DROP COLUMN IF EXISTS "stop_after_match";
        ALTER TABLE "price_list" DROP COLUMN IF EXISTS "match_policy";
        ALTER TABLE "price_list" DROP COLUMN IF EXISTS "stacking_policy";
        ALTER TABLE "price_list" DROP COLUMN IF EXISTS "status";
        ALTER TABLE "price_list" DROP COLUMN IF EXISTS "scope_json";
        ALTER TABLE "price_list" DROP COLUMN IF EXISTS "priority";
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema='public' AND table_name='product'
      ) THEN
        ALTER TABLE "product" DROP COLUMN IF EXISTS "metadata_json";
      END IF;
    END $$;`);
  }
}
