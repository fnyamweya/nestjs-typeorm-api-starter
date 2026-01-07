import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreatePromotionRuleEngine20260105_1760000000000
  implements MigrationInterface
{
  name = 'CreatePromotionRuleEngine20260105_1760000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    // Enums used by the new dynamic promotion engine
    await queryRunner.query(`DO $$ BEGIN
      CREATE TYPE "promotion_status_enum" AS ENUM ('draft','active','paused','archived');
    EXCEPTION
      WHEN duplicate_object THEN null;
    END $$;`);

    await queryRunner.query(`DO $$ BEGIN
      CREATE TYPE "promotion_stacking_policy_enum" AS ENUM ('exclusive','stackable','stackable_same_group');
    EXCEPTION
      WHEN duplicate_object THEN null;
    END $$;`);

    await queryRunner.query(`DO $$ BEGIN
      CREATE TYPE "promotion_condition_type_enum" AS ENUM ('cart_total','customer_segment','first_order','has_coupon','item_in_category','item_has_tag','payment_method');
    EXCEPTION
      WHEN duplicate_object THEN null;
    END $$;`);

    await queryRunner.query(`DO $$ BEGIN
      CREATE TYPE "promotion_condition_operator_enum" AS ENUM ('eq','neq','gt','gte','lt','lte','in','not_in','contains');
    EXCEPTION
      WHEN duplicate_object THEN null;
    END $$;`);

    await queryRunner.query(`DO $$ BEGIN
      CREATE TYPE "promotion_action_type_enum" AS ENUM ('percent_off','fixed_off','free_shipping','bogo','tiered_discount','gift_item');
    EXCEPTION
      WHEN duplicate_object THEN null;
    END $$;`);

    // Core table (alter existing if present)
    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "name" text;`,
    );
    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "description" text;`,
    );

    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "status" "promotion_status_enum" NOT NULL DEFAULT 'draft';`,
    );
    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "priority" int NOT NULL DEFAULT 100;`,
    );
    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "stacking_policy" "promotion_stacking_policy_enum" NOT NULL DEFAULT 'stackable';`,
    );
    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "stacking_group" text;`,
    );

    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "max_redemptions" int;`,
    );
    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "max_redemptions_per_customer" int;`,
    );

    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "channels" jsonb NOT NULL DEFAULT '[]'::jsonb;`,
    );
    await queryRunner.query(
      `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "metadata" jsonb NOT NULL DEFAULT '{}'::jsonb;`,
    );

    // Ensure unique code (best-effort)
    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS "promotion_code_unique" ON "promotion" ("code");`,
    );

    // Rule engine tables
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "promotion_condition" (
      "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      "promotion_id" uuid NOT NULL,
      "type" "promotion_condition_type_enum" NOT NULL,
      "operator" "promotion_condition_operator_enum" NOT NULL,
      "params" jsonb NOT NULL,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_promotion_condition_promotion" FOREIGN KEY ("promotion_id") REFERENCES "promotion" ("id") ON DELETE CASCADE
    );`);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_promotion_condition_promotion_id" ON "promotion_condition" ("promotion_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_promotion_condition_type" ON "promotion_condition" ("type");`,
    );

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "promotion_action" (
      "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      "promotion_id" uuid NOT NULL,
      "type" "promotion_action_type_enum" NOT NULL,
      "params" jsonb NOT NULL,
      "target" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_promotion_action_promotion" FOREIGN KEY ("promotion_id") REFERENCES "promotion" ("id") ON DELETE CASCADE
    );`);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_promotion_action_promotion_id" ON "promotion_action" ("promotion_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_promotion_action_type" ON "promotion_action" ("type");`,
    );

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "promotion_redemption" (
      "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      "promotion_id" uuid NOT NULL,
      "customer_id" uuid,
      "order_id" uuid,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_promotion_redemption_promotion" FOREIGN KEY ("promotion_id") REFERENCES "promotion" ("id") ON DELETE CASCADE
    );`);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_promotion_redemption_promotion_id" ON "promotion_redemption" ("promotion_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_promotion_redemption_customer_id" ON "promotion_redemption" ("customer_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_promotion_redemption_order_id" ON "promotion_redemption" ("order_id");`,
    );

    // Backfill legacy rows into metadata/status/actions when legacy columns exist.
    // - is_active -> status
    // - meta_json -> metadata (only if metadata is still default)
    // - type/value/currency_code -> initial action

    await queryRunner.query(`DO $$ BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='promotion' AND column_name='is_active'
      ) THEN
        UPDATE "promotion"
        SET "status" = CASE WHEN "is_active" = true THEN 'active'::"promotion_status_enum" ELSE 'paused'::"promotion_status_enum" END
        WHERE "status" = 'draft'::"promotion_status_enum";
      END IF;
    END $$;`);

    await queryRunner.query(`DO $$ BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='promotion' AND column_name='meta_json'
      ) THEN
        UPDATE "promotion"
        SET "metadata" = CASE
          WHEN "metadata" = '{}'::jsonb THEN COALESCE("meta_json", '{}'::jsonb)
          ELSE "metadata"
        END;
      END IF;
    END $$;`);

    // Insert actions for legacy promotions if no actions exist yet
    await queryRunner.query(`DO $$ BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='promotion' AND column_name='type'
      ) THEN
        -- percentage
        INSERT INTO "promotion_action" ("promotion_id", "type", "params", "target")
        SELECT p."id", 'percent_off', jsonb_build_object(
          'percent',
          COALESCE(
            CASE
              WHEN NULLIF(btrim(p."value"::text), '') IS NULL THEN NULL
              WHEN btrim(p."value"::text) ~ '^[0-9]+(\\.[0-9]+)?$' THEN btrim(p."value"::text)::numeric
              ELSE 0
            END,
            0
          )
        ), jsonb_build_object('scope', 'order')
        FROM "promotion" p
        WHERE p."type" = 'percentage'
          AND NOT EXISTS (SELECT 1 FROM "promotion_action" a WHERE a."promotion_id" = p."id");

        -- fixed
        INSERT INTO "promotion_action" ("promotion_id", "type", "params", "target")
        SELECT p."id", 'fixed_off', jsonb_build_object(
          'amount',
          COALESCE(
            CASE
              WHEN NULLIF(btrim(p."value"::text), '') IS NULL THEN NULL
              WHEN btrim(p."value"::text) ~ '^[0-9]+(\\.[0-9]+)?$' THEN btrim(p."value"::text)::numeric
              ELSE 0
            END,
            0
          ),
          'currency', p."currency_code"
        ), jsonb_build_object('scope', 'order')
        FROM "promotion" p
        WHERE p."type" = 'fixed'
          AND NOT EXISTS (SELECT 1 FROM "promotion_action" a WHERE a."promotion_id" = p."id");

        -- free shipping
        INSERT INTO "promotion_action" ("promotion_id", "type", "params", "target")
        SELECT p."id", 'free_shipping', '{}'::jsonb, '{}'::jsonb
        FROM "promotion" p
        WHERE p."type" = 'free_shipping'
          AND NOT EXISTS (SELECT 1 FROM "promotion_action" a WHERE a."promotion_id" = p."id");
      END IF;
    END $$;`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TABLE IF EXISTS "promotion_redemption" CASCADE;`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "promotion_action" CASCADE;`);
    await queryRunner.query(
      `DROP TABLE IF EXISTS "promotion_condition" CASCADE;`,
    );

    // We keep added columns on promotion table in down (best-effort rollback would be destructive).

    await queryRunner.query(
      `DROP TYPE IF EXISTS "promotion_action_type_enum";`,
    );
    await queryRunner.query(
      `DROP TYPE IF EXISTS "promotion_condition_operator_enum";`,
    );
    await queryRunner.query(
      `DROP TYPE IF EXISTS "promotion_condition_type_enum";`,
    );
    await queryRunner.query(
      `DROP TYPE IF EXISTS "promotion_stacking_policy_enum";`,
    );
    await queryRunner.query(`DROP TYPE IF EXISTS "promotion_status_enum";`);
  }
}
