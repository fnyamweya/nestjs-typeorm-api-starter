import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddShippingGlobalMethods20260107_1767776362448 implements MigrationInterface {
  name = 'AddShippingGlobalMethods20260107_1767776362448';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Providers
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "shipping_provider" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "code" text NOT NULL,
        "name" text NOT NULL,
        "is_active" boolean NOT NULL DEFAULT true,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now()
      );
    `);
    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS "uq_shipping_provider_code" ON "shipping_provider" ("code");`,
    );

    // Make shipping_method global-capable
    await queryRunner.query(
      `ALTER TABLE "shipping_method" ADD COLUMN IF NOT EXISTS "provider_id" uuid;`,
    );
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'fk_shipping_method_provider'
        ) THEN
          ALTER TABLE "shipping_method"
            ADD CONSTRAINT "fk_shipping_method_provider"
            FOREIGN KEY ("provider_id")
            REFERENCES "shipping_provider"("id")
            ON DELETE SET NULL;
        END IF;
      END $$;
    `);

    // Legacy zone_id becomes nullable (methods become global)
    await queryRunner.query(
      `ALTER TABLE "shipping_method" ALTER COLUMN "zone_id" DROP NOT NULL;`,
    );

    // Attachments: zone ↔ global method
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "shipping_zone_method" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "zone_id" uuid NOT NULL,
        "shipping_method_id" uuid NOT NULL,
        "is_active" boolean NOT NULL DEFAULT true,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "fk_shipping_zone_method_zone" FOREIGN KEY ("zone_id") REFERENCES "shipping_zone"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_shipping_zone_method_method" FOREIGN KEY ("shipping_method_id") REFERENCES "shipping_method"("id") ON DELETE CASCADE
      );
    `);
    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS "uq_shipping_zone_method_zone_method" ON "shipping_zone_method" ("zone_id", "shipping_method_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_shipping_zone_method_zone" ON "shipping_zone_method" ("zone_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_shipping_zone_method_method" ON "shipping_zone_method" ("shipping_method_id");`,
    );

    // Backfill: existing zone-scoped shipping methods become attached rows.
    await queryRunner.query(`
      INSERT INTO "shipping_zone_method" ("zone_id", "shipping_method_id", "is_active")
      SELECT m."zone_id", m."id", COALESCE(m."is_active", true)
      FROM "shipping_method" m
      WHERE m."zone_id" IS NOT NULL
      ON CONFLICT ("zone_id", "shipping_method_id") DO NOTHING;
    `);

    // Make them truly global by clearing legacy zone_id.
    await queryRunner.query(`UPDATE "shipping_method" SET "zone_id" = NULL WHERE "zone_id" IS NOT NULL;`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Best-effort rollback.
    await queryRunner.query(`DROP TABLE IF EXISTS "shipping_zone_method";`);
    await queryRunner.query(
      `ALTER TABLE "shipping_method" DROP CONSTRAINT IF EXISTS "fk_shipping_method_provider";`,
    );
    await queryRunner.query(
      `ALTER TABLE "shipping_method" DROP COLUMN IF EXISTS "provider_id";`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "shipping_provider";`);

    // Note: we do not restore shipping_method.zone_id NOT NULL because legacy data was nulled.
  }
}
