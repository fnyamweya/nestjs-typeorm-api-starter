import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateBrands20260106_1760180000000 implements MigrationInterface {
  name = 'CreateBrands20260106_1760180000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "brand" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "name" text NOT NULL,
        "slug" text NOT NULL,
        "description" text,
        "logo_url" text,
        "website_url" text,
        "is_active" boolean NOT NULL DEFAULT true,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "uq_brand_slug" UNIQUE ("slug")
      );
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_brand_is_active" ON "brand" ("is_active")',
    );

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_brand_id" ON "product" ("brand_id")',
    );

    await queryRunner.query(`DO $$ BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_product_brand'
          AND table_name = 'product'
      ) THEN
        ALTER TABLE "product"
          ADD CONSTRAINT "fk_product_brand"
          FOREIGN KEY ("brand_id") REFERENCES "brand"("id")
          ON DELETE SET NULL;
      END IF;
    END $$;`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "product" DROP CONSTRAINT IF EXISTS "fk_product_brand"',
    );
    await queryRunner.query('DROP INDEX IF EXISTS "idx_product_brand_id"');
    await queryRunner.query('DROP INDEX IF EXISTS "idx_brand_is_active"');
    await queryRunner.query('DROP TABLE IF EXISTS "brand"');
  }
}
