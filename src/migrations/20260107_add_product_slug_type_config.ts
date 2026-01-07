import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddProductSlugTypeConfig20260107_1760260000000
  implements MigrationInterface
{
  name = 'AddProductSlugTypeConfig20260107_1760260000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`DO $$ BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'product' AND column_name = 'handle'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'product' AND column_name = 'slug'
      ) THEN
        ALTER TABLE "product" RENAME COLUMN "handle" TO "slug";
      END IF;
    END $$;`);

    await queryRunner.query(`DO $$ BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'product' AND column_name = 'slug'
      ) THEN
        ALTER TABLE "product" ADD COLUMN "slug" text;
      END IF;
    END $$;`);

    await queryRunner.query(
      'CREATE UNIQUE INDEX IF NOT EXISTS "uq_product_slug" ON "product" ("slug")',
    );

    await queryRunner.query(
      'ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "type_fields_json" jsonb NOT NULL DEFAULT \'{}\'::jsonb',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_type_config" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "code" text NOT NULL,
        "name" text,
        "is_active" boolean NOT NULL DEFAULT true,
        "config_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "uq_product_type_config_code" UNIQUE ("code")
      );
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_product_type_config_active" ON "product_type_config" ("is_active")',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_product_type_config_active"',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "product_type_config"');
    await queryRunner.query(
      'ALTER TABLE "product" DROP COLUMN IF EXISTS "type_fields_json"',
    );
    await queryRunner.query('DROP INDEX IF EXISTS "uq_product_slug"');

    await queryRunner.query(`DO $$ BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'product' AND column_name = 'slug'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'product' AND column_name = 'handle'
      ) THEN
        ALTER TABLE "product" RENAME COLUMN "slug" TO "handle";
      END IF;
    END $$;`);
  }
}
