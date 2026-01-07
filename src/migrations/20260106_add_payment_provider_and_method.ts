import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPaymentProviderAndMethod20260106010000
  implements MigrationInterface
{
  name = 'AddPaymentProviderAndMethod20260106010000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "payment_provider" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "code" TEXT NOT NULL UNIQUE,
        "name" TEXT NOT NULL,
        "description" TEXT,
        "is_active" BOOLEAN NOT NULL DEFAULT TRUE,
        "config_json" JSONB NOT NULL DEFAULT '{}'::JSONB,
        "metadata" JSONB NOT NULL DEFAULT '{}'::JSONB,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_provider_active" ON "payment_provider" ("is_active")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "payment_method" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "code" TEXT NOT NULL UNIQUE,
        "provider_id" uuid NOT NULL REFERENCES "payment_provider"("id"),
        "name" TEXT NOT NULL,
        "description" TEXT,
        "is_active" BOOLEAN NOT NULL DEFAULT TRUE,
        "channels" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
        "config_json" JSONB NOT NULL DEFAULT '{}'::JSONB,
        "metadata" JSONB NOT NULL DEFAULT '{}'::JSONB,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // If the table existed before this migration, ensure newer columns exist.
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'payment_method'
            AND column_name = 'channels'
        ) THEN
          ALTER TABLE "payment_method"
          ADD COLUMN "channels" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
        END IF;
      END $$;
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_provider" ON "payment_method" ("provider_id")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_active" ON "payment_method" ("is_active")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_channels" ON "payment_method" USING GIN ("channels")',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE IF EXISTS "payment_method"');
    await queryRunner.query('DROP TABLE IF EXISTS "payment_provider"');
  }
}
