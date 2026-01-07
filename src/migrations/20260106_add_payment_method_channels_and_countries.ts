import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPaymentMethodChannelsAndCountries20260106020000
  implements MigrationInterface
{
  name = 'AddPaymentMethodChannelsAndCountries20260106020000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    // Join table: payment_method <-> channel
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "payment_method_channel" (
        "payment_method_id" uuid NOT NULL REFERENCES "payment_method"("id") ON DELETE CASCADE,
        "channel_id" uuid NOT NULL REFERENCES "channel"("id") ON DELETE CASCADE,
        "is_active" BOOLEAN NOT NULL DEFAULT TRUE,
        PRIMARY KEY ("payment_method_id", "channel_id")
      );
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_channel_active" ON "payment_method_channel" ("payment_method_id", "is_active")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_channel_channel" ON "payment_method_channel" ("channel_id", "is_active")',
    );

    // Add country scoping
    await queryRunner.query(
      'ALTER TABLE "payment_method" ADD COLUMN IF NOT EXISTS "country_codes" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_country_codes" ON "payment_method" USING GIN ("country_codes")',
    );

    // Backfill join table from the old channels column (if present)
    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'payment_method'
            AND column_name = 'channels'
        ) THEN
          INSERT INTO "payment_method_channel" ("payment_method_id", "channel_id", "is_active")
          SELECT pm."id", c."id", TRUE
          FROM "payment_method" pm
          JOIN LATERAL unnest(pm."channels") AS ch(code) ON TRUE
          JOIN "channel" c ON upper(c."code") = upper(ch.code)
          ON CONFLICT DO NOTHING;

          IF EXISTS (
            SELECT 1
            FROM pg_indexes
            WHERE schemaname = 'public'
              AND indexname = 'idx_payment_method_channels'
          ) THEN
            EXECUTE 'DROP INDEX IF EXISTS "idx_payment_method_channels"';
          END IF;

          EXECUTE 'ALTER TABLE "payment_method" DROP COLUMN IF EXISTS "channels"';
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Re-add channels column
    await queryRunner.query(
      'ALTER TABLE "payment_method" ADD COLUMN IF NOT EXISTS "channels" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_channels" ON "payment_method" USING GIN ("channels")',
    );

    // Backfill channels from join table
    await queryRunner.query(`
      UPDATE "payment_method" pm
      SET "channels" = COALESCE(
        (
          SELECT ARRAY_AGG(c."code" ORDER BY c."code")
          FROM "payment_method_channel" pmc
          JOIN "channel" c ON c."id" = pmc."channel_id"
          WHERE pmc."payment_method_id" = pm."id" AND pmc."is_active" = TRUE
        ),
        ARRAY[]::TEXT[]
      );
    `);

    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_payment_method_country_codes"',
    );
    await queryRunner.query(
      'ALTER TABLE "payment_method" DROP COLUMN IF EXISTS "country_codes"',
    );

    await queryRunner.query('DROP TABLE IF EXISTS "payment_method_channel"');
  }
}
