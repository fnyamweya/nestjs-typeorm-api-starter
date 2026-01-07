import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPaymentMethodRelationships20260106020000
  implements MigrationInterface
{
  name = 'AddPaymentMethodRelationships20260106020000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "payment_method_channel" (
        "payment_method_id" uuid NOT NULL,
        "channel_id" uuid NOT NULL,
        "is_active" boolean NOT NULL DEFAULT TRUE,
        CONSTRAINT "pk_payment_method_channel" PRIMARY KEY ("payment_method_id", "channel_id"),
        CONSTRAINT "fk_payment_method_channel_method" FOREIGN KEY ("payment_method_id") REFERENCES "payment_method"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_payment_method_channel_channel" FOREIGN KEY ("channel_id") REFERENCES "channel"("id") ON DELETE CASCADE
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_channel_active" ON "payment_method_channel" ("payment_method_id", "is_active")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_channel_channel" ON "payment_method_channel" ("channel_id")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "payment_method_country_config" (
        "payment_method_id" uuid NOT NULL,
        "country_config_id" uuid NOT NULL,
        "is_active" boolean NOT NULL DEFAULT TRUE,
        CONSTRAINT "pk_payment_method_country_config" PRIMARY KEY ("payment_method_id", "country_config_id"),
        CONSTRAINT "fk_payment_method_country_config_method" FOREIGN KEY ("payment_method_id") REFERENCES "payment_method"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_payment_method_country_config_country" FOREIGN KEY ("country_config_id") REFERENCES "country_config"("id") ON DELETE CASCADE
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_country_config_active" ON "payment_method_country_config" ("payment_method_id", "is_active")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "payment_method_currency" (
        "payment_method_id" uuid NOT NULL,
        "currency_code" char(3) NOT NULL,
        "is_active" boolean NOT NULL DEFAULT TRUE,
        CONSTRAINT "pk_payment_method_currency" PRIMARY KEY ("payment_method_id", "currency_code"),
        CONSTRAINT "fk_payment_method_currency_method" FOREIGN KEY ("payment_method_id") REFERENCES "payment_method"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_payment_method_currency_currency" FOREIGN KEY ("currency_code") REFERENCES "currency"("code") ON DELETE CASCADE
      );
    `);
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_method_currency_active" ON "payment_method_currency" ("payment_method_id", "is_active")',
    );

    // Migrate from legacy payment_method.channels (TEXT[]) to payment_method_channel if present.
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
          INSERT INTO payment_method_channel (payment_method_id, channel_id, is_active)
          SELECT pm.id, ch.id, TRUE
          FROM payment_method pm
          JOIN LATERAL unnest(pm.channels) AS codes(code) ON TRUE
          JOIN channel ch ON upper(ch.code) = upper(codes.code)
          ON CONFLICT DO NOTHING;
        END IF;
      END $$;
    `);

    // Migrate from legacy payment_method.country_codes (TEXT[]) to payment_method_country_config if present.
    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'payment_method'
            AND column_name = 'country_codes'
        ) THEN
          INSERT INTO payment_method_country_config (payment_method_id, country_config_id, is_active)
          SELECT pm.id, cc.id, TRUE
          FROM payment_method pm
          JOIN LATERAL unnest(pm.country_codes) AS codes(code) ON TRUE
          JOIN country_config cc ON upper(cc.country_code) = upper(codes.code) AND cc.is_active = TRUE
          ON CONFLICT DO NOTHING;
        END IF;
      END $$;
    `);

    // Drop legacy columns/indexes if they exist.
    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_payment_method_channels"',
    );
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
          ALTER TABLE payment_method DROP COLUMN channels;
        END IF;

        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'payment_method'
            AND column_name = 'country_codes'
        ) THEN
          ALTER TABLE payment_method DROP COLUMN country_codes;
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'payment_method'
            AND column_name = 'channels'
        ) THEN
          ALTER TABLE payment_method ADD COLUMN channels TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
          CREATE INDEX IF NOT EXISTS "idx_payment_method_channels" ON "payment_method" USING GIN ("channels");
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'payment_method'
            AND column_name = 'country_codes'
        ) THEN
          ALTER TABLE payment_method ADD COLUMN country_codes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
        END IF;
      END $$;
    `);

    await queryRunner.query('DROP TABLE IF EXISTS "payment_method_currency"');
    await queryRunner.query(
      'DROP TABLE IF EXISTS "payment_method_country_config"',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "payment_method_channel"');
  }
}
