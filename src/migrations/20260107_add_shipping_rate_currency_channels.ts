import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddShippingRateCurrencyChannels20260107_1767776384819
  implements MigrationInterface
{
  name = 'AddShippingRateCurrencyChannels20260107_1767776384819';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Ensure currency FK on shipping_rate.currency_code
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'fk_shipping_rate_currency'
        ) THEN
          ALTER TABLE "shipping_rate"
            ADD CONSTRAINT "fk_shipping_rate_currency"
            FOREIGN KEY ("currency_code")
            REFERENCES "currency"("code")
            ON DELETE RESTRICT;
        END IF;
      END $$;
    `);

    // Join table for channel-targeted rates
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "shipping_rate_channel" (
        "rate_id" uuid NOT NULL,
        "channel_id" uuid NOT NULL,
        CONSTRAINT "pk_shipping_rate_channel" PRIMARY KEY ("rate_id", "channel_id"),
        CONSTRAINT "fk_shipping_rate_channel_rate" FOREIGN KEY ("rate_id") REFERENCES "shipping_rate"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_shipping_rate_channel_channel" FOREIGN KEY ("channel_id") REFERENCES "channel"("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_shipping_rate_channel_rate" ON "shipping_rate_channel" ("rate_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_shipping_rate_channel_channel" ON "shipping_rate_channel" ("channel_id");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TABLE IF EXISTS "shipping_rate_channel";`,
    );

    await queryRunner.query(
      `ALTER TABLE "shipping_rate" DROP CONSTRAINT IF EXISTS "fk_shipping_rate_currency";`,
    );
  }
}
