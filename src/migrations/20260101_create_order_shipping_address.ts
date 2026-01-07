import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateOrderShippingAddress20260101174500
  implements MigrationInterface
{
  name = 'CreateOrderShippingAddress20260101174500';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "order_shipping_address" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "order_id" uuid NOT NULL,
        "customer_address_id" uuid,
        "first_name" text,
        "last_name" text,
        "phone" text,
        "country_code" char(2),
        "location_id" uuid,
        "fields_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "fk_order_shipping_address_order" FOREIGN KEY ("order_id") REFERENCES "order"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_order_shipping_address_customer_address" FOREIGN KEY ("customer_address_id") REFERENCES "customer_address"("id") ON DELETE SET NULL,
        CONSTRAINT "fk_order_shipping_address_location" FOREIGN KEY ("location_id") REFERENCES "location"("id") ON DELETE SET NULL
      );
    `);

    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS "uq_order_shipping_address_order" ON "order_shipping_address" ("order_id");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "uq_order_shipping_address_order";`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "order_shipping_address";`);
  }
}
