import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateCustomerShippingAddress20260106_120000
  implements MigrationInterface
{
  name = 'CreateCustomerShippingAddress20260106_120000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "customer_shipping_address" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "user_id" uuid NOT NULL,
        "address_id" uuid NOT NULL,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "uq_customer_shipping_address_user" UNIQUE ("user_id"),
        CONSTRAINT "fk_customer_shipping_address_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_customer_shipping_address_address" FOREIGN KEY ("address_id") REFERENCES "address"("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_customer_shipping_address_user_id" ON "customer_shipping_address" ("user_id");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_customer_shipping_address_user_id";`,
    );
    await queryRunner.query(
      `DROP TABLE IF EXISTS "customer_shipping_address";`,
    );
  }
}
