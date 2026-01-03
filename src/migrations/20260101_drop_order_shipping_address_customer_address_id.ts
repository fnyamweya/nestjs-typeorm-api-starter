import { MigrationInterface, QueryRunner } from 'typeorm';

export class DropOrderShippingAddressCustomerAddressId20260101190000
  implements MigrationInterface
{
  name = 'DropOrderShippingAddressCustomerAddressId20260101190000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Drop FK first (name depends on earlier migration)
    await queryRunner.query(
      `ALTER TABLE "order_shipping_address" DROP CONSTRAINT IF EXISTS "fk_order_shipping_address_customer_address";`,
    );

    await queryRunner.query(
      `ALTER TABLE "order_shipping_address" DROP COLUMN IF EXISTS "customer_address_id";`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "order_shipping_address" ADD COLUMN IF NOT EXISTS "customer_address_id" uuid;`,
    );

    await queryRunner.query(
      `ALTER TABLE "order_shipping_address" ADD CONSTRAINT "fk_order_shipping_address_customer_address" FOREIGN KEY ("customer_address_id") REFERENCES "customer_address"("id") ON DELETE SET NULL;`,
    );
  }
}
