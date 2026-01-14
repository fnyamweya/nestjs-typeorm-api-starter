import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCustomerProductViews20260114123000
  implements MigrationInterface
{
  name = 'AddCustomerProductViews20260114123000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "customer_product_view" (
        "id" uuid NOT NULL,
        "customer_id" uuid NOT NULL,
        "product_id" uuid NOT NULL,
        "viewed_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT "PK_customer_product_view_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_customer_product_view_customer_product" UNIQUE ("customer_id", "product_id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_customer_product_view_customer_viewed" ON "customer_product_view" ("customer_id", "viewed_at")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_customer_product_view_product" ON "customer_product_view" ("product_id")
    `);

    await queryRunner.query(`
      ALTER TABLE "customer_product_view"
      ADD CONSTRAINT "FK_customer_product_view_product" FOREIGN KEY ("product_id") REFERENCES "product"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE "customer_product_view"
      ADD CONSTRAINT "FK_customer_product_view_customer" FOREIGN KEY ("customer_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "customer_product_view" DROP CONSTRAINT "FK_customer_product_view_customer"',
    );
    await queryRunner.query(
      'ALTER TABLE "customer_product_view" DROP CONSTRAINT "FK_customer_product_view_product"',
    );
    await queryRunner.query(
      'DROP INDEX IF EXISTS "IDX_customer_product_view_product"',
    );
    await queryRunner.query(
      'DROP INDEX IF EXISTS "IDX_customer_product_view_customer_viewed"',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "customer_product_view"');
  }
}
