import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOrderPayments20260106030000 implements MigrationInterface {
  name = 'AddOrderPayments20260106030000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "order_payment" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "order_id" uuid NOT NULL,
        "type" text NOT NULL,
        "status" text NOT NULL DEFAULT 'PENDING',
        "provider" text NOT NULL,
        "method" text NOT NULL,
        "amount" numeric(18,4) NOT NULL,
        "currency_code" char(3) NOT NULL,
        "external_ref" text,
        "initiated_at" timestamptz,
        "confirmed_at" timestamptz,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_order_payment" PRIMARY KEY ("id"),
        CONSTRAINT "fk_order_payment_order" FOREIGN KEY ("order_id") REFERENCES "order"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_order_payment_currency" FOREIGN KEY ("currency_code") REFERENCES "currency"("code") ON DELETE RESTRICT
      );
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_order_payment_order" ON "order_payment" ("order_id")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_order_payment_status" ON "order_payment" ("status")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_order_payment_type" ON "order_payment" ("type")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_order_payment_provider" ON "order_payment" ("provider")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_order_payment_method" ON "order_payment" ("method")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_order_payment_external_ref" ON "order_payment" ("external_ref")',
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "payment_allocation" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "payment_id" uuid NOT NULL,
        "order_id" uuid NOT NULL,
        "applies_to" text NOT NULL,
        "order_item_id" uuid,
        "amount" numeric(18,4) NOT NULL,
        "currency_code" char(3) NOT NULL,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_payment_allocation" PRIMARY KEY ("id"),
        CONSTRAINT "fk_payment_allocation_payment" FOREIGN KEY ("payment_id") REFERENCES "order_payment"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_payment_allocation_order" FOREIGN KEY ("order_id") REFERENCES "order"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_payment_allocation_item" FOREIGN KEY ("order_item_id") REFERENCES "order_item"("id") ON DELETE SET NULL,
        CONSTRAINT "fk_payment_allocation_currency" FOREIGN KEY ("currency_code") REFERENCES "currency"("code") ON DELETE RESTRICT
      );
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_allocation_order" ON "payment_allocation" ("order_id")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_allocation_payment" ON "payment_allocation" ("payment_id")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_allocation_item" ON "payment_allocation" ("order_item_id")',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_payment_allocation_applies_to" ON "payment_allocation" ("applies_to")',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE IF EXISTS "payment_allocation"');
    await queryRunner.query('DROP TABLE IF EXISTS "order_payment"');
  }
}
