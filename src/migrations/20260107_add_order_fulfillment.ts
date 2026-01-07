import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOrderFulfillment20260107090000 implements MigrationInterface {
  name = 'AddOrderFulfillment20260107090000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "order_fulfillment" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "order_id" uuid NOT NULL,
        "status" text NOT NULL DEFAULT 'PACKED',
        "shipping_method_id" uuid,
        "shipping_method_snapshot_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "tracking_number" text,
        "tracking_url" text,
        "origin_location_id" uuid,
        "origin_name" text,
        "destination_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "currency_code" char(3) NOT NULL,
        "shipping_amount" numeric(18,4) NOT NULL DEFAULT 0,
        "insurance_amount" numeric(18,4) NOT NULL DEFAULT 0,
        "packed_at" timestamptz,
        "shipped_at" timestamptz,
        "delivered_at" timestamptz,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_order_fulfillment" PRIMARY KEY ("id"),
        CONSTRAINT "fk_order_fulfillment_order" FOREIGN KEY ("order_id") REFERENCES "order"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_order_fulfillment_shipping_method" FOREIGN KEY ("shipping_method_id") REFERENCES "shipping_method"("id") ON DELETE SET NULL,
        CONSTRAINT "fk_order_fulfillment_origin_location" FOREIGN KEY ("origin_location_id") REFERENCES "location"("id") ON DELETE SET NULL,
        CONSTRAINT "fk_order_fulfillment_currency" FOREIGN KEY ("currency_code") REFERENCES "currency"("code") ON DELETE RESTRICT
      );
    `);

    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_fulfillment_order" ON "order_fulfillment" ("order_id")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_fulfillment_status" ON "order_fulfillment" ("status")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_fulfillment_shipping_method" ON "order_fulfillment" ("shipping_method_id")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_fulfillment_origin_location" ON "order_fulfillment" ("origin_location_id")');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "fulfillment_package" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "fulfillment_id" uuid NOT NULL,
        "weight_value" numeric(18,4),
        "weight_unit" text,
        "dim_length" numeric(18,4),
        "dim_width" numeric(18,4),
        "dim_height" numeric(18,4),
        "dim_unit" text,
        "tracking_number" text,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_fulfillment_package" PRIMARY KEY ("id"),
        CONSTRAINT "fk_fulfillment_package_fulfillment" FOREIGN KEY ("fulfillment_id") REFERENCES "order_fulfillment"("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_fulfillment_package_fulfillment" ON "fulfillment_package" ("fulfillment_id")');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "order_fulfillment_item" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "fulfillment_id" uuid NOT NULL,
        "order_item_id" uuid NOT NULL,
        "quantity" int NOT NULL,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_order_fulfillment_item" PRIMARY KEY ("id"),
        CONSTRAINT "fk_order_fulfillment_item_fulfillment" FOREIGN KEY ("fulfillment_id") REFERENCES "order_fulfillment"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_order_fulfillment_item_order_item" FOREIGN KEY ("order_item_id") REFERENCES "order_item"("id") ON DELETE RESTRICT
      );
    `);

    await queryRunner.query('CREATE UNIQUE INDEX IF NOT EXISTS "uq_order_fulfillment_item" ON "order_fulfillment_item" ("fulfillment_id", "order_item_id")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_fulfillment_item_order_item" ON "order_fulfillment_item" ("order_item_id")');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "package_item" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "package_id" uuid NOT NULL,
        "order_item_id" uuid NOT NULL,
        "quantity" int NOT NULL,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_package_item" PRIMARY KEY ("id"),
        CONSTRAINT "fk_package_item_package" FOREIGN KEY ("package_id") REFERENCES "fulfillment_package"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_package_item_order_item" FOREIGN KEY ("order_item_id") REFERENCES "order_item"("id") ON DELETE RESTRICT
      );
    `);

    await queryRunner.query('CREATE UNIQUE INDEX IF NOT EXISTS "uq_package_item" ON "package_item" ("package_id", "order_item_id")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_package_item_order_item" ON "package_item" ("order_item_id")');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE IF EXISTS "package_item"');
    await queryRunner.query('DROP TABLE IF EXISTS "order_fulfillment_item"');
    await queryRunner.query('DROP TABLE IF EXISTS "fulfillment_package"');
    await queryRunner.query('DROP TABLE IF EXISTS "order_fulfillment"');
  }
}
