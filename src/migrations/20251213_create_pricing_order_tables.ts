import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreatePricingOrderTables20251213_1766123456789 implements MigrationInterface {
  name = 'CreatePricingOrderTables20251213_1766123456789';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "currency" (
      "code" char(3) PRIMARY KEY,
      "symbol" text,
      "precision" int NOT NULL DEFAULT 2
    );`);

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "price_list" (
      "id" bigserial PRIMARY KEY,
      "code" text NOT NULL UNIQUE,
      "name" text NOT NULL,
      "currency_code" char(3) NOT NULL,
      "is_active" boolean NOT NULL DEFAULT true,
      "valid_from" timestamptz,
      "valid_to" timestamptz,
      "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_price_list_currency" FOREIGN KEY ("currency_code") REFERENCES "currency" ("code") ON DELETE RESTRICT
    );`);

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "product_variant_price" (
      "id" bigserial PRIMARY KEY,
      "price_list_id" bigint NOT NULL,
      "product_variant_id" uuid NOT NULL,
      "unit_price" numeric(18,4) NOT NULL,
      "compare_at_price" numeric(18,4),
      "min_quantity" int NOT NULL DEFAULT 1,
      "max_quantity" int,
      "valid_from" timestamptz,
      "valid_to" timestamptz,
      "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_variant_price_pricelist" FOREIGN KEY ("price_list_id") REFERENCES "price_list" ("id") ON DELETE CASCADE,
      CONSTRAINT "fk_variant_price_variant" FOREIGN KEY ("product_variant_id") REFERENCES "product_variant" ("id") ON DELETE CASCADE
    );`);

    await queryRunner.query(`CREATE UNIQUE INDEX IF NOT EXISTS "uq_variant_price_tier" ON "product_variant_price" ("price_list_id", "product_variant_id", "min_quantity");`);

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "order" (
      "id" bigserial PRIMARY KEY,
      "order_number" text NOT NULL UNIQUE,
      "external_id" text,
      "customer_id" uuid,
      "customer_email" text NOT NULL,
      "customer_name" text,
      "price_list_id" bigint NOT NULL,
      "currency_code" char(3) NOT NULL,
      "locale" text,
      "sales_channel_code" text,
      "ip_address" inet,
      "user_agent" text,
      "status" text NOT NULL DEFAULT 'pending',
      "financial_status" text NOT NULL DEFAULT 'unpaid',
      "fulfillment_status" text NOT NULL DEFAULT 'unfulfilled',
      "risk_state" text,
      "items_subtotal" numeric(18,4) NOT NULL DEFAULT 0,
      "discount_total" numeric(18,4) NOT NULL DEFAULT 0,
      "fee_total" numeric(18,4) NOT NULL DEFAULT 0,
      "tax_total" numeric(18,4) NOT NULL DEFAULT 0,
      "shipping_subtotal" numeric(18,4) NOT NULL DEFAULT 0,
      "shipping_discount" numeric(18,4) NOT NULL DEFAULT 0,
      "shipping_tax" numeric(18,4) NOT NULL DEFAULT 0,
      "shipping_total" numeric(18,4) NOT NULL DEFAULT 0,
      "grand_total" numeric(18,4) NOT NULL DEFAULT 0,
      "item_count" int NOT NULL DEFAULT 0,
      "notes_customer" text,
      "notes_internal" text,
      "tags" text[],
      "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "placed_at" timestamptz,
      "confirmed_at" timestamptz,
      "cancelled_at" timestamptz,
      "completed_at" timestamptz,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_order_pricelist" FOREIGN KEY ("price_list_id") REFERENCES "price_list" ("id") ON DELETE RESTRICT,
      CONSTRAINT "fk_order_currency" FOREIGN KEY ("currency_code") REFERENCES "currency" ("code") ON DELETE RESTRICT
    );`);

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "order_item" (
      "id" bigserial PRIMARY KEY,
      "order_id" bigint NOT NULL,
      "product_id" uuid,
      "product_variant_id" uuid,
      "sku" text,
      "product_handle" text,
      "product_name" text NOT NULL,
      "variant_title" text,
      "variant_options_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "attributes_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "quantity" int NOT NULL,
      "price_list_id" bigint NOT NULL,
      "unit_price" numeric(18,4) NOT NULL,
      "compare_at_price" numeric(18,4),
      "base_subtotal" numeric(18,4) NOT NULL,
      "discount_total" numeric(18,4) NOT NULL DEFAULT 0,
      "fee_total" numeric(18,4) NOT NULL DEFAULT 0,
      "tax_total" numeric(18,4) NOT NULL DEFAULT 0,
      "total" numeric(18,4) NOT NULL,
      "requires_shipping" boolean NOT NULL DEFAULT true,
      "fulfillment_status" text NOT NULL DEFAULT 'unfulfilled',
      "fulfillment_group" text,
      "pricing_snapshot_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_orderitem_order" FOREIGN KEY ("order_id") REFERENCES "order" ("id") ON DELETE CASCADE,
      CONSTRAINT "fk_orderitem_pricelist" FOREIGN KEY ("price_list_id") REFERENCES "price_list" ("id") ON DELETE RESTRICT
    );`);

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "order_level_charge" (
      "id" bigserial PRIMARY KEY,
      "order_id" bigint NOT NULL,
      "charge_kind" text NOT NULL,
      "code" text,
      "display_name" text NOT NULL,
      "calculation_type" text NOT NULL,
      "rate" numeric(9,6),
      "base_amount" numeric(18,4),
      "amount" numeric(18,4) NOT NULL,
      "is_included_in_price" boolean NOT NULL DEFAULT false,
      "applies_to_shipping" boolean NOT NULL DEFAULT false,
      "source_type" text,
      "source_reference" text,
      "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_orderlevel_order" FOREIGN KEY ("order_id") REFERENCES "order" ("id") ON DELETE CASCADE
    );`);

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "order_item_charge" (
      "id" bigserial PRIMARY KEY,
      "order_item_id" bigint NOT NULL,
      "charge_kind" text NOT NULL,
      "code" text,
      "display_name" text NOT NULL,
      "calculation_type" text NOT NULL,
      "rate" numeric(9,6),
      "base_amount" numeric(18,4),
      "quantity_basis" int,
      "amount" numeric(18,4) NOT NULL,
      "is_included_in_price" boolean NOT NULL DEFAULT false,
      "source_type" text,
      "source_reference" text,
      "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_orderitemcharge_orderitem" FOREIGN KEY ("order_item_id") REFERENCES "order_item" ("id") ON DELETE CASCADE
    );`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "order_item_charge" CASCADE;`);
    await queryRunner.query(`DROP TABLE IF EXISTS "order_level_charge" CASCADE;`);
    await queryRunner.query(`DROP TABLE IF EXISTS "order_item" CASCADE;`);
    await queryRunner.query(`DROP TABLE IF EXISTS "order" CASCADE;`);
    await queryRunner.query(`DROP INDEX IF EXISTS "uq_variant_price_tier";`);
    await queryRunner.query(`DROP TABLE IF EXISTS "product_variant_price" CASCADE;`);
    await queryRunner.query(`DROP TABLE IF EXISTS "price_list" CASCADE;`);
    await queryRunner.query(`DROP TABLE IF EXISTS "currency" CASCADE;`);
  }
}
