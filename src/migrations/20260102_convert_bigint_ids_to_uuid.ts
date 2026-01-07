import { MigrationInterface, QueryRunner } from 'typeorm';

export class ConvertBigintIdsToUuid20260102_1767312000000
  implements MigrationInterface
{
  name = 'ConvertBigintIdsToUuid20260102_1767312000000';

  private async getUdtName(
    queryRunner: QueryRunner,
    tableName: string,
    columnName: string,
  ): Promise<string | undefined> {
    const rows = (await queryRunner.query(
      `SELECT udt_name
       FROM information_schema.columns
       WHERE table_schema = 'public'
         AND table_name = $1
         AND column_name = $2
       LIMIT 1;`,
      [tableName, columnName],
    )) as Array<{ udt_name: string }>;

    return rows?.[0]?.udt_name;
  }

  private async isBigintColumn(
    queryRunner: QueryRunner,
    tableName: string,
    columnName: string,
  ): Promise<boolean> {
    const udtName = await this.getUdtName(queryRunner, tableName, columnName);
    return udtName === 'int8';
  }

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    // Pricing + Orders + Mpesa (created by migrations, known constraint names)
    if (
      (await queryRunner.hasTable('price_list')) &&
      (await this.isBigintColumn(queryRunner, 'price_list', 'id'))
    ) {
      // 1) Add UUID columns + backfill
      await queryRunner.query(
        `ALTER TABLE "price_list" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "price_list" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_price_list_id_uuid" ON "price_list" ("id_uuid");`,
      );

      await queryRunner.query(
        `ALTER TABLE "order" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_order_id_uuid" ON "order" ("id_uuid");`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order_item" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_order_item_id_uuid" ON "order_item" ("id_uuid");`,
      );

      await queryRunner.query(
        `ALTER TABLE "product_variant_price" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "product_variant_price" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_level_charge" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order_level_charge" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item_charge" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order_item_charge" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );

      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "mpesa_transaction" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );

      // 2) Add + backfill UUID FK columns
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" ADD COLUMN IF NOT EXISTS "price_list_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "product_variant_price" p
         SET "price_list_id_uuid" = COALESCE("price_list_id_uuid", pl."id_uuid")
         FROM "price_list" pl
         WHERE p."price_list_id" = pl."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" ALTER COLUMN "price_list_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order" ADD COLUMN IF NOT EXISTS "price_list_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order" o
         SET "price_list_id_uuid" = COALESCE("price_list_id_uuid", pl."id_uuid")
         FROM "price_list" pl
         WHERE o."price_list_id" = pl."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order" ALTER COLUMN "price_list_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item" ADD COLUMN IF NOT EXISTS "order_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order_item" oi
         SET "order_id_uuid" = COALESCE("order_id_uuid", o."id_uuid")
         FROM "order" o
         WHERE oi."order_id" = o."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" ALTER COLUMN "order_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item" ADD COLUMN IF NOT EXISTS "price_list_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order_item" oi
         SET "price_list_id_uuid" = COALESCE("price_list_id_uuid", pl."id_uuid")
         FROM "price_list" pl
         WHERE oi."price_list_id" = pl."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" ALTER COLUMN "price_list_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_level_charge" ADD COLUMN IF NOT EXISTS "order_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order_level_charge" olc
         SET "order_id_uuid" = COALESCE("order_id_uuid", o."id_uuid")
         FROM "order" o
         WHERE olc."order_id" = o."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" ALTER COLUMN "order_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item_charge" ADD COLUMN IF NOT EXISTS "order_item_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "order_item_charge" oic
         SET "order_item_id_uuid" = COALESCE("order_item_id_uuid", oi."id_uuid")
         FROM "order_item" oi
         WHERE oic."order_item_id" = oi."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" ALTER COLUMN "order_item_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" ADD COLUMN IF NOT EXISTS "order_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "mpesa_transaction" tx
         SET "order_id_uuid" = COALESCE("order_id_uuid", o."id_uuid")
         FROM "order" o
         WHERE tx."order_id" = o."id";`,
      );

      // 3) Swap FK columns and recreate constraints pointing at UUID columns (id_uuid)
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" DROP CONSTRAINT IF EXISTS "fk_variant_price_pricelist";`,
      );
      await queryRunner.query(`DROP INDEX IF EXISTS "uq_variant_price_tier";`);
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" DROP COLUMN IF EXISTS "price_list_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" RENAME COLUMN "price_list_id_uuid" TO "price_list_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" ADD CONSTRAINT "fk_variant_price_pricelist" FOREIGN KEY ("price_list_id") REFERENCES "price_list" ("id_uuid") ON DELETE CASCADE;`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_variant_price_tier" ON "product_variant_price" ("price_list_id", "product_variant_id", "min_quantity");`,
      );

      await queryRunner.query(
        `ALTER TABLE "order" DROP CONSTRAINT IF EXISTS "fk_order_pricelist";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order" DROP COLUMN IF EXISTS "price_list_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order" RENAME COLUMN "price_list_id_uuid" TO "price_list_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order" ADD CONSTRAINT "fk_order_pricelist" FOREIGN KEY ("price_list_id") REFERENCES "price_list" ("id_uuid") ON DELETE RESTRICT;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item" DROP CONSTRAINT IF EXISTS "fk_orderitem_order";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" DROP CONSTRAINT IF EXISTS "fk_orderitem_pricelist";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" DROP COLUMN IF EXISTS "order_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" RENAME COLUMN "order_id_uuid" TO "order_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" DROP COLUMN IF EXISTS "price_list_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" RENAME COLUMN "price_list_id_uuid" TO "price_list_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" ADD CONSTRAINT "fk_orderitem_order" FOREIGN KEY ("order_id") REFERENCES "order" ("id_uuid") ON DELETE CASCADE;`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" ADD CONSTRAINT "fk_orderitem_pricelist" FOREIGN KEY ("price_list_id") REFERENCES "price_list" ("id_uuid") ON DELETE RESTRICT;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_level_charge" DROP CONSTRAINT IF EXISTS "fk_orderlevel_order";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" DROP COLUMN IF EXISTS "order_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" RENAME COLUMN "order_id_uuid" TO "order_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" ADD CONSTRAINT "fk_orderlevel_order" FOREIGN KEY ("order_id") REFERENCES "order" ("id_uuid") ON DELETE CASCADE;`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item_charge" DROP CONSTRAINT IF EXISTS "fk_orderitemcharge_orderitem";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" DROP COLUMN IF EXISTS "order_item_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" RENAME COLUMN "order_item_id_uuid" TO "order_item_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" ADD CONSTRAINT "fk_orderitemcharge_orderitem" FOREIGN KEY ("order_item_id") REFERENCES "order_item" ("id_uuid") ON DELETE CASCADE;`,
      );

      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" DROP CONSTRAINT IF EXISTS "fk_mpesa_tx_order";`,
      );
      await queryRunner.query(`DROP INDEX IF EXISTS "idx_mpesa_tx_order_id";`);
      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" DROP COLUMN IF EXISTS "order_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" RENAME COLUMN "order_id_uuid" TO "order_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" ADD CONSTRAINT "fk_mpesa_tx_order" FOREIGN KEY ("order_id") REFERENCES "order" ("id_uuid") ON DELETE SET NULL;`,
      );
      await queryRunner.query(
        `CREATE INDEX IF NOT EXISTS "idx_mpesa_tx_order_id" ON "mpesa_transaction" ("order_id");`,
      );

      // 4) Swap PK columns (id)
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" DROP CONSTRAINT IF EXISTS "product_variant_price_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "product_variant_price" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "product_variant_price_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_level_charge" DROP CONSTRAINT IF EXISTS "order_level_charge_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_level_charge" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "order_level_charge_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item_charge" DROP CONSTRAINT IF EXISTS "order_item_charge_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item_charge" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "order_item_charge_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" DROP CONSTRAINT IF EXISTS "mpesa_transaction_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "mpesa_transaction" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "mpesa_transaction_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "order_item" DROP CONSTRAINT IF EXISTS "order_item_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "order_item" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(`DROP SEQUENCE IF EXISTS "order_item_id_seq";`);

      await queryRunner.query(
        `ALTER TABLE "order" DROP CONSTRAINT IF EXISTS "order_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "order" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(`ALTER TABLE "order" ADD PRIMARY KEY ("id");`);
      await queryRunner.query(`DROP SEQUENCE IF EXISTS "order_id_seq";`);

      await queryRunner.query(
        `ALTER TABLE "price_list" DROP CONSTRAINT IF EXISTS "price_list_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "price_list" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "price_list" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "price_list" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "price_list" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(`DROP SEQUENCE IF EXISTS "price_list_id_seq";`);

      // 5) Drop helper unique indexes (now redundant)
      await queryRunner.query(`DROP INDEX IF EXISTS "uq_price_list_id_uuid";`);
      await queryRunner.query(`DROP INDEX IF EXISTS "uq_order_id_uuid";`);
      await queryRunner.query(`DROP INDEX IF EXISTS "uq_order_item_id_uuid";`);
    }

    // Shipping tables (handle if they exist and were bigint)
    if (
      (await queryRunner.hasTable('shipping_zone')) &&
      (await this.isBigintColumn(queryRunner, 'shipping_zone', 'id'))
    ) {
      await queryRunner.query(
        `ALTER TABLE "shipping_zone" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "shipping_zone" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_shipping_zone_id_uuid" ON "shipping_zone" ("id_uuid");`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_method" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "shipping_method" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_shipping_method_id_uuid" ON "shipping_method" ("id_uuid");`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_rate" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "shipping_rate" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "shipping_zone_location" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_method" ADD COLUMN IF NOT EXISTS "zone_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "shipping_method" m
         SET "zone_id_uuid" = COALESCE("zone_id_uuid", z."id_uuid")
         FROM "shipping_zone" z
         WHERE m."zone_id" = z."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_method" ALTER COLUMN "zone_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" ADD COLUMN IF NOT EXISTS "zone_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "shipping_zone_location" l
         SET "zone_id_uuid" = COALESCE("zone_id_uuid", z."id_uuid")
         FROM "shipping_zone" z
         WHERE l."zone_id" = z."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" ALTER COLUMN "zone_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_rate" ADD COLUMN IF NOT EXISTS "method_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "shipping_rate" r
         SET "method_id_uuid" = COALESCE("method_id_uuid", m."id_uuid")
         FROM "shipping_method" m
         WHERE r."method_id" = m."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" ALTER COLUMN "method_id_uuid" SET NOT NULL;`,
      );

      // swap child FK columns
      await queryRunner.query(
        `ALTER TABLE "shipping_method" DROP COLUMN IF EXISTS "zone_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_method" RENAME COLUMN "zone_id_uuid" TO "zone_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_method" ADD CONSTRAINT "fk_shipping_method_zone" FOREIGN KEY ("zone_id") REFERENCES "shipping_zone" ("id_uuid") ON DELETE CASCADE;`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" DROP COLUMN IF EXISTS "zone_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" RENAME COLUMN "zone_id_uuid" TO "zone_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" ADD CONSTRAINT "fk_shipping_zone_location_zone" FOREIGN KEY ("zone_id") REFERENCES "shipping_zone" ("id_uuid") ON DELETE CASCADE;`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_rate" DROP COLUMN IF EXISTS "method_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" RENAME COLUMN "method_id_uuid" TO "method_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" ADD CONSTRAINT "fk_shipping_rate_method" FOREIGN KEY ("method_id") REFERENCES "shipping_method" ("id_uuid") ON DELETE CASCADE;`,
      );

      // swap PKs
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" DROP CONSTRAINT IF EXISTS "shipping_rate_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_rate" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "shipping_rate_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" DROP CONSTRAINT IF EXISTS "shipping_zone_location_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone_location" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "shipping_zone_location_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_method" DROP CONSTRAINT IF EXISTS "shipping_method_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_method" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_method" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_method" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_method" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "shipping_method_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "shipping_zone" DROP CONSTRAINT IF EXISTS "shipping_zone_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "shipping_zone" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "shipping_zone_id_seq";`,
      );

      await queryRunner.query(
        `DROP INDEX IF EXISTS "uq_shipping_zone_id_uuid";`,
      );
      await queryRunner.query(
        `DROP INDEX IF EXISTS "uq_shipping_method_id_uuid";`,
      );
    }

    // Promotion (if exists and was bigint)
    if (
      (await queryRunner.hasTable('promotion')) &&
      (await this.isBigintColumn(queryRunner, 'promotion', 'id'))
    ) {
      await queryRunner.query(
        `ALTER TABLE "promotion" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "promotion" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `ALTER TABLE "promotion" DROP CONSTRAINT IF EXISTS "promotion_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "promotion" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "promotion" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "promotion" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "promotion" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(`DROP SEQUENCE IF EXISTS "promotion_id_seq";`);
    }

    // Feature flags (if exist and were bigint)
    if (
      (await queryRunner.hasTable('feature_flags')) &&
      (await this.isBigintColumn(queryRunner, 'feature_flags', 'id'))
    ) {
      await queryRunner.query(
        `ALTER TABLE "feature_flags" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "feature_flags" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_feature_flags_id_uuid" ON "feature_flags" ("id_uuid");`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_segments" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "feature_segments" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX IF NOT EXISTS "uq_feature_segments_id_uuid" ON "feature_segments" ("id_uuid");`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "feature_flag_overrides" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" ADD COLUMN IF NOT EXISTS "id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "feature_flag_audit" SET "id_uuid" = COALESCE("id_uuid", gen_random_uuid());`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ADD COLUMN IF NOT EXISTS "feature_flag_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "feature_flag_overrides" o
         SET "feature_flag_id_uuid" = COALESCE("feature_flag_id_uuid", f."id_uuid")
         FROM "feature_flags" f
         WHERE o."feature_flag_id" = f."id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ALTER COLUMN "feature_flag_id_uuid" SET NOT NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ADD COLUMN IF NOT EXISTS "segment_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "feature_flag_overrides" o
         SET "segment_id_uuid" = COALESCE("segment_id_uuid", s."id_uuid")
         FROM "feature_segments" s
         WHERE o."segment_id" IS NOT NULL AND o."segment_id" = s."id";`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" ADD COLUMN IF NOT EXISTS "feature_flag_id_uuid" uuid;`,
      );
      await queryRunner.query(
        `UPDATE "feature_flag_audit" a
         SET "feature_flag_id_uuid" = COALESCE("feature_flag_id_uuid", f."id_uuid")
         FROM "feature_flags" f
         WHERE a."feature_flag_id" IS NOT NULL AND a."feature_flag_id" = f."id";`,
      );

      // swap child FK columns
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" DROP COLUMN IF EXISTS "feature_flag_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" RENAME COLUMN "feature_flag_id_uuid" TO "feature_flag_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" DROP COLUMN IF EXISTS "segment_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" RENAME COLUMN "segment_id_uuid" TO "segment_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ADD CONSTRAINT "fk_feature_flag_overrides_flag" FOREIGN KEY ("feature_flag_id") REFERENCES "feature_flags" ("id_uuid") ON DELETE CASCADE;`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ADD CONSTRAINT "fk_feature_flag_overrides_segment" FOREIGN KEY ("segment_id") REFERENCES "feature_segments" ("id_uuid") ON DELETE SET NULL;`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" DROP COLUMN IF EXISTS "feature_flag_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" RENAME COLUMN "feature_flag_id_uuid" TO "feature_flag_id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" ADD CONSTRAINT "fk_feature_flag_audit_flag" FOREIGN KEY ("feature_flag_id") REFERENCES "feature_flags" ("id_uuid") ON DELETE SET NULL;`,
      );

      // swap PKs
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" DROP CONSTRAINT IF EXISTS "feature_flag_overrides_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_overrides" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "feature_flag_overrides_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" DROP CONSTRAINT IF EXISTS "feature_flag_audit_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flag_audit" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "feature_flag_audit_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_segments" DROP CONSTRAINT IF EXISTS "feature_segments_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_segments" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_segments" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_segments" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_segments" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "feature_segments_id_seq";`,
      );

      await queryRunner.query(
        `ALTER TABLE "feature_flags" DROP CONSTRAINT IF EXISTS "feature_flags_pkey";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flags" DROP COLUMN IF EXISTS "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flags" RENAME COLUMN "id_uuid" TO "id";`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flags" ALTER COLUMN "id" SET DEFAULT gen_random_uuid();`,
      );
      await queryRunner.query(
        `ALTER TABLE "feature_flags" ADD PRIMARY KEY ("id");`,
      );
      await queryRunner.query(
        `DROP SEQUENCE IF EXISTS "feature_flags_id_seq";`,
      );

      await queryRunner.query(
        `DROP INDEX IF EXISTS "uq_feature_flags_id_uuid";`,
      );
      await queryRunner.query(
        `DROP INDEX IF EXISTS "uq_feature_segments_id_uuid";`,
      );
    }
  }

  public async down(): Promise<void> {
    // Irreversible: bigint values are dropped after UUID backfill/swap.
    throw new Error('ConvertBigintIdsToUuid20260102 is irreversible');
  }
}
