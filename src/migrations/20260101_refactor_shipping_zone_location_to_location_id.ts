import { MigrationInterface, QueryRunner } from 'typeorm';

export class RefactorShippingZoneLocationToLocationId20260101173000
  implements MigrationInterface
{
  name = 'RefactorShippingZoneLocationToLocationId20260101173000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "shipping_zone_location"
      ADD COLUMN IF NOT EXISTS "location_id" uuid;
    `);

    // Best-effort backfill from legacy country_code -> Location(COUNTRY)
    await queryRunner.query(`
      UPDATE "shipping_zone_location" szl
      SET "location_id" = l.id
      FROM "location" l
      WHERE szl."location_id" IS NULL
        AND szl."country_code" IS NOT NULL
        AND l."type" = 'country'
        AND l."country_code" = szl."country_code";
    `);

    // Add FK (nullable for safety; admin endpoints will enforce locationId going forward)
    await queryRunner.query(`
      DO $$ BEGIN
        ALTER TABLE "shipping_zone_location"
        ADD CONSTRAINT "fk_shipping_zone_location_location"
        FOREIGN KEY ("location_id") REFERENCES "location"("id")
        ON DELETE CASCADE;
      EXCEPTION WHEN duplicate_object THEN NULL;
      END $$;
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_shipping_zone_location_location_id"
      ON "shipping_zone_location" ("location_id");
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_shipping_zone_location_location_id";`,
    );
    await queryRunner.query(
      `ALTER TABLE "shipping_zone_location" DROP CONSTRAINT IF EXISTS "fk_shipping_zone_location_location";`,
    );
    await queryRunner.query(
      `ALTER TABLE "shipping_zone_location" DROP COLUMN IF EXISTS "location_id";`,
    );
  }
}
