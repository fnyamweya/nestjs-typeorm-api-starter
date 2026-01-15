import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddLocationCountryId20260115130000
  implements MigrationInterface
{
  name = 'AddLocationCountryId20260115130000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');

    await queryRunner.query(
      'ALTER TABLE "location" ADD COLUMN "country_id" uuid',
    );

    // Ensure country_config has active entries for any existing location.country_code
    await queryRunner.query(
      "INSERT INTO \"country_config\" (\"id\", \"country_code\", \"is_active\", \"config_json\", \"created_at\", \"updated_at\")\n" +
        "SELECT gen_random_uuid(), t.code, true, '{}'::jsonb, now(), now()\n" +
        "FROM (SELECT DISTINCT COALESCE(country_code, 'KE') AS code FROM \"location\") t\n" +
        "WHERE NOT EXISTS (\n" +
        "  SELECT 1 FROM \"country_config\" cc WHERE cc.country_code = t.code AND cc.is_active = true\n" +
        ")",
    );

    // Ensure at least one active country_config exists (fallback)
    await queryRunner.query(
      "INSERT INTO \"country_config\" (\"id\", \"country_code\", \"is_active\", \"config_json\", \"created_at\", \"updated_at\")\n" +
        "SELECT gen_random_uuid(), 'KE', true, '{}'::jsonb, now(), now()\n" +
        "WHERE NOT EXISTS (SELECT 1 FROM \"country_config\" WHERE \"is_active\" = true)",
    );

    await queryRunner.query(
      'UPDATE "location" l SET "country_id" = cc.id FROM "country_config" cc WHERE l."country_code" = cc."country_code" AND cc."is_active" = true',
    );

    await queryRunner.query(
      'UPDATE "location" SET "country_id" = (SELECT id FROM "country_config" WHERE "is_active" = true ORDER BY "created_at" ASC LIMIT 1) WHERE "country_id" IS NULL',
    );

    await queryRunner.query(
      'ALTER TABLE "location" ALTER COLUMN "country_id" SET NOT NULL',
    );

    await queryRunner.query(
      'ALTER TABLE "location" ADD CONSTRAINT "FK_location_country" FOREIGN KEY ("country_id") REFERENCES "country_config"("id") ON DELETE RESTRICT',
    );

    await queryRunner.query(
      'CREATE INDEX "idx_location_country_id" ON "location" ("country_id")',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS "idx_location_country_id"');
    await queryRunner.query('ALTER TABLE "location" DROP CONSTRAINT IF EXISTS "FK_location_country"');
    await queryRunner.query('ALTER TABLE "location" DROP COLUMN IF EXISTS "country_id"');
  }
}
