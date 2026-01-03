import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCountryConfig20260102000000 implements MigrationInterface {
  name = 'AddCountryConfig20260102000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "country_config" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "country_code" char(2) NOT NULL,
        "is_active" boolean NOT NULL DEFAULT TRUE,
        "config_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT NOW(),
        "updated_at" timestamptz NOT NULL DEFAULT NOW(),
        CONSTRAINT "uq_country_config_country_active" UNIQUE ("country_code", "is_active")
      );
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "idx_country_config_country" ON "country_config" ("country_code", "updated_at")',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE IF EXISTS "country_config"');
  }
}
