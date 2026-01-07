import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateAddressFieldConfig20260103_1767400002000
  implements MigrationInterface
{
  name = 'CreateAddressFieldConfig20260103_1767400002000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "address_field_config" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "country_code" char(2) NOT NULL,
        "is_active" boolean NOT NULL DEFAULT true,
        "schema_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now()
      );
    `);

    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS "uq_address_field_config_country_active" ON "address_field_config" ("country_code", "is_active");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_address_field_config_country" ON "address_field_config" ("country_code");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TABLE IF EXISTS "address_field_config" CASCADE;`,
    );
  }
}
