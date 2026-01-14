import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOAuthProviderSettingsKey20260107173000
  implements MigrationInterface
{
  name = 'AddOAuthProviderSettingsKey20260107173000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      ADD COLUMN IF NOT EXISTS "key" character varying
    `);

    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "UQ_oauth_provider_settings_provider_key"
      ON "oauth_provider_settings" ("provider", "key")
      WHERE "key" IS NOT NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "UQ_oauth_provider_settings_provider_key"`,
    );
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      DROP COLUMN IF EXISTS "key"
    `);
  }
}
