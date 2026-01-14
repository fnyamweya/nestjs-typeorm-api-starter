import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOAuthProviderSettingsAppleFields20260107180000
  implements MigrationInterface
{
  name = 'AddOAuthProviderSettingsAppleFields20260107180000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      ADD COLUMN IF NOT EXISTS "teamId" character varying
    `);

    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      ADD COLUMN IF NOT EXISTS "keyId" character varying
    `);

    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      ADD COLUMN IF NOT EXISTS "privateKey" text
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      DROP COLUMN IF EXISTS "privateKey"
    `);
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      DROP COLUMN IF EXISTS "keyId"
    `);
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      DROP COLUMN IF EXISTS "teamId"
    `);
  }
}
