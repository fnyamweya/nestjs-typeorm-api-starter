import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOAuthProviderSettingsAllowedDomains20260107160000
  implements MigrationInterface
{
  name = 'AddOAuthProviderSettingsAllowedDomains20260107160000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      ADD COLUMN IF NOT EXISTS "allowedDomains" text
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "oauth_provider_settings"
      DROP COLUMN IF EXISTS "allowedDomains"
    `);
  }
}
