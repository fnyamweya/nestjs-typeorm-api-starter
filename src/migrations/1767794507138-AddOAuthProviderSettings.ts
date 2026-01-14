import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOAuthProviderSettings1767794507138
  implements MigrationInterface
{
  name = 'AddOAuthProviderSettings1767794507138';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "oauth_provider_settings" (
        "id" uuid NOT NULL,
        "provider" character varying NOT NULL,
        "name" character varying NOT NULL,
        "clientId" character varying NOT NULL,
        "clientSecret" text,
        "callbackUrl" character varying NOT NULL,
        "allowedDomains" text,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_oauth_provider_settings_id" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_oauth_provider_settings_provider" ON "oauth_provider_settings" ("provider")
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "oauth_provider_setting_roles" (
        "oauth_setting_id" uuid NOT NULL,
        "role_id" uuid NOT NULL,
        CONSTRAINT "PK_oauth_provider_setting_roles" PRIMARY KEY ("oauth_setting_id", "role_id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_oauth_provider_setting_roles_oauth" ON "oauth_provider_setting_roles" ("oauth_setting_id")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_oauth_provider_setting_roles_role" ON "oauth_provider_setting_roles" ("role_id")
    `);

    await queryRunner.query(`
      ALTER TABLE "oauth_provider_setting_roles"
      ADD CONSTRAINT "FK_oauth_provider_setting_roles_oauth"
      FOREIGN KEY ("oauth_setting_id") REFERENCES "oauth_provider_settings"("id")
      ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE "oauth_provider_setting_roles"
      ADD CONSTRAINT "FK_oauth_provider_setting_roles_role"
      FOREIGN KEY ("role_id") REFERENCES "roles"("id")
      ON DELETE CASCADE ON UPDATE NO ACTION
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "oauth_provider_setting_roles" DROP CONSTRAINT "FK_oauth_provider_setting_roles_role"`);
    await queryRunner.query(`ALTER TABLE "oauth_provider_setting_roles" DROP CONSTRAINT "FK_oauth_provider_setting_roles_oauth"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_oauth_provider_setting_roles_role"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_oauth_provider_setting_roles_oauth"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "oauth_provider_setting_roles"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_oauth_provider_settings_provider"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "oauth_provider_settings"`);
  }
}
