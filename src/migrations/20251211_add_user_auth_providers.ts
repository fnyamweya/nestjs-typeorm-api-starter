import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserAuthProviders20251211001000 implements MigrationInterface {
  name = 'AddUserAuthProviders20251211001000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "user_auth_providers" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "user_id" uuid NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
        "provider" varchar NOT NULL,
        "providerId" varchar NOT NULL,
        "linked_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
        CONSTRAINT "UQ_user_provider_providerId" UNIQUE ("provider", "providerId")
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE IF EXISTS "user_auth_providers"');
  }
}
