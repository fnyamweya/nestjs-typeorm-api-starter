import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateCheckoutSession20260106_130000
  implements MigrationInterface
{
  name = 'CreateCheckoutSession20260106_130000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "checkout_session" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "user_id" uuid NOT NULL,
        "status" text NOT NULL DEFAULT 'active',
        "expires_at" timestamptz NOT NULL,
        "completed_at" timestamptz NULL,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "fk_checkout_session_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_checkout_session_user_id" ON "checkout_session" ("user_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_checkout_session_status" ON "checkout_session" ("status");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_checkout_session_expires_at" ON "checkout_session" ("expires_at");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_checkout_session_expires_at";`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_checkout_session_status";`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_checkout_session_user_id";`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "checkout_session";`);
  }
}
