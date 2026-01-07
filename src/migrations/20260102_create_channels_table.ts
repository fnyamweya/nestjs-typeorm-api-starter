import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateChannelsTable20260102_1769990000000
  implements MigrationInterface
{
  name = 'CreateChannelsTable20260102_1769990000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "channel" (
      "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      "code" text NOT NULL,
      "name" text NOT NULL,
      "description" text,
      "is_active" boolean NOT NULL DEFAULT true,
      "config_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "metadata" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now()
    );`);

    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS "uq_channel_code" ON "channel" ("code");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_channel_is_active" ON "channel" ("is_active");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_channel_is_active";`);
    await queryRunner.query(`DROP INDEX IF EXISTS "uq_channel_code";`);
    await queryRunner.query(`DROP TABLE IF EXISTS "channel" CASCADE;`);
  }
}
