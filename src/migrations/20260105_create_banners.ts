import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateBanners1767679497335 implements MigrationInterface {
  name = 'CreateBanners1767679497335';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "banner" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "name" text NOT NULL,
        "is_active" boolean NOT NULL DEFAULT true,
        "starts_at" timestamptz NULL,
        "ends_at" timestamptz NULL,
        "priority" int NOT NULL DEFAULT 0,
        "creative_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "placements_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "targets_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now()
      );

      CREATE INDEX IF NOT EXISTS "idx_banner_is_active" ON "banner" ("is_active");
      CREATE INDEX IF NOT EXISTS "idx_banner_starts_at" ON "banner" ("starts_at");
      CREATE INDEX IF NOT EXISTS "idx_banner_ends_at" ON "banner" ("ends_at");
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DROP TABLE IF EXISTS "banner";
    `);
  }
}
