import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddProductContextOverride20260110_1768600000000
  implements MigrationInterface
{
  name = 'AddProductContextOverride20260110_1768600000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "product_context_override" (
      "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
      "product_id" uuid NOT NULL,
      "is_active" boolean NOT NULL DEFAULT true,
      "priority" integer NOT NULL DEFAULT 0,
      "valid_from" timestamptz NULL,
      "valid_until" timestamptz NULL,
      "match_context" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "rule" jsonb NULL,
      "patch" jsonb NOT NULL DEFAULT '[]'::jsonb,
      "description" text NULL,
      "audit" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "pk_product_context_override" PRIMARY KEY ("id"),
      CONSTRAINT "fk_product_context_override_product" FOREIGN KEY ("product_id") REFERENCES "product"("id") ON DELETE CASCADE
    )`);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_product_context_override_product" ON "product_context_override" ("product_id", "is_active")`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_product_context_override_valid" ON "product_context_override" ("valid_from", "valid_until")`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_product_context_override_valid"',
    );
    await queryRunner.query(
      'DROP INDEX IF EXISTS "idx_product_context_override_product"',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "product_context_override"');
  }
}
