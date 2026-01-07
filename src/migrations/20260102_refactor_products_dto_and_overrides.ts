import { MigrationInterface, QueryRunner } from 'typeorm';

export class RefactorProductsDtoAndOverrides20260102_1767390000000
  implements MigrationInterface
{
  name = 'RefactorProductsDtoAndOverrides20260102_1767390000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "code" text`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "valid_from" timestamptz`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "valid_until" timestamptz`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "tags" text[] NOT NULL DEFAULT ARRAY[]::text[]`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "collections" text[] NOT NULL DEFAULT ARRAY[]::text[]`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "attributes_json" jsonb NOT NULL DEFAULT '{}'::jsonb`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "attribute_schema_ref_json" jsonb NOT NULL DEFAULT '{"schemaId":"standard","schemaVersion":1}'::jsonb`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "pricing_json" jsonb NOT NULL DEFAULT '{}'::jsonb`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "availability_json" jsonb NOT NULL DEFAULT '{"channels":["WEB"]}'::jsonb`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" ADD COLUMN IF NOT EXISTS "media_json" jsonb NOT NULL DEFAULT '[]'::jsonb`,
    );

    // Backfill product.code for existing rows
    await queryRunner.query(
      `UPDATE "product" SET "code" = COALESCE("code", CONCAT('P-', REPLACE(LEFT(id::text, 12), '-', ''))) WHERE "code" IS NULL`,
    );

    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS "uq_product_code" ON "product" ("code")`,
    );

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
      `DROP INDEX IF EXISTS "idx_product_context_override_valid"`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_product_context_override_product"`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "product_context_override"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "uq_product_code"`);
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "media_json"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "availability_json"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "pricing_json"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "attribute_schema_ref_json"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "attributes_json"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "collections"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "tags"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "valid_until"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "valid_from"`,
    );
    await queryRunner.query(
      `ALTER TABLE "product" DROP COLUMN IF EXISTS "code"`,
    );
  }
}
