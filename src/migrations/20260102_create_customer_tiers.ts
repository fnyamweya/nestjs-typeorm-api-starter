import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateCustomerTiers20260102_1767390002000
  implements MigrationInterface
{
  name = 'CreateCustomerTiers20260102_1767390002000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "customer_tier" (
      "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
      "code" text NOT NULL,
      "name" text NOT NULL,
      "priority" int NOT NULL DEFAULT 0,
      "is_active" boolean NOT NULL DEFAULT true,
      "config_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "metadata" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "pk_customer_tier" PRIMARY KEY ("id"),
      CONSTRAINT "uq_customer_tier_code" UNIQUE ("code")
    )`);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_customer_tier_active" ON "customer_tier" ("is_active")`,
    );

    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "customer_tier_rule" (
      "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
      "tier_id" uuid NOT NULL,
      "is_active" boolean NOT NULL DEFAULT true,
      "priority" int NOT NULL DEFAULT 0,
      "valid_from" timestamptz NULL,
      "valid_until" timestamptz NULL,
      "rule_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "description" text NULL,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "pk_customer_tier_rule" PRIMARY KEY ("id"),
      CONSTRAINT "fk_customer_tier_rule_tier" FOREIGN KEY ("tier_id") REFERENCES "customer_tier"("id") ON DELETE CASCADE
    )`);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_customer_tier_rule_active" ON "customer_tier_rule" ("is_active", "priority")`,
    );

    await queryRunner.query(
      `ALTER TABLE "customer_profiles" ADD COLUMN IF NOT EXISTS "tier_override_code" text`,
    );
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" ADD COLUMN IF NOT EXISTS "tier_resolved_code" text`,
    );
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" ADD COLUMN IF NOT EXISTS "tier_resolved_at" timestamptz`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_customer_profiles_tier_override" ON "customer_profiles" ("tier_override_code")`,
    );

    // Seed BASE tier if missing
    await queryRunner.query(
      `INSERT INTO "customer_tier" ("code", "name", "priority", "is_active", "config_json", "metadata")
       VALUES ('BASE', 'Base', 0, true, '{}'::jsonb, '{}'::jsonb)
       ON CONFLICT ("code") DO NOTHING`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_customer_profiles_tier_override"`,
    );
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" DROP COLUMN IF EXISTS "tier_resolved_at"`,
    );
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" DROP COLUMN IF EXISTS "tier_resolved_code"`,
    );
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" DROP COLUMN IF EXISTS "tier_override_code"`,
    );

    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_customer_tier_rule_active"`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "customer_tier_rule"`);

    await queryRunner.query(`DROP INDEX IF EXISTS "idx_customer_tier_active"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "customer_tier"`);
  }
}
