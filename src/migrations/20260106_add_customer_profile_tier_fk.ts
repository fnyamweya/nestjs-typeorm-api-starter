import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCustomerProfileTierFk20260106_1768000000000
  implements MigrationInterface
{
  name = 'AddCustomerProfileTierFk20260106_1768000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" ADD COLUMN IF NOT EXISTS "tier_id" uuid`,
    );

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_customer_profiles_tier_id" ON "customer_profiles" ("tier_id")`,
    );

    await queryRunner.query(
      `DO $$
       BEGIN
         IF NOT EXISTS (
           SELECT 1
           FROM information_schema.table_constraints
           WHERE constraint_name = 'fk_customer_profiles_tier'
         ) THEN
           ALTER TABLE "customer_profiles"
             ADD CONSTRAINT "fk_customer_profiles_tier"
             FOREIGN KEY ("tier_id") REFERENCES "customer_tier"("id") ON DELETE SET NULL;
         END IF;
       END$$;`,
    );

    // Backfill tier_id from existing tier_override_code (if any)
    await queryRunner.query(
      `UPDATE "customer_profiles" cp
       SET "tier_id" = ct."id"
       FROM "customer_tier" ct
       WHERE cp."tier_id" IS NULL
         AND cp."tier_override_code" IS NOT NULL
         AND UPPER(cp."tier_override_code") = UPPER(ct."code")`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" DROP CONSTRAINT IF EXISTS "fk_customer_profiles_tier"`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_customer_profiles_tier_id"`,
    );
    await queryRunner.query(
      `ALTER TABLE "customer_profiles" DROP COLUMN IF EXISTS "tier_id"`,
    );
  }
}
