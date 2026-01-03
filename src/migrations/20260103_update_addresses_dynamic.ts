import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateAddressesDynamic20260103_1767400001000
  implements MigrationInterface
{
  name = 'UpdateAddressesDynamic20260103_1767400001000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    await queryRunner.query(
      `ALTER TABLE "address" ADD COLUMN IF NOT EXISTS "location_id" uuid;`,
    );
    await queryRunner.query(
      `ALTER TABLE "address" ADD COLUMN IF NOT EXISTS "fields_json" jsonb NOT NULL DEFAULT '{}'::jsonb;`,
    );

    // Make legacy address_line1 optional for dynamic schemas
    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'address'
            AND column_name = 'address_line1'
        ) THEN
          ALTER TABLE "address" ALTER COLUMN "address_line1" DROP NOT NULL;
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Best-effort rollback
    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'address'
            AND column_name = 'address_line1'
        ) THEN
          ALTER TABLE "address" ALTER COLUMN "address_line1" SET NOT NULL;
        END IF;
      END $$;
    `);
    await queryRunner.query(
      `ALTER TABLE "address" DROP COLUMN IF EXISTS "fields_json";`,
    );
    await queryRunner.query(
      `ALTER TABLE "address" DROP COLUMN IF EXISTS "location_id";`,
    );
  }
}
