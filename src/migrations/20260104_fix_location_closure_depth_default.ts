import { MigrationInterface, QueryRunner } from 'typeorm';

export class FixLocationClosureDepthDefault20260104_1767480000000
  implements MigrationInterface
{
  name = 'FixLocationClosureDepthDefault20260104_1767480000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // TypeORM's closure-table tree operations insert into the closure table
    // without specifying a "depth" column. Our initial migration created
    // "depth" as NOT NULL with no default, which breaks inserts.
    // If the table exists but was created earlier without a "depth" column,
    // add it so closure-table operations can function.
    await queryRunner.query(
      `ALTER TABLE "location_closure" ADD COLUMN IF NOT EXISTS "depth" int NOT NULL DEFAULT 0;`,
    );

    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'location_closure'
            AND column_name = 'depth'
        ) THEN
          ALTER TABLE "location_closure" ALTER COLUMN "depth" SET DEFAULT 0;
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'location_closure'
            AND column_name = 'depth'
        ) THEN
          ALTER TABLE "location_closure" ALTER COLUMN "depth" DROP DEFAULT;
        END IF;
      END $$;
    `);
  }
}
