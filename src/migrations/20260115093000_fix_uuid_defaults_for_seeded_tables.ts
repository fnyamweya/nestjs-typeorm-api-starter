import { MigrationInterface, QueryRunner } from 'typeorm';

export class FixUuidDefaultsForSeededTables20260115093000
  implements MigrationInterface
{
  name = 'FixUuidDefaultsForSeededTables20260115093000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Ensure we have a UUID generator available.
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');

    // Collections tables were created without UUID defaults, causing inserts to fail.
    await queryRunner.query(
      'ALTER TABLE "collection" ALTER COLUMN "id" SET DEFAULT gen_random_uuid()',
    );
    await queryRunner.query(
      'ALTER TABLE "collection_item" ALTER COLUMN "id" SET DEFAULT gen_random_uuid()',
    );

    // Reviews table should also have an ID default.
    await queryRunner.query(
      'ALTER TABLE "product_review" ALTER COLUMN "id" SET DEFAULT gen_random_uuid()',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "product_review" ALTER COLUMN "id" DROP DEFAULT',
    );
    await queryRunner.query(
      'ALTER TABLE "collection_item" ALTER COLUMN "id" DROP DEFAULT',
    );
    await queryRunner.query('ALTER TABLE "collection" ALTER COLUMN "id" DROP DEFAULT');
  }
}
