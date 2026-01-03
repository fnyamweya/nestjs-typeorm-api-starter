import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddTaxonomyIsActive20260101170000 implements MigrationInterface {
  name = 'AddTaxonomyIsActive20260101170000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "taxonomy"
      ADD COLUMN IF NOT EXISTS "is_active" BOOLEAN NOT NULL DEFAULT TRUE;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "taxonomy"
      DROP COLUMN IF EXISTS "is_active";
    `);
  }
}
