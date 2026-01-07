import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddTaxonomyMetaJson20260101180500 implements MigrationInterface {
  name = 'AddTaxonomyMetaJson20260101180500';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "taxonomy"
      ADD COLUMN IF NOT EXISTS "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "taxonomy" DROP COLUMN IF EXISTS "meta_json";`,
    );
  }
}
