import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAvatarIconFieldsToCatalog20260115103000
  implements MigrationInterface
{
  name = 'AddAvatarIconFieldsToCatalog20260115103000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "category" ADD COLUMN "avatar_url" text');

    await queryRunner.query('ALTER TABLE "taxonomy" ADD COLUMN "icon" text');
    await queryRunner.query('ALTER TABLE "taxonomy" ADD COLUMN "avatar_url" text');

    await queryRunner.query('ALTER TABLE "brand" ADD COLUMN "icon" text');
    await queryRunner.query('ALTER TABLE "brand" ADD COLUMN "avatar_url" text');

    await queryRunner.query('ALTER TABLE "collection" ADD COLUMN "icon" text');
    await queryRunner.query('ALTER TABLE "collection" ADD COLUMN "avatar_url" text');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "collection" DROP COLUMN "avatar_url"');
    await queryRunner.query('ALTER TABLE "collection" DROP COLUMN "icon"');

    await queryRunner.query('ALTER TABLE "brand" DROP COLUMN "avatar_url"');
    await queryRunner.query('ALTER TABLE "brand" DROP COLUMN "icon"');

    await queryRunner.query('ALTER TABLE "taxonomy" DROP COLUMN "avatar_url"');
    await queryRunner.query('ALTER TABLE "taxonomy" DROP COLUMN "icon"');

    await queryRunner.query('ALTER TABLE "category" DROP COLUMN "avatar_url"');
  }
}
