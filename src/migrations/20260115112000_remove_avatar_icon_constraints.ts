import { MigrationInterface, QueryRunner } from 'typeorm';

export class RemoveAvatarIconConstraints20260115112000
  implements MigrationInterface
{
  name = 'RemoveAvatarIconConstraints20260115112000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "category" DROP CONSTRAINT IF EXISTS "ck_category_icon_avatar"',
    );
    await queryRunner.query(
      'ALTER TABLE "taxonomy" DROP CONSTRAINT IF EXISTS "ck_taxonomy_icon_avatar"',
    );
    await queryRunner.query(
      'ALTER TABLE "brand" DROP CONSTRAINT IF EXISTS "ck_brand_icon_avatar"',
    );
    await queryRunner.query(
      'ALTER TABLE "collection" DROP CONSTRAINT IF EXISTS "ck_collection_icon_avatar"',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "category" ADD CONSTRAINT "ck_category_icon_avatar" CHECK (NOT ("icon" IS NOT NULL AND "avatar_url" IS NOT NULL))',
    );
    await queryRunner.query(
      'ALTER TABLE "taxonomy" ADD CONSTRAINT "ck_taxonomy_icon_avatar" CHECK (NOT ("icon" IS NOT NULL AND "avatar_url" IS NOT NULL))',
    );
    await queryRunner.query(
      'ALTER TABLE "brand" ADD CONSTRAINT "ck_brand_icon_avatar" CHECK (NOT ("icon" IS NOT NULL AND "avatar_url" IS NOT NULL))',
    );
    await queryRunner.query(
      'ALTER TABLE "collection" ADD CONSTRAINT "ck_collection_icon_avatar" CHECK (NOT ("icon" IS NOT NULL AND "avatar_url" IS NOT NULL))',
    );
  }
}
