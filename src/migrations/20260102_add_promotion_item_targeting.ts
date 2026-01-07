import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPromotionItemTargeting20260102_1760000000001
  implements MigrationInterface
{
  name = 'AddPromotionItemTargeting20260102_1760000000001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Extend the promotion_condition_type_enum with item targeting options.
    // Postgres enums cannot be easily removed in down migrations; we keep down as a no-op.

    await queryRunner.query(`DO $$ BEGIN
      BEGIN
        ALTER TYPE "promotion_condition_type_enum" ADD VALUE 'item_in_product';
      EXCEPTION
        WHEN duplicate_object THEN null;
      END;
    END $$;`);

    await queryRunner.query(`DO $$ BEGIN
      BEGIN
        ALTER TYPE "promotion_condition_type_enum" ADD VALUE 'item_in_taxonomy';
      EXCEPTION
        WHEN duplicate_object THEN null;
      END;
    END $$;`);
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    // no-op (cannot reliably remove enum values)
  }
}
