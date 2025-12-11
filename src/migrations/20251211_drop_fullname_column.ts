import { MigrationInterface, QueryRunner } from 'typeorm';

export class DropFullnameColumn20251211000000 implements MigrationInterface {
  name = 'DropFullnameColumn20251211000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "users" DROP COLUMN IF EXISTS "fullName"');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "users" ADD COLUMN "fullName" character varying',
    );
  }
}
