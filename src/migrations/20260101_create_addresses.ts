import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateAddresses20260101_1767225599000
  implements MigrationInterface
{
  name = 'CreateAddresses20260101_1767225599000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "address" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "full_name" text,
        "phone" text,
        "country_code" char(2) NOT NULL,
        "region" text,
        "city" text,
        "postal_code" text,
        "address_line1" text NOT NULL,
        "address_line2" text,
        "notes" text,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now()
      );
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "customer_address" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "user_id" uuid NOT NULL,
        "address_id" uuid NOT NULL,
        "type" text NOT NULL,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "uq_customer_address_user_type" UNIQUE ("user_id", "type"),
        CONSTRAINT "fk_customer_address_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_customer_address_address" FOREIGN KEY ("address_id") REFERENCES "address"("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_customer_address_user_id" ON "customer_address" ("user_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_customer_address_type" ON "customer_address" ("type");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_customer_address_type";`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_customer_address_user_id";`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "customer_address";`);
    await queryRunner.query(`DROP TABLE IF EXISTS "address";`);
  }
}
