import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateLocations20260103_1767400000000
  implements MigrationInterface
{
  name = 'CreateLocations20260103_1767400000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "location" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "country_code" char(2),
        "name" text NOT NULL,
        "code" text,
        "type" text NOT NULL,
        "parent_id" uuid,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "fk_location_parent" FOREIGN KEY ("parent_id") REFERENCES "location" ("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_location_parent_id" ON "location" ("parent_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_location_country_code" ON "location" ("country_code");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_location_type" ON "location" ("type");`,
    );

    // Closure table for TypeORM Tree("closure-table")
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "location_closure" (
        "id_ancestor" uuid NOT NULL,
        "id_descendant" uuid NOT NULL,
        "depth" int NOT NULL,
        CONSTRAINT "pk_location_closure" PRIMARY KEY ("id_ancestor", "id_descendant"),
        CONSTRAINT "fk_location_closure_ancestor" FOREIGN KEY ("id_ancestor") REFERENCES "location" ("id") ON DELETE CASCADE,
        CONSTRAINT "fk_location_closure_descendant" FOREIGN KEY ("id_descendant") REFERENCES "location" ("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_location_closure_descendant" ON "location_closure" ("id_descendant");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "location_closure" CASCADE;`);
    await queryRunner.query(`DROP TABLE IF EXISTS "location" CASCADE;`);
  }
}
