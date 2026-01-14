import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCollectionsTables20260114120000
  implements MigrationInterface
{
  name = 'AddCollectionsTables20260114120000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "collection" (
        "id" uuid NOT NULL,
        "title" text NOT NULL,
        "description" text,
        "slug" text NOT NULL,
        "type" text NOT NULL DEFAULT 'default',
        "rule_type" text NOT NULL DEFAULT 'STATIC',
        "rule_payload" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "is_active" boolean NOT NULL DEFAULT true,
        "priority" integer NOT NULL DEFAULT 0,
        "valid_from" TIMESTAMPTZ,
        "valid_to" TIMESTAMPTZ,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT "PK_collection_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_collection_slug" UNIQUE ("slug")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_collection_active_type" ON "collection" ("is_active", "type")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_collection_validity" ON "collection" ("valid_from", "valid_to")
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "collection_item" (
        "id" uuid NOT NULL,
        "collection_id" uuid NOT NULL,
        "product_id" uuid NOT NULL,
        "position" integer NOT NULL DEFAULT 0,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT "PK_collection_item_id" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_collection_item_collection_position" ON "collection_item" ("collection_id", "position")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_collection_item_product" ON "collection_item" ("product_id")
    `);

    await queryRunner.query(`
      ALTER TABLE "collection_item"
      ADD CONSTRAINT "FK_collection_item_collection" FOREIGN KEY ("collection_id") REFERENCES "collection"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE "collection_item"
      ADD CONSTRAINT "FK_collection_item_product" FOREIGN KEY ("product_id") REFERENCES "product"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "collection_item" DROP CONSTRAINT "FK_collection_item_product"',
    );
    await queryRunner.query(
      'ALTER TABLE "collection_item" DROP CONSTRAINT "FK_collection_item_collection"',
    );
    await queryRunner.query(
      'DROP INDEX IF EXISTS "IDX_collection_item_product"',
    );
    await queryRunner.query(
      'DROP INDEX IF EXISTS "IDX_collection_item_collection_position"',
    );
    await queryRunner.query('DROP TABLE IF EXISTS "collection_item"');
    await queryRunner.query('DROP INDEX IF EXISTS "IDX_collection_validity"');
    await queryRunner.query('DROP INDEX IF EXISTS "IDX_collection_active_type"');
    await queryRunner.query('DROP TABLE IF EXISTS "collection"');
  }
}
