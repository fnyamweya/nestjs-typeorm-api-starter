import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddProductReviewsAndRatings20260115090000
  implements MigrationInterface
{
  name = 'AddProductReviewsAndRatings20260115090000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_review" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "product_id" uuid NOT NULL,
        "customer_id" uuid NOT NULL,
        "rating" integer NOT NULL,
        "title" text,
        "body" text,
        "media_urls_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "is_verified_purchase" boolean NOT NULL DEFAULT false,
        "status" text NOT NULL DEFAULT 'PENDING',
        "status_reason" text,
        "moderated_by_user_id" uuid,
        "moderated_at" TIMESTAMPTZ,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT "PK_product_review_id" PRIMARY KEY ("id"),
        CONSTRAINT "CHK_product_review_rating" CHECK ("rating" >= 1 AND "rating" <= 5),
        CONSTRAINT "UQ_product_review_customer_product" UNIQUE ("customer_id", "product_id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_product_review_product_status_created" ON "product_review" ("product_id", "status", "created_at")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_product_review_customer" ON "product_review" ("customer_id")
    `);

    await queryRunner.query(`
      ALTER TABLE "product_review"
      ADD CONSTRAINT "FK_product_review_product" FOREIGN KEY ("product_id") REFERENCES "product"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE "product_review"
      ADD CONSTRAINT "FK_product_review_customer" FOREIGN KEY ("customer_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE "product_review"
      ADD CONSTRAINT "FK_product_review_moderated_by" FOREIGN KEY ("moderated_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "product_rating_summary" (
        "product_id" uuid NOT NULL,
        "rating_count" integer NOT NULL DEFAULT 0,
        "avg_rating" numeric(10,4) NOT NULL DEFAULT 0,
        "star_1_count" integer NOT NULL DEFAULT 0,
        "star_2_count" integer NOT NULL DEFAULT 0,
        "star_3_count" integer NOT NULL DEFAULT 0,
        "star_4_count" integer NOT NULL DEFAULT 0,
        "star_5_count" integer NOT NULL DEFAULT 0,
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT "PK_product_rating_summary_product_id" PRIMARY KEY ("product_id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_product_rating_summary_updated" ON "product_rating_summary" ("updated_at")
    `);

    await queryRunner.query(`
      ALTER TABLE "product_rating_summary"
      ADD CONSTRAINT "FK_product_rating_summary_product" FOREIGN KEY ("product_id") REFERENCES "product"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'ALTER TABLE "product_rating_summary" DROP CONSTRAINT "FK_product_rating_summary_product"',
    );
    await queryRunner.query('DROP INDEX IF EXISTS "IDX_product_rating_summary_updated"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_rating_summary"');

    await queryRunner.query(
      'ALTER TABLE "product_review" DROP CONSTRAINT "FK_product_review_moderated_by"',
    );
    await queryRunner.query(
      'ALTER TABLE "product_review" DROP CONSTRAINT "FK_product_review_customer"',
    );
    await queryRunner.query(
      'ALTER TABLE "product_review" DROP CONSTRAINT "FK_product_review_product"',
    );
    await queryRunner.query('DROP INDEX IF EXISTS "IDX_product_review_customer"');
    await queryRunner.query('DROP INDEX IF EXISTS "IDX_product_review_product_status_created"');
    await queryRunner.query('DROP TABLE IF EXISTS "product_review"');
  }
}
