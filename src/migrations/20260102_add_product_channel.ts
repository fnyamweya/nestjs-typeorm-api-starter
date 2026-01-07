import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddProductChannel20260102_1767390000001
  implements MigrationInterface
{
  name = 'AddProductChannel20260102_1767390000001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "product_channel" (
      "product_id" uuid NOT NULL,
      "channel_id" uuid NOT NULL,
      "is_active" boolean NOT NULL DEFAULT true,
      CONSTRAINT "pk_product_channel" PRIMARY KEY ("product_id", "channel_id"),
      CONSTRAINT "fk_product_channel_product" FOREIGN KEY ("product_id") REFERENCES "product"("id") ON DELETE CASCADE,
      CONSTRAINT "fk_product_channel_channel" FOREIGN KEY ("channel_id") REFERENCES "channel"("id") ON DELETE CASCADE
    )`);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_product_channel_active" ON "product_channel" ("product_id", "is_active")`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_product_channel_channel" ON "product_channel" ("channel_id")`,
    );

    // Backfill from product.availability_json.channels (if present)
    await queryRunner.query(`
      INSERT INTO "product_channel" ("product_id", "channel_id", "is_active")
      SELECT p.id, c.id, true
      FROM "product" p
      JOIN LATERAL jsonb_array_elements_text(COALESCE(p.availability_json->'channels', '[]'::jsonb)) AS ch(code) ON true
      JOIN "channel" c ON upper(c.code) = upper(ch.code)
      ON CONFLICT ("product_id", "channel_id") DO NOTHING
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_product_channel_channel"`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_product_channel_active"`,
    );
    await queryRunner.query(`DROP TABLE IF EXISTS "product_channel"`);
  }
}
