import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddWhatsappTemplates20260108_1760340000000
  implements MigrationInterface
{
  name = 'AddWhatsappTemplates20260108_1760340000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "whatsapp_template" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "name" text NOT NULL,
        "language" text NOT NULL DEFAULT 'en_US',
        "category" text NOT NULL,
        "status" text NOT NULL DEFAULT 'draft',
        "provider_template_id" text,
        "is_active" boolean NOT NULL DEFAULT true,
        "components_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "default_components_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "uq_whatsapp_template_name" UNIQUE ("name")
      );
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE IF EXISTS "whatsapp_template"');
  }
}
