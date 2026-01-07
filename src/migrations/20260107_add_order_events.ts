import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOrderEvents20260107103000 implements MigrationInterface {
  name = 'AddOrderEvents20260107103000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "order_event" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "order_id" uuid NOT NULL,
        "target_type" text NOT NULL,
        "target_id" uuid NOT NULL,
        "order_item_id" uuid,
        "fulfillment_id" uuid,
        "package_id" uuid,
        "action" text NOT NULL,
        "idempotency_key" text NOT NULL,
        "actor_type" text,
        "actor_id" text,
        "actor_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "previous_event_id" uuid,
        "previous_action" text,
        "previous_created_at" timestamptz,
        "next_action" text,
        "next_actions_json" jsonb NOT NULL DEFAULT '[]'::jsonb,
        "context_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_order_event" PRIMARY KEY ("id"),
        CONSTRAINT "fk_order_event_order" FOREIGN KEY ("order_id") REFERENCES "order"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_order_event_order_item" FOREIGN KEY ("order_item_id") REFERENCES "order_item"("id") ON DELETE SET NULL,
        CONSTRAINT "fk_order_event_fulfillment" FOREIGN KEY ("fulfillment_id") REFERENCES "order_fulfillment"("id") ON DELETE SET NULL,
        CONSTRAINT "fk_order_event_package" FOREIGN KEY ("package_id") REFERENCES "fulfillment_package"("id") ON DELETE SET NULL
      );
    `);

    await queryRunner.query('CREATE UNIQUE INDEX IF NOT EXISTS "uq_order_event_idempotency" ON "order_event" ("idempotency_key")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_event_order_created" ON "order_event" ("order_id", "created_at")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_event_target" ON "order_event" ("target_type", "target_id", "created_at")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_event_order_item" ON "order_event" ("order_item_id")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_event_fulfillment" ON "order_event" ("fulfillment_id")');
    await queryRunner.query('CREATE INDEX IF NOT EXISTS "idx_order_event_package" ON "order_event" ("package_id")');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE IF EXISTS "order_event"');
  }
}
