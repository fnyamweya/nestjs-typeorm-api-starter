import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateMpesaTransactions20260101_1767225600000
  implements MigrationInterface
{
  name = 'CreateMpesaTransactions20260101_1767225600000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE IF NOT EXISTS "mpesa_transaction" (
      "id" bigserial PRIMARY KEY,
      "order_id" bigint,
      "type" text NOT NULL,
      "status" text NOT NULL,
      "originator_conversation_id" text,
      "conversation_id" text,
      "transaction_id" text,
      "result_code" int,
      "result_desc" text,
      "amount" numeric(18,4),
      "msisdn" text,
      "bill_ref_number" text,
      "account_reference" text,
      "party_a" text,
      "party_b" text,
      "remarks" text,
      "raw_request_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "raw_response_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "raw_callback_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "fk_mpesa_tx_order" FOREIGN KEY ("order_id") REFERENCES "order" ("id") ON DELETE SET NULL
    );`);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_mpesa_tx_order_id" ON "mpesa_transaction" ("order_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_mpesa_tx_type" ON "mpesa_transaction" ("type");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_mpesa_tx_status" ON "mpesa_transaction" ("status");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_mpesa_tx_originator_conversation_id" ON "mpesa_transaction" ("originator_conversation_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_mpesa_tx_conversation_id" ON "mpesa_transaction" ("conversation_id");`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_mpesa_tx_transaction_id" ON "mpesa_transaction" ("transaction_id");`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TABLE IF EXISTS "mpesa_transaction" CASCADE;`,
    );
  }
}
