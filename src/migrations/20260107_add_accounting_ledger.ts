import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAccountingLedger20260107060000 implements MigrationInterface {
  name = 'AddAccountingLedger20260107060000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "accounting_account" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "code" text NOT NULL,
        "name" text NOT NULL,
        "type" text NOT NULL,
        "is_active" boolean NOT NULL DEFAULT TRUE,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        "updated_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_accounting_account" PRIMARY KEY ("id"),
        CONSTRAINT "uq_accounting_account_code" UNIQUE ("code")
      );
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "journal_entry" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "source_type" text,
        "source_id" text,
        "idempotency_key" text NOT NULL,
        "currency_code" char(3) NOT NULL,
        "posted_at" timestamptz NOT NULL DEFAULT now(),
        "memo" text,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_journal_entry" PRIMARY KEY ("id"),
        CONSTRAINT "uq_journal_entry_idempotency_key" UNIQUE ("idempotency_key")
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_journal_entry_source" ON "journal_entry" ("source_type", "source_id")`,
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "journal_entry_line" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "entry_id" uuid NOT NULL,
        "account_id" uuid NOT NULL,
        "debit" numeric(18,4) NOT NULL DEFAULT 0,
        "credit" numeric(18,4) NOT NULL DEFAULT 0,
        "currency_code" char(3) NOT NULL,
        "memo" text,
        "meta_json" jsonb NOT NULL DEFAULT '{}'::jsonb,
        "created_at" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "pk_journal_entry_line" PRIMARY KEY ("id"),
        CONSTRAINT "fk_journal_entry_line_entry" FOREIGN KEY ("entry_id") REFERENCES "journal_entry"("id") ON DELETE CASCADE,
        CONSTRAINT "fk_journal_entry_line_account" FOREIGN KEY ("account_id") REFERENCES "accounting_account"("id") ON DELETE RESTRICT,
        CONSTRAINT "ck_journal_entry_line_nonnegative" CHECK ("debit" >= 0 AND "credit" >= 0),
        CONSTRAINT "ck_journal_entry_line_one_sided" CHECK (("debit" = 0) <> ("credit" = 0))
      );
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_journal_entry_line_entry" ON "journal_entry_line" ("entry_id")`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_journal_entry_line_account" ON "journal_entry_line" ("account_id")`,
    );

    // Enforce: sum(debit) == sum(credit) per entry at transaction commit.
    await queryRunner.query(`
      CREATE OR REPLACE FUNCTION enforce_journal_entry_balanced() RETURNS trigger AS $$
      DECLARE
        v_entry_id uuid;
        v_debit_sum numeric(18,4);
        v_credit_sum numeric(18,4);
      BEGIN
        v_entry_id := COALESCE(NEW.entry_id, OLD.entry_id);

        SELECT COALESCE(SUM(jel.debit), 0), COALESCE(SUM(jel.credit), 0)
          INTO v_debit_sum, v_credit_sum
        FROM journal_entry_line jel
        WHERE jel.entry_id = v_entry_id;

        IF v_debit_sum <> v_credit_sum THEN
          RAISE EXCEPTION 'Journal entry % is unbalanced (debit %, credit %)', v_entry_id, v_debit_sum, v_credit_sum;
        END IF;

        RETURN NULL;
      END;
      $$ LANGUAGE plpgsql;
    `);

    await queryRunner.query(`
      DROP TRIGGER IF EXISTS trg_journal_entry_balanced ON journal_entry_line;
    `);

    await queryRunner.query(`
      CREATE CONSTRAINT TRIGGER trg_journal_entry_balanced
      AFTER INSERT OR UPDATE OR DELETE
      ON journal_entry_line
      DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW
      EXECUTE FUNCTION enforce_journal_entry_balanced();
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TRIGGER IF EXISTS trg_journal_entry_balanced ON journal_entry_line`);
    await queryRunner.query(`DROP FUNCTION IF EXISTS enforce_journal_entry_balanced`);

    await queryRunner.query(`DROP TABLE IF EXISTS "journal_entry_line"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "journal_entry"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "accounting_account"`);
  }
}
