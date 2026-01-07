import { MigrationInterface, QueryRunner } from 'typeorm';

export class MakeChargeTablesAppendOnly20260106_1768000000000
  implements MigrationInterface
{
  name = 'MakeChargeTablesAppendOnly20260106_1768000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Enforce append-only ledger semantics: prevent UPDATE/DELETE on charge tables.
    await queryRunner.query(`
      CREATE OR REPLACE FUNCTION prevent_charge_row_modification()
      RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'Charge rows are append-only; use reversal rows instead.';
      END;
      $$ LANGUAGE plpgsql;
    `);

    await queryRunner.query(`
      DROP TRIGGER IF EXISTS trg_order_level_charge_no_update_delete ON "order_level_charge";
      CREATE TRIGGER trg_order_level_charge_no_update_delete
      BEFORE UPDATE OR DELETE ON "order_level_charge"
      FOR EACH ROW EXECUTE FUNCTION prevent_charge_row_modification();
    `);

    await queryRunner.query(`
      DROP TRIGGER IF EXISTS trg_order_item_charge_no_update_delete ON "order_item_charge";
      CREATE TRIGGER trg_order_item_charge_no_update_delete
      BEFORE UPDATE OR DELETE ON "order_item_charge"
      FOR EACH ROW EXECUTE FUNCTION prevent_charge_row_modification();
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TRIGGER IF EXISTS trg_order_item_charge_no_update_delete ON "order_item_charge";`,
    );
    await queryRunner.query(
      `DROP TRIGGER IF EXISTS trg_order_level_charge_no_update_delete ON "order_level_charge";`,
    );
    await queryRunner.query(
      `DROP FUNCTION IF EXISTS prevent_charge_row_modification();`,
    );
  }
}
