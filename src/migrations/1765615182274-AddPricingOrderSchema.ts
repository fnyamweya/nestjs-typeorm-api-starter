import { MigrationInterface, QueryRunner } from "typeorm";

export class AddPricingOrderSchema1765615182274 implements MigrationInterface {
    name = 'AddPricingOrderSchema1765615182274'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "profile_preferences" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "price_list" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "order_item_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "variant_options_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "attributes_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "pricing_snapshot_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "order_level_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "order" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "sales_channel" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "category_channel_settings" ALTER COLUMN "merchandising_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "attribute_definition" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "category_attribute" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "category" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "product" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "product_variant" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
        await queryRunner.query(`ALTER TABLE "product_variant_price" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "product_variant_price" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "product_variant" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "product" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "category" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "category_attribute" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "attribute_definition" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "category_channel_settings" ALTER COLUMN "merchandising_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "sales_channel" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "order" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "order_level_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "pricing_snapshot_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "attributes_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "order_item" ALTER COLUMN "variant_options_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "order_item_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "price_list" ALTER COLUMN "meta_json" SET DEFAULT '{}'`);
        await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "profile_preferences" SET DEFAULT '{}'`);
    }

}

