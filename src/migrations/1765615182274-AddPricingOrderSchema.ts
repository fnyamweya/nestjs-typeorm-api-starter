import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPricingOrderSchema1765615182274 implements MigrationInterface {
  name = 'AddPricingOrderSchema1765615182274';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Many installations may not have all of these json/jsonb columns yet.
    // Guard every ALTER so migrations remain forwards-compatible across schemas.
    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'profile_preferences'
                ) THEN
                    ALTER TABLE "users" ALTER COLUMN "profile_preferences" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'price_list' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "price_list" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item_charge' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order_item_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'variant_options_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "variant_options_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'attributes_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "attributes_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'pricing_snapshot_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "pricing_snapshot_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_level_charge' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order_level_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'sales_channel' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "sales_channel" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'category_channel_settings' AND column_name = 'merchandising_json'
                ) THEN
                    ALTER TABLE "category_channel_settings" ALTER COLUMN "merchandising_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'attribute_definition' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "attribute_definition" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'category_attribute' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "category_attribute" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'category' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "category" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'product' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "product" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'product_variant' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "product_variant" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = 'product_variant_price'
                      AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "product_variant_price" ALTER COLUMN "meta_json" SET DEFAULT '{}'::jsonb;
                END IF;
            END $$;
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'product_variant_price' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "product_variant_price" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'product_variant' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "product_variant" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'product' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "product" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'category' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "category" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'category_attribute' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "category_attribute" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'attribute_definition' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "attribute_definition" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'category_channel_settings' AND column_name = 'merchandising_json'
                ) THEN
                    ALTER TABLE "category_channel_settings" ALTER COLUMN "merchandising_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'sales_channel' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "sales_channel" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_level_charge' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order_level_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'pricing_snapshot_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "pricing_snapshot_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'attributes_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "attributes_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item' AND column_name = 'variant_options_json'
                ) THEN
                    ALTER TABLE "order_item" ALTER COLUMN "variant_options_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'order_item_charge' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "order_item_charge" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'price_list' AND column_name = 'meta_json'
                ) THEN
                    ALTER TABLE "price_list" ALTER COLUMN "meta_json" SET DEFAULT '{}';
                END IF;
            END $$;
        `);

    await queryRunner.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'profile_preferences'
                ) THEN
                    ALTER TABLE "users" ALTER COLUMN "profile_preferences" SET DEFAULT '{}';
                END IF;
            END $$;
        `);
  }
}
