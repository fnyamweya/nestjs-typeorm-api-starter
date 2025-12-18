import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { SettingSeeder } from '../src/setting/seeders/setting.seeder';
import { CatalogSeeder } from '../src/catalog/seeders/catalog.seeder';
import { ShippingSeeder } from '../src/shipping/seeders/shipping.seeder';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProductVariant } from '../src/catalog/entities/product-variant.entity';
import { OrderLevelCharge } from '../src/order/entities/order-level-charge.entity';

describe('Orders E2E - Shipping integration', () => {
  let app: INestApplication;
  let variantRepo: Repository<ProductVariant>;
  let chargeRepo: Repository<OrderLevelCharge>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    await app.init();

    // Run seeders (settings, catalog, shipping)
    const settingSeeder = moduleRef.get(SettingSeeder);
    const catalogSeeder = moduleRef.get(CatalogSeeder);
    const shippingSeeder = moduleRef.get(ShippingSeeder);

    await settingSeeder.seed();
    await catalogSeeder.seed();
    await shippingSeeder.seed();

    variantRepo = moduleRef.get(getRepositoryToken(ProductVariant));
    chargeRepo = moduleRef.get(getRepositoryToken(OrderLevelCharge));
  }, 20000);

  afterAll(async () => {
    await app.close();
  });

  it('creates an order and persists shipping and tax charges', async () => {
    const variant = await variantRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(variant).toBeDefined();

    if (!variant) {
      throw new Error('Variant not found');
    }

    const payload = {
      customerEmail: 'e2e@example.com',
      items: [{ productVariantId: variant.id, quantity: 2 }],
      shippingCountry: 'KE',
    };

    const res = await request(app.getHttpServer()).post('/orders').send(payload).expect(201);

    const createdOrder = res.body.data;
    expect(createdOrder).toBeDefined();
    expect(createdOrder.itemsSubtotal).toBeDefined();

    // Fetch order level charges
    const charges = await chargeRepo.find({ where: { orderId: createdOrder.id } });
    // Expect shipping and tax charges (no discount for this subtotal)
    const shippingCharges = charges.filter((c) => c.chargeKind === 'shipping');
    const taxCharges = charges.filter((c) => c.chargeKind === 'tax');

    expect(shippingCharges.length).toBeGreaterThan(0);
    expect(taxCharges.length).toBeGreaterThan(0);

    // Check totals compute correctly: items subtotal = 200*2 = 400, shipping 50 (Kenya flat), tax 16% on 450 = 72
    expect(createdOrder.grandTotal).toBe('522.0000');
    expect(createdOrder.taxTotal).toBe('72.0000');
  }, 20000);
});
