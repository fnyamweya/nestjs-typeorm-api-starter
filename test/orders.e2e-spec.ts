import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProductVariant } from '../src/catalog/entities/product-variant.entity';
import { OrderLevelCharge } from '../src/order/entities/order-level-charge.entity';
import { createTestApp, truncateDb } from './e2e/bootstrap';


describe('Orders E2E - Shipping integration', () => {
  let app: INestApplication;
  let variantRepo: Repository<ProductVariant>;
  let chargeRepo: Repository<OrderLevelCharge>;

  beforeAll(async () => {
    try {
      const t = await createTestApp();
      app = t.app;

      // ensure a clean DB and run seeders via existing seed entrypoint
      await truncateDb(t.ds);
      const settingSeeder = app.get(require('../src/setting/seeders/setting.seeder').SettingSeeder);
      const catalogSeeder = app.get(require('../src/catalog/seeders/catalog.seeder').CatalogSeeder);
      const shippingSeeder = app.get(require('../src/shipping/seeders/shipping.seeder').ShippingSeeder);
      await settingSeeder.seed();
      await catalogSeeder.seed();
      await shippingSeeder.seed();

      variantRepo = app.get(getRepositoryToken(ProductVariant));
      chargeRepo = app.get(getRepositoryToken(OrderLevelCharge));
    } catch (err) {
      console.error('beforeAll failed in Orders E2E', err);
      throw err;
    }
  }, 120000);

  afterAll(async () => {
    try {
      if (app) await app.close();
    } catch (err) {
      console.error('afterAll failed closing app in Orders E2E', err);
      throw err;
    }
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
