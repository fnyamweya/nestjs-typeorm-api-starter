import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProductVariant } from '../../src/catalog/entities/product-variant.entity';
import { Order } from '../../src/order/entities/order.entity';
import { OrderLevelCharge } from '../../src/order/entities/order-level-charge.entity';
import { createTestApp, truncateDb } from '../e2e/bootstrap';

describe('Order Shipping E2E', () => {
  let app: INestApplication;
  let variantRepo: Repository<ProductVariant>;
  let orderRepo: Repository<Order>;
  let chargeRepo: Repository<OrderLevelCharge>;

  beforeAll(async () => {
    try {
      const t = await createTestApp();
      app = t.app;
      await truncateDb(t.ds);

      // run seeders necessary for the test
      const catalogSeeder = app.get(require('../../src/catalog/seeders/catalog.seeder').CatalogSeeder);
      const shippingSeeder = app.get(require('../../src/shipping/seeders/shipping.seeder').ShippingSeeder);
      const settingSeeder = app.get(require('../../src/setting/seeders/setting.seeder').SettingSeeder);

      await catalogSeeder.seed();
      await settingSeeder.seed();
      await shippingSeeder.seed();

      variantRepo = app.get(getRepositoryToken(ProductVariant));
      orderRepo = app.get(getRepositoryToken(Order));
      chargeRepo = app.get(getRepositoryToken(OrderLevelCharge));
    } catch (err) {
      console.error('beforeAll failed in Order Shipping E2E', err);
      throw err;
    }
  }, 120000);

  afterAll(async () => {
    try {
      if (app) await app.close();
    } catch (err) {
      console.error('afterAll failed in Order Shipping E2E', err);
      throw err;
    }
  });

  it('creates an order and applies shipping + tax charges', async () => {
    const variant = await variantRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(variant).toBeDefined();

    const payload = {
      customerEmail: 'buyer@example.com',
      items: [{ productVariantId: variant!.id, quantity: 1 }],
      shippingCountry: 'KE',
    };

    const res = await request(app.getHttpServer()).post('/orders').send(payload).expect(201);
    const body = res.body;
    expect(body).toBeDefined();
    const orderId = body.data?.id || body.id;
    expect(orderId).toBeDefined();

    // Get order from DB and verify charges
    const order = await orderRepo.findOne({ where: { id: orderId } });
    expect(order).toBeDefined();

    const charges = await chargeRepo.find({ where: { orderId: orderId } });
    // should include shipping and tax
    const shippingCharge = charges.find((c) => c.chargeKind === 'shipping');
    const taxCharge = charges.find((c) => c.chargeKind === 'tax');

    expect(shippingCharge).toBeDefined();
    expect(shippingCharge!.amount).toBeDefined();
    // standard kenya flat rate for subtotal 200 should be 50
    expect(parseFloat(shippingCharge!.amount)).toBeCloseTo(50, 2);

    expect(taxCharge).toBeDefined();
    // tax 16% on (200 + 50) = 40
    expect(parseFloat(taxCharge!.amount)).toBeCloseTo(40, 2);

    // grand total should be 290 (200 + 50 + 40)
    expect(parseFloat(order!.grandTotal)).toBeCloseTo(290, 2);
  });
});
