import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { SettingSeeder } from '../src/setting/seeders/setting.seeder';
import { CatalogSeeder } from '../src/catalog/seeders/catalog.seeder';
import { ShippingSeeder } from '../src/shipping/seeders/shipping.seeder';
import { DataSource } from 'typeorm';
import { ShippingZone } from '../src/shipping/entities/shipping-zone.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProductVariant } from '../src/catalog/entities/product-variant.entity';
import { OrderLevelCharge } from '../src/order/entities/order-level-charge.entity';
import { ShippingMethod } from '../src/shipping/entities/shipping-method.entity';
import { ShippingRate } from '../src/shipping/entities/shipping-rate.entity';

describe('Orders E2E - Formula shipping integration', () => {
  let app: INestApplication;
  let variantRepo: Repository<ProductVariant>;
  let chargeRepo: Repository<OrderLevelCharge>;
  let methodRepo: Repository<ShippingMethod>;
  let rateRepo: Repository<ShippingRate>;
  let ds: DataSource;
  let kenyaZone: ShippingZone | undefined;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    await app.init();

    // Ensure a clean DB (truncate all public tables) to avoid flakiness between runs
    ds = moduleRef.get(DataSource);
    const tables: Array<{ tablename: string }> = await ds.query(`
      SELECT tablename FROM pg_tables 
      WHERE schemaname = 'public' 
      AND tablename NOT LIKE 'pg_%' 
      AND tablename != 'information_schema'
    `);
    if (tables.length) {
      const list = tables.map((t) => `"${t.tablename}"`).join(', ');
      await ds.query(`TRUNCATE TABLE ${list} CASCADE;`);
    }

    // Run seeders (settings, catalog, shipping)
    const settingSeeder = moduleRef.get(SettingSeeder);
    const catalogSeeder = moduleRef.get(CatalogSeeder);
    const shippingSeeder = moduleRef.get(ShippingSeeder);

    try {
      await settingSeeder.seed();
      await catalogSeeder.seed();
      await shippingSeeder.seed();
    } catch (err) {
      // Surface seeder errors with context
      console.error('Seeder failed during e2e setup', err);
      throw err;
    }

    variantRepo = moduleRef.get(getRepositoryToken(ProductVariant));
    chargeRepo = moduleRef.get(getRepositoryToken(OrderLevelCharge));
    methodRepo = moduleRef.get(getRepositoryToken(ShippingMethod));
    rateRepo = moduleRef.get(getRepositoryToken(ShippingRate));

    // Ensure we have the Kenya zone and use it explicitly for the formula method
    const zone = (await ds.query(`SELECT * FROM shipping_zone WHERE code = 'kenya' LIMIT 1`))[0];
    if (!zone) throw new Error('Kenya shipping zone not found after seeding');
    kenyaZone = zone as any;
  }, 120000);

  afterAll(async () => {
    await app.close();
  });

  it('creates an order using a formula rate and persists expected shipping charge', async () => {
    const variant = await variantRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(variant).toBeDefined();
    if (!variant) throw new Error('Variant not found');

    // Create a high-priority formula method/rate for Kenya
    if (!kenyaZone) throw new Error('Kenya zone not available');
    const m = methodRepo.create({ zoneId: kenyaZone.id, code: 'formula-method', displayName: 'Formula Shipping' });
    const savedMethod = await methodRepo.save(m);

    const r = rateRepo.create({ methodId: savedMethod.id, calculationType: 'formula', price: '0', priority: 100, metaJson: { formula: 'subtotal * 0.05' } });
    await rateRepo.save(r);

    // sanity check: ensure ShippingMatrixService returns expected quote for KE
    const shippingMatrixService = app.get(require('../src/shipping/services/shipping-matrix.service').ShippingMatrixService);

    // Set variant weight so per_weight routes produce non-zero amounts and priority tie-breakers favor formula
    await variantRepo.update({ sku: 'PHONE-001' } as any, { weight: '1' } as any);

    const quotes = await shippingMatrixService.getQuotes({ countryCode: 'KE', subtotal: 400, totalWeight: 1, itemCount: 2, currencyCode: 'KES' });
    expect(quotes.length).toBeGreaterThan(0);
    expect(quotes[0].method.code).toBe('formula-method');
    expect(quotes[0].amount).toBeCloseTo(400 * 0.05, 6);

    const payload = {
      customerEmail: 'e2e-formula@example.com',
      items: [{ productVariantId: variant.id, quantity: 2 }],
      shippingCountry: 'KE',
    };

    const res = await request(app.getHttpServer()).post('/orders').send(payload).expect(201);
    const createdOrder = res.body.data;

    const charges = await chargeRepo.find({ where: { orderId: createdOrder.id } });
    const shippingCharges = charges.filter((c) => c.chargeKind === 'shipping');
    expect(shippingCharges.length).toBeGreaterThan(0);

    // subtotal = 200*2 = 400; formula = subtotal * 0.05 = 20
    const shipping = shippingCharges.find((s) => s.sourceReference === 'formula-method');
    expect(shipping).toBeDefined();
    expect(Number(shipping!.amount)).toBeCloseTo(20, 2);
  }, 30000);
});