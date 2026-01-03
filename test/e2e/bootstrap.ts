import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';
import { DataSource } from 'typeorm';

export type TestApp = {
  app: INestApplication;
  ds: DataSource;
};

export async function createTestApp(): Promise<TestApp> {
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app = moduleRef.createNestApplication({
    // Needed for webhook signature verification tests.
    rawBody: true,
  });

  // Optionally configure global pipes/filters/logging for e2e clarity
  app.enableShutdownHooks();

  await app.init();

  const ds = moduleRef.get(DataSource);

  return { app, ds };
}

export async function truncateDb(ds: DataSource) {
  try {
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
  } catch (err) {
    // Surface DB truncation errors to test logs
    console.error('truncateDb failed', err);
    throw err;
  }
}
