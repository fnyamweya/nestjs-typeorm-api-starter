import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { TestingModuleBuilder } from '@nestjs/testing';
import { DataSource } from 'typeorm';
import { HttpExceptionFilter } from '../../src/common/filters/http-exception.filter';

export type TestApp = {
  app: INestApplication;
  ds: DataSource;
};

export async function createTestApp(options?: {
  override?: (builder: TestingModuleBuilder) => void;
}): Promise<TestApp> {
  // Force test mode for e2e. The repository's `.env` typically points to
  // hosted DB/Redis, which is not appropriate (or reliable) for automated tests.
  process.env.NODE_ENV = 'test';

  // Prefer explicit E2E_* overrides; otherwise default to local docker-compose.
  process.env.DB_HOST = process.env.E2E_DB_HOST ?? 'localhost';
  process.env.DB_PORT = process.env.E2E_DB_PORT ?? '5432';
  process.env.DB_USERNAME = process.env.E2E_DB_USERNAME ?? 'postgres';
  process.env.DB_PASSWORD = process.env.E2E_DB_PASSWORD ?? 'postgres';
  process.env.DB_NAME = process.env.E2E_DB_NAME ?? 'qtech_db';
  process.env.DB_SSL = process.env.E2E_DB_SSL ?? 'false';

  process.env.REDIS_HOST = process.env.E2E_REDIS_HOST ?? 'localhost';
  process.env.REDIS_PORT = process.env.E2E_REDIS_PORT ?? '6379';
  process.env.REDIS_USERNAME = process.env.E2E_REDIS_USERNAME ?? '';
  process.env.REDIS_PASSWORD = process.env.E2E_REDIS_PASSWORD ?? '';
  process.env.REDIS_DB = process.env.E2E_REDIS_DB ?? '0';
  process.env.REDIS_TLS = process.env.E2E_REDIS_TLS ?? 'false';

  // Ensure auth/JWT infrastructure can bootstrap in e2e.
  // These defaults are only used if the environment doesn't provide them.
  process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'e2e_jwt_secret';
  process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? 'e2e_jwt_refresh_secret';
  process.env.SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL ?? 'superadmin@gmail.com';
  process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY ?? 'e2e_encryption_key';

  // Import AppModule only after env is set, so TypeORM picks up the test DB.
  const { AppModule } = await import('../../src/app.module');

  const builder = Test.createTestingModule({ imports: [AppModule] });
  options?.override?.(builder);
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication({
    // Needed for webhook signature verification tests.
    rawBody: true,
  });

  // Align e2e error responses with production.
  app.useGlobalFilters(new HttpExceptionFilter());

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
