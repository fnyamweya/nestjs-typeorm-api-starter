import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { App } from 'supertest/types';
import { createTestApp } from './e2e/bootstrap';

describe('AppController (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(() => {
    // Fail fast and make root-cause visible in logs.
    process.on('unhandledRejection', (err) => {
      // eslint-disable-next-line no-console
      console.error('Unhandled promise rejection in e2e', err);
      process.exitCode = 1;
    });
    process.on('uncaughtException', (err) => {
      // eslint-disable-next-line no-console
      console.error('Uncaught exception in e2e', err);
      process.exitCode = 1;
    });
  });

  beforeAll(async () => {
    try {
      const t = await createTestApp();
      app = t.app as INestApplication<App>;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('beforeAll failed in AppController e2e', err);
      process.exitCode = 1;
      throw err;
    }
  }, 120000);

  afterAll(async () => {
    try {
      if (app) await app.close();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('afterAll failed closing app in AppController e2e', err);
      process.exitCode = 1;
      throw err;
    }
  });

  it('/ (GET)', async () => {
    expect(app).toBeDefined();

    const res = await request(app.getHttpServer()).get('/').expect(200);
    expect(res.text).toContain('Have a good day');
  });
});
