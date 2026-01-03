import 'reflect-metadata';
import { DataSource } from 'typeorm';
import 'dotenv/config';

const isJest = typeof process.env.JEST_WORKER_ID !== 'undefined';

export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST,
  port: +process.env.DB_PORT!,
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  entities: [__dirname + '/**/*.entity.{ts,js}'],
  migrations: [__dirname + '/migrations/*.{ts,js}'],
  // In normal runs, use migrations (synchronize can attempt unsafe rewrites like bigint -> uuid).
  // In Jest e2e, we rely on synchronize+dropSchema because the repo doesn't include a full
  // baseline migration for all tables (e.g. "users").
  synchronize: isJest,
  dropSchema: isJest,
  migrationsRun: !isJest,
  logging: isJest ? false : true,
  ssl:
    process.env.DB_SSL === 'true'
      ? {
          rejectUnauthorized: false,
        }
      : false,
});
