import 'reflect-metadata';
import 'dotenv/config';
import { DataSource } from 'typeorm';
import baseDataSource from '../data-source';

async function migrate() {
  const ds = new DataSource({
    ...(baseDataSource.options as any),
    // make behavior explicit for scripts
    migrationsRun: false,
    synchronize: false,
    dropSchema: false,
    logging: true,
  });

  try {
    await ds.initialize();
    const migrations = await ds.runMigrations();
    console.log(`✅ Migrations applied: ${migrations.length}`);
  } catch (err) {
    console.error('❌ Migration run failed:', err);
    process.exitCode = 1;
  } finally {
    if (ds.isInitialized) {
      await ds.destroy();
    }
  }
}

migrate();
