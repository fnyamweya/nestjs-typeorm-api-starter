import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { DataSource } from 'typeorm';

async function clearDatabase() {
  console.log('🧹 Starting database cleanup...');

  const app = await NestFactory.createApplicationContext(AppModule);
  const dataSource = app.get(DataSource);

  try {
    console.log('🗑️ Truncating all tables...');

    // Get all table names
    const tables: Array<{ tablename: string }> = await dataSource.query(`
      SELECT tablename FROM pg_tables 
      WHERE schemaname = 'public' 
      AND tablename NOT LIKE 'pg_%' 
      AND tablename != 'information_schema'
    `);

    if (!tables.length) {
      console.log('ℹ️ No tables found to truncate.');
      return;
    }

    // Use TRUNCATE ... CASCADE to safely clear tables without superuser privileges
    const tableList = tables
      .map((t) => `"${t.tablename}"`)
      .join(', ');

    await dataSource.query(`TRUNCATE TABLE ${tableList} CASCADE;`);
    console.log('🎉 All tables truncated successfully!');
  } catch (error) {
    console.error('❌ Database cleanup failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

// Run the cleanup
clearDatabase().catch((error) => {
  console.error('❌ Fatal error during cleanup:', error);
  process.exit(1);
});
