import 'reflect-metadata';
import 'dotenv/config';
import * as argon2 from 'argon2';
import { DataSource } from 'typeorm';
import baseDataSource from '../data-source';
import { User } from '../user/entities/user.entity';

function getArg(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  if (idx === -1) return undefined;
  return process.argv[idx + 1];
}

async function resetPassword() {
  const email = getArg('--email') ?? process.env.SUPER_ADMIN_EMAIL;
  const password = getArg('--password') ?? 'AdminP@ss123';

  if (!email) {
    console.error('❌ Missing --email (or SUPER_ADMIN_EMAIL)');
    process.exit(1);
  }

  const ds = new DataSource({
    ...(baseDataSource.options as any),
    migrationsRun: false,
    synchronize: false,
    dropSchema: false,
    logging: true,
  });

  try {
    await ds.initialize();
    const repo = ds.getRepository(User);

    const user = await repo.findOne({ where: { email } });
    if (!user) {
      console.error(`❌ No user found for email: ${email}`);
      process.exit(1);
    }

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: parseInt(process.env.ARGON2_MEMORY_COST || '19456', 10),
      timeCost: parseInt(process.env.ARGON2_TIME_COST || '3', 10),
      parallelism: parseInt(process.env.ARGON2_PARALLELISM || '1', 10),
      hashLength: parseInt(process.env.ARGON2_HASH_LENGTH || '32', 10),
    });

    user.passwordHash = passwordHash;
    await repo.save(user);

    console.log(`✅ Password reset for ${email}`);
    console.log(`ℹ️ New password: ${password}`);
  } catch (err) {
    console.error('❌ Password reset failed:', err);
    process.exitCode = 1;
  } finally {
    if (ds.isInitialized) {
      await ds.destroy();
    }
  }
}

resetPassword();
