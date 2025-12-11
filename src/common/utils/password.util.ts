import type { Options as Argon2Options } from 'argon2';
import * as argon2 from 'argon2';

const defaultArgon2Options: Argon2Options & { raw?: false } = {
  type: argon2.argon2id,
  memoryCost: Number(process.env.ARGON2_MEMORY_COST ?? 19456), // ~19 MiB
  timeCost: Number(process.env.ARGON2_TIME_COST ?? 3),
  parallelism: Number(process.env.ARGON2_PARALLELISM ?? 1),
  hashLength: Number(process.env.ARGON2_HASH_LENGTH ?? 32),
};

export async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, defaultArgon2Options);
}

export async function verifyPassword(
  storedHash: string | null | undefined,
  plain: string,
): Promise<boolean> {
  if (!storedHash) {
    return false;
  }

  if (isArgon2Hash(storedHash)) {
    return argon2.verify(storedHash, plain);
  }

  return false;
}

export function isArgon2Hash(hash?: string | null): boolean {
  return Boolean(hash?.startsWith('$argon2id$'));
}
