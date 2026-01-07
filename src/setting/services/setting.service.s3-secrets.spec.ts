import { SettingService } from './setting.service';

class InMemorySettingRepo {
  private items = new Map<string, any>();

  async findOne({ where }: any) {
    const key = where?.key;
    return this.items.get(key) ?? null;
  }

  create(input: any) {
    return {
      key: input.key,
      value: input.value,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  async save(entity: any) {
    const existing = this.items.get(entity.key);
    const next = {
      ...(existing ?? {}),
      ...entity,
      updatedAt: new Date(),
      createdAt: existing?.createdAt ?? entity.createdAt ?? new Date(),
    };
    this.items.set(entity.key, next);
    return next;
  }

  async find({ where }: any) {
    const keys: string[] = (where ?? []).map((w: any) => w.key).filter(Boolean);
    return keys.map((k) => this.items.get(k)).filter((v) => v !== undefined);
  }
}

describe('SettingService.updateS3Secrets', () => {
  it('stores S3 secrets encrypted and never returns their values', async () => {
    const repo = new InMemorySettingRepo();
    const cache = {
      del: jest.fn(),
      remember: jest.fn(async (_k: any, fn: any) => fn()),
    } as any;
    const crypto = {
      encrypt: jest.fn((v: string) => `enc:v1:${v}`),
      decrypt: jest.fn((v: string) => v),
    } as any;

    const svc = new SettingService(repo as any, cache, crypto);

    const res = await svc.updateS3Secrets({
      accessKeyId: 'access_key',
      secretAccessKey: 'secret_key',
    });

    expect(crypto.encrypt).toHaveBeenCalledWith('access_key');
    expect(crypto.encrypt).toHaveBeenCalledWith('secret_key');

    const storedAccess = await repo.findOne({
      where: { key: 's3_access_key_id' },
    });
    const storedSecret = await repo.findOne({
      where: { key: 's3_secret_access_key' },
    });

    expect(storedAccess.value).toBe('enc:v1:access_key');
    expect(storedSecret.value).toBe('enc:v1:secret_key');

    expect(res).toEqual(
      expect.objectContaining({
        hasAccessKeyId: true,
        hasSecretAccessKey: true,
      }),
    );

    expect((res as any).accessKeyId).toBeUndefined();
    expect((res as any).secretAccessKey).toBeUndefined();
  });

  it('is idempotent and can update one secret at a time', async () => {
    const repo = new InMemorySettingRepo();
    const cache = {
      del: jest.fn(),
      remember: jest.fn(async (_k: any, fn: any) => fn()),
    } as any;
    const crypto = {
      encrypt: jest.fn((v: string) => `enc:v1:${v}`),
      decrypt: jest.fn((v: string) => v),
    } as any;

    const svc = new SettingService(repo as any, cache, crypto);

    await svc.updateS3Secrets({ accessKeyId: 'a' });
    await svc.updateS3Secrets({ secretAccessKey: 'b' });

    const res = await svc.updateS3Secrets({});
    expect(res.hasAccessKeyId).toBe(true);
    expect(res.hasSecretAccessKey).toBe(true);
  });
});
