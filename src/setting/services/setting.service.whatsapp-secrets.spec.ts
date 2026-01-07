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

describe('SettingService.updateWhatsappSecrets', () => {
  it('stores secrets encrypted and never returns their values', async () => {
    const repo = new InMemorySettingRepo();
    const cache = { del: jest.fn() } as any;
    const crypto = {
      encrypt: jest.fn((v: string) => `enc:v1:${v}`),
      decrypt: jest.fn((v: string) => v),
    } as any;

    const svc = new SettingService(repo as any, cache, crypto);

    const res = await svc.updateWhatsappSecrets({
      appSecret: 'app_secret_value',
      webhookVerifyToken: 'verify_token_value',
    });

    expect(crypto.encrypt).toHaveBeenCalledWith('app_secret_value');
    expect(crypto.encrypt).toHaveBeenCalledWith('verify_token_value');

    const storedAppSecret = await repo.findOne({
      where: { key: 'whatsapp_app_secret' },
    });
    const storedVerifyToken = await repo.findOne({
      where: { key: 'whatsapp_webhook_verify_token' },
    });

    expect(storedAppSecret.value).toBe('enc:v1:app_secret_value');
    expect(storedVerifyToken.value).toBe('enc:v1:verify_token_value');

    expect(res).toEqual(
      expect.objectContaining({
        hasAppSecret: true,
        hasWebhookVerifyToken: true,
      }),
    );

    // Critically: response must not include raw secrets.
    expect((res as any).appSecret).toBeUndefined();
    expect((res as any).webhookVerifyToken).toBeUndefined();
  });

  it('is idempotent and can update one secret at a time', async () => {
    const repo = new InMemorySettingRepo();
    const cache = { del: jest.fn() } as any;
    const crypto = {
      encrypt: jest.fn((v: string) => `enc:v1:${v}`),
      decrypt: jest.fn((v: string) => v),
    } as any;

    const svc = new SettingService(repo as any, cache, crypto);

    await svc.updateWhatsappSecrets({ appSecret: 'a' });
    await svc.updateWhatsappSecrets({ webhookVerifyToken: 'b' });

    const res = await svc.updateWhatsappSecrets({});
    expect(res.hasAppSecret).toBe(true);
    expect(res.hasWebhookVerifyToken).toBe(true);
  });
});
