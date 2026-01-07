import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'crypto';

const ENCRYPTION_PREFIX = 'enc:v1:';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

@Injectable()
export class SettingCryptoService {
  constructor(private readonly configService: ConfigService) {}

  encrypt(value: string): string {
    if (!value) return value;
    if (this.isEncrypted(value)) return value;

    const key = this.getKey();
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(value, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([iv, tag, encrypted]).toString('base64');
    return `${ENCRYPTION_PREFIX}${payload}`;
  }

  decrypt(value: string): string {
    if (!value) return value;
    if (!this.isEncrypted(value)) return value;

    const key = this.getKey();
    const raw = Buffer.from(value.slice(ENCRYPTION_PREFIX.length), 'base64');
    if (raw.length <= IV_LENGTH + TAG_LENGTH) {
      throw new Error('Invalid encrypted payload');
    }

    const iv = raw.subarray(0, IV_LENGTH);
    const tag = raw.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const data = raw.subarray(IV_LENGTH + TAG_LENGTH);

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString('utf8');
  }

  isEncrypted(value: string): boolean {
    return value.startsWith(ENCRYPTION_PREFIX);
  }

  private getKey(): Buffer {
    const raw = this.configService.get<string>('ENCRYPTION_KEY') ?? '';
    if (!raw) {
      throw new Error('ENCRYPTION_KEY is required for secrets');
    }
    return createHash('sha256').update(raw).digest();
  }
}
