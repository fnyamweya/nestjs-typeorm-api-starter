import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Setting } from 'src/setting/entities/setting.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { SettingCryptoService } from 'src/common/utils/setting-crypto.service';

export interface S3Config {
  endpoint?: string;
  region: string;
  bucketName: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle: boolean;
  enabled: boolean;
  /**
   * Optional public base URL (e.g. https://media.example.com) used to construct permanent object URLs.
   * If not provided, clients should use objectKey/bucketName or presigned URLs.
   */
  publicBaseUrl?: string;
  /**
   * Optional Cloudflare R2 Public Development URL base (r2.dev). Prefer this for public URL construction when set.
   * Example: https://pub-xxxxxxxxxxxxxxxx.r2.dev
   */
  publicDevBaseUrl?: string;
}

@Injectable()
export class S3ConfigService {
  constructor(
    @InjectRepository(Setting)
    private readonly settingRepository: Repository<Setting>,
    private readonly cache: AppCacheService,
    private readonly configService: ConfigService,
    private readonly crypto: SettingCryptoService,
  ) {}

  async getConfig(): Promise<S3Config> {
    return this.cache.remember(
      'settings:s3:internal',
      async () => {
        const keys = [
          's3_endpoint',
          's3_region',
          's3_bucket_name',
          's3_access_key_id',
          's3_secret_access_key',
          's3_force_path_style',
          's3_enabled',
          's3_public_base_url',
          's3_public_dev_base_url',
        ];

        const settings = await this.settingRepository.find({
          where: keys.map((key) => ({ key })),
        });

        const getValue = (key: string) =>
          settings.find((s) => s.key === key)?.value || '';

        const envValue = (key: string) =>
          this.configService.get<string>(key) ?? process.env[key] ?? '';

        const rawEnabled =
          getValue('s3_enabled') ||
          envValue('S3_ENABLED') ||
          envValue('AWS_S3_ENABLED');

        const enabled = (rawEnabled || 'true').toLowerCase() === 'true';

        const endpoint =
          getValue('s3_endpoint') || envValue('AWS_ENDPOINT') || undefined;

        const region =
          getValue('s3_region') || envValue('AWS_REGION') || 'us-east-1';

        const bucketName =
          getValue('s3_bucket_name') || envValue('AWS_BUCKET_NAME') || '';

        const accessKeyId =
          this.crypto.decrypt(getValue('s3_access_key_id')) ||
          envValue('AWS_ACCESS_KEY_ID') ||
          '';

        const secretAccessKey =
          this.crypto.decrypt(getValue('s3_secret_access_key')) ||
          envValue('AWS_SECRET_ACCESS_KEY') ||
          '';

        const rawForcePathStyle =
          getValue('s3_force_path_style') ||
          envValue('S3_FORCE_PATH_STYLE') ||
          envValue('AWS_FORCE_PATH_STYLE');

        const forcePathStyle =
          (rawForcePathStyle || 'true').toLowerCase() === 'true';

        const publicBaseUrl =
          getValue('s3_public_base_url') ||
          envValue('S3_PUBLIC_BASE_URL') ||
          envValue('R2_PUBLIC_BASE_URL') ||
          undefined;

        const publicDevBaseUrl =
          getValue('s3_public_dev_base_url') ||
          envValue('S3_PUBLIC_DEV_BASE_URL') ||
          envValue('R2_PUBLIC_DEV_BASE_URL') ||
          undefined;

        return {
          endpoint: endpoint?.trim() ? endpoint.trim() : undefined,
          region: region.trim(),
          bucketName: bucketName.trim(),
          accessKeyId: accessKeyId.trim(),
          secretAccessKey: secretAccessKey.trim(),
          forcePathStyle,
          enabled,
          publicBaseUrl: publicBaseUrl?.trim()
            ? publicBaseUrl.trim()
            : undefined,
          publicDevBaseUrl: publicDevBaseUrl?.trim()
            ? publicDevBaseUrl.trim()
            : undefined,
        };
      },
      { ttlSeconds: 300 },
    );
  }
}
