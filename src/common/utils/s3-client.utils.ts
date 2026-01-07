import {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Injectable, Logger } from '@nestjs/common';
import { S3ConfigService } from 'src/common/s3/s3-config.service';
import { Readable } from 'stream';

@Injectable()
export class S3ClientUtils {
  private readonly logger = new Logger(S3ClientUtils.name);
  private cached: {
    signature: string;
    client: S3Client;
    bucketName: string;
  } | null = null;

  constructor(private readonly s3Config: S3ConfigService) {}

  private normalizeEndpoint(endpoint?: string): string | undefined {
    const trimmed = endpoint?.trim();
    if (!trimmed) return undefined;
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      return trimmed;
    }

    // Common misconfig: providing host:port without scheme.
    return `http://${trimmed}`;
  }

  private async getClientAndBucket(): Promise<{
    client: S3Client;
    bucketName: string;
  }> {
    const config = await this.s3Config.getConfig();

    if (!config.enabled) {
      throw new Error('S3 is disabled');
    }

    if (!config.bucketName) {
      throw new Error('S3 bucket name is not configured');
    }

    const endpoint = this.normalizeEndpoint(config.endpoint);

    // If the endpoint already includes the bucket in the hostname (virtual-hosted style),
    // forcing path-style would duplicate the bucket segment in URLs (e.g. /bucket/key).
    // This commonly happens with Cloudflare R2 bucket endpoints:
    //   https://<bucket>.<accountid>.r2.cloudflarestorage.com
    let effectiveForcePathStyle = config.forcePathStyle;
    if (endpoint) {
      try {
        const parsed = new URL(endpoint);
        if (parsed.hostname.startsWith(`${config.bucketName}.`)) {
          effectiveForcePathStyle = false;
        }
      } catch {
        // ignore parse errors; fall back to configured value
      }
    }

    const signature = JSON.stringify({
      endpoint: endpoint ?? '',
      region: config.region,
      bucketName: config.bucketName,
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
      forcePathStyle: effectiveForcePathStyle,
    });

    if (this.cached?.signature === signature) {
      return { client: this.cached.client, bucketName: this.cached.bucketName };
    }

    const client = new S3Client({
      region: config.region,
      endpoint,
      credentials:
        config.accessKeyId && config.secretAccessKey
          ? {
              accessKeyId: config.accessKeyId,
              secretAccessKey: config.secretAccessKey,
            }
          : undefined,
      forcePathStyle: effectiveForcePathStyle,
    });

    this.cached = { signature, client, bucketName: config.bucketName };
    return { client, bucketName: config.bucketName };
  }

  async getBucketName(): Promise<string> {
    const { bucketName } = await this.getClientAndBucket();
    return bucketName;
  }

  async getPublicUrl(objectKey: string): Promise<string | null> {
    if (!objectKey || objectKey.trim().length === 0) return null;
    const config = await this.s3Config.getConfig();
    const base = (config.publicDevBaseUrl ?? config.publicBaseUrl)?.trim();
    if (!base) return null;
    const normalizedBase = base.replace(/\/+$/g, '');
    const normalizedKey = objectKey.replace(/^\/+/, '');
    // Encode each path segment so spaces and special chars don't break URLs.
    const encodedKey = normalizedKey
      .split('/')
      .map((segment) => encodeURIComponent(segment))
      .join('/');
    return `${normalizedBase}/${encodedKey}`;
  }

  /**
   * Generate a presigned URL for a file in S3
   */
  async generatePresignedUrl(
    key: string,
    expiresIn: number = 3600,
  ): Promise<string | null> {
    try {
      if (!key || key.trim().length === 0) {
        return null;
      }
      const { client, bucketName } = await this.getClientAndBucket();
      const command = new GetObjectCommand({
        Bucket: bucketName,
        Key: key,
      });

      const url = await getSignedUrl(client, command, { expiresIn });

      return url;
    } catch (error: unknown) {
      const err = error as Error;
      if (key && key.trim().length > 0) {
        this.logger.error(
          `Failed to generate download URL for ${key}: ${err.message}`,
          err.stack,
        );
      }
      return null;
    }
  }

  /**
   * Check if an object exists in S3
   */
  async objectExists(key: string): Promise<boolean> {
    try {
      if (!key || key.trim().length === 0) {
        return false;
      }
      const { client, bucketName } = await this.getClientAndBucket();
      const command = new HeadObjectCommand({
        Bucket: bucketName,
        Key: key,
      });

      await client.send(command);
      return true;
    } catch (error) {
      const err = error as Error;
      if (key && key.trim().length > 0) {
        this.logger.error(
          `Failed to check object existence for ${key}: ${err.message}`,
          err.stack,
        );
      }
      return false;
    }
  }

  /**
   * Upload a file to S3
   */
  async uploadFile({
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    body: Buffer | Uint8Array | string | Readable;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {
    try {
      const { client, bucketName } = await this.getClientAndBucket();
      const prefix = (path?.trim() || 'uploads').replace(/\/+$/g, '');
      const command = new PutObjectCommand({
        Bucket: bucketName,
        Key: `${prefix}/${key}`,
        Body: body,
        ContentType: contentType,
        Metadata: metadata,
      });

      await client.send(command);

      this.logger.log(`Successfully uploaded file: ${key}`);
      return { success: true, key: `${prefix}/${key}` };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to upload file ${key}: ${err.message}`,
        err.stack,
      );
      const prefix = (path?.trim() || 'uploads').replace(/\/+$/g, '');
      return { success: false, error: err.message, key: `${prefix}/${key}` };
    }
  }

  /**
   * Update an existing file in S3
   * Note: This method overwrites the existing file with the new content.
   */
  async updateFile({
    oldKey,
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    oldKey: string;
    body: Buffer | Uint8Array | string | Readable;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {
    const prefix = (path?.trim() || 'uploads').replace(/\/+$/g, '');
    const newKey = `${prefix}/${key}`;
    if (oldKey === key) {
      throw new Error('oldKey and key must be different');
    }

    if (!(await this.objectExists(oldKey))) {
      throw new Error(`oldKey ${oldKey} does not exist`);
    }

    try {
      const { client, bucketName } = await this.getClientAndBucket();
      const command = new PutObjectCommand({
        Bucket: bucketName,
        Key: newKey,
        Body: body,
        ContentType: contentType,
        Metadata: metadata,
      });

      await client.send(command);
      this.logger.log(`Successfully updated file: ${key}`);
      // Delete old data
      await this.deleteObject(oldKey);

      return { success: true, key: newKey };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to update file ${key}: ${err.message}`,
        err.stack,
      );
      // When error occur and image is uploaded, rollback and delete new image
      await this.deleteObject(newKey);
      this.logger.error(
        `Rollback: Successfully deleted new uploaded file: ${newKey}`,
      );

      return { success: false, error: err.message, key: newKey };
    }
  }

  /**
   * Delete a file from S3
   */
  async deleteObject(
    key: string,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      if (!key || key.trim().length === 0) {
        return { success: false, error: 'Key is empty' };
      }
      const { client, bucketName } = await this.getClientAndBucket();
      const command = new DeleteObjectCommand({
        Bucket: bucketName,
        Key: key,
      });

      await client.send(command);

      this.logger.log(`Successfully deleted file: ${key}`);
      return { success: true };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to delete file ${key}: ${err.message}`,
        err.stack,
      );
      return { success: false, error: err.message };
    }
  }
}
