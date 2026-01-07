import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Job } from 'bullmq';
import { createReadStream, promises as fs } from 'fs';
import { QueueService } from 'src/queue/queue.service';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { UploadFilesJobData, UploadFilesJobResult } from './upload-jobs.types';
import { randomUUID } from 'crypto';

const UPLOADS_QUEUE = 'uploads';
const UPLOADS_JOB = 'upload-files';

@Injectable()
export class UploadWorkerService implements OnModuleInit {
  private readonly logger = new Logger(UploadWorkerService.name);

  constructor(
    private readonly queueService: QueueService,
    private readonly s3: S3ClientUtils,
  ) {}

  async onModuleInit() {
    if (process.env.NODE_ENV === 'test') {
      return;
    }

    // Worker runs in-process; it will consume async upload jobs.
    this.queueService.createWorker<UploadFilesJobData, UploadFilesJobResult>(
      UPLOADS_QUEUE,
      async (job: Job<UploadFilesJobData>) => {
        if (job.name !== UPLOADS_JOB) {
          return { uploaded: [], failed: [] };
        }

        const { folder, files, generateSignedUrl, isPublic, filetype } =
          job.data;
        const shouldSign = generateSignedUrl ?? true;
        const shouldPublic =
          isPublic ?? (filetype === 'image' || filetype === 'avatar');
        const bucketName = await this.s3.getBucketName();

        const uploaded: UploadFilesJobResult['uploaded'] = [];
        const failed: UploadFilesJobResult['failed'] = [];

        for (let i = 0; i < files.length; i++) {
          const f = files[i];
          const original = f.originalName?.trim() || 'file';
          const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
          const key = `${randomUUID()}-${sanitized}`;

          try {
            await job.updateProgress(Math.round((i / files.length) * 100));

            const res = await this.s3.uploadFile({
              key,
              body: createReadStream(f.path),
              contentType: f.mimeType,
              path: folder,
              metadata: { filename: original },
            });

            if (!res.success || !res.key) {
              throw new Error(res.error || 'Upload failed');
            }

            const publicUrl = shouldPublic
              ? await this.s3.getPublicUrl(res.key)
              : null;
            // Ensure we always return a usable url:
            // - For private objects, return a signed URL (even if generateSignedUrl is false)
            // - For public objects, prefer publicUrl; if missing/misconfigured, fall back to signed
            const signedUrl =
              !shouldPublic || shouldSign || !publicUrl
                ? await this.s3.generatePresignedUrl(res.key)
                : null;
            const url = publicUrl ?? signedUrl;

            uploaded.push({
              key: res.key,
              objectKey: res.key,
              bucketName,
              publicUrl,
              signedUrl,
              url,
              size: f.size,
              mimeType: f.mimeType,
              filename: original,
            });
          } catch (error) {
            failed.push({
              filename: original,
              error: error?.message || 'Upload failed',
            });
          } finally {
            // Always attempt cleanup.
            try {
              await fs.unlink(f.path);
            } catch {
              // ignore
            }
          }
        }

        await job.updateProgress(100);

        if (uploaded.length === 0) {
          throw new Error(failed[0]?.error || 'All uploads failed');
        }

        return { uploaded, failed };
      },
      { concurrency: 3 },
    );

    // Register queue events (logs + visibility).
    await this.queueService.getQueueEvents(UPLOADS_QUEUE);

    this.logger.log(`Upload worker started for queue '${UPLOADS_QUEUE}'`);
  }
}

export { UPLOADS_QUEUE, UPLOADS_JOB };
