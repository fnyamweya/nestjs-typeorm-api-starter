import {
  Body,
  Controller,
  Get,
  Post,
  Param,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseInterceptors,
  UploadedFiles,
  ValidationPipe,
  UsePipes,
  BadRequestException,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { FilesInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { UploadFileDto, UploadFileType } from '../dto/upload-file.dto';
import { S3ClientUtils } from '../utils/s3-client.utils';
import { ResponseUtil } from '../utils/response.util';
import { existsSync, mkdirSync } from 'fs';
import { QueueService } from 'src/queue/queue.service';
import { UPLOADS_JOB, UPLOADS_QUEUE } from '../uploads/upload-worker.service';
import { ApiResponse } from '../interfaces/api-response.interface';
import { UploadFilesJobResult } from '../uploads/upload-jobs.types';
import { randomUUID } from 'crypto';
import { PresignObjectDto } from '../dto/presign-object.dto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiAcceptedResponse,
  ApiBadRequestResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
  ApiOkResponse,
} from '@nestjs/swagger';

@Controller('common')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@ApiTags('Common Uploads')
@ApiBearerAuth('access-token')
export class CommonUploadController {
  constructor(
    private readonly s3: S3ClientUtils,
    private readonly queueService: QueueService,
  ) {}

  private resolveFolder(dto: UploadFileDto): string {
    const filetype = dto.filetype?.trim() as UploadFileType | undefined;

    if (filetype) {
      const mapping: Record<UploadFileType, string> = {
        image: 'images',
        document: 'documents',
        video: 'videos',
        audio: 'audio',
        avatar: 'avatars',
        other: 'uploads',
      };

      return mapping[filetype] || 'uploads';
    }

    const folder = dto.folder?.trim() || 'uploads';

    // Keep backward compatibility, but block obviously unsafe paths.
    if (
      folder.startsWith('/') ||
      folder.includes('..') ||
      !/^[a-zA-Z0-9/_-]{1,128}$/.test(folder)
    ) {
      throw new BadRequestException('Invalid folder');
    }

    return folder;
  }

  private assertMimeAllowed(
    filetype: UploadFileType | undefined,
    mimeType: string,
  ) {
    const ft = filetype?.trim() as UploadFileType | undefined;

    if (!ft) return;
    if (!mimeType) {
      throw new BadRequestException('Invalid file: missing mimetype');
    }

    const allowed: Record<UploadFileType, Array<string | RegExp>> = {
      image: [/^image\//],
      avatar: [/^image\//],
      video: [/^video\//],
      audio: [/^audio\//],
      document: [
        'application/pdf',
        'text/plain',
        'text/csv',
        'application/json',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      ],
      other: [],
    };

    const rules = allowed[ft] ?? [];
    if (rules.length === 0) return;

    const ok = rules.some((rule) =>
      typeof rule === 'string' ? rule === mimeType : rule.test(mimeType),
    );

    if (!ok) {
      throw new BadRequestException(
        `Invalid file type: filetype '${ft}' does not allow mimetype '${mimeType}'`,
      );
    }
  }

  @Post('upload')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @HttpCode(HttpStatus.ACCEPTED)
  @UseInterceptors(
    FilesInterceptor('files', 20, {
      storage: diskStorage({
        destination: (req, file, cb) => {
          try {
            const dir = process.env.UPLOAD_STAGING_DIR || '/tmp/qtech-uploads';
            if (!existsSync(dir)) {
              mkdirSync(dir, { recursive: true });
            }
            cb(null, dir);
          } catch (e) {
            cb(e, '');
          }
        },
        filename: (req, file, cb) => {
          const original = file.originalname?.trim() || 'file';
          const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
          cb(null, `${Date.now()}-${sanitized}`);
        },
      }),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype)
          return cb(new BadRequestException('Invalid file'), false);
        cb(null, true);
      },
    }),
  )
  @ApiOperation({
    summary: 'Queue upload of one or multiple files (async)',
    description:
      'Accepts multipart form-data and returns 202 with a jobId. A background worker performs the actual S3 uploads.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description:
      'Multipart request containing file and optional upload metadata',
    schema: {
      type: 'object',
      properties: {
        files: {
          type: 'array',
          items: { type: 'string', format: 'binary' },
        },
        filetype: {
          type: 'string',
          example: 'image',
          description:
            'Optional category used to choose the upload directory. If provided, it takes precedence over folder.',
        },
        folder: { type: 'string', example: 'avatars' },
        isPublic: {
          type: 'boolean',
          example: true,
          description:
            'If true, the worker will return a permanent publicUrl/url when a public base URL is configured. If false, it will prefer returning a signed URL.',
        },
        generateSignedUrl: { type: 'boolean', example: true },
      },
      required: ['files'],
    },
  })
  @ApiAcceptedResponse({ description: 'Upload job accepted' })
  @ApiBadRequestResponse({
    description: 'Invalid file payload or validation failed',
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  async upload(
    @UploadedFiles() files: Express.Multer.File[] | undefined,
    @Body() dto: UploadFileDto,
  ) {
    if (!files || files.length === 0) {
      throw new BadRequestException('Files are required');
    }

    const folder = this.resolveFolder(dto);
    const generateSignedUrl = dto.generateSignedUrl ?? true;

    // If not explicitly provided, default public-ness by filetype.
    const isPublic =
      dto.isPublic ??
      (dto.filetype === 'image' || dto.filetype === 'avatar' ? true : false);

    const invalid: Array<{ filename: string; error: string }> = [];
    for (const f of files) {
      try {
        this.assertMimeAllowed(dto.filetype, f.mimetype);
      } catch (e) {
        invalid.push({
          filename: f.originalname || 'file',
          error: e?.message || 'Invalid file type',
        });
      }
    }
    if (invalid.length > 0) {
      throw new BadRequestException({ message: 'Invalid file type', invalid });
    }

    const job = await this.queueService.addJob(
      UPLOADS_QUEUE,
      UPLOADS_JOB,
      {
        folder,
        filetype: dto.filetype,
        generateSignedUrl,
        isPublic,
        files: files.map((f) => ({
          path: f.path,
          originalName: f.originalname,
          mimeType: f.mimetype,
          size: f.size,
        })),
      },
      {
        jobId: randomUUID(),
        removeOnComplete: false,
        removeOnFail: false,
      },
    );

    return ResponseUtil.success(
      { jobId: job.id, count: files.length },
      'Upload job accepted',
      HttpStatus.ACCEPTED,
    );
  }

  @Post('upload/multi')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @HttpCode(HttpStatus.ACCEPTED)
  @UseInterceptors(
    FilesInterceptor('files', 20, {
      storage: diskStorage({
        destination: (req, file, cb) => {
          try {
            const dir = process.env.UPLOAD_STAGING_DIR || '/tmp/qtech-uploads';
            if (!existsSync(dir)) {
              mkdirSync(dir, { recursive: true });
            }
            cb(null, dir);
          } catch (e) {
            cb(e, '');
          }
        },
        filename: (req, file, cb) => {
          const original = file.originalname?.trim() || 'file';
          const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
          cb(null, `${Date.now()}-${sanitized}`);
        },
      }),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype)
          return cb(new BadRequestException('Invalid file'), false);
        cb(null, true);
      },
    }),
  )
  @ApiOperation({
    summary: 'Deprecated: use POST /api/v1/common/upload with files[]',
  })
  async uploadMany(
    @UploadedFiles() files: Express.Multer.File[] | undefined,
    @Body() dto: UploadFileDto,
  ) {
    return this.upload(files, dto);
  }

  @Get('upload/jobs/:jobId')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Get async upload job status/result' })
  @ApiOkResponse({ description: 'Upload job status' })
  async getUploadJob(@Param('jobId') jobId: string): Promise<ApiResponse<any>> {
    const queue = this.queueService.getQueue(UPLOADS_QUEUE);
    const job = await queue.getJob(jobId);
    if (!job) {
      throw new BadRequestException('Job not found');
    }

    const state = await job.getState();

    return ResponseUtil.success(
      {
        id: job.id,
        name: job.name,
        state,
        progress: job.progress,
        result: (job.returnvalue as UploadFilesJobResult | undefined) ?? null,
        failedReason: job.failedReason ?? null,
        timestamp: job.timestamp,
        finishedOn: job.finishedOn ?? null,
        processedOn: job.processedOn ?? null,
      },
      'Upload job status',
    );
  }

  @Get('upload/job/:jobId')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Alias: Get async upload job status/result' })
  @ApiOkResponse({ description: 'Upload job status' })
  async getUploadJobAlias(
    @Param('jobId') jobId: string,
  ): Promise<ApiResponse<any>> {
    return this.getUploadJob(jobId);
  }

  @Post('files/presign')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({
    summary: 'Generate a signed URL for a stored object key (private access)',
    description:
      'Production-grade pattern for private files (e.g. invoices): store objectKey and generate short-lived URLs when needed.',
  })
  @ApiOkResponse({ description: 'Signed URL generated' })
  async presign(@Body() dto: PresignObjectDto): Promise<ApiResponse<any>> {
    const objectKey = dto.objectKey?.trim();
    if (!objectKey) {
      throw new BadRequestException('objectKey is required');
    }
    const url = await this.s3.generatePresignedUrl(
      objectKey,
      dto.expiresIn ?? 3600,
    );
    if (!url) {
      throw new BadRequestException('Failed to generate signed URL');
    }
    return ResponseUtil.success(
      { objectKey, signedUrl: url },
      'Signed URL generated',
    );
  }
}
