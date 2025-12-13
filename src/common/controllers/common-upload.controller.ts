import {
  Body,
  Controller,
  Post,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  UploadedFiles,
  ValidationPipe,
  UsePipes,
  BadRequestException,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { UploadFileDto } from '../dto/upload-file.dto';
import { S3ClientUtils } from '../utils/s3-client.utils';
import { ResponseUtil } from '../utils/response.util';
import { randomUUID } from 'crypto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiCreatedResponse,
  ApiBadRequestResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@Controller('api/common')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@ApiTags('Common Uploads')
@ApiBearerAuth('access-token')
export class CommonUploadController {
  constructor(private readonly s3: S3ClientUtils) {}

  @Post('upload')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'create' })
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype)
          return cb(new BadRequestException('Invalid file'), false);
        cb(null, true);
      },
    }),
  )
  @ApiOperation({ summary: 'Upload a single file to object storage' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description:
      'Multipart request containing file and optional upload metadata',
    schema: {
      type: 'object',
      properties: {
        file: { type: 'string', format: 'binary' },
        folder: { type: 'string', example: 'avatars' },
        filenameOverride: { type: 'string', example: 'profile-picture.png' },
        generateSignedUrl: { type: 'boolean', example: true },
      },
      required: ['file'],
    },
  })
  @ApiCreatedResponse({ description: 'File uploaded successfully' })
  @ApiBadRequestResponse({
    description: 'Invalid file payload or validation failed',
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  async upload(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadFileDto,
  ) {
    if (!file) {
      throw new BadRequestException('File is required');
    }

    const folder = dto.folder?.trim() || 'uploads';
    const original = file.originalname?.trim() || 'file';
    const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const key = dto.filenameOverride?.trim() || `${randomUUID()}-${sanitized}`;

    try {
      const res = await this.s3.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: folder,
        metadata: { filename: original },
      });

      if (!res.success) {
        throw new BadRequestException(res.error || 'Upload failed');
      }

      const signedUrl = dto.generateSignedUrl
        ? await this.s3.generatePresignedUrl(res.key!)
        : null;

      return ResponseUtil.created(
        {
          key: res.key,
          url: signedUrl,
          size: file.size,
          mimeType: file.mimetype,
          filename: original,
        },
        'File uploaded successfully',
      );
    } catch (error) {
      console.log(error, ' image upload failed ');
      throw new BadRequestException(error?.message || 'Upload failed');
    }
  }

  @Post('upload/multi')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'create' })
  @UseInterceptors(
    FilesInterceptor('files', 20, {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype)
          return cb(new BadRequestException('Invalid file'), false);
        cb(null, true);
      },
    }),
  )
  @ApiOperation({ summary: 'Upload multiple files to object storage' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description:
      'Multipart request containing files array and optional upload metadata',
    schema: {
      type: 'object',
      properties: {
        files: {
          type: 'array',
          items: { type: 'string', format: 'binary' },
        },
        folder: { type: 'string', example: 'documents' },
        generateSignedUrl: { type: 'boolean', example: false },
      },
      required: ['files'],
    },
  })
  @ApiCreatedResponse({ description: 'Files uploaded successfully' })
  @ApiBadRequestResponse({
    description: 'Validation failed or uploads unsuccessful',
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  async uploadMany(
    @UploadedFiles() files: Express.Multer.File[],
    @Body() dto: UploadFileDto,
  ) {
    if (!files || files.length === 0) {
      throw new BadRequestException('Files are required');
    }

    const folder = dto.folder?.trim() || 'uploads';

    const uploaded: Array<{
      key: string | undefined;
      url: string | null;
      size: number;
      mimeType: string;
      filename: string;
    }> = [];
    const failed: Array<{ filename: string; error: string }> = [];

    for (const file of files) {
      const original = file.originalname?.trim() || 'file';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;

      const res = await this.s3.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: folder,
        metadata: { filename: original },
      });

      if (!res.success) {
        failed.push({
          filename: original,
          error: res.error || 'Upload failed',
        });
        continue;
      }

      const signedUrl = dto.generateSignedUrl
        ? await this.s3.generatePresignedUrl(res.key!)
        : null;

      uploaded.push({
        key: res.key,
        url: signedUrl,
        size: file.size,
        mimeType: file.mimetype,
        filename: original,
      });
    }

    if (uploaded.length === 0) {
      throw new BadRequestException(failed[0]?.error || 'All uploads failed');
    }

    return ResponseUtil.created(
      { uploaded, failed },
      'Files uploaded successfully',
    );
  }
}
