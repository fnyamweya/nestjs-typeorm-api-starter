import { UploadFileType } from 'src/common/dto/upload-file.dto';

export interface StagedUploadFile {
  path: string;
  originalName: string;
  mimeType: string;
  size: number;
}

export interface UploadFilesJobData {
  folder: string;
  filetype?: UploadFileType;
  generateSignedUrl?: boolean;
  isPublic?: boolean;
  files: StagedUploadFile[];
}

export interface UploadFilesJobResult {
  uploaded: Array<{
    /**
     * Backward-compatible alias for objectKey.
     * Prefer objectKey going forward.
     */
    key: string;
    /**
     * The full object key in the bucket (e.g. "uploads/images/<uuid>-file.png").
     */
    objectKey: string;
    bucketName: string;
    /**
     * Permanent URL when s3_public_base_url/S3_PUBLIC_BASE_URL is configured.
     */
    publicUrl: string | null;
    /**
     * Presigned URL fallback (time-limited). Useful when a public URL is configured but not reachable yet.
     */
    signedUrl: string | null;
    /**
     * Usable URL: prefers publicUrl, otherwise presigned (if enabled).
     */
    url: string | null;
    size: number;
    mimeType: string;
    filename: string;
  }>;
  failed: Array<{ filename: string; error: string }>;
}
