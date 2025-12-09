import { IsEnum, IsString, IsOptional, IsObject } from 'class-validator';
import { ActivityAction } from '../entities/user-activity-log.entity';

export class CreateActivityLogDto {
  @IsString()
  userId: string;

  @IsEnum(ActivityAction)
  action: ActivityAction;

  @IsString()
  description: string;

  @IsOptional()
  @IsString()
  resourceType?: string;

  @IsOptional()
  @IsString()
  resourceId?: string;

  @IsOptional()
  @IsString()
  ipAddress?: string;

  @IsOptional()
  @IsString()
  userAgent?: string;

  @IsOptional()
  @IsString()
  device?: string;

  @IsOptional()
  @IsString()
  browser?: string;

  @IsOptional()
  @IsString()
  os?: string;

  @IsOptional()
  @IsString()
  location?: string;

  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
