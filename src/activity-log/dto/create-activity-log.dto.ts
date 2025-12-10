import { IsEnum, IsString, IsOptional, IsObject } from 'class-validator';
import { ActivityAction } from '../entities/user-activity-log.entity';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateActivityLogDto {
  @ApiProperty({
    description: 'Identifier of the user associated with the activity',
    example: '1ab0c8f0-7d3a-4f5f-80ab-e3f98cd5ef70',
  })
  @IsString()
  userId: string;

  @ApiProperty({
    description: 'Type of activity performed by the user',
    enum: ActivityAction,
    example: ActivityAction.LOGIN,
  })
  @IsEnum(ActivityAction)
  action: ActivityAction;

  @ApiProperty({
    description: 'Human readable description of the activity',
    example: 'User logged into the dashboard',
  })
  @IsString()
  description: string;

  @ApiPropertyOptional({
    description: 'Domain entity affected by the action',
    example: 'user',
  })
  @IsOptional()
  @IsString()
  resourceType?: string;

  @ApiPropertyOptional({
    description: 'Identifier of the resource affected by the action',
    example: '42',
  })
  @IsOptional()
  @IsString()
  resourceId?: string;

  @ApiPropertyOptional({
    description: 'IP address recorded for the action',
    example: '203.0.113.10',
  })
  @IsOptional()
  @IsString()
  ipAddress?: string;

  @ApiPropertyOptional({
    description: 'Raw user agent string of the client',
    example: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)',
  })
  @IsOptional()
  @IsString()
  userAgent?: string;

  @ApiPropertyOptional({
    description: 'Device name or identifier recorded during the action',
    example: 'MacBook Pro',
  })
  @IsOptional()
  @IsString()
  device?: string;

  @ApiPropertyOptional({
    description: 'Browser name recorded for the action',
    example: 'Chrome',
  })
  @IsOptional()
  @IsString()
  browser?: string;

  @ApiPropertyOptional({
    description: 'Operating system detected for the client',
    example: 'macOS',
  })
  @IsOptional()
  @IsString()
  os?: string;

  @ApiPropertyOptional({
    description: 'Geographical location of the client if available',
    example: 'San Francisco, US',
  })
  @IsOptional()
  @IsString()
  location?: string;

  @ApiPropertyOptional({
    description: 'Additional structured metadata captured for the event',
    example: { ip: '203.0.113.10', method: 'POST' },
    type: Object,
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
