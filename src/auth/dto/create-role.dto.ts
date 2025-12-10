import {
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsOptional,
  IsArray,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateRoleDto {
  @ApiProperty({
    description: 'Display name for the role',
    example: 'Administrator',
    minLength: 2,
    maxLength: 50,
  })
  @IsString({ message: 'Role name must be a string' })
  @IsNotEmpty({ message: 'Role name is required' })
  @MinLength(2, { message: 'Role name must be at least 2 characters long' })
  @MaxLength(50, { message: 'Role name must not exceed 50 characters' })
  name: string;

  @ApiPropertyOptional({
    description: 'Human readable description of the role responsibilities',
    example: 'Full administrative access to the platform',
    maxLength: 255,
  })
  @IsOptional()
  @IsString({ message: 'Description must be a string' })
  @MaxLength(255, { message: 'Description must not exceed 255 characters' })
  description?: string;

  @ApiProperty({
    description: 'List of permission identifiers assigned to the role',
    example: ['user.read', 'user.write'],
    type: [String],
  })
  @IsArray({ message: 'Permission IDs must be an array' })
  @IsString({ each: true, message: 'Permission ID must be a string' })
  permissionIds: string[];
}
