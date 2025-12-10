import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class AdminRegisterDto {
  @ApiProperty({ description: 'Admin email address', example: 'admin@example.com' })
  @IsEmail({}, { message: 'Provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({ description: 'Admin password', example: 'AdminP@ss123', minLength: 8 })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  password: string;

  @ApiPropertyOptional({ description: 'Full name', example: 'Alex Admin' })
  @IsOptional()
  @IsString({ message: 'Full name must be a string' })
  fullName?: string;

  @ApiPropertyOptional({ description: 'First name', example: 'Alex' })
  @IsOptional()
  @IsString({ message: 'First name must be a string' })
  firstName?: string;

  @ApiPropertyOptional({ description: 'Last name', example: 'Admin' })
  @IsOptional()
  @IsString({ message: 'Last name must be a string' })
  lastName?: string;

  @ApiPropertyOptional({ description: 'Phone number', example: '+14155551234' })
  @IsOptional()
  @IsString({ message: 'Phone must be a string' })
  phone?: string;
}
