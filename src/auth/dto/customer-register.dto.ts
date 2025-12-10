import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class CustomerRegisterDto {
  @ApiProperty({ description: 'Customer phone number', example: '+14155551234' })
  @IsString({ message: 'Phone must be a string' })
  @IsNotEmpty({ message: 'Phone is required' })
  phone: string;

  @ApiProperty({ description: 'Password', example: 'Str0ngP@ssw0rd', minLength: 8 })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  password: string;

  @ApiPropertyOptional({ description: 'Email address', example: 'customer@example.com' })
  @IsOptional()
  @IsEmail({}, { message: 'Provide a valid email' })
  email?: string;

  @ApiPropertyOptional({ description: 'First name', example: 'Jane' })
  @IsOptional()
  @IsString({ message: 'First name must be a string' })
  firstName?: string;

  @ApiPropertyOptional({ description: 'Last name', example: 'Doe' })
  @IsOptional()
  @IsString({ message: 'Last name must be a string' })
  lastName?: string;

  @ApiPropertyOptional({ description: 'Full name', example: 'Jane Doe' })
  @IsOptional()
  @IsString({ message: 'Full name must be a string' })
  fullName?: string;
}
