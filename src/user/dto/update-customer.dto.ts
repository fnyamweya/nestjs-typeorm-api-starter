import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class UpdateCustomerDto {
  @ApiPropertyOptional({
    description: 'Email address',
    example: 'customer@example.com',
  })
  @IsOptional()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email?: string;

  @ApiPropertyOptional({ description: 'First name', example: 'Jane' })
  @IsOptional()
  @IsString({ message: 'First name must be a string' })
  @MinLength(1, { message: 'First name must be at least 1 character long' })
  @MaxLength(60, { message: 'First name must not exceed 60 characters' })
  firstName?: string;

  @ApiPropertyOptional({ description: 'Last name', example: 'Doe' })
  @IsOptional()
  @IsString({ message: 'Last name must be a string' })
  @MinLength(1, { message: 'Last name must be at least 1 character long' })
  @MaxLength(60, { message: 'Last name must not exceed 60 characters' })
  lastName?: string;

  @ApiPropertyOptional({ description: 'Phone number', example: '+14155551234' })
  @IsOptional()
  @IsString({ message: 'Phone must be a string' })
  phone?: string;

  @ApiPropertyOptional({
    description: 'New password',
    example: 'Str0ngP@ssw0rd',
    minLength: 8,
  })
  @IsOptional()
  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password?: string;
}
