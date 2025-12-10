import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class AdminLoginDto {
  @ApiProperty({
    description: 'Admin email or username used for authentication',
    example: 'admin@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid admin email' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({ description: 'Admin account password', example: 'AdminPass123!' })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @ApiPropertyOptional({
    description: 'Two-factor authentication code (if already received)',
    example: '123456',
  })
  @IsString({ message: 'Two-factor code must be a string' })
  @IsOptional()
  twoFactorCode?: string;
}
