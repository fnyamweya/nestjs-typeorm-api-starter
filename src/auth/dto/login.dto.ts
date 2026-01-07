import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    description: 'User email used to sign in',
    example: 'jane.doe@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'User password used to sign in',
    example: 'Str0ngP@ssw0rd',
  })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @ApiPropertyOptional({
    description: 'Two-factor authentication code (if already received)',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString({ message: 'Two-factor code must be a string' })
  @IsOptional()
  @Length(6, 6, { message: 'Two-factor code must be exactly 6 characters' })
  twoFactorCode?: string;
}
