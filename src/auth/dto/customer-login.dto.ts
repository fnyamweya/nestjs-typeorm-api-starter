import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, Length } from 'class-validator';

export class CustomerLoginDto {
  @ApiProperty({
    description: 'Email address or phone number registered for the customer',
    example: '+14155551234',
  })
  @IsString({ message: 'Identifier must be a string' })
  @IsNotEmpty({ message: 'Email or phone is required' })
  identifier: string;

  @ApiProperty({
    description: 'Customer account password',
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
