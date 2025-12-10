import {
  IsString,
  IsNotEmpty,
  MaxLength,
  IsEmail,
  IsOptional,
  IsBoolean,
  IsNumber,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateSMTPDto {
  @ApiProperty({
    description: 'Hostname of the SMTP server',
    example: 'smtp.mailgun.org',
    maxLength: 255,
  })
  @IsString({ message: 'SMTP host must be a string' })
  @IsNotEmpty({ message: 'SMTP host is required' })
  @MaxLength(255, { message: 'SMTP host must not exceed 255 characters' })
  smtpHost: string;

  @ApiProperty({
    description: 'Port used to connect to the SMTP server',
    example: 587,
  })
  @IsNumber({}, { message: 'SMTP port must be a valid port number' })
  @Transform(({ value }) => parseInt(value))
  smtpPort: number;

  @ApiProperty({
    description: 'Whether to use TLS/SSL when connecting to the SMTP server',
    example: true,
  })
  @IsBoolean({ message: 'SMTP secure must be a boolean value' })
  @Transform(({ value }) => value === 'true' || value === true)
  smtpSecure: boolean;

  @ApiPropertyOptional({
    description: 'Username credential for the SMTP server',
    example: 'apikey',
    maxLength: 255,
  })
  @IsString({ message: 'SMTP username must be a string' })
  @IsOptional()
  @MaxLength(255, { message: 'SMTP username must not exceed 255 characters' })
  smtpUsername?: string;

  @ApiPropertyOptional({
    description: 'Password credential for the SMTP server',
    example: 'secret-password',
    maxLength: 255,
  })
  @IsString({ message: 'SMTP password must be a string' })
  @IsOptional()
  @MaxLength(255, { message: 'SMTP password must not exceed 255 characters' })
  smtpPassword?: string;

  @ApiProperty({
    description: 'Default from email address used for outgoing mail',
    example: 'no-reply@qtechapis.com',
    maxLength: 255,
  })
  @IsEmail({}, { message: 'SMTP from email must be a valid email address' })
  @IsNotEmpty({ message: 'SMTP from email is required' })
  @MaxLength(255, { message: 'SMTP from email must not exceed 255 characters' })
  smtpFromEmail: string;

  @ApiProperty({
    description: 'Display name used for outgoing mail',
    example: 'QTech APIs',
    maxLength: 255,
  })
  @IsString({ message: 'SMTP from name must be a string' })
  @IsNotEmpty({ message: 'SMTP from name is required' })
  @MaxLength(255, { message: 'SMTP from name must not exceed 255 characters' })
  smtpFromName: string;

  @ApiProperty({
    description: 'Whether SMTP notifications are enabled',
    example: true,
  })
  @IsBoolean({ message: 'SMTP enabled must be a boolean value' })
  @Transform(({ value }) => value === 'true' || value === true)
  smtpEnabled: boolean;
}
