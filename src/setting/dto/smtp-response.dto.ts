import { Expose } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class SMTPResponseDto {
  @ApiProperty({
    description: 'Hostname of the SMTP server',
    example: 'smtp.mailgun.org',
  })
  @Expose()
  smtpHost: string;

  @ApiProperty({
    description: 'Port used to connect to the SMTP server',
    example: 587,
  })
  @Expose()
  smtpPort: number;

  @ApiProperty({
    description: 'Indicates if the connection is secure (TLS/SSL)',
    example: true,
  })
  @Expose()
  smtpSecure: boolean;

  @ApiProperty({
    description: 'Username credential for the SMTP server',
    example: 'apikey',
    nullable: true,
  })
  @Expose()
  smtpUsername: string;

  @ApiProperty({
    description: 'Password credential for the SMTP server',
    example: 'secret-password',
    nullable: true,
  })
  @Expose()
  smtpPassword: string;

  @ApiProperty({
    description: 'Default from email address',
    example: 'no-reply@qtechapis.com',
  })
  @Expose()
  smtpFromEmail: string;

  @ApiProperty({
    description: 'Default from display name',
    example: 'QTech APIs',
  })
  @Expose()
  smtpFromName: string;

  @ApiProperty({ description: 'Indicates if SMTP is enabled', example: true })
  @Expose()
  smtpEnabled: boolean;

  @ApiProperty({
    description: 'Date when the configuration was created',
    example: '2025-01-01T12:00:00.000Z',
  })
  @Expose()
  createdAt: Date;

  @ApiProperty({
    description: 'Date when the configuration was last updated',
    example: '2025-02-01T13:30:00.000Z',
  })
  @Expose()
  updatedAt: Date;
}
