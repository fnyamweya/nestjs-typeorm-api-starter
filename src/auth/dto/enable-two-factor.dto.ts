import {
  IsEmail,
  IsIn,
  IsNotEmpty,
  IsOptional,
  ValidateIf,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class EnableTwoFactorDto {
  @ApiProperty({
    description: 'Preferred MFA channel',
    example: 'email',
    enum: ['email', 'sms'],
    default: 'email',
  })
  @IsIn(['email', 'sms'])
  channel: 'email' | 'sms' = 'email';

  @ApiPropertyOptional({
    description: 'Email to which the verification code should be sent (required when channel=email)',
    example: 'jane.doe@example.com',
  })
  @ValidateIf((dto) => dto.channel === 'email')
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsOptional()
  email?: string;
}
