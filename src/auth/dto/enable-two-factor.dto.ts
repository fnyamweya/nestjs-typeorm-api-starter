import { IsEmail, IsEnum, IsOptional, ValidateIf } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { MfaChannel } from 'src/user/enums';

export class EnableTwoFactorDto {
  @ApiProperty({
    description: 'Preferred MFA channel',
    example: MfaChannel.EMAIL,
    enum: MfaChannel,
    default: MfaChannel.EMAIL,
  })
  @IsEnum(MfaChannel)
  channel: MfaChannel = MfaChannel.EMAIL;

  @ApiPropertyOptional({
    description: 'Email to which the verification code should be sent (required when channel=email)',
    example: 'jane.doe@example.com',
  })
  @ValidateIf((dto) => dto.channel === MfaChannel.EMAIL)
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsOptional()
  email?: string;
}
