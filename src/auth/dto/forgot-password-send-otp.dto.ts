import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateIf,
} from 'class-validator';

export class ForgotPasswordSendOTPDto {
  @ApiPropertyOptional({
    description:
      'Deprecated: use identifier. Email address associated with the account requesting recovery.',
    example: 'jane.doe@example.com',
    deprecated: true,
  })
  @ValidateIf((o) => !o.identifier)
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  @IsOptional()
  email?: string;

  @ApiProperty({
    description:
      'Email address or phone number associated with the account requesting recovery.',
    example: 'jane.doe@example.com',
  })
  @ValidateIf((o) => !o.email)
  @IsString({ message: 'Identifier must be a string' })
  @IsNotEmpty({ message: 'Identifier is required' })
  identifier?: string;
}
