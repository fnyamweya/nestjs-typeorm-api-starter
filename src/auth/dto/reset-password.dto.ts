import {
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
  ValidateIf,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
  @ApiProperty({
    description:
      'Short-lived reset token returned after OTP verification (preferred).',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @ValidateIf((o) => !o.accessToken)
  @IsString({ message: 'Reset token must be a string' })
  @IsNotEmpty({ message: 'Reset token is required' })
  resetToken?: string;

  @ApiProperty({
    description:
      'Deprecated: use resetToken. Time-limited token provided after OTP verification.',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    deprecated: true,
  })
  @ValidateIf((o) => !o.resetToken)
  @IsString({ message: 'Access token must be a string' })
  @IsNotEmpty({ message: 'Access token is required' })
  accessToken?: string;

  @ApiProperty({
    description: 'New password to set for the account',
    example: 'N3wP@ssw0rd',
    minLength: 6,
  })
  @IsString({ message: 'New password must be a string' })
  @IsNotEmpty({ message: 'New password is required' })
  @MinLength(6, { message: 'New password must be at least 6 characters long' })
  newPassword: string;
}
