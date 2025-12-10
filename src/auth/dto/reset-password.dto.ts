import { IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
  @ApiProperty({
    description: 'Time limited access token provided after OTP verification',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString({ message: 'Access Token must be a string' })
  @IsNotEmpty({ message: 'Access Token is required' })
  accessToken: string;

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
