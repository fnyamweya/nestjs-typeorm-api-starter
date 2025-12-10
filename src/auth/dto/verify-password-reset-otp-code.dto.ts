import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyPasswordResetOTPCodeDto {
  @ApiProperty({
    description: 'Identifier of the user who requested password reset',
    example: '1ab0c8f0-7d3a-4f5f-80ab-e3f98cd5ef70',
    format: 'uuid',
  })
  @IsUUID()
  @IsString()
  @IsNotEmpty({ message: 'User ID is required' })
  userId: string;

  @ApiProperty({
    description: 'Verification code received via email',
    example: '482913',
  })
  @IsString({ message: 'Verification code must be a string' })
  @IsNotEmpty({ message: 'Verification code is required' })
  code: string;
}
