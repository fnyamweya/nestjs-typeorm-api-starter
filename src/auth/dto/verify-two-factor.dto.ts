import { IsString, IsNotEmpty, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyTwoFactorDto {
  @ApiProperty({
    description: 'Identifier of the user performing verification',
    example: '1ab0c8f0-7d3a-4f5f-80ab-e3f98cd5ef70',
  })
  @IsString({ message: 'User ID must be a string' })
  @IsNotEmpty({ message: 'User ID is required' })
  userId: string;

  @ApiProperty({
    description: 'Six digit verification code delivered to the user',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString({ message: 'Verification code must be a string' })
  @IsNotEmpty({ message: 'Verification code is required' })
  @Length(6, 6, { message: 'Verification code must be exactly 6 characters' })
  code: string;
}
