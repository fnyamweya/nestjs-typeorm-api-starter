import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString } from 'class-validator';

export class C2BRegisterUrlsDto {
  @ApiProperty({
    description: 'ShortCode / PayBill / Till number to register for C2B',
    example: '600000',
  })
  @IsString()
  shortCode: string;

  @ApiPropertyOptional({
    description:
      'Validation URL for C2B. Defaults to <callbackBaseUrl>/api/v1/mpesa/c2b/validation',
  })
  @IsOptional()
  @IsString()
  validationUrl?: string;

  @ApiPropertyOptional({
    description:
      'Confirmation URL for C2B. Defaults to <callbackBaseUrl>/api/v1/mpesa/c2b/confirmation',
  })
  @IsOptional()
  @IsString()
  confirmationUrl?: string;

  @ApiPropertyOptional({
    description:
      'Response type for validation. Usually Completed or Cancelled.',
    example: 'Completed',
  })
  @IsOptional()
  @IsIn(['Completed', 'Cancelled'])
  responseType?: 'Completed' | 'Cancelled';
}
