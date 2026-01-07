import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsIn,
  IsNumber,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';

export class B2CPaymentRequestDto {
  @ApiPropertyOptional({
    description: 'Optional internal Order ID (UUID) to link this payout to',
    example: 'b9a1c0d2-9e9a-4a2a-bb8e-4d5c1c0a1e2f',
  })
  @IsOptional()
  @IsString()
  orderId?: string;

  @ApiPropertyOptional({
    description: 'Initiator name configured on Daraja (defaults to env)',
  })
  @IsOptional()
  @IsString()
  initiatorName?: string;

  @ApiPropertyOptional({
    description:
      'Daraja SecurityCredential (encrypted initiator password). Defaults to env',
  })
  @IsOptional()
  @IsString()
  securityCredential?: string;

  @ApiPropertyOptional({
    description: 'B2C CommandID (defaults to BusinessPayment)',
    example: 'BusinessPayment',
  })
  @IsOptional()
  @IsIn(['BusinessPayment', 'SalaryPayment', 'PromotionPayment'])
  commandId?: 'BusinessPayment' | 'SalaryPayment' | 'PromotionPayment';

  @ApiProperty({ description: 'Amount to send', example: 100 })
  @IsNumber()
  @Min(1)
  amount: number;

  @ApiPropertyOptional({
    description:
      'Organization short code (PartyA). Defaults to env shortcode if not provided',
    example: '600000',
  })
  @IsOptional()
  @IsString()
  partyA?: string;

  @ApiProperty({
    description: 'Recipient phone number (PartyB) in international format',
    example: '254708374149',
  })
  @IsString()
  partyB: string;

  @ApiProperty({ description: 'Remarks', example: 'Withdrawal' })
  @IsString()
  @MaxLength(100)
  remarks: string;

  @ApiPropertyOptional({
    description:
      'Result URL. Defaults to <callbackBaseUrl>/api/v1/mpesa/b2c/result',
  })
  @IsOptional()
  @IsString()
  resultUrl?: string;

  @ApiPropertyOptional({
    description:
      'Queue timeout URL. Defaults to <callbackBaseUrl>/api/v1/mpesa/b2c/timeout',
  })
  @IsOptional()
  @IsString()
  queueTimeoutUrl?: string;

  @ApiPropertyOptional({ description: 'Occasion', example: 'Order#123' })
  @IsOptional()
  @IsString()
  occasion?: string;
}
