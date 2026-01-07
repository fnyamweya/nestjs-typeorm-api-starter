import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsIn,
  IsNumber,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';

export class B2BPaymentRequestDto {
  @ApiPropertyOptional({
    description: 'Optional internal Order ID (UUID) to link this transfer to',
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
    description: 'B2B CommandID',
    example: 'BusinessPayBill',
  })
  @IsOptional()
  @IsIn([
    'BusinessPayBill',
    'BusinessBuyGoods',
    'DisburseFundsToBusiness',
    'MerchantToMerchantTransfer',
  ])
  commandId?:
    | 'BusinessPayBill'
    | 'BusinessBuyGoods'
    | 'DisburseFundsToBusiness'
    | 'MerchantToMerchantTransfer';

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
    description:
      'Recipient short code / paybill / till (PartyB). Provided by Safaricom for the receiver',
    example: '600000',
  })
  @IsString()
  partyB: string;

  @ApiProperty({
    description: 'Account reference (AccountReference)',
    example: 'INV-1001',
  })
  @IsString()
  @MaxLength(50)
  accountReference: string;

  @ApiProperty({ description: 'Remarks', example: 'Settlement' })
  @IsString()
  @MaxLength(100)
  remarks: string;

  @ApiPropertyOptional({
    description:
      'Result URL. Defaults to <callbackBaseUrl>/api/v1/mpesa/b2b/result',
  })
  @IsOptional()
  @IsString()
  resultUrl?: string;

  @ApiPropertyOptional({
    description:
      'Queue timeout URL. Defaults to <callbackBaseUrl>/api/v1/mpesa/b2b/timeout',
  })
  @IsOptional()
  @IsString()
  queueTimeoutUrl?: string;
}
