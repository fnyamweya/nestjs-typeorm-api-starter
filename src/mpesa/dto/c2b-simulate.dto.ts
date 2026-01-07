import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsNumber, IsOptional, IsString } from 'class-validator';

export class C2BSimulateDto {
  @ApiProperty({
    description: 'ShortCode to simulate payment to',
    example: '600000',
  })
  @IsString()
  shortCode: string;

  @ApiProperty({ description: 'Amount to simulate', example: 100 })
  @IsNumber()
  amount: number;

  @ApiProperty({
    description: 'Customer MSISDN (phone number in international format)',
    example: '254708374149',
  })
  @IsString()
  msisdn: string;

  @ApiProperty({ description: 'Bill reference number', example: 'INV-1001' })
  @IsString()
  billRefNumber: string;

  @ApiPropertyOptional({
    description:
      'Daraja CommandID for C2B simulation. Common: CustomerPayBillOnline or CustomerBuyGoodsOnline',
    example: 'CustomerPayBillOnline',
  })
  @IsOptional()
  @IsIn(['CustomerPayBillOnline', 'CustomerBuyGoodsOnline'])
  commandId?: 'CustomerPayBillOnline' | 'CustomerBuyGoodsOnline';
}
