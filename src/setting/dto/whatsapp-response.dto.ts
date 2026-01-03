import { ApiProperty } from '@nestjs/swagger';

export class WhatsappResponseDto {
  @ApiProperty({ example: 'meta' })
  provider: string;

  @ApiProperty({ example: '123456789012345' })
  businessAccountId: string;

  @ApiProperty({ example: '109876543210987' })
  phoneNumberId: string;

  @ApiProperty({ example: 'v19.0' })
  apiVersion: string;

  @ApiProperty({ example: 'https://graph.facebook.com' })
  baseUrl: string;

  @ApiProperty({ example: true })
  whatsappEnabled: boolean;

  @ApiProperty({ required: false, type: Date })
  createdAt?: Date;

  @ApiProperty({ required: false, type: Date })
  updatedAt?: Date;
}
