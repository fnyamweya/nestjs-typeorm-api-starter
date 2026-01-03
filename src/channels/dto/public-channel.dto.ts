import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PublicChannelDto {
  @ApiProperty()
  id: string;

  @ApiProperty({ example: 'WEB' })
  code: string;

  @ApiProperty({ example: 'Web Store' })
  name: string;

  @ApiPropertyOptional({ example: 'Primary ecommerce storefront channel.' })
  description?: string;
}
