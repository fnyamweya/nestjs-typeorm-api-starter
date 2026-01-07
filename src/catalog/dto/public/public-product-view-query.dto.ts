import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsUUID } from 'class-validator';
import { ProductViewContextDto } from '../product-v2/product-view-context.dto';

export class PublicProductViewQueryDto extends ProductViewContextDto {
  @ApiPropertyOptional({
    description: 'Preferred locale for translated fields',
    example: 'en',
  })
  @IsOptional()
  @IsString()
  locale?: string;

  @ApiPropertyOptional({ description: 'Price list id for price resolution' })
  @IsOptional()
  @IsUUID('4')
  priceListId?: string;

  @ApiPropertyOptional({
    description: 'Currency code for price resolution',
    example: 'KES',
  })
  @IsOptional()
  @IsString()
  currencyCode?: string;
}
