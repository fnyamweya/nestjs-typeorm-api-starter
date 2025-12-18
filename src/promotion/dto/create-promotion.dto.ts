import { IsNotEmpty, IsOptional, IsIn, IsNumberString, IsString } from 'class-validator';
import { PromotionType } from '../entities/promotion.entity';

export class CreatePromotionDto {
  @IsNotEmpty()
  code: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsIn(['percentage', 'fixed', 'free_shipping'])
  type: PromotionType;

  @IsOptional()
  @IsNumberString()
  value?: string;

  @IsOptional()
  @IsString()
  currencyCode?: string;
}
