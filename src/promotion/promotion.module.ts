import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Promotion } from './entities/promotion.entity';
import { PromotionService } from './services/promotion.service';

@Module({
  imports: [TypeOrmModule.forFeature([Promotion])],
  providers: [PromotionService],
  exports: [PromotionService],
})
export class PromotionModule {}
