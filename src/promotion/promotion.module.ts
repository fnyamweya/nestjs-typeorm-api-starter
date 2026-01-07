import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Promotion } from './entities/promotion.entity';
import { PromotionAction } from './entities/promotion-action.entity';
import { PromotionCondition } from './entities/promotion-condition.entity';
import { PromotionRedemption } from './entities/promotion-redemption.entity';
import { PromotionService } from './services/promotion.service';
import { PromotionController } from './controllers/promotion.controller';
import { PublicPromotionController } from './controllers/public-promotion.controller';
import { CurrencyModule } from 'src/currency/currency.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Promotion,
      PromotionCondition,
      PromotionAction,
      PromotionRedemption,
    ]),
    CurrencyModule,
  ],
  controllers: [PromotionController, PublicPromotionController],
  providers: [PromotionService],
  exports: [PromotionService],
})
export class PromotionModule {}
