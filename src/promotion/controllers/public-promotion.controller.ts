import { Controller, Get, Query } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { PromotionService } from '../services/promotion.service';
import { PublicPromotionDto } from '../dto/public-promotion.dto';

@ApiTags('Public Promotions')
@Controller('public/promotions')
export class PublicPromotionController {
  constructor(private readonly promotionService: PromotionService) {}

  @Get()
  @ApiOperation({
    summary: 'List active promotions (public marketing view)',
    description:
      'Returns a limited, storefront-safe view of active promotions. Does not expose conditions/actions/limits.',
  })
  @ApiOkResponse({ type: PublicPromotionDto, isArray: true })
  async list(@Query('channel') channel?: string) {
    const rows = await this.promotionService.listPublicPromotions({ channel });
    return ResponseUtil.success(rows, 'Public promotions retrieved');
  }
}
