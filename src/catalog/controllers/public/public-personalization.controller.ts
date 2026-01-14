import {
  Controller,
  Get,
  Req,
  UseGuards,
  UsePipes,
  ValidationPipe,
  Query,
} from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { OptionalJwtAuthGuard } from 'src/auth/guards/optional-jwt-auth.guard';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CustomerProductViewService } from '../../services/customer-product-view.service';
import { RecommendationsService } from '../../services/recommendations.service';

class PersonalizationQueryDto {
  limit?: number;
}

@Controller('public/catalog')
@ApiTags('Public Catalog: Personalization')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class PublicPersonalizationController {
  constructor(
    private readonly customerProductViewService: CustomerProductViewService,
    private readonly recommendationsService: RecommendationsService,
  ) {}

  @Get('recently-viewed')
  @UseGuards(OptionalJwtAuthGuard)
  @ApiOperation({ summary: "Get customer's recently viewed products" })
  @ApiOkResponse({ description: 'Recently viewed products retrieved successfully' })
  async recentlyViewed(@Req() req: Request, @Query() query: PersonalizationQueryDto) {
    const user = (req as any).user as { id: string } | undefined;
    if (!user?.id) {
      return ResponseUtil.success([], 'Not authenticated');
    }

    const views = await this.customerProductViewService.listRecentlyViewed(
      user.id,
      query.limit ?? 20,
    );

    const items = views.map((v) => ({
      viewedAt: v.viewedAt,
      product: v.product,
    }));

    return ResponseUtil.success(items, 'Recently viewed products retrieved successfully');
  }

  @Get('recommendations')
  @UseGuards(OptionalJwtAuthGuard)
  @ApiOperation({ summary: "Get 'Recommended For You' products" })
  @ApiOkResponse({ description: 'Recommendations retrieved successfully' })
  async recommendedForYou(@Req() req: Request, @Query() query: PersonalizationQueryDto) {
    const user = (req as any).user as { id: string } | undefined;
    if (!user?.id) {
      return ResponseUtil.success([], 'Not authenticated');
    }

    const products = await this.recommendationsService.recommendForCustomer(
      user.id,
      query.limit ?? 12,
    );

    return ResponseUtil.success(products, 'Recommendations retrieved successfully');
  }
}
