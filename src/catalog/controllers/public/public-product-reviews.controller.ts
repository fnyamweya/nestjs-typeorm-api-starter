import {
  Controller,
  Get,
  Param,
  Query,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ProductReviewService } from '../../services/product-review.service';
import { ListProductReviewsQueryDto } from '../../dto/product-review.dto';

@Controller('public/catalog/products')
@ApiTags('Public Catalog: Product Reviews')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class PublicProductReviewsController {
  constructor(private readonly productReviewService: ProductReviewService) {}

  @Get(':productId/rating-summary')
  @ApiOperation({ summary: 'Get product rating summary' })
  @ApiOkResponse({ description: 'Product rating summary retrieved successfully' })
  async ratingSummary(@Param('productId') productId: string) {
    const summary = await this.productReviewService.getRatingSummary(productId);
    return ResponseUtil.success(summary, 'Product rating summary retrieved successfully');
  }

  @Get(':productId/reviews')
  @ApiOperation({ summary: 'List approved product reviews' })
  @ApiOkResponse({ description: 'Product reviews retrieved successfully' })
  async list(
    @Param('productId') productId: string,
    @Query() query: ListProductReviewsQueryDto,
  ) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;

    const result = await this.productReviewService.listApprovedReviews(
      productId,
      page,
      limit,
      query.sort ?? 'newest',
    );

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Product reviews retrieved successfully',
    );
  }
}
