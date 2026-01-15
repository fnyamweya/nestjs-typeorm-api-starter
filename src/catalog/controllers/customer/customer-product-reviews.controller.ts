import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Put,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { AuthenticatedUser } from 'src/auth/interfaces/user.interface';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ProductReviewService } from '../../services/product-review.service';
import { UpsertProductReviewDto } from '../../dto/product-review.dto';

@Controller('customer/product-reviews')
@UseGuards(JwtAuthGuard)
@ApiTags('Customer: Product Reviews')
@ApiBearerAuth('access-token')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class CustomerProductReviewsController {
  constructor(private readonly productReviewService: ProductReviewService) {}

  @Get(':productId')
  @ApiOperation({ summary: 'Get my review for a product' })
  @ApiOkResponse({ description: 'My product review retrieved successfully' })
  async getMyReview(
    @CurrentUser() user: AuthenticatedUser,
    @Param('productId') productId: string,
  ) {
    const review = await this.productReviewService.getMyReview(user.id, productId);
    return ResponseUtil.success(review, 'My product review retrieved successfully');
  }

  @Put(':productId')
  @ApiOperation({ summary: 'Create or update my product review (submits for moderation)' })
  @ApiOkResponse({ description: 'My product review saved successfully' })
  async upsert(
    @CurrentUser() user: AuthenticatedUser,
    @Param('productId') productId: string,
    @Body() payload: UpsertProductReviewDto,
  ) {
    const review = await this.productReviewService.upsertMyReview(
      user.id,
      productId,
      payload,
    );
    return ResponseUtil.success(review, 'My product review saved successfully');
  }

  @Delete(':productId')
  @ApiOperation({ summary: 'Delete my review for a product' })
  @ApiOkResponse({ description: 'My product review deleted successfully' })
  async deleteMyReview(
    @CurrentUser() user: AuthenticatedUser,
    @Param('productId') productId: string,
  ) {
    const result = await this.productReviewService.deleteMyReview(user.id, productId);
    return ResponseUtil.success(result, 'My product review deleted successfully');
  }
}
