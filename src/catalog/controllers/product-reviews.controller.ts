import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { AuthenticatedUser } from 'src/auth/interfaces/user.interface';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ProductReviewService } from '../services/product-review.service';
import {
  ListPendingProductReviewsQueryDto,
  RejectProductReviewDto,
} from '../dto/product-review.dto';

@Controller('catalog/product-reviews')
@ApiTags('Catalog: Product Reviews')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class ProductReviewsController {
  constructor(private readonly productReviewService: ProductReviewService) {}

  @Get('pending')
  @RequirePermissions({ module: PermissionModule.CATALOG, permission: 'read' })
  @ApiOperation({ summary: 'List pending product reviews' })
  @ApiOkResponse({ description: 'Pending product reviews retrieved successfully' })
  async listPending(@Query() query: ListPendingProductReviewsQueryDto) {
    const result = await this.productReviewService.listPendingReviews(
      query.page ?? 1,
      query.limit ?? 50,
    );

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Pending product reviews retrieved successfully',
    );
  }

  @Patch(':id/approve')
  @RequirePermissions({ module: PermissionModule.CATALOG, permission: 'update' })
  @ApiOperation({ summary: 'Approve a product review' })
  @ApiOkResponse({ description: 'Product review approved successfully' })
  async approve(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const review = await this.productReviewService.approveReview(id, user.id);
    return ResponseUtil.updated(review, 'Product review approved successfully');
  }

  @Patch(':id/reject')
  @RequirePermissions({ module: PermissionModule.CATALOG, permission: 'update' })
  @ApiOperation({ summary: 'Reject a product review' })
  @ApiOkResponse({ description: 'Product review rejected successfully' })
  async reject(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() payload: RejectProductReviewDto,
  ) {
    const review = await this.productReviewService.rejectReview(
      id,
      user.id,
      payload.statusReason,
    );
    return ResponseUtil.updated(review, 'Product review rejected successfully');
  }
}
