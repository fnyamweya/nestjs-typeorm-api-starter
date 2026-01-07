import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CreatePromotionDto } from '../dto/create-promotion.dto';
import { UpdatePromotionDto } from '../dto/update-promotion.dto';
import { PromotionService } from '../services/promotion.service';

@Controller('promotions')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Promotions')
@ApiBearerAuth('access-token')
export class PromotionController {
  constructor(private readonly promotionService: PromotionService) {}

  @Get()
  @RequirePermissions({
    module: PermissionModule.PROMOTIONS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'List promotions (admin)' })
  @ApiOkResponse({ description: 'Promotions retrieved' })
  async list() {
    const rows = await this.promotionService.listPromotions();
    return ResponseUtil.success(rows, 'Promotions retrieved');
  }

  @Get(':id')
  @RequirePermissions({
    module: PermissionModule.PROMOTIONS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Get promotion (admin)' })
  @ApiOkResponse({ description: 'Promotion retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.promotionService.getPromotion(id);
    return ResponseUtil.success(row, 'Promotion retrieved');
  }

  @Post()
  @RequirePermissions({
    module: PermissionModule.PROMOTIONS,
    permission: 'create',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create promotion (rule + conditions + actions)' })
  @ApiBody({ type: CreatePromotionDto })
  @ApiCreatedResponse({ description: 'Promotion created' })
  async create(@Body() payload: CreatePromotionDto) {
    const row = await this.promotionService.createPromotion(payload);
    return ResponseUtil.created(row, 'Promotion created');
  }

  @Put(':id')
  @RequirePermissions({
    module: PermissionModule.PROMOTIONS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update promotion (admin)' })
  @ApiBody({ type: UpdatePromotionDto })
  @ApiOkResponse({ description: 'Promotion updated' })
  async update(@Param('id') id: string, @Body() payload: UpdatePromotionDto) {
    const row = await this.promotionService.updatePromotion(id, payload);
    return ResponseUtil.success(row, 'Promotion updated');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.PROMOTIONS,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete promotion (admin)' })
  @ApiOkResponse({ description: 'Promotion deleted' })
  async delete(@Param('id') id: string) {
    const ok = await this.promotionService.deletePromotion(id);
    return ResponseUtil.success(ok, 'Promotion deleted');
  }
}
