import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { BannerService } from './banner.service';
import { CreateBannerDto } from './dto/create-banner.dto';
import { UpdateBannerDto } from './dto/update-banner.dto';
import { FilterBannerDto } from './dto/filter-banner.dto';

@Controller('banners')
@ApiTags('Banners')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class BannerController {
  constructor(private readonly bannerService: BannerService) {}

  @Get('public')
  @ApiOperation({
    summary: 'List banners for storefront (public)',
    description:
      'Returns only banners that are currently active (isActive + startsAt/endsAt window). Use dynamic filters for placement/targets.',
  })
  @ApiQuery({ name: 'placementPage', required: false, example: 'landing' })
  @ApiQuery({ name: 'placementSection', required: false, example: 'hero' })
  @ApiQuery({ name: 'targetKind', required: false, example: 'category' })
  @ApiQuery({
    name: 'targetRefId',
    required: false,
    example: 'uuid-of-category',
  })
  @ApiOkResponse({ description: 'Public banners retrieved' })
  async listPublic(@Query() filters: FilterBannerDto) {
    const result = await this.bannerService.findAll(filters, {
      publicOnly: true,
    });

    if (filters.getAll) {
      return ResponseUtil.success(result.data, 'Public banners retrieved');
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Public banners retrieved',
    );
  }

  @Post()
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.BANNERS,
    permission: 'create',
  })
  @ApiOperation({
    summary: 'Create a banner',
    description:
      "Banners support dynamic placements/targets (JSON). creative.kind can be 'image' (imageKey/imageUrl) or 'color' (backgroundColor).",
  })
  @ApiCreatedResponse({ description: 'Banner created' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to create banners',
  })
  async create(@Body() payload: CreateBannerDto) {
    const row = await this.bannerService.create(payload);
    return ResponseUtil.created(row, 'Banner created');
  }

  @Get()
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.BANNERS, permission: 'read' })
  @ApiOperation({ summary: 'List banners (admin)' })
  @ApiOkResponse({ description: 'Banners retrieved' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read banners',
  })
  async list(@Query() filters: FilterBannerDto) {
    const result = await this.bannerService.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(result.data, 'All banners retrieved');
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Banners retrieved',
    );
  }

  @Get(':id')
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.BANNERS, permission: 'read' })
  @ApiOperation({ summary: 'Get a banner by id' })
  @ApiParam({ name: 'id', description: 'Banner UUID' })
  @ApiOkResponse({ description: 'Banner retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.bannerService.findOne(id);
    return ResponseUtil.success(row, 'Banner retrieved');
  }

  @Patch(':id')
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.BANNERS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update a banner' })
  @ApiParam({ name: 'id', description: 'Banner UUID' })
  @ApiOkResponse({ description: 'Banner updated' })
  async update(@Param('id') id: string, @Body() payload: UpdateBannerDto) {
    const row = await this.bannerService.update(id, payload);
    return ResponseUtil.success(row, 'Banner updated');
  }

  @Delete(':id')
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.BANNERS,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete a banner' })
  @ApiParam({ name: 'id', description: 'Banner UUID' })
  @ApiOkResponse({ description: 'Banner deleted' })
  async remove(@Param('id') id: string) {
    const res = await this.bannerService.remove(id);
    return ResponseUtil.success(res, 'Banner deleted');
  }
}
