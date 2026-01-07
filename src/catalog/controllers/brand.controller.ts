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
  ApiCreatedResponse,
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { BrandService } from '../services/brand.service';
import { CreateBrandDto } from '../dto/create-brand.dto';
import { UpdateBrandDto } from '../dto/update-brand.dto';
import { FilterBrandDto } from '../dto/filter-brand.dto';

@Controller('catalog/brands')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Catalog: Brands')
export class BrandController {
  constructor(private readonly brandService: BrandService) {}

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'create',
  })
  @ApiOperation({ summary: 'Create brand' })
  @ApiCreatedResponse({ description: 'Brand created successfully' })
  async create(@Body() payload: CreateBrandDto) {
    const brand = await this.brandService.create(payload);
    return ResponseUtil.created(brand, 'Brand created successfully');
  }

  @Get()
  @ApiOperation({ summary: 'List brands with pagination' })
  @ApiOkResponse({ description: 'Brands retrieved successfully' })
  async findAll(@Query() filters: FilterBrandDto) {
    const result = await this.brandService.findAll(filters);
    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Brands retrieved successfully',
    );
  }

  @Get('/:id')
  @ApiOperation({ summary: 'Get brand by id' })
  @ApiOkResponse({ description: 'Brand retrieved successfully' })
  async findOne(@Param('id') id: string) {
    const brand = await this.brandService.findOne(id);
    return ResponseUtil.success(brand, 'Brand retrieved successfully');
  }

  @Patch('/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update brand' })
  @ApiOkResponse({ description: 'Brand updated successfully' })
  async update(@Param('id') id: string, @Body() payload: UpdateBrandDto) {
    const brand = await this.brandService.update(id, payload);
    return ResponseUtil.updated(brand, 'Brand updated successfully');
  }

  @Delete('/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete brand' })
  @ApiOkResponse({ description: 'Brand deleted successfully' })
  async remove(@Param('id') id: string) {
    await this.brandService.remove(id);
    return ResponseUtil.deleted('Brand deleted successfully');
  }
}
