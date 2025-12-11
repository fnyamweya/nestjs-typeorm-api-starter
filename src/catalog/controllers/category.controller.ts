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
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CategoryService } from '../services/category.service';
import { CreateCategoryDto } from '../dto/create-category.dto';
import { UpdateCategoryDto } from '../dto/update-category.dto';
import { FilterCategoryDto } from '../dto/filter-category.dto';

@Controller('catalog/categories')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Catalog: Categories')
@ApiBearerAuth('access-token')
export class CategoryController {
  constructor(private readonly categoryService: CategoryService) {}

  @Post()
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'create' })
  @ApiOperation({ summary: 'Create category' })
  @ApiCreatedResponse({ description: 'Category created successfully' })
  async create(@Body() payload: CreateCategoryDto) {
    const category = await this.categoryService.create(payload);
    return ResponseUtil.created(category, 'Category created successfully');
  }

  @Get()
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'List categories by taxonomy' })
  @ApiQuery({ name: 'taxonomyId', type: String, required: true })
  @ApiQuery({ name: 'isActive', type: Boolean, required: false })
  @ApiOkResponse({ description: 'Categories retrieved successfully' })
  async findAll(@Query() filters: FilterCategoryDto) {
    const categories = await this.categoryService.findAll(filters);
    return ResponseUtil.success(categories, 'Categories retrieved successfully');
  }

  @Get('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'Get category by id' })
  @ApiOkResponse({ description: 'Category retrieved successfully' })
  async findOne(@Param('id') id: string) {
    const category = await this.categoryService.findOne(id);
    return ResponseUtil.success(category, 'Category retrieved successfully');
  }

  @Patch('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'update' })
  @ApiOperation({ summary: 'Update category' })
  @ApiOkResponse({ description: 'Category updated successfully' })
  async update(@Param('id') id: string, @Body() payload: UpdateCategoryDto) {
    const category = await this.categoryService.update(id, payload);
    return ResponseUtil.updated(category, 'Category updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'delete' })
  @ApiOperation({ summary: 'Delete category' })
  @ApiOkResponse({ description: 'Category deleted successfully' })
  async remove(@Param('id') id: string) {
    await this.categoryService.remove(id);
    return ResponseUtil.deleted('Category deleted successfully');
  }
}
