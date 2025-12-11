import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
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
import { TaxonomyService } from '../services/taxonomy.service';
import { CreateTaxonomyDto } from '../dto/create-taxonomy.dto';
import { UpdateTaxonomyDto } from '../dto/update-taxonomy.dto';

@Controller('catalog/taxonomies')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Catalog: Taxonomies')
@ApiBearerAuth('access-token')
export class TaxonomyController {
  constructor(private readonly taxonomyService: TaxonomyService) {}

  @Post()
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'create' })
  @ApiOperation({ summary: 'Create a taxonomy' })
  @ApiCreatedResponse({ description: 'Taxonomy created successfully' })
  async create(@Body() payload: CreateTaxonomyDto) {
    const taxonomy = await this.taxonomyService.create(payload);
    return ResponseUtil.created(taxonomy, 'Taxonomy created successfully');
  }

  @Get()
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'List all taxonomies' })
  @ApiOkResponse({ description: 'Taxonomies retrieved successfully' })
  async findAll() {
    const data = await this.taxonomyService.findAll();
    return ResponseUtil.success(data, 'Taxonomies retrieved successfully');
  }

  @Get('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'Get taxonomy by id' })
  @ApiOkResponse({ description: 'Taxonomy retrieved successfully' })
  async findOne(@Param('id') id: string) {
    const taxonomy = await this.taxonomyService.findOne(id);
    return ResponseUtil.success(taxonomy, 'Taxonomy retrieved successfully');
  }

  @Patch('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'update' })
  @ApiOperation({ summary: 'Update taxonomy' })
  @ApiOkResponse({ description: 'Taxonomy updated successfully' })
  async update(
    @Param('id') id: string,
    @Body() payload: UpdateTaxonomyDto,
  ) {
    const taxonomy = await this.taxonomyService.update(id, payload);
    return ResponseUtil.updated(taxonomy, 'Taxonomy updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'delete' })
  @ApiOperation({ summary: 'Delete taxonomy' })
  @ApiOkResponse({ description: 'Taxonomy deleted successfully' })
  async remove(@Param('id') id: string) {
    await this.taxonomyService.remove(id);
    return ResponseUtil.deleted('Taxonomy deleted successfully');
  }
}
