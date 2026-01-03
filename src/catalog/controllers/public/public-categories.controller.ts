import { Controller, Get, Param, Query, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CategoryService } from '../../services/category.service';
import { PublicListCategoriesDto } from '../../dto/public/public-list-categories.dto';

@Controller('public/catalog/categories')
@ApiTags('Public Catalog: Categories')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
export class PublicCategoriesController {
  constructor(private readonly categoryService: CategoryService) {}

  @Get()
  @ApiOkResponse({ description: 'Public categories retrieved successfully' })
  async list(@Query() query: PublicListCategoriesDto) {
    const rows = await this.categoryService.findAllPublic(query);
    return ResponseUtil.success(rows, 'Public categories retrieved successfully');
  }

  @Get(':id')
  @ApiOkResponse({ description: 'Public category retrieved successfully' })
  async get(@Param('id') id: string, @Query('locale') locale?: string) {
    const row = await this.categoryService.findOnePublic(id, { locale });
    return ResponseUtil.success(row, 'Public category retrieved successfully');
  }
}
