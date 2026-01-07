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
import { CurrencyService } from './currency.service';
import { CreateCurrencyDto } from './dto/create-currency.dto';
import { UpdateCurrencyDto } from './dto/update-currency.dto';

@Controller('currencies')
@ApiTags('Currencies')
export class CurrencyController {
  constructor(private readonly currencyService: CurrencyService) {}

  @Get()
  @ApiOperation({ summary: 'List currencies' })
  @ApiOkResponse({ description: 'Currencies retrieved' })
  async list() {
    const rows = await this.currencyService.list();
    return ResponseUtil.success(rows, 'Currencies retrieved');
  }

  @Get(':code')
  @ApiOperation({ summary: 'Get currency by code' })
  @ApiOkResponse({ description: 'Currency retrieved' })
  async get(@Param('code') code: string) {
    const row = await this.currencyService.getByCode(code);
    return ResponseUtil.success(row, 'Currency retrieved');
  }

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @UsePipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  )
  @RequirePermissions({
    module: PermissionModule.CURRENCIES,
    permission: 'create',
  })
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Create (or upsert) currency (admin)' })
  @ApiBody({ type: CreateCurrencyDto })
  @ApiCreatedResponse({ description: 'Currency saved' })
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() payload: CreateCurrencyDto) {
    const row = await this.currencyService.upsert(payload);
    return ResponseUtil.created(row, 'Currency saved');
  }

  @Put(':code')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @UsePipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  )
  @RequirePermissions({
    module: PermissionModule.CURRENCIES,
    permission: 'update',
  })
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Update currency (admin)' })
  @ApiBody({ type: UpdateCurrencyDto })
  @ApiOkResponse({ description: 'Currency updated' })
  async update(
    @Param('code') code: string,
    @Body() payload: UpdateCurrencyDto,
  ) {
    const row = await this.currencyService.update(code, payload);
    return ResponseUtil.success(row, 'Currency updated');
  }

  @Delete(':code')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.CURRENCIES,
    permission: 'delete',
  })
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Delete currency (admin)' })
  @ApiOkResponse({ description: 'Currency deleted' })
  async delete(@Param('code') code: string) {
    const res = await this.currencyService.remove(code);
    return ResponseUtil.success(res, 'Currency deleted');
  }
}
