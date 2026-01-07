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
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CreateChannelDto } from '../dto/create-channel.dto';
import { UpdateChannelDto } from '../dto/update-channel.dto';
import { ListChannelsDto } from '../dto/list-channels.dto';
import { ChannelsService } from '../services/channels.service';

@Controller('channels')
@ApiTags('Channels')
@ApiBearerAuth('access-token')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class ChannelsController {
  constructor(private readonly channelsService: ChannelsService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.CHANNELS,
    permission: 'create',
  })
  @ApiCreatedResponse({ description: 'Channel created' })
  async create(@Body() payload: CreateChannelDto) {
    const row = await this.channelsService.create(payload);
    return ResponseUtil.created(row, 'Channel created');
  }

  @Get()
  @RequirePermissions({ module: PermissionModule.CHANNELS, permission: 'read' })
  @ApiOkResponse({ description: 'Channels retrieved' })
  async list(@Query() query: ListChannelsDto) {
    const rows = await this.channelsService.list(query);
    return ResponseUtil.success(rows, 'Channels retrieved');
  }

  @Get(':id')
  @RequirePermissions({ module: PermissionModule.CHANNELS, permission: 'read' })
  @ApiOkResponse({ description: 'Channel retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.channelsService.getById(id);
    return ResponseUtil.success(row, 'Channel retrieved');
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.CHANNELS,
    permission: 'update',
  })
  @ApiOkResponse({ description: 'Channel updated' })
  async update(@Param('id') id: string, @Body() payload: UpdateChannelDto) {
    const row = await this.channelsService.update(id, payload);
    return ResponseUtil.success(row, 'Channel updated');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.CHANNELS,
    permission: 'delete',
  })
  @ApiOkResponse({ description: 'Channel deleted' })
  async delete(@Param('id') id: string) {
    const res = await this.channelsService.delete(id);
    return ResponseUtil.success(res, 'Channel deleted');
  }
}
