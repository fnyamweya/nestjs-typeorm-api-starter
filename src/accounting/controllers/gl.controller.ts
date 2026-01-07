import {
  Controller,
  Get,
  Header,
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
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../../auth/guards/permissions.guard';
import { RequirePermissions } from '../../auth/decorators/permissions.decorator';
import { PermissionModule } from '../../auth/entities/permission.entity';
import { ResponseUtil } from '../../common/utils/response.util';
import { AccountingService } from '../accounting.service';
import { GlListAccountsQueryDto } from '../dto/gl-list-accounts.query.dto';
import { GlListJournalEntriesQueryDto } from '../dto/gl-list-journal-entries.query.dto';

@Controller('gl')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('GL')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@RequirePermissions({ module: PermissionModule.REPORTING, permission: 'read' })
export class GlController {
  constructor(private readonly accountingService: AccountingService) {}

  @Get('accounts')
  @ApiOperation({ summary: 'List chart of accounts' })
  @ApiOkResponse({ description: 'Accounts retrieved successfully' })
  async listAccounts(@Query() query: GlListAccountsQueryDto) {
    const includeInactive = query.includeInactive === 'true';
    const accounts = await this.accountingService.listAccounts({
      includeInactive,
    });
    return ResponseUtil.success(accounts, 'Accounts retrieved successfully');
  }

  @Get('accounts/export')
  @ApiOperation({ summary: 'Export chart of accounts' })
  @ApiOkResponse({ description: 'Chart of accounts exported' })
  @Header('Content-Type', 'text/csv; charset=utf-8')
  @Header(
    'Content-Disposition',
    'attachment; filename="chart-of-accounts.csv"',
  )
  async exportAccounts(@Query() query: GlListAccountsQueryDto): Promise<string> {
    const includeInactive = query.includeInactive === 'true';
    return this.accountingService.exportChartOfAccountsCsv({ includeInactive });
  }

  @Get('journal-entries')
  @ApiOperation({ summary: 'List journal entries (with lines)' })
  @ApiOkResponse({ description: 'Journal entries retrieved successfully' })
  async listJournalEntries(@Query() query: GlListJournalEntriesQueryDto) {
    const from = query.from ? new Date(query.from) : undefined;
    const to = query.to ? new Date(query.to) : undefined;

    const result = await this.accountingService.listJournalEntries({
      page: query.page,
      limit: query.limit,
      from,
      to,
      sourceType: query.sourceType,
      sourceId: query.sourceId,
      idempotencyKey: query.idempotencyKey,
      accountCode: query.accountCode,
    });

    return ResponseUtil.paginated(
      result.data as any,
      result.total,
      result.page,
      result.limit,
      'Journal entries retrieved successfully',
    );
  }

  @Get('reports/trial-balance')
  @ApiOperation({ summary: 'Trial balance (as of date)' })
  @ApiOkResponse({ description: 'Trial balance retrieved successfully' })
  async trialBalance(@Query('asOf') asOf?: string) {
    const asOfDate = asOf ? new Date(asOf) : new Date();
    const rows = await this.accountingService.getTrialBalance({ asOf: asOfDate });
    return ResponseUtil.success(rows, 'Trial balance retrieved successfully');
  }

  @Get('reports/sales-revenue')
  @ApiOperation({ summary: 'Periodic sales revenue (recognized)' })
  @ApiOkResponse({ description: 'Sales revenue report retrieved successfully' })
  async salesRevenue(
    @Query('from') from: string,
    @Query('to') to: string,
    @Query('bucket') bucket: 'day' | 'month' = 'day',
  ) {
    const rows = await this.accountingService.getPeriodicRevenue({
      from: new Date(from),
      to: new Date(to),
      bucket,
    });
    return ResponseUtil.success(rows, 'Sales revenue report retrieved successfully');
  }

  @Get('reports/cash-receipts')
  @ApiOperation({ summary: 'Periodic net cash receipts' })
  @ApiOkResponse({ description: 'Cash receipts report retrieved successfully' })
  async cashReceipts(
    @Query('from') from: string,
    @Query('to') to: string,
    @Query('bucket') bucket: 'day' | 'month' = 'day',
  ) {
    const rows = await this.accountingService.getPeriodicCashReceipts({
      from: new Date(from),
      to: new Date(to),
      bucket,
    });
    return ResponseUtil.success(rows, 'Cash receipts report retrieved successfully');
  }
}
