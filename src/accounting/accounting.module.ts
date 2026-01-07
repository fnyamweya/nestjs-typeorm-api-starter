import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AccountingService } from './accounting.service';
import { AccountingAccount } from './entities/accounting-account.entity';
import { JournalEntry } from './entities/journal-entry.entity';
import { JournalEntryLine } from './entities/journal-entry-line.entity';
import { GlController } from './controllers/gl.controller';

@Module({
  imports: [TypeOrmModule.forFeature([AccountingAccount, JournalEntry, JournalEntryLine])],
  providers: [AccountingService],
  controllers: [GlController],
  exports: [AccountingService],
})
export class AccountingModule {}
