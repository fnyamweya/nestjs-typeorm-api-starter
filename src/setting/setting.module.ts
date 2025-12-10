import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SettingController } from './controllers/setting.controller';
import { SettingService } from './services/setting.service';
import { Setting } from './entities/setting.entity';
import { ActivityLogModule } from '../activity-log/activity-log.module';
import { SettingSeeder } from './seeders/setting.seeder';
import { SmsServiceUtils } from 'src/common/utils/sms-service.utils';

@Module({
  imports: [TypeOrmModule.forFeature([Setting]), ActivityLogModule],
  controllers: [SettingController],
  providers: [SettingService, SettingSeeder, SmsServiceUtils],
  exports: [SettingService, SmsServiceUtils],
})
export class SettingModule {}
