import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  Repository,
  Between,
  FindManyOptions,
  FindOptionsWhere,
} from 'typeorm';
import { UserActivityLog } from '../entities/user-activity-log.entity';
import { CreateActivityLogDto } from '../dto/create-activity-log.dto';
import { FilterActivityLogDto } from '../dto/filter-activity-log.dto';

@Injectable()
export class ActivityLogService {
  constructor(
    @InjectRepository(UserActivityLog)
    private readonly activityLogRepository: Repository<UserActivityLog>,
  ) {}

  async create(
    createActivityLogDto: CreateActivityLogDto,
  ): Promise<UserActivityLog> {
    const activityLog = this.activityLogRepository.create(createActivityLogDto);
    return await this.activityLogRepository.save(activityLog);
  }

  async findAll(filterDto: FilterActivityLogDto) {
    const {
      userId,
      action,
      resourceType,
      resourceId,
      ipAddress,
      device,
      location,
      startDate,
      endDate,
      isActivityLog,
      page = 1,
      limit = 10,
    } = filterDto;

    const whereConditions: FindOptionsWhere<UserActivityLog> = {};

    if (isActivityLog !== undefined) {
      whereConditions.isActivityLog = isActivityLog;
    }
    if (userId) {
      whereConditions.userId = userId;
    }
    if (action) {
      whereConditions.action = action;
    }
    if (resourceType) {
      whereConditions.resourceType = resourceType;
    }
    if (resourceId) {
      whereConditions.resourceId = resourceId;
    }
    if (ipAddress) {
      whereConditions.ipAddress = ipAddress;
    }
    if (device) {
      whereConditions.device = device;
    }
    if (location) {
      whereConditions.location = location;
    }

    if (startDate && endDate) {
      whereConditions.createdAt = Between(
        new Date(startDate),
        new Date(endDate),
      );
    } else if (startDate) {
      whereConditions.createdAt = Between(new Date(startDate), new Date());
    }

    const options: FindManyOptions<UserActivityLog> = {
      where: whereConditions,
      relations: ['user'],
      skip: (page - 1) * limit,
      take: limit,
      order: {
        createdAt: 'DESC',
      },
    };

    const [data, total] =
      await this.activityLogRepository.findAndCount(options);

    return {
      data,
      total,
    };
  }

  async findById(id: number): Promise<UserActivityLog | null> {
    return await this.activityLogRepository.findOne({
      where: { id },
      relations: ['user'],
    });
  }

  async deleteOldLogs(daysToKeep: number = 90): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    await this.activityLogRepository
      .createQueryBuilder()
      .delete()
      .where('createdAt < :cutoffDate', { cutoffDate })
      .execute();
  }
}
