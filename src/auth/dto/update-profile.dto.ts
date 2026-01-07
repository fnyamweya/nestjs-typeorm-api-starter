import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsObject, IsOptional } from 'class-validator';
import { UserProfilePreferences } from 'src/user/profile-preferences';

export class UpdateProfileDto extends PartialType(CreateUserDto) {
  @ApiPropertyOptional({
    description:
      'User profile preferences (notifications, theme, locale, ui, privacy)',
    type: 'object',
    additionalProperties: true,
  })
  @IsOptional()
  @IsObject()
  profilePreferences?: Partial<UserProfilePreferences>;
}
