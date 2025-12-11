import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsUUID } from 'class-validator';

export class CreateAdminInviteDto {
  @ApiProperty({ description: 'Email address of the admin to invite' })
  @IsEmail({}, { message: 'Provide a valid email address' })
  email: string;

  @ApiPropertyOptional({ description: 'First name of the invitee' })
  @IsOptional()
  firstName?: string;

  @ApiPropertyOptional({ description: 'Last name of the invitee' })
  @IsOptional()
  lastName?: string;

  @ApiPropertyOptional({ description: 'Role id to assign to the invited admin' })
  @IsOptional()
  @IsUUID(undefined, { message: 'roleId must be a valid UUID' })
  roleId?: string;
}
