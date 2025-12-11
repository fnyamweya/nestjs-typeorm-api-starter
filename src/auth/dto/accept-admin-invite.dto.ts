import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength, IsUUID, IsOptional } from 'class-validator';

export class AcceptAdminInviteDto {
  @ApiProperty({ description: 'Invitation token delivered via email' })
  @IsString({ message: 'token must be a string' })
  @IsNotEmpty({ message: 'token is required' })
  token: string;

  @ApiProperty({ description: 'Password to activate the invited admin account', minLength: 8 })
  @IsString({ message: 'password must be a string' })
  @IsNotEmpty({ message: 'password is required' })
  @MinLength(8, { message: 'password must be at least 8 characters' })
  password: string;

  @ApiPropertyOptional({ description: 'Phone number for the new admin' })
  @IsOptional()
  @IsString({ message: 'phone must be a string' })
  phone?: string;

  @ApiPropertyOptional({ description: 'Override role id (fallbacks to invite role or admin role)' })
  @IsOptional()
  @IsUUID(undefined, { message: 'roleId must be a valid UUID' })
  roleId?: string;
}
