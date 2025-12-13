import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateUserInviteDto {
  @ApiProperty({ description: 'Email address of the user to invite' })
  @IsEmail({}, { message: 'Provide a valid email address' })
  email: string;

  @ApiPropertyOptional({ description: 'First name of the invitee' })
  @IsOptional()
  firstName?: string;

  @ApiPropertyOptional({ description: 'Last name of the invitee' })
  @IsOptional()
  lastName?: string;

  @ApiProperty({ description: 'Phone number of the invitee' })
  @IsString({ message: 'phone must be a string' })
  @IsNotEmpty({ message: 'phone is required' })
  phone: string;

  @ApiProperty({ description: 'Role id to assign to the invited user' })
  @IsUUID(undefined, { message: 'roleId must be a valid UUID' })
  roleId: string;
}