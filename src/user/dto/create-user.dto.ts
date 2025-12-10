import {
  IsEmail,
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsOptional,
  IsUUID,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({
    description: 'Unique email address for the user',
    example: 'jane.doe@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'Full name of the user',
    example: 'Jane Doe',
    minLength: 2,
    maxLength: 100,
  })
  @IsString({ message: 'Full name must be a string' })
  @IsNotEmpty({ message: 'Full name is required' })
  @MinLength(2, { message: 'Full name must be at least 2 characters long' })
  @MaxLength(100, { message: 'Full name must not exceed 100 characters' })
  fullName: string;

  @ApiProperty({
    description: 'User password used for authentication',
    example: 'Str0ngP@ssw0rd',
    minLength: 8,
  })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;

  @ApiPropertyOptional({
    description: 'Contact phone number for the user',
    example: '+14155551234',
  })
  @IsOptional()
  @IsString({ message: 'Phone must be a string' })
  phone?: string;

  @ApiPropertyOptional({
    description: 'Identifier of the role assigned to the user',
    format: 'uuid',
    example: '2d931510-d99f-494a-8c67-87feb05e1594',
  })
  @IsOptional()
  @IsUUID('4', { message: 'Role ID must be a valid UUID' })
  @IsNotEmpty({ message: 'Role ID is required' })
  roleId?: string;
}
