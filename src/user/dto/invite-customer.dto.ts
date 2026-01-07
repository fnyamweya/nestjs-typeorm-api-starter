import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class InviteCustomerDto {
  @ApiProperty({
    description: 'Customer email address (invite link will be sent here)',
    example: 'customer@example.com',
  })
  @IsEmail({}, { message: 'Provide a valid email address' })
  email: string;

  @ApiProperty({
    description: 'Customer phone number (WhatsApp invite will be sent here)',
    example: '+254712345678',
  })
  @IsString({ message: 'phone must be a string' })
  @IsNotEmpty({ message: 'phone is required' })
  phone: string;

  @ApiPropertyOptional({
    description: 'First name of the invitee',
    example: 'Jane',
  })
  @IsOptional()
  @IsString()
  firstName?: string;

  @ApiPropertyOptional({
    description: 'Last name of the invitee',
    example: 'Doe',
  })
  @IsOptional()
  @IsString()
  lastName?: string;
}
