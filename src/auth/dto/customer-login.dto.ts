import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CustomerLoginDto {
  @ApiProperty({
    description: 'Email address or phone number registered for the customer',
    example: '+14155551234',
  })
  @IsString({ message: 'Identifier must be a string' })
  @IsNotEmpty({ message: 'Email or phone is required' })
  identifier: string;

  @ApiProperty({ description: 'Customer account password', example: 'Str0ngP@ssw0rd' })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}
