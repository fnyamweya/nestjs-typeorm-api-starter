import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsIn, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateSMSSettingDto {
  @ApiProperty({
    description: 'SMS provider identifier',
    example: 'africastalking',
    enum: ['africastalking'],
    default: 'africastalking',
  })
  @IsString({ message: 'Provider must be a string' })
  @IsIn(['africastalking'], { message: 'Only africastalking is supported currently' })
  provider: string = 'africastalking';

  @ApiProperty({
    description: 'Africa’s Talking API key',
    example: 'AT_API_KEY',
  })
  @IsString({ message: 'API key must be a string' })
  @IsNotEmpty({ message: 'API key is required' })
  apiKey: string;

  @ApiProperty({
    description: 'Africa’s Talking username',
    example: 'sandbox',
  })
  @IsString({ message: 'Username must be a string' })
  @IsNotEmpty({ message: 'Username is required' })
  username: string;

  @ApiProperty({
    description: 'Sender ID or short code configured in Africa’s Talking',
    example: 'MyApp',
  })
  @IsString({ message: 'Sender ID must be a string' })
  @IsOptional()
  senderId?: string;

  @ApiProperty({ description: 'Enable or disable SMS delivery', example: true })
  @IsBoolean({ message: 'smsEnabled must be a boolean' })
  smsEnabled: boolean;
}
