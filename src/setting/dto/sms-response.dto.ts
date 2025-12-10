import { ApiProperty } from '@nestjs/swagger';

export class SMSResponseDto {
  @ApiProperty({ description: 'Configured SMS provider', example: 'africastalking' })
  provider: string;

  @ApiProperty({ description: 'Africa’s Talking username', example: 'sandbox' })
  username: string;

  @ApiProperty({ description: 'Sender ID or short code', example: 'MyApp' })
  senderId?: string;

  @ApiProperty({ description: 'Flag indicating if SMS is enabled', example: true })
  smsEnabled: boolean;

  @ApiProperty({ description: 'Creation timestamp', example: new Date().toISOString() })
  createdAt?: Date;

  @ApiProperty({ description: 'Update timestamp', example: new Date().toISOString() })
  updatedAt?: Date;
}
