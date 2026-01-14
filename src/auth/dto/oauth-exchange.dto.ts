import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class OAuthExchangeDto {
  @ApiProperty({ example: 'uH8...base64url...' })
  @IsString()
  @IsNotEmpty()
  exchangeCode: string;
}
