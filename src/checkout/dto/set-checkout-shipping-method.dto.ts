import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class SetCheckoutShippingMethodDto {
  @ApiProperty({
    description: 'Shipping method code chosen from /shipping/quotes',
    example: 'standard',
  })
  @IsString()
  @IsNotEmpty()
  shippingMethodCode: string;
}
