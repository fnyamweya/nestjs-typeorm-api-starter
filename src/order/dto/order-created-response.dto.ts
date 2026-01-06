import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { OrderDto } from './order.dto';

class ResponseMetaDto {
  @ApiPropertyOptional({ example: 100 })
  total?: number;

  @ApiPropertyOptional({ example: 1 })
  page?: number;

  @ApiPropertyOptional({ example: 10 })
  limit?: number;

  @ApiPropertyOptional({ example: 10 })
  totalPages?: number;
}

export class OrderCreatedResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 201 })
  statusCode: number;

  @ApiProperty({ example: 'Order created successfully' })
  message: string;

  @ApiProperty({ type: () => OrderDto })
  data: OrderDto;

  @ApiPropertyOptional({ type: () => ResponseMetaDto })
  meta?: ResponseMetaDto;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  timestamp: string;
}
