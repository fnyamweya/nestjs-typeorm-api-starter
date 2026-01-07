import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsPositive, IsUUID } from 'class-validator';

export class PackageItemDto {
  @ApiProperty({ example: 'pitem_uuid' })
  @IsUUID()
  id: string;

  @ApiProperty({ example: 'pkg_uuid' })
  @IsUUID()
  packageId: string;

  @ApiProperty({ example: 'item_uuid' })
  @IsUUID()
  orderItemId: string;

  @ApiProperty({ example: 1 })
  @IsInt()
  @IsPositive()
  quantity: number;
}
