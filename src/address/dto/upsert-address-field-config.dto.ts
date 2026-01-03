import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsObject } from 'class-validator';

export class UpsertAddressFieldConfigDto {
  @ApiProperty({
    description:
      'Schema JSON describing required address fields and location mappings for a country',
    example: {
      version: 1,
      locationChain: ['country', 'county', 'sub_county', 'ward', 'town'],
      fields: [
        { key: 'firstName', type: 'text', required: true },
        { key: 'lastName', type: 'text', required: true },
        { key: 'phone', type: 'text', required: true },
        { key: 'addressLine1', type: 'text', required: true },
        { key: 'addressLine2', type: 'text', required: false },
        { key: 'notes', type: 'text', required: false },
      ],
    },
  })
  @IsNotEmpty()
  @IsObject()
  schema: Record<string, unknown>;
}
