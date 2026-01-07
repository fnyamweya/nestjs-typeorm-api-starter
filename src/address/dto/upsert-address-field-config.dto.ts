import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsObject } from 'class-validator';

export class UpsertAddressFieldConfigDto {
  @ApiProperty({
    description:
      'Schema JSON describing required address fields and location mappings for a country',
    examples: {
      kenya: {
        summary: 'Kenya (typical structure)',
        value: {
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
      },
      uganda: {
        summary: 'Uganda (custom structure)',
        value: {
          version: 1,
          locationChain: [
            'country',
            'district',
            'county',
            'subcounty',
            'parish',
            'village',
          ],
          fields: [
            { key: 'firstName', type: 'text', required: true },
            { key: 'lastName', type: 'text', required: true },
            { key: 'phone', type: 'text', required: true },
            { key: 'addressLine1', type: 'text', required: true },
          ],
        },
      },
    },
  })
  @IsNotEmpty()
  @IsObject()
  schema: Record<string, unknown>;
}
