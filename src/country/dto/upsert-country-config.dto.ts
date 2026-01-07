import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsObject } from 'class-validator';

export class UpsertCountryConfigDto {
  @ApiProperty({
    description:
      'Country configuration JSON. This is intended to be extensible (currencies, Google mapping rules, etc).',
    example: {
      version: 1,
      currencies: ['KES'],
      googleLocationMapping: {
        candidates: [
          {
            locationType: 'town',
            googleComponentTypes: ['locality', 'postal_town', 'neighborhood'],
          },
          {
            locationType: 'ward',
            googleComponentTypes: [
              'administrative_area_level_3',
              'sublocality_level_1',
              'sublocality',
            ],
          },
        ],
      },
    },
  })
  @IsNotEmpty()
  @IsObject()
  config: Record<string, unknown>;
}
