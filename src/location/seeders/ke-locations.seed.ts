import { LocationType } from '../entities/location.entity';

export type SeedLocationNode = {
  name: string;
  type: LocationType;
  code?: string;
  children?: SeedLocationNode[];
};

// NOTE: This is a starter dataset.
// - Includes Kenya + all 47 counties.
// - Includes Nairobi sub-counties (example depth: Nairobi -> Embakasi East).
// Extend this structure to include a full town/ward dataset if needed.
export const KENYA_LOCATION_TREE: SeedLocationNode = {
  name: 'Kenya',
  type: LocationType.COUNTRY,
  code: 'KE',
  children: [
    {
      name: 'Nairobi',
      type: LocationType.COUNTY,
      children: [
        { name: 'Westlands', type: LocationType.SUB_COUNTY },
        { name: 'Dagoretti North', type: LocationType.SUB_COUNTY },
        { name: 'Dagoretti South', type: LocationType.SUB_COUNTY },
        { name: 'Langata', type: LocationType.SUB_COUNTY },
        { name: 'Kibra', type: LocationType.SUB_COUNTY },
        { name: 'Roysambu', type: LocationType.SUB_COUNTY },
        { name: 'Kasarani', type: LocationType.SUB_COUNTY },
        { name: 'Ruaraka', type: LocationType.SUB_COUNTY },
        { name: 'Embakasi South', type: LocationType.SUB_COUNTY },
        { name: 'Embakasi North', type: LocationType.SUB_COUNTY },
        {
          name: 'Embakasi East',
          type: LocationType.SUB_COUNTY,
          children: [
            // Example wards under Embakasi East (extend as needed)
            { name: 'Umoja I', type: LocationType.WARD },
            { name: 'Umoja II', type: LocationType.WARD },
            { name: 'Mowlem', type: LocationType.WARD },
            { name: 'Kariobangi South', type: LocationType.WARD },
          ],
        },
        { name: 'Embakasi West', type: LocationType.SUB_COUNTY },
        { name: 'Embakasi Central', type: LocationType.SUB_COUNTY },
        { name: 'Makadara', type: LocationType.SUB_COUNTY },
        { name: 'Kamukunji', type: LocationType.SUB_COUNTY },
        { name: 'Starehe', type: LocationType.SUB_COUNTY },
        { name: 'Mathare', type: LocationType.SUB_COUNTY },
      ],
    },

    // Remaining 46 counties
    { name: 'Mombasa', type: LocationType.COUNTY },
    { name: 'Kwale', type: LocationType.COUNTY },
    { name: 'Kilifi', type: LocationType.COUNTY },
    { name: 'Tana River', type: LocationType.COUNTY },
    { name: 'Lamu', type: LocationType.COUNTY },
    { name: 'Taita Taveta', type: LocationType.COUNTY },
    { name: 'Garissa', type: LocationType.COUNTY },
    { name: 'Wajir', type: LocationType.COUNTY },
    { name: 'Mandera', type: LocationType.COUNTY },
    { name: 'Marsabit', type: LocationType.COUNTY },
    { name: 'Isiolo', type: LocationType.COUNTY },
    { name: 'Meru', type: LocationType.COUNTY },
    { name: 'Tharaka-Nithi', type: LocationType.COUNTY },
    { name: 'Embu', type: LocationType.COUNTY },
    { name: 'Kitui', type: LocationType.COUNTY },
    { name: 'Machakos', type: LocationType.COUNTY },
    { name: 'Makueni', type: LocationType.COUNTY },
    { name: 'Nyandarua', type: LocationType.COUNTY },
    { name: 'Nyeri', type: LocationType.COUNTY },
    { name: 'Kirinyaga', type: LocationType.COUNTY },
    { name: "Murang'a", type: LocationType.COUNTY },
    { name: 'Kiambu', type: LocationType.COUNTY },
    { name: 'Turkana', type: LocationType.COUNTY },
    { name: 'West Pokot', type: LocationType.COUNTY },
    { name: 'Samburu', type: LocationType.COUNTY },
    { name: 'Trans Nzoia', type: LocationType.COUNTY },
    { name: 'Uasin Gishu', type: LocationType.COUNTY },
    { name: 'Elgeyo-Marakwet', type: LocationType.COUNTY },
    { name: 'Nandi', type: LocationType.COUNTY },
    { name: 'Baringo', type: LocationType.COUNTY },
    { name: 'Laikipia', type: LocationType.COUNTY },
    { name: 'Nakuru', type: LocationType.COUNTY },
    { name: 'Narok', type: LocationType.COUNTY },
    { name: 'Kajiado', type: LocationType.COUNTY },
    { name: 'Kericho', type: LocationType.COUNTY },
    { name: 'Bomet', type: LocationType.COUNTY },
    { name: 'Kakamega', type: LocationType.COUNTY },
    { name: 'Vihiga', type: LocationType.COUNTY },
    { name: 'Bungoma', type: LocationType.COUNTY },
    { name: 'Busia', type: LocationType.COUNTY },
    { name: 'Siaya', type: LocationType.COUNTY },
    { name: 'Kisumu', type: LocationType.COUNTY },
    { name: 'Homa Bay', type: LocationType.COUNTY },
    { name: 'Migori', type: LocationType.COUNTY },
    { name: 'Kisii', type: LocationType.COUNTY },
    { name: 'Nyamira', type: LocationType.COUNTY },
  ],
};
