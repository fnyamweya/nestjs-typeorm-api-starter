export enum OrderFulfillmentStatus {
  PACKED = 'PACKED',
  SHIPPED = 'SHIPPED',
  DELIVERED = 'DELIVERED',
  CANCELLED = 'CANCELLED',
}

export type WeightUnit = 'kg' | 'g' | 'lb' | 'oz';
export type DimensionUnit = 'cm' | 'mm' | 'in';
