export enum OrderEventTargetType {
  ORDER = 'order',
  ORDER_ITEM = 'order_item',
  FULFILLMENT = 'fulfillment',
  PACKAGE = 'package',
}

export type OrderEventActorType = 'user' | 'system';
