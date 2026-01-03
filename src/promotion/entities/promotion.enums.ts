export enum PromotionStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  PAUSED = 'paused',
  ARCHIVED = 'archived',
}

export enum StackingPolicy {
  EXCLUSIVE = 'exclusive',
  STACKABLE = 'stackable',
  STACKABLE_SAME_GROUP = 'stackable_same_group',
}

export enum PromotionConditionType {
  CART_TOTAL = 'cart_total',
  CUSTOMER_SEGMENT = 'customer_segment',
  FIRST_ORDER = 'first_order',
  HAS_COUPON = 'has_coupon',
  ITEM_IN_PRODUCT = 'item_in_product',
  ITEM_IN_CATEGORY = 'item_in_category',
  ITEM_IN_TAXONOMY = 'item_in_taxonomy',
  ITEM_HAS_TAG = 'item_has_tag',
  PAYMENT_METHOD = 'payment_method',
}

export enum ConditionOperator {
  EQ = 'eq',
  NEQ = 'neq',
  GT = 'gt',
  GTE = 'gte',
  LT = 'lt',
  LTE = 'lte',
  IN = 'in',
  NOT_IN = 'not_in',
  CONTAINS = 'contains',
}

export enum PromotionActionType {
  PERCENT_OFF = 'percent_off',
  FIXED_OFF = 'fixed_off',
  FREE_SHIPPING = 'free_shipping',
  BOGO = 'bogo',
  TIERED_DISCOUNT = 'tiered_discount',
  GIFT_ITEM = 'gift_item',
}
