# Client Implementation Guide: Checkout Sessions + Orders

This guide describes the **client-side flow** for:
- Creating a checkout session (step-based draft)
- Setting delivery + choosing a shipping method
- Confirming checkout to create an order
- Creating an order directly (server-side order creation)

All endpoints use the global prefix + URI versioning:
- Base URL: `/api/v1`
- Swagger UI: `/api/docs`

## Auth

All routes below require a Bearer JWT.

**Header**

- `Authorization: Bearer <access_token>`

---

## Data model overview (what gets saved)

### Checkout sessions

Checkout is persisted in **two layers**:

1) **Postgres row** (`checkout_session`)
- Stores identity/status/expiry: `id`, `userId`, `status`, `expiresAt`, `completedAt`, `metaJson`

2) **Redis state** (`checkout:session:{id}`)
- Stores the evolving draft state with a TTL (~30 minutes): items, delivery location, selected shipping method, etc.

A delayed queue job expires the session and cleans up Redis state.

### Orders

Orders are persisted with:
- An `order` row containing totals and metadata
- `order_item` rows for line items (with computed totals)
- **Ledger rows**:
  - `order_level_charge` (shipping, order-level discounts, taxes)
  - `order_item_charge` (allocated discounts/taxes/fees at item level)

Charges are intended to be **append-only** (ledger/audit).

---

## Common response envelope

Most endpoints return the standard response envelope:

```json
{
  "success": true,
  "statusCode": 200,
  "message": "...",
  "data": {},
  "timestamp": "2026-01-06T12:00:00.000Z"
}
```

On create routes, `statusCode` is typically `201`.

---

## Shipping quotes (optional pre-checkout)

If you want to show shipping options before creating a checkout session, you can use quotes directly.

### POST `/shipping/quotes`

**Request**

```json
{
  "shippingLocationId": "9b2d2c8b-1a24-4f64-a1e6-0e8c1c3c9d10",
  "orderItems": [
    { "productSkuId": "3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11", "quantity": 2 }
  ],
  "priceListId": "11111111-2222-3333-4444-555555555555",
  "currencyCode": "KES"
}
```

**Response (example)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Shipping quotes returned successfully",
  "data": [
    {
      "method": { "id": "...", "code": "standard", "displayName": "Standard" },
      "rate": { "id": "...", "calculationType": "flat", "metaJson": {} },
      "amount": 50
    }
  ],
  "timestamp": "2026-01-06T12:00:00.000Z"
}
```

**Client note**: the value you later send as `shippingMethodCode` is `quote.method.code`.

---

## Checkout sessions (recommended client flow)

### Step 1 — Create a checkout session

#### POST `/checkout/sessions`

**Request**

```json
{
  "orderItems": [
    { "productSkuId": "3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11", "quantity": 2 }
  ],
  "priceListId": "11111111-2222-3333-4444-555555555555",
  "currencyCode": "KES"
}
```

**Response**

```json
{
  "success": true,
  "statusCode": 201,
  "message": "Checkout session created",
  "data": {
    "id": "f3c86d0f-4b4b-4a89-8c5a-2c4a0c2e64a1",
    "status": "active",
    "expiresAt": "2026-01-06T12:30:00.000Z"
  },
  "timestamp": "2026-01-06T12:00:00.000Z"
}
```

Store the `id` client-side; it identifies the checkout session.

---

### Step 2 — Set delivery (shipping address)

#### PUT `/checkout/sessions/:id/delivery`

**Request**

```json
{
  "shippingAddress": {
    "countryCode": "KE",
    "locationId": "9b2d2c8b-1a24-4f64-a1e6-0e8c1c3c9d10",
    "firstName": "Test",
    "lastName": "Customer",
    "phone": "+254700000000",
    "fieldsJson": {
      "street": "Kenyatta Avenue",
      "city": "Nairobi"
    }
  }
}
```

**Behavior**
- This will **upsert** the customer’s saved shipping address.
- The order will later store an **immutable snapshot** of the shipping address.

---

### Step 3 — List shipping methods

#### GET `/checkout/sessions/:id/shipping-methods`

Returns quotes for the chosen destination.

Use this to populate a shipping method selector.

---

### Step 4 — Select shipping method

#### PUT `/checkout/sessions/:id/shipping-method`

**Request**

```json
{
  "shippingMethodCode": "standard"
}
```

Validation rules:
- The code must match one of the available quotes for the destination.

---

### Step 5 — Review

#### GET `/checkout/sessions/:id/review`

Returns a summary (items, address, available quotes, selected quote, and TTL remaining).

---

### Step 6 — Confirm (creates the order)

#### POST `/checkout/sessions/:id/confirm`

Creates an order and completes the session.

**Response**

```json
{
  "success": true,
  "statusCode": 201,
  "message": "Order created",
  "data": {
    "sessionId": "f3c86d0f-4b4b-4a89-8c5a-2c4a0c2e64a1",
    "order": {
      "id": "a0b1c2d3-e4f5-6789-0123-456789abcdef",
      "orderNumber": "ORD-1736170000000-123456",
      "grandTotal": "266.8000"
    }
  },
  "timestamp": "2026-01-06T12:00:00.000Z"
}
```

After confirmation:
- DB session row becomes `completed`
- Redis state is deleted

---

## Creating an order directly

If you don’t want checkout sessions, you can create orders directly.

### POST `/orders`

**Request**

```json
{
  "customerId": "0f3c7d0b-8bb6-4b48-9d53-71f2d9f0a1a9",
  "orderItems": [
    { "productSkuId": "3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11", "quantity": 2 }
  ],
  "priceListId": "11111111-2222-3333-4444-555555555555",

  "shippingAddress": {
    "countryCode": "KE",
    "locationId": "9b2d2c8b-1a24-4f64-a1e6-0e8c1c3c9d10",
    "firstName": "Test",
    "lastName": "Customer",
    "phone": "+254700000000",
    "fieldsJson": { "street": "Kenyatta Avenue" }
  },

  "shippingMethodCode": "standard"
}
```

**Notes**
- `shippingAddress` is optional. If provided, it is upserted into the customer’s shipping address and also snapshotted onto the order.
- `shippingLocationId` may be provided instead of `shippingAddress` for backward compatibility.
- `shippingMethodCode` should be one of the quotes for the destination.

---

## Order response shape

On order creation, the API returns the standard envelope, where `data` is the order.

The order may include:
- `items[]`
- `items[].itemCharges[]` (allocated per-item ledger rows)
- `orderLevelCharges[]` (order-level ledger rows)

Example (simplified):

```json
{
  "success": true,
  "statusCode": 201,
  "message": "Order created successfully",
  "data": {
    "id": "a0b1c2d3-e4f5-6789-0123-456789abcdef",
    "orderNumber": "ORD-1736170000000-123456",
    "currencyCode": "KES",

    "itemsSubtotal": "200.0000",
    "discountTotal": "20.0000",

    "taxTotal": "28.8000",
    "shippingSubtotal": "50.0000",
    "shippingTax": "8.0000",
    "shippingTotal": "58.0000",

    "grandTotal": "266.8000",

    "items": [
      {
        "id": "...",
        "productSkuId": "...",
        "quantity": 2,
        "baseSubtotal": "200.0000",
        "discountTotal": "20.0000",
        "taxTotal": "28.8000",
        "total": "208.8000",
        "itemCharges": [
          { "chargeKind": "discount", "amount": "-20.0000" },
          { "chargeKind": "tax", "amount": "28.8000" }
        ]
      }
    ],

    "orderLevelCharges": [
      { "chargeKind": "shipping", "amount": "50.0000", "appliesToShipping": true },
      { "chargeKind": "discount", "amount": "-20.0000", "appliesToShipping": false },
      { "chargeKind": "tax", "amount": "28.8000", "appliesToShipping": false },
      { "chargeKind": "tax", "amount": "8.0000", "appliesToShipping": true }
    ]
  },
  "timestamp": "2026-01-06T12:00:00.000Z"
}
```

---

## Client-side reference flow (recommended)

1) Build cart (items + quantities)
2) `POST /checkout/sessions`
3) Collect delivery info, `PUT /checkout/sessions/:id/delivery`
4) `GET /checkout/sessions/:id/shipping-methods`
5) User selects, `PUT /checkout/sessions/:id/shipping-method`
6) `GET /checkout/sessions/:id/review`
7) `POST /checkout/sessions/:id/confirm`

If the session expires, recreate it by calling `POST /checkout/sessions` again.
