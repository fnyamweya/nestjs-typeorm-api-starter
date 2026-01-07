# API Guide

Base URL and versioning:
- Base prefix: `/api`
- URI versioning: `/v1`
- Example: `GET /api/v1/orders`

Swagger:
- `/api/docs` (enabled when `SWAGGER_ENABLED=true` or `NODE_ENV!=production`)

Auth:
- Most endpoints require `Authorization: Bearer <JWT>`.
- Some endpoints additionally require permissions via `RequirePermissions` (e.g. Orders read/update/create).

Response format:
- Endpoints generally return a wrapper via `ResponseUtil` (e.g. `{ data, message, ... }`).

Settings:
- Admin OAuth settings (Google/Apple) can be managed via `/api/v1/settings/oauth/*`.
- Guide: [docs/oauth-settings.md](docs/oauth-settings.md)

---

## Orders

Tag: `Orders`

### List orders
- `GET /api/v1/orders`
- Auth: JWT + `ORDERS:read`
- Query params:
  - `page` (default 1)
  - `limit` (default 10, max 100)
- Notes:
  - Returns a minimal list of orders.
  - Response includes computed `paymentSummary` per order (no schema change; derived from allocations).

### Get order by id
- `GET /api/v1/orders/:id`
- Auth: JWT + `ORDERS:read`
- Notes:
  - Returns a hydrated order.
  - Response includes computed `paymentSummary`.

### Create order
- `POST /api/v1/orders`
- Auth: JWT + `ORDERS:create`
- Body: `CreateOrderDto`

---

## Order Payments

Tag: `Order Payments`

### List payments for an order
- `GET /api/v1/orders/:orderId/payments`
- Auth: JWT + `ORDERS:read`

### Get payment summary for an order
- `GET /api/v1/orders/:orderId/payments/summary`
- Auth: JWT + `ORDERS:read`

### Record a payment for an order (with allocations)
- `POST /api/v1/orders/:orderId/payments`
- Auth: JWT + `ORDERS:update`
- Body: `CreateOrderPaymentDto`
- Allocation rules:
  - If `allocations` are omitted, the service defaults to a single allocation for the whole order.
  - If `allocations` are provided, their sum must equal `amount`.
  - Allocation currency must match payment currency.

Payment types supported:
- `CAPTURE`
- `REFUND`
- `REVERSAL`
- `ADJUSTMENT` (can be negative; other types require positive amounts)

Status supported:
- `PENDING`, `SUCCEEDED`, `FAILED`, `CANCELLED`

Double-entry GL behavior:
- Only `SUCCEEDED` payments post to the general ledger.

---

## Order Fulfillments

Tag: `Order Fulfillments`

### List fulfillments for an order
- `GET /api/v1/orders/:orderId/fulfillments`
- Auth: JWT + `ORDERS:read`

### Get fulfillment by id
- `GET /api/v1/orders/:orderId/fulfillments/:fulfillmentId`
- Auth: JWT + `ORDERS:read`

### Create fulfillment
- `POST /api/v1/orders/:orderId/fulfillments`
- Auth: JWT + `ORDERS:update`
- Body: `CreateOrderFulfillmentDto`
- Notes:
  - Supports splitting order items across packages within a fulfillment.
  - Validates against over-fulfillment across prior fulfillments.

### Update fulfillment
- `PATCH /api/v1/orders/:orderId/fulfillments/:fulfillmentId`
- Auth: JWT + `ORDERS:update`
- Body: `UpdateOrderFulfillmentDto`

---

## Checkout

Tag: `Checkout`

All checkout endpoints:
- Auth: JWT (customer context; uses `CurrentUser`)

### Create a checkout session (draft)
- `POST /api/v1/checkout/sessions`
- Body: `CreateCheckoutSessionDto`

### Set delivery (shipping address)
- `PUT /api/v1/checkout/sessions/:id/delivery`
- Body: `SetCheckoutDeliveryDto`

### List shipping methods
- `GET /api/v1/checkout/sessions/:id/shipping-methods`

### Choose a shipping method
- `PUT /api/v1/checkout/sessions/:id/shipping-method`
- Body: `SetCheckoutShippingMethodDto`

### Review checkout (draft)
- `GET /api/v1/checkout/sessions/:id/review`

### Confirm checkout (creates order)
- `POST /api/v1/checkout/sessions/:id/confirm`

---

## General Ledger (GL)

### What exists today
A minimal, real double-entry ledger is implemented at the database + service layer:
- Tables:
  - `accounting_account`
  - `journal_entry`
  - `journal_entry_line`
- Safety:
  - Journal entry lines enforce one-sided amounts (debit xor credit) and non-negative values.
  - A deferrable constraint trigger enforces balanced entries at commit time.
- Posting:
  - `OrderPaymentService` posts a balanced journal entry for every `SUCCEEDED` order payment.

### Posting policy (current)
- `CAPTURE` (SUCCEEDED): Dr Cash/Processor Clearing, Cr Order Liability
- `REFUND`/`REVERSAL` (SUCCEEDED): Dr Order Liability, Cr Cash/Processor Clearing
- `ADJUSTMENT` (SUCCEEDED):
  - If `provider=INTERNAL` and `method=MANUAL`: posts against the “Payment Adjustments” account (no cash movement)

### GL APIs

Auth:
- JWT + `REPORTING:read`

Accounts:
- `GET /api/v1/gl/accounts`
  - Query: `includeInactive=true|false`
- `GET /api/v1/gl/accounts/export`
  - Query: `includeInactive=true|false`
  - Returns: `text/csv` attachment (`chart-of-accounts.csv`)

Journal entries:
- `GET /api/v1/gl/journal-entries`
  - Query:
    - `page` (default 1)
    - `limit` (default 50, max 200)
    - `from` / `to` (ISO timestamps; filters by `postedAt`)
    - `sourceType` / `sourceId`
    - `idempotencyKey`
    - `accountCode` (filters entries that touch a given account)
  - Notes:
    - Includes entry lines and account info.

Reports:
- `GET /api/v1/gl/reports/trial-balance?asOf=<ISO timestamp>`
- `GET /api/v1/gl/reports/sales-revenue?from=<ISO>&to=<ISO>&bucket=day|month`
  - Sales revenue is based on the `SALES_REVENUE` account (recognized revenue).
- `GET /api/v1/gl/reports/cash-receipts?from=<ISO>&to=<ISO>&bucket=day|month`
  - Net cash receipts is based on the `CASH_CLEARING` account.
