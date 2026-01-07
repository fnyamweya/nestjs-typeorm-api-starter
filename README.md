# qtech-apis

A comprehensive, production-ready NestJS template with TypeORM, featuring authentication, authorization, activity logging, file uploads, email services, and a powerful CLI for rapid development.

## 🚀 Features

### Core Features

- **NestJS Framework** - Modern Node.js framework for building scalable server-side applications
- **TypeORM Integration** - Powerful ORM with PostgreSQL support
- **JWT Authentication** - Secure authentication with access and refresh tokens
- **Role-Based Access Control (RBAC)** - Flexible permission system with roles and permissions
- **Two-Factor Authentication (2FA)** - Enhanced security with TOTP support
- **Admin OAuth (Google & Apple)** - Social login flows dedicated to platform administrators
- **Forgot Password** - Secure password reset with email verification
- **Activity Logging** - Comprehensive user activity tracking and audit trails
- **File Upload Support** - AWS S3 integration for file storage
- **Email Service** - SMTP configuration for transactional emails
- **Redis-Powered Queues** - BullMQ + Redis pipeline for background jobs and domain events
- **Global Exception Handling** - Centralized error handling and logging
- **Request/Response Interceptors** - Standardized API responses
- **Validation & Serialization** - Built-in data validation and transformation
- **Winston Logging** - Advanced logging with daily rotation and multiple transports

### CLI Tools

- **Code Generation** - Powerful CLI for generating modules, services, and controllers

## 📋 Prerequisites

- Node.js (v18 or higher)
- PostgreSQL database
- Redis server (for BullMQ queues)
- Google & Apple developer credentials (for admin OAuth flows)
- AWS S3 account (for file uploads)
- SMTP server (for email services)

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
  cd qtech-apis
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Environment Configuration**

   Copy the `.env` file and configure your environment variables:

   ```bash
   cp .env.example .env
   ```

   Update the following variables in your `.env` file:

   ```env
    # App Config
    APP_NAME=qtech-apis
    PORT=8090
    SWAGGER_ENABLED=true

    # Password Hashing (Argon2id)
    ARGON2_MEMORY_COST=19456
    ARGON2_TIME_COST=3
    ARGON2_PARALLELISM=1
    ARGON2_HASH_LENGTH=32
    ARGON2_SALT_LENGTH=16

    # Database Configuration
    DB_HOST=localhost
    DB_PORT=5432
    DB_USERNAME=postgres
    DB_PASSWORD=postgres
    DB_NAME=nestjs_typeorm_postgres_db
    NODE_ENV=development

    # JWT Configuration
    JWT_SECRET=74db5010c1cd2989e21f49160e22e014b51625097bb721535c529de2cb97f58d
    JWT_EXPIRATION=5m
    JWT_REFRESH_SECRET=59292b190434a15524d53f2e03df1a5f961d5852ee9ed42b9a4c5f8601b80a81
    JWT_REFRESH_EXPIRATION=7d

    # AWS S3 Configuration
    AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
    AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
    AWS_REGION=<AWS_REGION>
    AWS_BUCKET_NAME=<AWS_BUCKET_NAME>

    # Email Configuration
    EMAIL_FROM_NAME="qtech-apis"

    # Redis / Queue Configuration
    REDIS_HOST=127.0.0.1
    REDIS_PORT=6379
    REDIS_USERNAME=
    REDIS_PASSWORD=
    REDIS_DB=0
    REDIS_TLS=false

    # OAuth Providers (Admin)
    APP_URL=http://localhost:8090
    GOOGLE_CLIENT_ID=
    GOOGLE_CLIENT_SECRET=
    GOOGLE_CALLBACK_URL=http://localhost:8090/api/v1/auth/admin/google/callback
    APPLE_CLIENT_ID=
    APPLE_TEAM_ID=
    APPLE_KEY_ID=
    APPLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
    APPLE_CALLBACK_URL=http://localhost:8090/api/v1/auth/admin/apple/callback

      # Encryption key (required for storing secrets in DB Settings)
      ENCRYPTION_KEY=
   ```

       Notes:

       - Admin OAuth can be configured either via env vars **or** via the Settings API (DB-backed, encrypted secrets).
       - See [docs/oauth-settings.md](docs/oauth-settings.md).

4. **Database Setup**

Create your PostgreSQL database and run the application. TypeORM will automatically create tables based on your entities.

5. **Start the application**

```bash
# Development
npm run start:dev

# Production
npm run build
npm run start:prod
```

## 🏗️ Project Structure

```
src/
├── activity-log/           # Activity logging module
│   ├── controllers/        # Activity log controllers
│   ├── decorators/         # Activity logging decorators
│   ├── dto/               # Data transfer objects
│   ├── entities/          # Activity log entities
│   ├── interceptors/      # Activity logging interceptor
│   └── services/          # Activity log services
├── auth/                  # Authentication & authorization
│   ├── controllers/       # Auth controllers
│   ├── decorators/        # Auth decorators (permissions, roles)
│   ├── dto/              # Auth DTOs
│   ├── entities/         # User, role, permission entities
│   ├── guards/           # JWT, permissions, roles guards
│   ├── interfaces/       # Auth interfaces
│   ├── services/         # Auth services
│   └── strategies/       # Passport strategies
├── common/               # Shared utilities and configurations
│   ├── config/          # Configuration files (logger, etc.)
│   ├── filters/         # Global exception filters
│   ├── interceptors/    # Response interceptors
│   ├── interfaces/      # Common interfaces
│   └── utils/           # Utility functions (S3, email, response)
├── queue/               # BullMQ + Redis queue and event bus layer
├── setting/             # Application settings module
│   ├── controllers/     # Settings controllers
│   ├── dto/            # Settings DTOs
│   ├── entities/       # Settings entities
│   └── services/       # Settings services
├── user/               # User management module
│   ├── controllers/    # User controllers
│   ├── dto/           # User DTOs
│   ├── entities/      # User entities
│   └── services/      # User services
├── app.controller.ts   # Main app controller
├── app.module.ts      # Main app module
├── app.service.ts     # Main app service
└── main.ts           # Application entry point

cli/                   # CLI tools for code generation
└── easy-generate/     # CLI for easy code generation
```

## 🔧 CLI Usage

This template includes a powerful CLI for rapid development:

### Generate Module

```bash
npm run make:module <module-name> [--path=custom/path]
```

Generates a complete module with:

- Entity with TypeORM decorators
- Service with CRUD operations
- Controller with REST endpoints
- DTOs (Create, Update, Filter)
- Module configuration

### Example

```bash
# Generate a complete book module
npm run make:module book

# Generate with custom path
npm run make:module product --path=src/ecommerce
```

## 🔐 Authentication & Authorization

### JWT Authentication

- Access tokens (1 day default)
- Refresh tokens (7 days default)
- Automatic token refresh
- Argon2id password hashing for all accounts

### Role-Based Access Control

```typescript
// Protect routes with permissions
@RequirePermissions({
  module: PermissionModule.USERS,
  permission: 'create'
})
```

## 🏷️ Promotions (Rule Engine)

The Promotions module supports rule-based promotions made up of **conditions** and **actions**.

### Item Targeting Conditions

These conditions evaluate against the order's line items. For safety, if an item-targeted condition exists and the order evaluation context does **not** include items, the promotion will **not** apply.

- `item_in_product`
  - Params: `{ productIds: string[] }` or `{ productId: string }` (also supports `{ ids }` / `{ id }`)
- `item_in_category`
  - Params: `{ categoryIds: string[] }` or `{ categoryId: string }` (also supports `{ ids }` / `{ id }`)
  - Category matching includes **ancestor categories** via `category_closure` (so targeting a parent category matches products in descendant categories).
- `item_in_taxonomy`
  - Params: `{ taxonomyIds: string[] }` or `{ taxonomyId: string }` (also supports `{ ids }` / `{ id }`)
- `item_has_tag`
  - Params: `{ tags: string[] }` or `{ tag: string }` (also supports `{ ids }` / `{ id }`)
  - Tags are best-effort derived from `product.meta_json.tags` when present.

For these item conditions, operators should typically be:

- Require match: `eq` | `in` | `contains`
- Require no match: `neq` | `not_in`

### Example: Create a promotion targeting a taxonomy

`POST /api/v1/promotions`

```json
{
  "code": "TAX10",
  "name": "10% off Phones Taxonomy",
  "status": "active",
  "conditions": [
    {
      "type": "item_in_taxonomy",
      "operator": "in",
      "params": {
        "taxonomyIds": ["1f64a1e6-0e8c-4f64-a1e6-0e8c1c3c9d10"]
      }
    }
  ],
  "actions": [
    {
      "type": "percent_off",
      "params": { "percent": 10 },
      "target": { "scope": "order" }
    }
  ]
}
```

### Example: Create a promotion targeting product tags

```json
{
  "code": "CLEARANCE5",
  "status": "active",
  "conditions": [
    {
      "type": "item_has_tag",
      "operator": "contains",
      "params": { "tags": ["clearance"] }
    }
  ],
  "actions": [
    { "type": "fixed_off", "params": { "amount": 5, "currency": "KES" } }
  ]
}
```

## 🚚 Shipping (Location-Based Zones)

Shipping zones are matched using the Location tree (`location_closure`) via `locationId`.

- **Configure zone destinations**: attach a zone to a Location node via the admin API:
  - `POST /api/v1/shipping/zone-locations` (body: `{ zoneId, locationId }`)
  - `GET /api/v1/shipping/zone-locations`
  - `DELETE /api/v1/shipping/zone-locations/:id`
- **Order checkout**:
  - Provide `shippingLocationId` (UUID) for shipping zone matching.

- **Get quotes (pre-checkout UI)**:
  - `POST /api/shipping/quotes` with `{ shippingLocationId, orderItems: [{ productVariantId, quantity }], priceListId? }`

Shipping quote selection is **priority-first**, then cheapest among ties.

### Seeding (recommended)

Seeders set up a working baseline for development (settings, locations, catalog, shipping, auth roles/permissions).

```bash
npm run db:migrate
npm run db:seed
```

### Permissions

- Admin shipping endpoints require `Shipping` module permissions (CRUD).
- Order creation requires `Orders:create`.
- Shipping quotes require a valid JWT access token.

### Two-Factor Authentication

This project uses an **OTP-based step-up** 2FA flow.

- 2FA is enforced only when `user.twoFactorEnabled === true`.
- OTP delivery is **queued** (BullMQ) and can be delivered via **email + WhatsApp**, with **SMS fallback**.
- OTP send endpoints are rate limited to reduce abuse.

#### Login flow (step-up)

1) Call a login endpoint:
- `POST /api/auth/login`
- `POST /api/auth/customer/login`
- `POST /api/auth/admin/login`

2) If the user has 2FA enabled and no `twoFactorCode` was supplied, the response is:

```json
{
  "requiresTwoFactor": true,
  "userId": "...",
  "twoFactorToken": "...",
  "message": "Two-factor authentication code queued for delivery"
}
```

3) Verify the OTP:
- `POST /api/auth/verify-2fa` with `{ "twoFactorToken": "...", "code": "123456" }`

4) On success, the API returns auth tokens:

```json
{
  "accessToken": "...",
  "refreshToken": "..."
}
```

Notes:
- You may also provide `twoFactorCode` directly in the login request to complete login in a single call.
- `twoFactorToken` is the recommended verification mechanism; `userId` exists for legacy compatibility.

#### Rate limiting

OTP sends are rate limited (per identifier):
- Cooldown: max 1 request / 30 seconds
- Burst: max 3 requests / 10 minutes

If exceeded, the API returns HTTP `429`.

### Password Reset (step-up)

Password reset is aligned with the same step-up pattern:

1) Request an OTP:
- `POST /api/auth/otp/send/forgot-password` with `{ "identifier": "user@example.com" }`
  - `identifier` can be an email address or a phone number

2) Verify the OTP:
- `POST /api/auth/otp/verify/forgot-password` with `{ "userId": "...", "code": "123456" }`

Response includes a short-lived `resetToken`:

```json
{
  "userId": "...",
  "resetToken": "..."
}
```

3) Reset the password:
- `POST /api/auth/reset-password` with `{ "resetToken": "...", "newPassword": "N3wP@ssw0rd" }`

`accessToken` is still accepted as a deprecated alias for `resetToken`.

### Admin OAuth Providers

- `GET /api/auth/admin/google` → Redirects to Google, callback issues JWTs
- `GET /api/auth/admin/google/callback` → Completes Google OAuth login
- `GET /api/auth/admin/apple` & `POST /api/auth/admin/apple/callback` → Sign in with Apple support
- Auto-provisions admins (using Google/Apple email) and stores tokens just like password logins

## 📊 Activity Logging

Automatic activity logging with the `@LogActivity` decorator:

```typescript
@LogActivity({
  action: ActivityAction.CREATE,
  description: 'User created successfully',
  resourceType: 'user',
  getResourceId: (result: User) => result.id
})
async createUser(@Body() createUserDto: CreateUserDto) {
  // Your logic here
}
```

## 🪣 S3 Utilities

AWS S3 integration:

```typescript
  /**
   * Generate a presigned URL for a file in S3
   */
  async generatePresignedUrl(
    key: string,
    expiresIn: number = 3600,
  ): Promise<string | null> {}

  /**
   * Check if an object exists in S3
   */
  async objectExists(key: string): Promise<boolean> {}

  /**
   * Upload a file to S3
   */
  async uploadFile({
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    body: Buffer | Uint8Array | string;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {}

  /**
   * Update an existing file in S3
   * Note: This method overwrites the existing file with the new content.
   */
  async updateFile({
    oldKey,
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    oldKey: string;
    body: Buffer | Uint8Array | string;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {}

  /**
   * Delete a file from S3
   */
  async deleteObject(
    key: string,
  ): Promise<{ success: boolean; error?: string }> {...}
```

## 📧 Email Service

SMTP configuration for sending emails:

```typescript
// Send two-factor authentication code
await this.emailServiceUtils.sendTwoFactorCode({...});

// Send forgot password reset code
await this.emailServiceUtils.sendForgotPasswordResetCode({...});
```

## 📮 Message Queues & Event Bus

BullMQ + Redis power background jobs and domain events. Configure the Redis variables in `.env`, then inject the provided services anywhere in the app (the `QueueModule` is global).

### Dispatch background work

```typescript
@Injectable()
export class SmsQueueProducer {
  constructor(private readonly queueService: QueueService) {}

  async enqueue(payload: SendSmsPayload) {
    await this.queueService.addJob('sms-delivery', 'send-sms', payload, {
      attempts: 5,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }
}
```

### Event-driven flows

```typescript
@Injectable()
export class UserEventsListener implements OnApplicationBootstrap {
  constructor(
    private readonly eventBus: EventBusService,
    private readonly queueService: QueueService,
  ) {}

  async onApplicationBootstrap() {
    await this.eventBus.subscribe('user.created', (payload: { userId: string }) =>
      this.handleUserCreated(payload),
    );
  }

  private async handleUserCreated(payload: { userId: string }) {
    await this.queueService.addJob('notifications', 'welcome-email', payload);
  }
}

// Somewhere in your domain logic
await this.eventBus.emit('user.created', { userId: user.id });
```

- `QueueService` exposes `addJob`, `getQueue`, `createWorker`, and `getQueueEvents` helpers.
- `EventBusService` routes domain events through the shared `domain-events` queue and lets you register handlers programmatically.
- Both services automatically handle connection reuse, retries, and graceful shutdown.

## 📝 API Documentation

### Swagger & OpenAPI

- Swagger UI automatically mounts at `http://localhost:8090/api/docs` when `SWAGGER_ENABLED=true` (default outside production)
- Title and version pull from `APP_NAME` and `npm_package_version`, so keep those values current for accurate docs metadata
- JWT bearer auth is already wired—authorize once via the green "Authorize" button to test secured routes against your dev API
- To disable docs in production, set `NODE_ENV=production` and leave `SWAGGER_ENABLED` unset or `false`

### Standardized Responses

The template includes standardized API responses:

### Success Response

```typescript
return ResponseUtil.success(user, `User retrieved by ID ${id} successfully`);
```

```json
{
  "success": true,
  "message": "Operation successful",
  "data": { ... },
  "statusCode": 200
}
```

### Paginated Response

```typescript
return ResponseUtil.paginated(
  result.data,
  result.total,
  result.page,
  result.limit,
  'Users retrieved successfully',
);
```

```json
{
  "success": true,
  "message": "Data retrieved successfully",
  "data": [...],
  "meta": {
        "total": 1,
        "page": 1,
        "limit": 10,
        "totalPages": 1
  },
  "statusCode": 200,
  "timestamp": "2025-11-03T15:43:11.561Z"
}
```

### Error Response

```json
{
  "success": false,
  "message": "Error message",
  "error": "Detailed error information",
  "statusCode": 400
}
```

## 🔧 Configuration

### Database Configuration

The template uses TypeORM with PostgreSQL. Configuration is handled through environment variables with automatic entity discovery.

### CORS Configuration

CORS is configured for development with `localhost:3000`. Update in `main.ts` for production.

### Validation

Global validation is enabled with:

- Whitelist unknown properties
- Transform incoming data
- Forbid non-whitelisted properties

## 🚀 Deployment

### Production Build

```bash
npm run build
npm run start:prod
```

### Environment Variables

Ensure all production environment variables are set:

- Database credentials
- JWT secrets
- AWS S3 configuration
- SMTP settings

### Docker Support

The template is Docker-ready. Create a `Dockerfile` and `docker-compose.yml` for containerized deployment.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:

- Create an issue in the repository
- Check the documentation
- Review the example implementations

## 🔄 Updates

This template is actively maintained with:

- Security updates
- New features
- Bug fixes
- Performance improvements

---

**Happy coding! 🎉**
