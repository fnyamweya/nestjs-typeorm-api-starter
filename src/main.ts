import { NestFactory, Reflector } from '@nestjs/core';
import {
  ClassSerializerInterceptor,
  RequestMethod,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { WinstonModule } from 'nest-winston';
import { winstonConfig } from './common/config/logger.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
    // Required for verifying Meta webhook signatures (X-Hub-Signature-256)
    // against the exact raw request body.
    rawBody: true,
  });

  // Lightweight root handler so GET / returns a helpful response
  const httpAdapter = app.getHttpAdapter();
  httpAdapter.get('/', (_req, res) => {
    res.json({
      status: 'ok',
      message: 'API running',
      docs: '/api/docs',
      health: '/api/v1',
    });
  });

  // Environment-based CORS configuration
  const corsOptions = {
    origin: [
      'http://localhost:3000',
      'http://localhost:5000',
      'http://127.0.0.1:5000',
      'http://localhost:5173',
      'http://localhost:5174',
      'https://junemobile-admin.shwecode.xyz',
      'https://junemobile.shwecode.xyz',
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
    ],
    credentials: true,
  };

  app.enableCors(corsOptions);

  // Global API prefix and URI versioning
  // NOTE: OAuth providers may require exact callback URLs. We expose
  // /axis/auth/google/callback without the /api prefix for the admin UI flow.
  app.setGlobalPrefix('api', {
    exclude: [
      // Unified Google OAuth endpoints must be reachable without /api prefix
      // so callback URLs can be configured as: <APP_URL>/auth/<key>/google/callback
      { path: 'auth/:oauthKey/google', method: RequestMethod.GET },
      { path: 'auth/:oauthKey/google/callback', method: RequestMethod.GET },
      { path: 'auth/oauth/exchange', method: RequestMethod.POST },
    ],
  });
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // Enable global validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Enable global serialization
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));

  // Apply global exception filter
  app.useGlobalFilters(new HttpExceptionFilter());

  const swaggerEnabled =
    process.env.SWAGGER_ENABLED === 'true' ||
    process.env.NODE_ENV !== 'production';

  if (swaggerEnabled) {
    const swaggerConfig = new DocumentBuilder()
      .setTitle(process.env.APP_NAME ?? 'qtech-apis')
      .setDescription('REST API documentation')
      .setVersion(process.env.npm_package_version ?? '1.0.0')
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          name: 'Authorization',
          in: 'header',
        },
        'access-token',
      )
      .build();

    const document = SwaggerModule.createDocument(app, swaggerConfig, {
      deepScanRoutes: true,
    });

    SwaggerModule.setup('docs', app, document, {
      useGlobalPrefix: true,
      swaggerOptions: {
        persistAuthorization: true,
      },
    });
  }

  await app.listen(process.env.PORT ?? 3000);
  console.log(`Application is running on port ${process.env.PORT ?? 3000}`);
}
bootstrap();
