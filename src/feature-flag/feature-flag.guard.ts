import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { FeatureFlagService } from './feature-flag.service';
import { FEATURE_FLAG_METADATA_KEY } from './feature-flag.decorator';
import { UserContext } from './feature-flag.types';
import { AuthenticatedUser } from 'src/auth/interfaces/user.interface';

@Injectable()
export class FeatureFlagGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly featureFlagService: FeatureFlagService,
    private readonly configService: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    let flagKey = this.reflector.getAllAndOverride<string>(
      FEATURE_FLAG_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );

    const request = context.switchToHttp().getRequest();
    const user = request.user as AuthenticatedUser | undefined;
    const env = this.configService.get<string>('NODE_ENV', 'development');

    if (!flagKey) {
      const path: string = request?.baseUrl || request?.path || '';
      const moduleSegment = (path || '').replace(/^\//, '').split('/')[0];
      if (!moduleSegment) return true;
      flagKey = `${moduleSegment}:v1`;
    }

    const ctx: UserContext = {
      userId: user?.id,
      roles: user?.role ? [user.role.name || (user as any).role] : [],
      tenantId: (user as any)?.tenantId,
      env,
      attributes: {
        email: (user as any)?.email,
      },
    };

    const result = await this.featureFlagService.evaluate(flagKey, ctx);
    if (!result.exists) {
      return true; // missing flag -> allow by default
    }

    if (!result.enabled) {
      throw new ForbiddenException(`Feature '${flagKey}' is disabled`);
    }

    return true;
  }
}
