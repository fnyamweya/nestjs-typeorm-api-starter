import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class OptionalJwtAuthGuard extends AuthGuard('jwt') {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const authHeader =
      request?.headers?.authorization ?? request?.headers?.Authorization;
    if (!authHeader) {
      return true;
    }

    // If a token is present, validate it (and attach req.user).
    return (await super.canActivate(context)) as boolean;
  }

  handleRequest(err: any, user: any) {
    // If token is present but invalid, still reject.
    if (err) throw err;
    return user;
  }
}
