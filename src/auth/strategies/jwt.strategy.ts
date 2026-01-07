import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';
import { AuthenticatedUser, JwtPayload } from '../interfaces/user.interface';
import { normalizeProfilePreferences } from 'src/user/profile-preferences';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET')!,
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    const user = await this.authService.validateUserById(payload.userId);
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    user.profilePreferences = normalizeProfilePreferences(
      user.profilePreferences,
    );

    // Never expose password-derived fields on request.user
    const { passwordHash, password, ...userWithoutSensitive } = user as any;
    void passwordHash;
    void password;

    return userWithoutSensitive as AuthenticatedUser;
  }
}
