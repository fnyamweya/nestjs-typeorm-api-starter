import { AuthenticatedUser } from '../auth/interfaces/user.interface';
import { OAuthProfile } from '../auth/interfaces/oauth-profile.interface';

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser | OAuthProfile;
    }
  }
}
