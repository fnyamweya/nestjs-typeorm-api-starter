import { AuthenticatedUser } from '../auth/interfaces/user.interface';
import { OAuthAdminProfile } from '../auth/interfaces/oauth-admin-profile.interface';

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser | OAuthAdminProfile;
    }
  }
}
