import type { RenderSuperAdminCredentialsTemplateInput } from '../email.types';

export function renderSuperAdminCredentialsTemplate({
  appName,
  email,
  password,
}: RenderSuperAdminCredentialsTemplateInput): string {
  return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1.0" />
          <title>${appName} Super Admin Credentials</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f9fafb; color: #111827; margin: 0; padding: 0; }
            .wrapper { padding: 32px 12px; }
            .card { max-width: 640px; margin: 0 auto; background: #ffffff; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); border: 1px solid #e5e7eb; }
            .header { padding: 24px; background: linear-gradient(135deg, #0ea5e9, #2563eb); color: #ffffff; border-radius: 12px 12px 0 0; }
            .header h1 { margin: 0; font-size: 22px; }
            .content { padding: 24px; }
            .content h2 { margin-top: 0; font-size: 20px; }
            .item { margin: 12px 0; padding: 14px 16px; background: #f3f4f6; border-radius: 10px; font-weight: 600; letter-spacing: 0.3px; }
            .label { display: block; font-size: 13px; color: #6b7280; font-weight: 500; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.4px; }
            .note { margin-top: 18px; font-size: 14px; color: #374151; line-height: 1.5; }
          </style>
        </head>
        <body>
          <div class="wrapper">
            <div class="card">
              <div class="header">
                <h1>${appName} Super Admin Ready</h1>
              </div>
              <div class="content">
                <h2>Credentials Generated</h2>
                <p>Use the credentials below to sign in as the super admin.</p>
                <div class="item">
                  <span class="label">Email</span>
                  ${email}
                </div>
                <div class="item">
                  <span class="label">Temporary Password</span>
                  ${password}
                </div>
                <p class="note">Please log in and change this password immediately after your first sign-in.</p>
              </div>
            </div>
          </div>
        </body>
      </html>
    `;
}
