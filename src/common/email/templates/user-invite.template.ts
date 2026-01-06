import type { RenderUserInviteTemplateInput } from '../email.types';

export function renderUserInviteTemplate({
  inviteLink,
  invitedBy,
  inviteeName,
}: RenderUserInviteTemplateInput): string {
  const greetingName = inviteeName || 'there';

  return `
      <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1.0" />
          <title>You're Invited</title>

          <style>
            body {
              margin: 0;
              padding: 0;
              background: #f3f4f6;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
              color: #111827;
              line-height: 1.6;
            }

            .wrapper {
              width: 100%;
              padding: 40px 0;
            }

            .container {
              max-width: 640px;
              margin: 0 auto;
              background: #ffffff;
              border-radius: 14px;
              box-shadow: 0px 6px 22px rgba(0, 0, 0, 0.06);
              overflow: hidden;
              border: 1px solid #e5e7eb;
            }

            .header {
              background: linear-gradient(135deg, #2563eb, #1e40af);
              padding: 32px;
              text-align: center;
              color: #ffffff;
            }

            .header h1 {
              margin: 0;
              font-size: 26px;
              font-weight: 700;
              letter-spacing: -0.4px;
            }

            .content {
              padding: 32px;
            }

            .content h2 {
              margin-top: 0;
              font-size: 22px;
              font-weight: 600;
              color: #111827;
            }

            .lead {
              font-size: 16px;
              margin-bottom: 20px;
              color: #374151;
            }

            .btn {
              display: inline-block;
              padding: 14px 26px;
              background: #2563eb;
              color: #fff !important;
              text-decoration: none;
              font-size: 16px;
              font-weight: 600;
              border-radius: 10px;
              margin: 20px 0;
              box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
            }

            .footer-note {
              margin-top: 28px;
              font-size: 14px;
              color: #6b7280;
              line-height: 1.5;
            }
          </style>
        </head>

        <body>
          <div class="wrapper">
            <div class="container">

              <div class="header">
                <h1>You're Invited</h1>
              </div>

              <div class="content">
                <h2>Hello ${greetingName},</h2>

                <p class="lead">
                  <strong>${invitedBy}</strong> has invited you to join our platform.  
                  We’re excited to welcome you aboard!
                </p>

                <p class="lead">
                  Click the button below to accept your invitation and set up your account:
                </p>

                <p style="text-align: center;">
                  <a class="btn" 
                    href="${inviteLink}" 
                    target="_blank" 
                    rel="noopener noreferrer">
                    Accept Invitation
                  </a>
                </p>

                <p class="footer-note">
                  If you weren’t expecting this, feel free to ignore the message—nothing will happen until you confirm.
                </p>
              </div>

            </div>
          </div>
        </body>
      </html>
    `;
}
