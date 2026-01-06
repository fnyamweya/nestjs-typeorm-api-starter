import type { RenderSetPasswordTemplateInput } from '../email.types';

export function renderSetPasswordTemplate({
  title,
  headline,
  appName,
  link,
  expiresInMinutes,
  lead,
  footerNote,
}: RenderSetPasswordTemplateInput): string {
  // expiresInMinutes is included so callers can build copy safely; template does not interpolate it directly.
  void expiresInMinutes;

  return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1.0" />
          <title>${title}</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f3f4f6; color: #0f172a; margin: 0; padding: 0; }
            .wrapper { padding: 32px 12px; }
            .card { max-width: 640px; margin: 0 auto; background: #ffffff; border-radius: 12px; box-shadow: 0 10px 28px rgba(0,0,0,0.08); border: 1px solid #e5e7eb; }
            .header { padding: 24px; background: linear-gradient(135deg, #0ea5e9, #2563eb); color: #ffffff; border-radius: 12px 12px 0 0; }
            .header h1 { margin: 0; font-size: 22px; letter-spacing: -0.2px; }
            .content { padding: 24px; }
            .content h2 { margin-top: 0; font-size: 20px; }
            .lead { font-size: 15px; color: #1f2937; margin: 12px 0 18px; }
            .btn { display: inline-block; padding: 14px 20px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 10px; font-weight: 600; box-shadow: 0 6px 16px rgba(37,99,235,0.35); }
            .note { margin-top: 18px; font-size: 14px; color: #475569; line-height: 1.6; }
          </style>
        </head>
        <body>
          <div class="wrapper">
            <div class="card">
              <div class="header">
                <h1>${headline}</h1>
              </div>
              <div class="content">
                <h2>Welcome to ${appName}</h2>
                <p class="lead">${lead}</p>
                <p style="text-align:center;">
                  <a class="btn" href="${link}" target="_blank" rel="noopener noreferrer">Set Password</a>
                </p>
                <p class="note">${footerNote}</p>
              </div>
            </div>
          </div>
        </body>
      </html>
    `;
}
