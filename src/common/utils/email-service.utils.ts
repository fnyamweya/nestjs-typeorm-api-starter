import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as nodemailer from 'nodemailer';
import { Setting } from 'src/setting/entities/setting.entity';

@Injectable()
export class EmailServiceUtils {
  private readonly logger = new Logger(EmailServiceUtils.name);

  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
  ) {}

  private async getTransporter() {
    const smtpSettings = await this.getSMTPSettings();

    if (!smtpSettings.smtpEnabled) {
      throw new Error('SMTP is not enabled');
    }

    return nodemailer.createTransport({
      host: smtpSettings.smtpHost,
      port: smtpSettings.smtpPort,
      secure: smtpSettings.smtpSecure,
      auth:
        smtpSettings.smtpUsername && smtpSettings.smtpPassword
          ? {
              user: smtpSettings.smtpUsername,
              pass: smtpSettings.smtpPassword,
            }
          : undefined,
    });
  }

  private async getSMTPSettings() {
    const smtpKeys = [
      'smtp_host',
      'smtp_port',
      'smtp_secure',
      'smtp_username',
      'smtp_password',
      'smtp_from_email',
      'smtp_from_name',
      'smtp_enabled',
    ];

    const settings = await this.settingRepository.find({
      where: smtpKeys.map((key) => ({ key })),
    });

    return {
      smtpHost: this.getSettingValue(settings, 'smtp_host'),
      smtpPort: parseInt(this.getSettingValue(settings, 'smtp_port') || '587'),
      smtpSecure: this.getSettingValue(settings, 'smtp_secure') === 'true',
      smtpUsername: this.getSettingValue(settings, 'smtp_username'),
      smtpPassword: this.getSettingValue(settings, 'smtp_password'),
      smtpFromEmail: this.getSettingValue(settings, 'smtp_from_email'),
      smtpFromName: this.getSettingValue(settings, 'smtp_from_name'),
      smtpEnabled: this.getSettingValue(settings, 'smtp_enabled') === 'true',
    };
  }

  private getSettingValue(settings: Setting[], key: string): string {
    const setting = settings.find((s) => s.key === key);
    return setting?.value || '';
  }

  async sendTwoFactorCode({
    code,
    email,
    userName,
    fromUsername,
    expiresIn,
  }: {
    code: string;
    email: string;
    userName: string;
    fromUsername: string;
    expiresIn: number;
  }): Promise<void> {
    try {
      const transporter = await this.getTransporter();
      const smtpSettings = await this.getSMTPSettings();

      const mailOptions = {
        from: `"${smtpSettings.smtpFromName}" <${smtpSettings.smtpFromEmail}>`,
        to: email,
        subject: `Two-Factor Authentication Code - ${fromUsername}`,
        html: this.getTwoFactorEmailTemplate({
          code,
          userName,
          fromUsername,
          expiresIn,
        }),
      };

      await transporter.sendMail(mailOptions);
      this.logger.log(`2FA code sent successfully to ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send 2FA code to ${email}:`, error);
      throw new Error('Failed to send verification email');
    }
  }

  async sendUserInviteEmail({
    email,
    inviteLink,
    invitedBy,
    inviteeName,
  }: {
    email: string;
    inviteLink: string;
    invitedBy: string;
    inviteeName?: string;
  }): Promise<void> {
    try {
      const transporter = await this.getTransporter();
      const smtpSettings = await this.getSMTPSettings();

      const mailOptions = {
        from: `"${smtpSettings.smtpFromName}" <${smtpSettings.smtpFromEmail}>`,
        to: email,
        subject: `You are invited to join`,
        html: this.getUserInviteTemplate({
          inviteLink,
          invitedBy,
          inviteeName,
        }),
      };

      await transporter.sendMail(mailOptions);
      this.logger.log(`User invite sent to ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send user invite to ${email}:`, error);
      throw new Error('Failed to send user invite email');
    }
  }

  async sendSuperAdminCredentials({
    email,
    password,
    appName,
  }: {
    email: string;
    password: string;
    appName: string;
  }): Promise<void> {
    try {
      const transporter = await this.getTransporter();
      const smtpSettings = await this.getSMTPSettings();

      const mailOptions = {
        from: `"${smtpSettings.smtpFromName}" <${smtpSettings.smtpFromEmail}>`,
        to: email,
        subject: `${appName} super admin credentials`,
        html: this.getSuperAdminCredentialsTemplate({
          appName,
          email,
          password,
        }),
      };

      await transporter.sendMail(mailOptions);
      this.logger.log(`Super admin credentials sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send super admin credentials to ${email}:`,
        error,
      );
      throw new Error('Failed to send super admin credentials email');
    }
  }

  async sendSetPasswordLink({
    email,
    link,
    appName,
    expiresInMinutes,
  }: {
    email: string;
    link: string;
    appName: string;
    expiresInMinutes: number;
  }): Promise<void> {
    try {
      const transporter = await this.getTransporter();
      const smtpSettings = await this.getSMTPSettings();

      const mailOptions = {
        from: `"${smtpSettings.smtpFromName}" <${smtpSettings.smtpFromEmail}>`,
        to: email,
        subject: `${appName} password setup`,
        html: this.getSetPasswordTemplate({
          appName,
          link,
          expiresInMinutes,
        }),
      };

      await transporter.sendMail(mailOptions);
      this.logger.log(`Password set link sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send set-password link to ${email}:`,
        error,
      );
      throw new Error('Failed to send set-password email');
    }
  }

  private getUserInviteTemplate({
    inviteLink,
    invitedBy,
    inviteeName,
  }: {
    inviteLink: string;
    invitedBy: string;
    inviteeName?: string;
  }): string {
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

  private getSuperAdminCredentialsTemplate({
    appName,
    email,
    password,
  }: {
    appName: string;
    email: string;
    password: string;
  }): string {
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

  private getSetPasswordTemplate({
    appName,
    link,
    expiresInMinutes,
  }: {
    appName: string;
    link: string;
    expiresInMinutes: number;
  }): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1.0" />
          <title>${appName} Password Setup</title>
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
                <h1>Set your password</h1>
              </div>
              <div class="content">
                <h2>Welcome to ${appName}</h2>
                <p class="lead">Use the button below to create or update your password. This link expires in ${expiresInMinutes} minutes.</p>
                <p style="text-align:center;">
                  <a class="btn" href="${link}" target="_blank" rel="noopener noreferrer">Set Password</a>
                </p>
                <p class="note">If you did not request this, you can safely ignore this email.</p>
              </div>
            </div>
          </div>
        </body>
      </html>
    `;
  }

  private getTwoFactorEmailTemplate({
    code,
    userName,
    fromUsername,
    expiresIn,
  }: {
    code: string;
    userName: string;
    fromUsername: string;
    expiresIn: number;
  }): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Two-Factor Authentication Code</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2c5aa0; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
          .code-box { background: #fff; border: 2px solid #2c5aa0; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
          .code { font-size: 32px; font-weight: bold; color: #2c5aa0; letter-spacing: 5px; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Two-Factor Authentication</h1>
          </div>
          <div class="content">
            <h2>Hello ${userName},</h2>
            <p>You have requested to enable Two-Factor Authentication for your account. Please use the verification code below to complete the setup:</p>
            
            <div class="code-box">
              <div class="code">${code}</div>
            </div>
            
            <div class="warning">
              <strong>⚠️ Important:</strong>
              <ul>
                <li>This code will expire in ${expiresIn} minutes</li>
                <li>Do not share this code with anyone</li>
                <li>If you didn't request this, please contact your administrator immediately</li>
              </ul>
            </div>
            
            <p>If you have any questions or need assistance, please contact our support team.</p>
            
            <p>Best regards,<br>
            <strong>${fromUsername} Team</strong></p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  async sendForgotPasswordResetCode({
    code,
    email,
    userName,
    fromUsername,
    expiresIn,
  }: {
    code: string;
    email: string;
    userName: string;
    fromUsername: string;
    expiresIn: number;
  }): Promise<void> {
    try {
      const transporter = await this.getTransporter();
      const smtpSettings = await this.getSMTPSettings();

      const mailOptions = {
        from: `"${smtpSettings.smtpFromName}" <${smtpSettings.smtpFromEmail}>`,
        to: email,
        subject: `Password Reset Code - ${fromUsername}`,
        html: this.getResetPasswordEmailTemplate({
          code,
          userName,
          fromUsername,
          expiresIn,
        }),
      };

      await transporter.sendMail(mailOptions);
      this.logger.log(`Password reset code sent successfully to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset code to ${email}:`,
        error,
      );
      throw new Error('Failed to send password reset email');
    }
  }

  private getResetPasswordEmailTemplate({
    code,
    userName,
    fromUsername,
    expiresIn,
  }: {
    code: string;
    userName: string;
    fromUsername: string;
    expiresIn: number;
  }): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Reset Code</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #d9534f; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
        .code-box { background: #fff; border: 2px solid #d9534f; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
        .code { font-size: 32px; font-weight: bold; color: #d9534f; letter-spacing: 5px; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        .button { display: inline-block; padding: 12px 24px; background: #d9534f; color: white; text-decoration: none; border-radius: 4px; margin: 15px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔒 Password Reset Request</h1>
        </div>
        <div class="content">
          <h2>Hello ${userName},</h2>
          <p>We received a request to reset your password for your account. Please use the verification code below to reset your password:</p>
          
          <div class="code-box">
            <div class="code">${code}</div>
          </div>
          
          <div class="warning">
            <strong>⚠️ Important Security Notice:</strong>
            <ul>
              <li>This code will expire in ${expiresIn} minutes</li>
              <li>Do not share this code with anyone</li>
              <li>If you didn't request a password reset, please ignore this email and contact your administrator immediately</li>
              <li>Your account security is important to us</li>
            </ul>
          </div>
          
          <p>Enter this code in the password reset page to create a new password for your account.</p>
          
          <p>If you have any questions or need assistance, please contact our support team.</p>
          
          <p>Best regards,<br>
          <strong>${fromUsername}</strong></p>
        </div>
        <div class="footer">
          <p>This is an automated message. Please do not reply to this email.</p>
          <p>For security reasons, this code can only be used once and will expire shortly.</p>
        </div>
      </div>
    </body>
    </html>
  `;
  }
}
