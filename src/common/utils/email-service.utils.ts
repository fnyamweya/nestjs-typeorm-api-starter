import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as nodemailer from 'nodemailer';
import { Setting } from 'src/setting/entities/setting.entity';
import type { SetPasswordAudience } from 'src/common/email/email.types';
import {
  getSetPasswordEmailContent,
  resolveSetPasswordAudience,
} from 'src/common/email/content/set-password.content';
import { renderUserInviteTemplate } from 'src/common/email/templates/user-invite.template';
import { renderSuperAdminCredentialsTemplate } from 'src/common/email/templates/super-admin-credentials.template';
import { renderTwoFactorEmailTemplate } from 'src/common/email/templates/two-factor.template';
import { renderResetPasswordEmailTemplate } from 'src/common/email/templates/reset-password-code.template';

@Injectable()
export class EmailServiceUtils {
  private readonly logger = new Logger(EmailServiceUtils.name);

  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
  ) {}

  private async sendEmail({
    to,
    subject,
    html,
  }: {
    to: string;
    subject: string;
    html: string;
  }): Promise<void> {
    const transporter = await this.getTransporter();
    const smtpSettings = await this.getSMTPSettings();

    const mailOptions = {
      from: `"${smtpSettings.smtpFromName}" <${smtpSettings.smtpFromEmail}>`,
      to,
      subject,
      html,
    };

    await transporter.sendMail(mailOptions);
  }

  private async getTransporter() {
    if (
      process.env.NODE_ENV === 'test' ||
      process.env.EMAIL_DISABLED === 'true'
    ) {
      // Avoid external SMTP calls during tests.
      return {
        // nodemailer expects sendMail to resolve with an info object; we don't need it in tests.
        sendMail: async () => ({
          accepted: [],
          rejected: [],
          response: 'skipped',
        }),
      } as any;
    }

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
      await this.sendEmail({
        to: email,
        subject: `Two-Factor Authentication Code - ${fromUsername}`,
        html: renderTwoFactorEmailTemplate({
          code,
          userName,
          fromUsername,
          expiresIn,
        }),
      });
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
      await this.sendEmail({
        to: email,
        subject: `You are invited to join`,
        html: renderUserInviteTemplate({
          inviteLink,
          invitedBy,
          inviteeName,
        }),
      });
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
      await this.sendEmail({
        to: email,
        subject: `${appName} super admin credentials`,
        html: renderSuperAdminCredentialsTemplate({
          appName,
          email,
          password,
        }),
      });
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
    audience,
  }: {
    email: string;
    link: string;
    appName: string;
    expiresInMinutes: number;
    audience?: SetPasswordAudience;
  }): Promise<void> {
    try {
      const resolvedAudience = resolveSetPasswordAudience(audience);
      const { subject, html } = getSetPasswordEmailContent({
        audience: resolvedAudience,
        appName,
        link,
        expiresInMinutes,
      });

      await this.sendEmail({ to: email, subject, html });
      this.logger.log(`Password set link sent to ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send set-password link to ${email}:`, error);
      throw new Error('Failed to send set-password email');
    }
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
      await this.sendEmail({
        to: email,
        subject: `Password Reset Code - ${fromUsername}`,
        html: renderResetPasswordEmailTemplate({
          code,
          userName,
          fromUsername,
          expiresIn,
        }),
      });
      this.logger.log(`Password reset code sent successfully to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset code to ${email}:`,
        error,
      );
      throw new Error('Failed to send password reset email');
    }
  }
}
